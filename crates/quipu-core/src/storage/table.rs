use super::segment::{skim, Segment, SegmentReader};
use crate::error::Result;
use crate::merkle::{leaf_hash, Hash};
use crate::merkle_log::{ConsistencyProof, InclusionProof, MerkleLog};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".log";
const META_SUFFIX: &str = ".meta";

/// Sidecar metadata persisted next to each *sealed* segment
/// (`seg-NNNNNNNNNN.meta`): the segment's time-range bounds and record count.
/// Written once at seal time, so reopening a table never has to re-skim
/// sealed segments, and time-range scans can skip out-of-range segments
/// without opening them. The sidecar is a *pruning/recovery hint only* — it
/// is rebuilt from a skim when missing or unreadable, and the
/// tamper-evidence chain never depends on it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SegmentMeta {
    /// `u64::MAX` when the segment holds no records.
    min_timestamp: u64,
    max_timestamp: u64,
    records: u64,
    /// Spine leaf index of this segment's first record (mirrors the segment
    /// header, kept here so reopening never has to read sealed headers).
    #[serde(default)]
    base_index: u64,
}

/// In-memory bookkeeping for one sealed segment.
#[derive(Debug, Clone)]
struct SealedSeg {
    path: PathBuf,
    meta: SegmentMeta,
}

/// A typed, append-only table: a directory of rolling segment files plus the
/// retention-independent Merkle spine that holds every record's leaf hash.
pub struct Table<T> {
    dir: PathBuf,
    active: Segment,
    active_seq: u64,
    /// Sealed segments by sequence number. Used by scans (read in seq order),
    /// retention (drop whole old segments) and checkpointing (record count).
    sealed: BTreeMap<u64, SealedSeg>,
    /// Append-only leaf-hash spine: the canonical integrity structure. Survives
    /// retention (it is never purged), so the Merkle root and every
    /// inclusion/consistency proof remain derivable after old segments are gone.
    spine: MerkleLog,
    max_segment_bytes: u64,
    _marker: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Table<T> {
    pub fn open(dir: &Path, max_segment_bytes: u64) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut seqs: Vec<u64> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name
                .strip_prefix(SEGMENT_PREFIX)
                .and_then(|s| s.strip_suffix(SEGMENT_SUFFIX))
                .and_then(|s| s.parse::<u64>().ok())
            {
                seqs.push(num);
            }
        }
        seqs.sort_unstable();
        let active_seq = seqs.last().copied().unwrap_or(0);
        let mut sealed = BTreeMap::new();
        for &seq in seqs.iter().filter(|&&s| s != active_seq) {
            let path = segment_path(dir, seq);
            let meta = match read_meta(&meta_path(dir, seq)) {
                Some(m) => m,
                None => {
                    // sidecar missing/unreadable (e.g. crash between seal and
                    // meta write): rebuild it from a one-time skim. The skim
                    // recovers base_index from the segment header.
                    let m = skim(&path)?
                        .map(|s| SegmentMeta {
                            min_timestamp: s.min_timestamp,
                            max_timestamp: s.max_timestamp,
                            records: s.records,
                            base_index: s.base_index,
                        })
                        .unwrap_or(SegmentMeta {
                            min_timestamp: u64::MAX,
                            max_timestamp: 0,
                            records: 0,
                            base_index: 0,
                        });
                    write_meta(&meta_path(dir, seq), &m);
                    m
                }
            };
            sealed.insert(seq, SealedSeg { path, meta });
        }
        // the base_index only matters when the active file is brand new, i.e.
        // the table is empty — an existing active segment keeps its own header.
        // When fresh, its base is the count of all already-sealed records.
        let active_base = sealed
            .values()
            .map(|s| s.meta.base_index + s.meta.records)
            .max()
            .unwrap_or(0);
        let active = Segment::open(&segment_path(dir, active_seq), active_base)?;
        let spine = MerkleLog::open(dir)?;
        let mut table = Self {
            dir: dir.to_path_buf(),
            active,
            active_seq,
            sealed,
            spine,
            max_segment_bytes,
            _marker: PhantomData,
        };
        table.reconcile_spine()?;
        Ok(table)
    }

    /// Bring the spine into lock-step with the segments after a crash. The
    /// append path writes a record's payload to its segment first, then its leaf
    /// hash to the spine, so a crash can leave the spine one or more leaves
    /// behind; torn-tail recovery truncating a segment can leave the spine
    /// ahead. Either way the segments are authoritative for *which records are
    /// durable*, so the spine is repaired to match them.
    ///
    /// `expected_total` is the absolute count of records ever appended that
    /// survive recovery: the active segment's base plus its record count
    /// (segment bases are contiguous, so this is the high-water mark).
    fn reconcile_spine(&mut self) -> Result<()> {
        let expected_total = self.active.base_index() + self.active.records();
        let spine_size = self.spine.size();
        if spine_size > expected_total {
            // spine ahead of durable records (segment lost a torn tail)
            self.spine.truncate(expected_total)?;
            self.spine.sync()?;
            return Ok(());
        }
        if spine_size == expected_total {
            return Ok(());
        }
        // spine behind: re-derive the missing tail leaves from the segments
        // that hold records at absolute index >= spine_size, in append order.
        let mut segments: Vec<(PathBuf, u64, u64)> = self
            .sealed
            .values()
            .map(|s| (s.path.clone(), s.meta.base_index, s.meta.records))
            .collect();
        segments.push((
            self.active.path().to_path_buf(),
            self.active.base_index(),
            self.active.records(),
        ));
        segments.sort_by_key(|(_, base, _)| *base);
        for (path, base, records) in segments {
            if base + records <= spine_size {
                continue; // every leaf in this segment is already on the spine
            }
            let mut reader = SegmentReader::open(&path)?;
            let mut idx = 0u64;
            while let Some((_, payload)) = reader.next_record()? {
                if base + idx >= spine_size {
                    self.spine.append(leaf_hash(&payload))?;
                }
                idx += 1;
            }
        }
        self.spine.sync()?;
        Ok(())
    }

    /// Append a row. `timestamp` is the row's logical time (drives retention).
    /// The payload lands in its segment first, then its leaf hash on the spine,
    /// in lock-step — a crash between the two is repaired on reopen by
    /// [`reconcile_spine`](Self::reconcile_spine).
    pub fn append(&mut self, row: &T, timestamp: u64) -> Result<()> {
        let payload = bincode::serialize(row)?;
        if !self.active.is_empty()
            && self.active.len() + payload.len() as u64 > self.max_segment_bytes
        {
            self.roll()?;
        }
        self.active.append(&payload, timestamp)?;
        self.spine.append(leaf_hash(&payload))?;
        Ok(())
    }

    fn roll(&mut self) -> Result<()> {
        self.active.sync()?;
        let meta = SegmentMeta {
            min_timestamp: self.active.min_timestamp,
            max_timestamp: self.active.max_timestamp,
            records: self.active.records(),
            base_index: self.active.base_index(),
        };
        // best-effort sidecar: a lost write is repaired by a skim on reopen
        write_meta(&meta_path(&self.dir, self.active_seq), &meta);
        self.sealed.insert(
            self.active_seq,
            SealedSeg {
                path: self.active.path().to_path_buf(),
                meta,
            },
        );
        self.active_seq += 1;
        // the new segment's first record sits at the next absolute spine index
        let next_base = meta.base_index + meta.records;
        self.active = Segment::open(&segment_path(&self.dir, self.active_seq), next_base)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.active.flush()?;
        self.spine.flush()
    }

    pub fn sync(&mut self) -> Result<()> {
        self.active.sync()?;
        self.spine.sync()
    }

    /// Stream every row in append order. The active segment is flushed first so
    /// the scan sees all appended data.
    pub fn scan(&mut self) -> Result<TableScan<T>> {
        Ok(TableScan::over(self.slices()?))
    }

    /// A point-in-time view of this table's data: every segment path with the
    /// byte length valid *right now*, plus the segment's time-range bounds
    /// and sequence number (which make time-range pruning and positional
    /// cursors possible). A reader holding these can scan on another thread
    /// while this table keeps appending — bytes past the recorded bound are
    /// simply outside the snapshot.
    pub fn slices(&mut self) -> Result<Vec<SegmentSlice>> {
        self.active.flush()?;
        let mut slices: Vec<SegmentSlice> = self
            .sealed
            .iter()
            .map(|(&seq, s)| SegmentSlice {
                path: s.path.clone(),
                bound: u64::MAX,
                seq,
                min_ts: s.meta.min_timestamp,
                max_ts: s.meta.max_timestamp,
            })
            .collect();
        slices.push(SegmentSlice {
            path: self.active.path().to_path_buf(),
            bound: self.active.len(),
            seq: self.active_seq,
            min_ts: self.active.min_timestamp,
            max_ts: self.active.max_timestamp,
        });
        Ok(slices)
    }

    /// Verify the table's tamper-evidence: re-derive each surviving record's
    /// leaf hash from its payload and confirm it matches the spine leaf at the
    /// record's absolute index (`segment base + offset`). An in-place payload
    /// edit changes the recomputed leaf and is caught here; editing both the
    /// payload and its spine leaf changes the Merkle root, which a signed
    /// checkpoint pins. Finally the spine is checked against its own on-disk
    /// leaves. Returns the verified Merkle root.
    pub fn verify(&mut self) -> Result<Hash> {
        self.active.flush()?;
        let leaves = self.spine.leaves()?;
        let mut segments: Vec<(PathBuf, u64)> = self
            .sealed
            .values()
            .map(|s| (s.path.clone(), s.meta.base_index))
            .collect();
        segments.push((self.active.path().to_path_buf(), self.active.base_index()));
        segments.sort_by_key(|(_, base)| *base);
        for (path, base) in segments {
            let mut reader = SegmentReader::open(&path)?;
            let mut idx = 0u64;
            while let Some((_, payload)) = reader.next_record()? {
                let abs = base + idx;
                let expected =
                    leaves
                        .get(abs as usize)
                        .ok_or_else(|| crate::error::Error::Corrupt {
                            segment: path.display().to_string(),
                            offset: abs,
                            reason: "record has no matching leaf in the merkle spine — the spine \
                                 was truncated or a segment was replaced"
                                .into(),
                        })?;
                if leaf_hash(&payload) != *expected {
                    return Err(crate::error::Error::Corrupt {
                        segment: path.display().to_string(),
                        offset: abs,
                        reason: "record payload does not match its merkle leaf — the record \
                                 was modified after being written"
                            .into(),
                    });
                }
                idx += 1;
            }
        }
        self.spine.verify()
    }

    /// Delete sealed segments whose newest record is older than `cutoff_micros`.
    /// Returns the number of segments removed. The active segment is never
    /// dropped, so the most recent rows always survive.
    pub fn purge_older_than(&mut self, cutoff_micros: u64) -> Result<usize> {
        let doomed: Vec<u64> = self
            .sealed
            .iter()
            .filter(|(_, s)| s.meta.max_timestamp < cutoff_micros)
            .map(|(&seq, _)| seq)
            .collect();
        for seq in &doomed {
            if let Some(s) = self.sealed.remove(seq) {
                std::fs::remove_file(s.path)?;
                let _ = std::fs::remove_file(meta_path(&self.dir, *seq));
            }
        }
        Ok(doomed.len())
    }

    /// Bytes on disk across all segments: sealed file sizes plus the active
    /// segment's current length (flushed first so the number is accurate).
    pub fn total_bytes(&mut self) -> Result<u64> {
        self.active.flush()?;
        let mut total = self.active.len();
        for s in self.sealed.values() {
            total += std::fs::metadata(&s.path)?.len();
        }
        Ok(total)
    }

    /// Max record timestamp of the oldest sealed segment (`None` when only
    /// the active segment exists). Drives the cross-table "drop the globally
    /// oldest first" order of capacity-based retention.
    pub fn oldest_sealed_max_ts(&self) -> Option<u64> {
        self.sealed.values().next().map(|s| s.meta.max_timestamp)
    }

    /// Unlink the oldest sealed segment and return the bytes freed (`None`
    /// when there is no sealed segment — the active one is never dropped).
    /// Like [`purge_older_than`](Self::purge_older_than) this removes a whole
    /// chain prefix, so it cannot break hash-chain verification.
    pub fn purge_oldest_sealed(&mut self) -> Result<Option<u64>> {
        let Some(&seq) = self.sealed.keys().next() else {
            return Ok(None);
        };
        let path = self.sealed.remove(&seq).expect("key just observed").path;
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        std::fs::remove_file(path)?;
        Ok(Some(bytes))
    }

    /// Sequence number of the segment currently being written.
    pub fn active_seq(&self) -> u64 {
        self.active_seq
    }

    /// Current Merkle root over every record ever appended (the canonical
    /// integrity value a checkpoint signs and an anchor exports).
    pub fn root(&self) -> Hash {
        self.spine.root()
    }

    /// Total records ever appended (the Merkle tree size). Unlike
    /// [`record_count`](Self::record_count) this never decreases — the spine is
    /// not subject to retention.
    pub fn spine_size(&self) -> u64 {
        self.spine.size()
    }

    /// Absolute spine index of the oldest record still on disk — the count of
    /// records retention has purged.
    pub fn purged_count(&self) -> u64 {
        self.sealed
            .values()
            .map(|s| s.meta.base_index)
            .min()
            .unwrap_or_else(|| self.active.base_index())
    }

    /// Records currently on disk across all segments. Decreases when
    /// retention unlinks sealed segments.
    pub fn record_count(&self) -> u64 {
        self.active.records() + self.sealed.values().map(|s| s.meta.records).sum::<u64>()
    }

    /// Inclusion proof for the record at absolute spine index `leaf_index`
    /// against the current tree.
    pub fn prove_inclusion(&mut self, leaf_index: u64) -> Result<InclusionProof> {
        self.spine.prove_inclusion(leaf_index)
    }

    /// Consistency proof that the tree of size `first_size` is a prefix of the
    /// current tree (append-only history preserved).
    pub fn prove_consistency(&mut self, first_size: u64) -> Result<ConsistencyProof> {
        self.spine.prove_consistency(first_size)
    }
}

impl<T: Serialize + DeserializeOwned> Table<T> {
    /// Drop every row: delete all sealed segments, reset the spine and start a
    /// fresh active segment. This is a full table wipe (not append-only) — it
    /// discards the Merkle history along with the data, so it must never be used
    /// on an audit table whose integrity must be provable; it exists for
    /// scratch/staging tables only.
    pub fn clear(&mut self) -> Result<()> {
        let old_active = self.active.path().to_path_buf();
        let old_seqs: Vec<u64> = self.sealed.keys().copied().collect();
        self.active_seq += 1;
        // open the new segment first so the old writer is dropped before its
        // file is unlinked (required for OS-independence, e.g. Windows)
        self.active = Segment::open(&segment_path(&self.dir, self.active_seq), 0)?;
        self.spine.truncate(0)?;
        self.spine.sync()?;
        std::fs::remove_file(old_active)?;
        for (_, s) in std::mem::take(&mut self.sealed) {
            std::fs::remove_file(s.path)?;
        }
        for seq in old_seqs {
            let _ = std::fs::remove_file(meta_path(&self.dir, seq));
        }
        Ok(())
    }
}

fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{seq:010}{SEGMENT_SUFFIX}"))
}

/// What [`rewrite_table`] did: the Merkle root before and after, and the
/// number of records carried over. The caller is expected to persist the
/// root transition somewhere auditable — a rewritten table (fresh spine) is
/// otherwise indistinguishable from a tampered one.
#[derive(Debug, Clone)]
pub struct RewriteStats {
    pub old_root: Hash,
    pub new_root: Hash,
    pub records: u64,
}

/// Rewrite every row of the table at `dir` through `f`, producing a *fresh*
/// Merkle spine. Row order and per-row timestamps are preserved.
///
/// The rewrite goes to a sibling `<dir>.rewrite` directory first and is
/// fsynced before the swap, so a crash mid-rewrite leaves the original table
/// untouched; a crash between the two renames leaves a `<dir>.pre-rewrite`
/// backup to recover from by hand. Offline use only — the caller must hold
/// the store lock and have dropped every other handle to this table.
pub fn rewrite_table<T: Serialize + DeserializeOwned>(
    dir: &Path,
    max_segment_bytes: u64,
    mut f: impl FnMut(T) -> Result<T>,
) -> Result<RewriteStats> {
    let name = dir
        .file_name()
        .ok_or_else(|| crate::error::Error::Encode("table dir has no name".into()))?
        .to_string_lossy();
    let tmp = dir.with_file_name(format!("{name}.rewrite"));
    let backup = dir.with_file_name(format!("{name}.pre-rewrite"));
    for stale in [&tmp, &backup] {
        if stale.exists() {
            std::fs::remove_dir_all(stale)?;
        }
    }

    let mut old: Table<T> = Table::open(dir, max_segment_bytes)?;
    let old_root = old.root();
    let slices = old.slices()?;
    let mut fresh: Table<T> = Table::open(&tmp, max_segment_bytes)?;
    for slice in slices {
        let mut reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
        while let Some((ts, payload)) = reader.next_record()? {
            let row: T = bincode::deserialize(&payload)?;
            fresh.append(&f(row)?, ts)?;
        }
    }
    fresh.sync()?;
    let new_root = fresh.root();
    let records = fresh.record_count();

    // close both tables before touching their directories
    drop(old);
    drop(fresh);
    std::fs::rename(dir, &backup)?;
    std::fs::rename(&tmp, dir)?;
    std::fs::remove_dir_all(&backup)?;
    Ok(RewriteStats {
        old_root,
        new_root,
        records,
    })
}

fn meta_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{seq:010}{META_SUFFIX}"))
}

fn read_meta(path: &Path) -> Option<SegmentMeta> {
    let bytes = std::fs::read(path).ok()?;
    bincode::deserialize(&bytes).ok()
}

/// Best-effort: the sidecar is a hint, not a source of truth, so a failed
/// write only means a skim on the next open.
fn write_meta(path: &Path, meta: &SegmentMeta) {
    if let Ok(bytes) = bincode::serialize(meta) {
        let _ = std::fs::write(path, bytes);
    }
}

/// One segment file plus the byte length that belongs to a snapshot, its
/// sequence number, and its time-range bounds (`min_ts == u64::MAX` when the
/// segment holds no records).
#[derive(Debug, Clone)]
pub struct SegmentSlice {
    pub path: PathBuf,
    pub bound: u64,
    pub seq: u64,
    pub min_ts: u64,
    pub max_ts: u64,
}

pub struct TableScan<T> {
    slices: Vec<SegmentSlice>,
    current: Option<SegmentReader>,
    idx: usize,
    _marker: PhantomData<T>,
}

impl<T> TableScan<T> {
    /// Scan rows out of a set of snapshot slices (see [`Table::slices`]).
    pub fn over(slices: Vec<SegmentSlice>) -> Self {
        Self {
            slices,
            current: None,
            idx: 0,
            _marker: PhantomData,
        }
    }
}

impl<T: DeserializeOwned> TableScan<T> {
    pub fn next_row(&mut self) -> Result<Option<T>> {
        loop {
            if self.current.is_none() {
                if self.idx >= self.slices.len() {
                    return Ok(None);
                }
                let s = &self.slices[self.idx];
                self.idx += 1;
                // a slice may have been unlinked by retention between the
                // snapshot and this scan — the rows were past the retention
                // window anyway, so a vanished segment is "aged out", not an
                // error (concurrent retention + query must not fail reads)
                self.current = match SegmentReader::open_bounded(&s.path, s.bound) {
                    Ok(r) => Some(r),
                    Err(crate::error::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        continue;
                    }
                    Err(e) => return Err(e),
                };
            }
            if let Some((_, payload)) = self.current.as_mut().unwrap().next_record()? {
                return Ok(Some(bincode::deserialize(&payload)?));
            }
            self.current = None;
        }
    }
}

impl<T: DeserializeOwned> Iterator for TableScan<T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_row().transpose()
    }
}

/// Physical position of a record inside a table snapshot: (segment sequence
/// number, record index within that segment). Append-only storage makes a
/// position permanent — a record never moves, so positions are stable across
/// snapshots and survive concurrent appends. Retention can only *remove*
/// whole old segments, which scans handle by skipping absent sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub seq: u64,
    pub idx: u64,
}

/// Time/position-bounded scan over snapshot slices, in ascending or
/// descending position order. This is the scalable query primitive:
///
/// - segments entirely outside `[from, to]` are never opened (their bounds
///   come from the slice metadata),
/// - segments entirely before/after a positional cursor are never opened,
/// - rows outside the time range are skipped *before* deserialization (the
///   timestamp lives in the frame header).
///
/// Descending order buffers one segment at a time (segments are read
/// front-to-back, then drained in reverse) — memory is bounded by
/// `max_segment_bytes`, never by table size.
pub struct PositionedScan<T> {
    /// Remaining slices in scan order (reversed up front for descending).
    slices: Vec<SegmentSlice>,
    slice_idx: usize,
    desc: bool,
    from: u64,
    to: u64,
    /// Exclusive start position in scan direction: ascending yields only
    /// positions > after, descending only positions < after.
    after: Option<Position>,
    /// Forward reader state (ascending).
    current: Option<(u64, u64, SegmentReader)>, // (seq, next idx, reader)
    /// Buffered rows of the current segment (descending), drained from the back.
    buffered: Vec<(Position, u64, Vec<u8>)>,
    /// Segments actually opened — observability for pruning tests/benches.
    segments_opened: u64,
    _marker: PhantomData<T>,
}

impl<T> PositionedScan<T> {
    pub fn new(
        mut slices: Vec<SegmentSlice>,
        desc: bool,
        from: Option<u64>,
        to: Option<u64>,
        after: Option<Position>,
    ) -> Self {
        slices.sort_by_key(|s| s.seq);
        if desc {
            slices.reverse();
        }
        Self {
            slices,
            slice_idx: 0,
            desc,
            from: from.unwrap_or(0),
            to: to.unwrap_or(u64::MAX),
            after,
            current: None,
            buffered: Vec::new(),
            segments_opened: 0,
            _marker: PhantomData,
        }
    }

    /// Number of segment files this scan actually opened so far.
    pub fn segments_opened(&self) -> u64 {
        self.segments_opened
    }

    /// True when the whole segment can be skipped without opening it.
    fn prune(&self, s: &SegmentSlice) -> bool {
        // time-range pruning: bounds never assume rows are time-ordered
        if s.max_ts < self.from || s.min_ts > self.to {
            return true;
        }
        // cursor pruning: whole segments on the consumed side of the cursor
        match self.after {
            Some(p) if !self.desc && s.seq < p.seq => true,
            Some(p) if self.desc && s.seq > p.seq => true,
            _ => false,
        }
    }

    fn in_range(&self, ts: u64) -> bool {
        ts >= self.from && ts <= self.to
    }

    fn past_cursor(&self, pos: Position) -> bool {
        match self.after {
            None => true,
            Some(p) => {
                if self.desc {
                    pos < p
                } else {
                    pos > p
                }
            }
        }
    }
}

impl<T: DeserializeOwned> PositionedScan<T> {
    /// Next matching row with its position, or `None` when exhausted.
    pub fn next_row(&mut self) -> Result<Option<(Position, T)>> {
        if self.desc {
            self.next_desc()
        } else {
            self.next_asc()
        }
    }

    fn next_asc(&mut self) -> Result<Option<(Position, T)>> {
        loop {
            if self.current.is_none() {
                let Some(slice) = self.next_slice()? else {
                    return Ok(None);
                };
                let reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
                self.current = Some((slice.seq, 0, reader));
            }
            let (seq, idx, reader) = self.current.as_mut().unwrap();
            match reader.next_record()? {
                Some((ts, payload)) => {
                    let pos = Position {
                        seq: *seq,
                        idx: *idx,
                    };
                    *idx += 1;
                    if self.in_range(ts) && self.past_cursor(pos) {
                        return Ok(Some((pos, bincode::deserialize(&payload)?)));
                    }
                }
                None => self.current = None,
            }
        }
    }

    fn next_desc(&mut self) -> Result<Option<(Position, T)>> {
        loop {
            if let Some((pos, _, payload)) = self.buffered.pop() {
                return Ok(Some((pos, bincode::deserialize(&payload)?)));
            }
            let Some(slice) = self.next_slice()? else {
                return Ok(None);
            };
            // segments only support forward reads (frames are forward-framed),
            // so buffer the matching rows of this one segment and drain the
            // buffer back-to-front
            let mut reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
            let mut idx = 0u64;
            while let Some((ts, payload)) = reader.next_record()? {
                let pos = Position {
                    seq: slice.seq,
                    idx,
                };
                idx += 1;
                if self.in_range(ts) && self.past_cursor(pos) {
                    self.buffered.push((pos, ts, payload));
                }
            }
        }
    }

    /// Advance to the next non-prunable slice; counts opened segments. A
    /// slice whose file vanished (retention ran between snapshot and scan
    /// for sealed segments is impossible — the snapshot holder keeps paths,
    /// not file handles) is surfaced as the underlying I/O error.
    fn next_slice(&mut self) -> Result<Option<SegmentSlice>> {
        while self.slice_idx < self.slices.len() {
            let s = self.slices[self.slice_idx].clone();
            self.slice_idx += 1;
            if self.prune(&s) {
                continue;
            }
            self.segments_opened += 1;
            return Ok(Some(s));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Row {
        ts: u64,
        msg: String,
    }

    fn fill(t: &mut Table<Row>, n: u64) {
        for i in 0..n {
            t.append(
                &Row {
                    ts: i,
                    msg: format!("row-{i}"),
                },
                i,
            )
            .unwrap();
        }
        t.sync().unwrap();
    }

    #[test]
    fn rolls_segments_scans_and_purges() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let rows: Vec<Row> = t.scan().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 50);
        let files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(SEGMENT_SUFFIX)
            })
            .count();
        assert!(files > 1, "expected rolled segments, got {files}");

        // reopen: scan still complete, then purge old segments
        drop(t);
        let mut t2: Table<Row> = Table::open(dir.path(), 256).unwrap();
        assert_eq!(t2.scan().unwrap().count(), 50);
        let purged = t2.purge_older_than(40).unwrap();
        assert!(purged > 0);
        let remaining: Vec<Row> = t2.scan().unwrap().map(|r| r.unwrap()).collect();
        assert!(remaining.len() < 50);
        // newest rows survive (active segment is never purged)
        assert_eq!(remaining.last().unwrap().msg, "row-49");
        // purged segments take their sidecars with them
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy().to_string();
            if let Some(seq) = name
                .strip_prefix(SEGMENT_PREFIX)
                .and_then(|s| s.strip_suffix(META_SUFFIX))
            {
                let seg = dir.path().join(format!("seg-{seq}.log"));
                assert!(seg.exists(), "orphaned sidecar {name}");
            }
        }
    }

    #[test]
    fn sidecar_meta_survives_reopen_and_rebuilds_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let slices_before = t.slices().unwrap();
        assert!(slices_before.len() > 1);
        drop(t);

        // delete one sidecar — open must rebuild identical bounds via skim
        let victim = meta_path(dir.path(), slices_before[0].seq);
        assert!(victim.exists());
        std::fs::remove_file(&victim).unwrap();
        let mut t2: Table<Row> = Table::open(dir.path(), 256).unwrap();
        let slices_after = t2.slices().unwrap();
        for (b, a) in slices_before.iter().zip(&slices_after) {
            assert_eq!((b.seq, b.min_ts, b.max_ts), (a.seq, a.min_ts, a.max_ts));
        }
        assert!(victim.exists(), "sidecar was not rebuilt");
    }

    #[test]
    fn positioned_scan_prunes_by_time_and_orders_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let slices = t.slices().unwrap();
        let total_segments = slices.len() as u64;

        // ascending, full range
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices.clone(), false, None, None, None);
        let mut asc = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            asc.push(row.ts);
        }
        assert_eq!(asc, (0..50).collect::<Vec<_>>());
        assert_eq!(scan.segments_opened(), total_segments);

        // descending, full range
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices.clone(), true, None, None, None);
        let mut desc = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            desc.push(row.ts);
        }
        assert_eq!(desc, (0..50).rev().collect::<Vec<_>>());

        // narrow time range: only segments overlapping [45, 49] are opened
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices, true, Some(45), Some(49), None);
        let mut hits = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            hits.push(row.ts);
        }
        assert_eq!(hits, vec![49, 48, 47, 46, 45]);
        assert!(
            scan.segments_opened() < total_segments,
            "pruning opened all {total_segments} segments"
        );
    }

    #[test]
    fn verify_passes_and_root_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let root;
        {
            let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
            fill(&mut t, 40);
            root = t.verify().unwrap();
            assert_eq!(t.spine_size(), 40);
        }
        let mut t2: Table<Row> = Table::open(dir.path(), 256).unwrap();
        assert_eq!(t2.spine_size(), 40);
        assert_eq!(t2.root(), root);
        assert_eq!(t2.verify().unwrap(), root);
    }

    /// A crash after a segment append but before the spine append leaves the
    /// spine one or more leaves behind; reopen must re-derive them.
    #[test]
    fn reconcile_repairs_a_spine_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let root;
        {
            let mut t: Table<Row> = Table::open(dir.path(), 4096).unwrap();
            fill(&mut t, 25);
            root = t.root();
        }
        // simulate the crash: drop the last 2 leaf entries (64 bytes) from the
        // spine, as if those appends never reached it
        let spine = dir.path().join("merkle.spine");
        let len = std::fs::metadata(&spine).unwrap().len();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&spine)
            .unwrap();
        f.set_len(len - 64).unwrap();
        drop(f);

        let mut t: Table<Row> = Table::open(dir.path(), 4096).unwrap();
        assert_eq!(t.spine_size(), 25, "spine re-derived from the segments");
        assert_eq!(t.root(), root);
        assert_eq!(t.verify().unwrap(), root);
    }

    /// A crash that loses a torn segment tail can leave the spine ahead of the
    /// durable records; reopen must truncate it back to match.
    #[test]
    fn reconcile_truncates_a_spine_ahead() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut t: Table<Row> = Table::open(dir.path(), 4096).unwrap();
            fill(&mut t, 25);
        }
        // shrink the (single) segment by one whole record's worth of bytes so
        // skim drops it, while the spine still holds its leaf
        let seg = dir.path().join("seg-0000000000.log");
        let len = std::fs::metadata(&seg).unwrap().len();
        let row_bytes = (crate::storage::segment::FRAME_HEADER as u64)
            + bincode::serialize(&Row {
                ts: 0,
                msg: "row-24".into(),
            })
            .unwrap()
            .len() as u64;
        let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        f.set_len(len - row_bytes).unwrap();
        drop(f);

        let mut t: Table<Row> = Table::open(dir.path(), 4096).unwrap();
        assert_eq!(
            t.spine_size(),
            24,
            "spine truncated to the surviving records"
        );
        assert_eq!(t.record_count(), 24);
        t.verify().unwrap();
    }

    /// Retention can unlink a sealed segment between a snapshot and the scan
    /// that uses it; the scan must treat the vanished file as aged-out data,
    /// not fail the whole query.
    #[test]
    fn scan_skips_segments_purged_after_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        for i in 0..50u64 {
            t.append(
                &Row {
                    ts: i,
                    msg: format!("row-{i}"),
                },
                i,
            )
            .unwrap();
        }
        t.sync().unwrap();
        let slices = t.slices().unwrap();
        assert!(slices.len() > 2, "need several segments for this test");

        // "retention" unlinks the first sealed segment after the snapshot
        std::fs::remove_file(&slices[0].path).unwrap();

        let rows: Vec<Row> = TableScan::<Row>::over(slices)
            .collect::<Result<Vec<_>>>()
            .expect("scan must not fail on a purged segment");
        assert!(!rows.is_empty() && rows.len() < 50);
        assert_eq!(rows.last().unwrap().msg, "row-49");
    }
}

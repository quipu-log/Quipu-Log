use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Segment file header: magic + format version + base index. The version byte
/// is the migration hook — readers reject formats they do not understand instead
/// of misparsing frames.
///
/// Format v2 dropped the per-record hash chain entirely (no header seed, no
/// per-frame chain hash). Tamper-evidence now lives in the retention-independent
/// Merkle spine ([`crate::merkle_log`]); a segment carries only payloads plus a
/// CRC for accidental-corruption detection. See [`crate::merkle`] for why the
/// integrity backbone cannot live in purgeable segment frames.
///
/// `base_index` is the spine leaf index of this segment's first record — the
/// count of all records appended to the table before this segment opened. It is
/// written once at creation and lets a record's absolute Merkle position survive
/// retention (which unlinks whole older segments): a surviving record's leaf
/// index is `base_index + its offset within the segment`, independent of how
/// many older segments were purged. Storing it per-segment (not as a mutable
/// counter) is what makes the mapping crash-safe across a partial purge.
pub const MAGIC: [u8; 4] = *b"ALOG";
pub const FORMAT_VERSION: u8 = 2;
pub const SEGMENT_HEADER: usize = MAGIC.len() + 1 + 8;

/// Frame layout: u32 payload length, u32 crc32(payload), u64 record timestamp,
/// then the payload. The timestamp lives in the header (not the payload) so
/// retention can skim a segment's time range without deserializing rows. The
/// CRC catches accidental damage only; in-place payload edits are caught by the
/// Merkle spine, which verification re-derives leaf hashes against.
pub const FRAME_HEADER: usize = 4 + 4 + 8;
/// Hard upper bound for a single record; protects recovery from interpreting
/// garbage as a multi-gigabyte length and trying to allocate it.
pub const MAX_RECORD: u32 = 64 * 1024 * 1024;

/// What [`skim`] learned about an existing segment file.
#[derive(Debug)]
pub struct Skim {
    /// Length of the valid prefix (header + whole, CRC-clean frames).
    pub valid_len: u64,
    /// Lowest record timestamp in the file (`u64::MAX` when empty); paired
    /// with `max_timestamp` it bounds the segment's time range so scans can
    /// skip segments entirely outside a queried window.
    pub min_timestamp: u64,
    pub max_timestamp: u64,
    /// Number of valid frames; feeds the table-level record count that
    /// integrity checkpoints attest to.
    pub records: u64,
    /// Spine leaf index of this segment's first record (from the header).
    pub base_index: u64,
}

/// One append-only segment file, opened for writing.
pub struct Segment {
    path: PathBuf,
    writer: BufWriter<File>,
    len: u64,
    /// Lowest record timestamp in the file (`u64::MAX` while empty); together
    /// with `max_timestamp` it gives the time-range bound used to prune scans.
    pub min_timestamp: u64,
    /// Highest record timestamp in the file; drives retention decisions.
    pub max_timestamp: u64,
    records: u64,
    base_index: u64,
}

impl Segment {
    /// Open (creating if needed) a segment for appending. `base_index` is the
    /// spine leaf index of the first record and is written only when the file is
    /// created; an existing file keeps its own. A torn tail from a crash is
    /// truncated back to the last whole record.
    pub fn open(path: &Path, base_index: u64) -> Result<Self> {
        let skimmed = skim(path)?;
        // append-style open: existing contents must survive (truncate(false))
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        match skimmed {
            Some(s) => {
                if file.metadata()?.len() > s.valid_len {
                    file.set_len(s.valid_len)?;
                }
                let mut writer = BufWriter::with_capacity(256 * 1024, file);
                writer.seek(SeekFrom::Start(s.valid_len))?;
                Ok(Self {
                    path: path.to_path_buf(),
                    writer,
                    len: s.valid_len,
                    min_timestamp: s.min_timestamp,
                    max_timestamp: s.max_timestamp,
                    records: s.records,
                    base_index: s.base_index,
                })
            }
            None => {
                // fresh file (or a header torn mid-write): write a new header
                file.set_len(0)?;
                let mut writer = BufWriter::with_capacity(256 * 1024, file);
                writer.write_all(&MAGIC)?;
                writer.write_all(&[FORMAT_VERSION])?;
                writer.write_all(&base_index.to_le_bytes())?;
                Ok(Self {
                    path: path.to_path_buf(),
                    writer,
                    len: SEGMENT_HEADER as u64,
                    min_timestamp: u64::MAX,
                    max_timestamp: 0,
                    records: 0,
                    base_index,
                })
            }
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len <= SEGMENT_HEADER as u64
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of records in this segment.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Spine leaf index of this segment's first record.
    pub fn base_index(&self) -> u64 {
        self.base_index
    }

    /// Append one framed payload. Returns the offset the record starts at.
    /// Data lands in the buffer; call [`flush`]/[`sync`] per the durability policy.
    pub fn append(&mut self, payload: &[u8], timestamp: u64) -> Result<u64> {
        if payload.len() as u64 > MAX_RECORD as u64 {
            return Err(Error::Encode(format!(
                "record of {} bytes exceeds MAX_RECORD",
                payload.len()
            )));
        }
        let offset = self.len;
        let crc = crc32fast::hash(payload);
        self.writer
            .write_all(&(payload.len() as u32).to_le_bytes())?;
        self.writer.write_all(&crc.to_le_bytes())?;
        self.writer.write_all(&timestamp.to_le_bytes())?;
        self.writer.write_all(payload)?;
        self.len += (FRAME_HEADER + payload.len()) as u64;
        self.min_timestamp = self.min_timestamp.min(timestamp);
        self.max_timestamp = self.max_timestamp.max(timestamp);
        self.records += 1;
        Ok(offset)
    }

    /// Push buffered bytes to the OS page cache.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Flush and fsync — survives power loss, costs a disk round-trip.
    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }
}

/// Returns the segment's `base_index` from the header.
fn read_header(reader: &mut impl Read, path: &Path) -> Result<u64> {
    let mut head = [0u8; SEGMENT_HEADER];
    reader.read_exact(&mut head)?;
    if head[0..4] != MAGIC {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: "bad magic (not an audit segment file)".into(),
        });
    }
    let version = head[4];
    if version != FORMAT_VERSION {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: format!(
                "unsupported segment format version {version} (this build reads version {FORMAT_VERSION})"
            ),
        });
    }
    let base_index = u64::from_le_bytes(head[5..SEGMENT_HEADER].try_into().unwrap());
    Ok(base_index)
}

/// Skim an existing segment: validate the header and every frame (length +
/// crc), returning `None` for a missing/empty file. Payloads are read only for
/// the crc.
pub fn skim(path: &Path) -> Result<Option<Skim>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let total = file.metadata()?.len();
    if total < SEGMENT_HEADER as u64 {
        // empty, or the header itself was torn mid-write: rewrite from scratch
        return Ok(None);
    }
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let base_index = read_header(&mut reader, path)?;
    let mut valid = SEGMENT_HEADER as u64;
    let mut min_ts = u64::MAX;
    let mut max_ts = 0u64;
    let mut records = 0u64;
    let mut header = [0u8; FRAME_HEADER];
    let mut buf = Vec::new();
    loop {
        if total - valid < FRAME_HEADER as u64 {
            break;
        }
        reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let ts = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if len > MAX_RECORD || total - valid - (FRAME_HEADER as u64) < len as u64 {
            break;
        }
        buf.resize(len as usize, 0);
        reader.read_exact(&mut buf)?;
        if crc32fast::hash(&buf) != crc {
            break;
        }
        valid += (FRAME_HEADER + len as usize) as u64;
        min_ts = min_ts.min(ts);
        max_ts = max_ts.max(ts);
        records += 1;
    }
    Ok(Some(Skim {
        valid_len: valid,
        min_timestamp: min_ts,
        max_timestamp: max_ts,
        records,
        base_index,
    }))
}

/// Sequential reader over one segment's records.
pub struct SegmentReader {
    path: PathBuf,
    reader: BufReader<File>,
    offset: u64,
    end: u64,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_bounded(path, u64::MAX)
    }

    /// Open with an upper read bound — a snapshot reader uses the length the
    /// writer had reached at snapshot time, so bytes appended concurrently
    /// afterwards (possibly half-flushed) are never touched.
    pub fn open_bounded(path: &Path, bound: u64) -> Result<Self> {
        let file = File::open(path)?;
        let end = file.metadata()?.len().min(bound);
        let mut reader = BufReader::with_capacity(256 * 1024, file);
        if end >= SEGMENT_HEADER as u64 {
            read_header(&mut reader, path)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            reader,
            offset: SEGMENT_HEADER.min(end as usize) as u64,
            end,
        })
    }

    /// Read the next record as (timestamp, payload), or `None` at end of segment.
    pub fn next_record(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        if self.end - self.offset < FRAME_HEADER as u64 {
            return Ok(None);
        }
        let mut header = [0u8; FRAME_HEADER];
        self.reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let ts = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if len > MAX_RECORD || self.end - self.offset - (FRAME_HEADER as u64) < len as u64 {
            // torn tail: treat like EOF (writer-side recovery truncates it)
            return Ok(None);
        }
        let mut buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut buf)?;
        if crc32fast::hash(&buf) != crc {
            return Err(Error::Corrupt {
                segment: self.path.display().to_string(),
                offset: self.offset,
                reason: "crc mismatch".into(),
            });
        }
        self.offset += (FRAME_HEADER + len as usize) as u64;
        Ok(Some((ts, buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_read_and_recover_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, 0).unwrap();
            seg.append(b"alpha", 1).unwrap();
            seg.append(b"beta", 2).unwrap();
            seg.sync().unwrap();
        }
        // simulate a crash mid-write: append garbage half-frame
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        }
        let mut seg = Segment::open(&path, 0).unwrap();
        assert_eq!(seg.max_timestamp, 2);
        seg.append(b"gamma", 3).unwrap();
        seg.sync().unwrap();

        let mut r = SegmentReader::open(&path).unwrap();
        let mut got = Vec::new();
        while let Some((ts, rec)) = r.next_record().unwrap() {
            got.push((ts, rec));
        }
        assert_eq!(
            got,
            vec![
                (1, b"alpha".to_vec()),
                (2, b"beta".to_vec()),
                (3, b"gamma".to_vec())
            ]
        );
    }

    #[test]
    fn crc_catches_accidental_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, 0).unwrap();
            seg.append(b"original", 1).unwrap();
            seg.sync().unwrap();
        }
        // flip a payload byte without fixing the crc
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start((SEGMENT_HEADER + FRAME_HEADER) as u64))
                .unwrap();
            f.write_all(b"X").unwrap();
        }
        let mut r = SegmentReader::open(&path).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("crc mismatch"), "{err}");
    }

    #[test]
    fn unsupported_format_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, 0).unwrap();
            seg.append(b"x", 1).unwrap();
            seg.sync().unwrap();
        }
        {
            let mut f = OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(4)).unwrap();
            f.write_all(&[99]).unwrap(); // future format version
        }
        let err = skim(&path).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported segment format version"),
            "{err}"
        );
    }
}

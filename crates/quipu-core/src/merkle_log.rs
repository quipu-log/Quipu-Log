//! Persistent append-only spine for the [`crate::merkle`] history tree.
//!
//! The Merkle root is computed over the ordered list of record leaf hashes. The
//! segment frames already hold those leaf hashes, but retention deletes whole
//! old segments — and once a leaf is gone the root can no longer be recomputed
//! from what survives. The integrity backbone therefore cannot live only in the
//! purgeable segments.
//!
//! `MerkleLog` is that backbone: a single append-only file at the store root
//! holding every leaf hash, 32 bytes each, behind a small header. It is *not*
//! subject to retention (hashes carry no payload, so keeping them leaks
//! nothing), which is what lets the root — and every inclusion/consistency
//! proof — survive after the underlying records have been purged.
//!
//! ```text
//! [ "QMKL" magic ][ u8 version ][ leaf_0 (32B) ][ leaf_1 (32B) ] ...
//! ```
//!
//! The append hot path writes 32 bytes and updates the incremental
//! [`crate::merkle::Roots`] tracker (amortised O(1)); the current root is then
//! free. Proof generation reads the leaf hashes back and defers to the RFC 6962
//! routines in [`crate::merkle`]. Reloading the spine on open recomputes the
//! `Roots` tracker by streaming the file once.

use crate::error::{Error, Result};
use crate::merkle::{consistency_proof, inclusion_proof, Hash, Roots};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "merkle.spine";
const MAGIC: [u8; 4] = *b"QMKL";
const VERSION: u8 = 1;
const HEADER: usize = MAGIC.len() + 1;
const ENTRY: usize = 32;

/// An inclusion proof carried alongside the tree size it was produced against,
/// so a verifier has everything [`crate::merkle::verify_inclusion`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the proven leaf (0-based, append order).
    pub leaf_index: u64,
    /// Tree size the proof and root refer to.
    pub tree_size: u64,
    /// Leaf hash of the proven record.
    pub leaf: Hash,
    /// Audit path, leaf-to-root.
    pub path: Vec<Hash>,
}

/// A consistency proof between two tree sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub path: Vec<Hash>,
}

/// The append-only leaf-hash spine. Owns a buffered writer positioned at the
/// end of the file and the incremental root tracker.
pub struct MerkleLog {
    path: PathBuf,
    writer: BufWriter<File>,
    roots: Roots,
}

impl MerkleLog {
    /// Open (creating if needed) the spine under `dir`. A torn tail — a partial
    /// 32-byte entry left by a crash mid-append — is truncated back to the last
    /// whole leaf, mirroring segment recovery.
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join(FILE_NAME);
        let leaves = load(&path)?;
        let roots = Roots::from_leaves(&leaves);
        let valid_len = (HEADER + leaves.len() * ENTRY) as u64;

        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        if file.metadata()?.len() != valid_len {
            // either a fresh/empty file (write the header) or a torn tail
            if valid_len <= HEADER as u64 {
                file.set_len(0)?;
                let mut w = BufWriter::new(file);
                w.write_all(&MAGIC)?;
                w.write_all(&[VERSION])?;
                w.flush()?;
                let file = w.into_inner().map_err(|e| Error::Io(e.into_error()))?;
                let mut writer = BufWriter::new(file);
                writer.seek(SeekFrom::Start(HEADER as u64))?;
                return Ok(Self {
                    path,
                    writer,
                    roots,
                });
            }
            file.set_len(valid_len)?;
        }
        let mut writer = BufWriter::new(file);
        writer.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            path,
            writer,
            roots,
        })
    }

    /// Number of leaves committed so far.
    pub fn size(&self) -> u64 {
        self.roots.size()
    }

    /// Current Merkle root over every appended leaf.
    pub fn root(&self) -> Hash {
        self.roots.root()
    }

    /// Append one record's leaf hash. Buffered; pair with [`flush`](Self::flush)
    /// or [`sync`](Self::sync) per the store's durability policy.
    pub fn append(&mut self, leaf: Hash) -> Result<()> {
        self.writer.write_all(&leaf)?;
        self.roots.push(leaf);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Every committed leaf hash, in append order. Flushes first so the buffer
    /// is visible. Used by table verification to re-derive leaves against the
    /// surviving record payloads.
    pub fn leaves(&mut self) -> Result<Vec<Hash>> {
        self.flush()?;
        load(&self.path)
    }

    /// Truncate the spine back to `new_size` leaves and rebuild the root
    /// tracker. Used only by crash reconciliation: when a torn segment tail was
    /// truncated below what the spine already recorded, the orphaned leaves
    /// correspond to records that never became durable, so dropping them keeps
    /// the spine and segments consistent. `new_size` must not exceed the current
    /// size.
    pub fn truncate(&mut self, new_size: u64) -> Result<()> {
        self.flush()?;
        let leaves = load(&self.path)?;
        let n = leaves.len() as u64;
        if new_size > n {
            return Err(Error::Encode(format!(
                "cannot truncate spine to {new_size}: only {n} leaves present"
            )));
        }
        if new_size == n {
            return Ok(());
        }
        let valid_len = HEADER as u64 + new_size * ENTRY as u64;
        self.writer.flush()?;
        self.writer.get_ref().set_len(valid_len)?;
        self.writer.seek(SeekFrom::Start(valid_len))?;
        self.roots = Roots::from_leaves(&leaves[..new_size as usize]);
        Ok(())
    }

    /// Flush and fsync — the spine must be at least as durable as any
    /// checkpoint that pins its root.
    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    /// Inclusion proof for the leaf at `leaf_index` against the current tree.
    pub fn prove_inclusion(&mut self, leaf_index: u64) -> Result<InclusionProof> {
        self.flush()?;
        let leaves = load(&self.path)?;
        let n = leaves.len() as u64;
        if leaf_index >= n {
            return Err(Error::Encode(format!(
                "leaf index {leaf_index} out of range for tree size {n}"
            )));
        }
        let path = inclusion_proof(&leaves, leaf_index as usize);
        Ok(InclusionProof {
            leaf_index,
            tree_size: n,
            leaf: leaves[leaf_index as usize],
            path,
        })
    }

    /// Consistency proof that the tree of size `first_size` is a prefix of the
    /// current tree.
    pub fn prove_consistency(&mut self, first_size: u64) -> Result<ConsistencyProof> {
        self.flush()?;
        let leaves = load(&self.path)?;
        let n = leaves.len() as u64;
        if first_size > n {
            return Err(Error::Encode(format!(
                "prior size {first_size} exceeds tree size {n}"
            )));
        }
        let path = consistency_proof(&leaves, first_size as usize);
        Ok(ConsistencyProof {
            first_size,
            second_size: n,
            path,
        })
    }

    /// Re-read the spine from disk and confirm it still hashes to `self.root()`.
    /// Catches in-place edits to the spine file itself (a record's committed
    /// leaf hash cannot be altered without changing the root, which a signed
    /// checkpoint pins). Returns the verified root.
    pub fn verify(&mut self) -> Result<Hash> {
        self.flush()?;
        let leaves = load(&self.path)?;
        let on_disk = Roots::from_leaves(&leaves).root();
        let live = self.roots.root();
        if on_disk != live {
            return Err(Error::Corrupt {
                segment: self.path.display().to_string(),
                offset: 0,
                reason: "merkle spine root does not match its leaves — the spine was edited".into(),
            });
        }
        Ok(live)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Read and validate the spine header, returning every whole leaf hash. A
/// trailing partial entry (torn append) is ignored — the caller truncates it.
fn load(path: &Path) -> Result<Vec<Hash>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let total = file.metadata()?.len();
    if total < HEADER as u64 {
        return Ok(Vec::new());
    }
    let mut reader = BufReader::new(file);
    let mut head = [0u8; HEADER];
    reader.read_exact(&mut head)?;
    if head[0..4] != MAGIC {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: "bad magic (not a merkle spine file)".into(),
        });
    }
    if head[4] != VERSION {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: format!(
                "unsupported merkle spine version {} (this build reads {VERSION})",
                head[4]
            ),
        });
    }
    let count = (total - HEADER as u64) / ENTRY as u64;
    let mut leaves = Vec::with_capacity(count as usize);
    let mut buf = [0u8; ENTRY];
    for _ in 0..count {
        reader.read_exact(&mut buf)?;
        leaves.push(buf);
    }
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{leaf_hash, mth, verify_consistency, verify_inclusion};

    fn leaf(i: usize) -> Hash {
        leaf_hash(format!("event-{i}").as_bytes())
    }

    #[test]
    fn root_matches_reference_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let expected;
        {
            let mut log = MerkleLog::open(dir.path()).unwrap();
            for i in 0..100 {
                log.append(leaf(i)).unwrap();
            }
            log.sync().unwrap();
            let leaves: Vec<Hash> = (0..100).map(leaf).collect();
            expected = mth(&leaves);
            assert_eq!(log.root(), expected);
            assert_eq!(log.size(), 100);
        }
        // reopen: incremental root rebuilt from disk equals the same value
        let log = MerkleLog::open(dir.path()).unwrap();
        assert_eq!(log.size(), 100);
        assert_eq!(log.root(), expected);
    }

    #[test]
    fn proofs_from_disk_verify_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = MerkleLog::open(dir.path()).unwrap();
        for i in 0..73 {
            log.append(leaf(i)).unwrap();
        }
        log.sync().unwrap();
        let root = log.root();

        for i in 0..73u64 {
            let p = log.prove_inclusion(i).unwrap();
            assert!(verify_inclusion(
                &p.leaf,
                p.leaf_index as usize,
                p.tree_size as usize,
                &p.path,
                &root
            ));
        }

        // consistency between an earlier size and now
        let earlier_leaves: Vec<Hash> = (0..40).map(leaf).collect();
        let earlier_root = mth(&earlier_leaves);
        let c = log.prove_consistency(40).unwrap();
        assert!(verify_consistency(
            c.first_size as usize,
            c.second_size as usize,
            &earlier_root,
            &root,
            &c.path
        ));
    }

    #[test]
    fn torn_tail_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = MerkleLog::open(dir.path()).unwrap();
            for i in 0..10 {
                log.append(leaf(i)).unwrap();
            }
            log.sync().unwrap();
        }
        // simulate a crash mid-append: half a leaf entry
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&[1, 2, 3, 4, 5]).unwrap();
        }
        let mut log = MerkleLog::open(dir.path()).unwrap();
        assert_eq!(log.size(), 10);
        // appends still land correctly after recovery
        log.append(leaf(10)).unwrap();
        log.sync().unwrap();
        let leaves: Vec<Hash> = (0..11).map(leaf).collect();
        assert_eq!(log.root(), mth(&leaves));
    }

    #[test]
    fn in_place_edit_of_spine_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = MerkleLog::open(dir.path()).unwrap();
        for i in 0..20 {
            log.append(leaf(i)).unwrap();
        }
        log.sync().unwrap();
        assert!(log.verify().is_ok());

        // flip a byte inside the third leaf entry
        {
            let mut f = OpenOptions::new()
                .write(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.seek(SeekFrom::Start((HEADER + 2 * ENTRY + 7) as u64))
                .unwrap();
            f.write_all(&[0xaa]).unwrap();
        }
        // a freshly opened log hashes the tampered leaves to a different root...
        let tampered = MerkleLog::open(dir.path()).unwrap();
        assert_ne!(tampered.root(), log.root());
        // ...and verify() against the live (pre-tamper) tracker fails
        assert!(log.verify().is_err());
    }
}

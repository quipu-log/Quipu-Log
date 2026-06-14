//! Append-only segment storage.
//!
//! A *table* is a directory of numbered segment files plus a Merkle spine
//! ([`crate::merkle_log`]). Every segment starts with a header (`ALOG` magic,
//! format version byte, base index) and every record is framed as
//!
//! ```text
//! [u32 LE payload length][u32 crc32(payload)][u64 timestamp][payload]
//! ```
//!
//! Tamper-evidence lives in the spine, not the segments: each record's leaf
//! hash is appended to the retention-independent spine, whose Merkle root a
//! signed checkpoint pins. The segment CRC catches only accidental corruption.
//! Appends go through a `BufWriter` and are flushed to the OS per batch; an
//! optional fsync policy controls durability vs. throughput. Recovery scans
//! each segment, truncates a torn tail (partial last record after a crash), and
//! reconciles the spine to match. Retention deletes whole segments, which keeps
//! purging an O(1) filesystem operation; the spine (hashes only, no payloads)
//! is kept so proofs survive. Only `std::fs`/`std::io` are used, so behaviour is
//! identical on every OS Rust targets.

mod segment;
mod table;

pub use segment::{Segment, SegmentReader};
pub use table::{
    rewrite_table, Position, PositionedScan, RewriteStats, SegmentSlice, Table, TableScan,
};

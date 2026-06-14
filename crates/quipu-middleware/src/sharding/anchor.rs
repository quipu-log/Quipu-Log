//! Cross-shard checkpoint anchoring — global integrity glue (option D, ADR-5).
//!
//! Sharding splits one chain into many, and per-shard [`verify_integrity`] keeps
//! each chain honest. But splitting opens a class of attack no single shard can
//! see: an insider can **delete a whole shard**, **roll one shard back** to an
//! earlier state, or **edit the shard map** to hide a shard — and every
//! surviving shard still verifies clean, because each chain is internally
//! consistent. Nothing inside one shard vouches for the *set* of shards.
//!
//! A [`GlobalCheckpoint`] closes that gap. It pins, under one signature, every
//! shard's latest checkpoint head (Merkle root + tree size) together with a
//! hash of the routing manifest, and is exported to the same external anchor a
//! single store already uses. Later, [`verify_global`](super::ShardRouter::verify_global)
//! recomputes the current heads and compares: a shard that went missing, went
//! backwards, or a map that changed is now detectable.
//!
//! This is about *integrity*, not *order*: there is still no global sequence
//! (ADR-2). Ordering across shards stays clock-based; this signature is purely
//! cryptographic tamper-evidence over the shard set.
//!
//! Pinning the Merkle *tree size* (total records ever appended) rather than the
//! live record count means retention no longer looks like a rollback: the tree
//! size only ever grows, even as retention purges old segments. A rollback is a
//! shard whose tree size went *down*, or whose root changed at an unchanged
//! size — both genuine tampering.

use super::shard_map::{ShardId, ShardMap};
use quipu_core::{Error, KeyRing, Result as CoreResult};
use serde::{Deserialize, Serialize};

/// Domain separation: a global-checkpoint signature must never be confusable
/// with a per-shard [`quipu_core::Checkpoint`] signature made by the same key.
const SIGNING_DOMAIN: &[u8] = b"quipu-global-checkpoint-v2\0";

/// One shard's pinned position inside a [`GlobalCheckpoint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHead {
    pub shard: ShardId,
    /// Hex of the shard's Merkle root at anchor time.
    pub merkle_root_hex: String,
    /// Total records ever appended to the shard at anchor time — the Merkle tree
    /// size. Monotonic: never decreases, even under retention.
    pub tree_size: u64,
}

/// A signed pin over the whole sharded store: every shard's latest checkpoint
/// head plus a hash of the routing manifest. See the module docs for the threat
/// it addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalCheckpoint {
    /// UTC micros at signing time.
    pub signed_at: u64,
    /// SHA-256 (hex) of [`ShardMap::manifest_bytes`] at anchor time.
    pub manifest_hash: String,
    /// Every shard's pinned head, sorted by shard id.
    pub heads: Vec<ShardHead>,
    /// [`quipu_core::KeyVersion`] of the RSA key that signed this anchor.
    pub key_version: u32,
    /// RSA PKCS#1 v1.5 / SHA-256 signature over the fields above.
    pub signature: Vec<u8>,
}

/// Outcome of a [`verify_global`](super::ShardRouter::verify_global) pass. Like
/// a per-shard [`VerifyReport`](crate::VerifyReport), a detected problem is a
/// *successful* verification with `ok: false` — `Err` means the check itself
/// could not run.
#[derive(Debug, Clone, Default)]
pub struct GlobalVerifyReport {
    pub ok: bool,
    pub problems: Vec<String>,
}

fn signing_bytes(signed_at: u64, manifest_hash: &str, heads: &[ShardHead]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + 12 + manifest_hash.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(&signed_at.to_le_bytes());
    out.extend_from_slice(manifest_hash.as_bytes());
    out.extend_from_slice(&(heads.len() as u32).to_le_bytes());
    for h in heads {
        out.extend_from_slice(&h.shard.0.to_le_bytes());
        out.extend_from_slice(&h.tree_size.to_le_bytes());
        out.extend_from_slice(h.merkle_root_hex.as_bytes());
    }
    out
}

impl GlobalCheckpoint {
    pub(crate) fn sign(
        keys: &KeyRing,
        signed_at: u64,
        manifest_hash: String,
        heads: Vec<ShardHead>,
    ) -> CoreResult<Self> {
        let (key_version, signature) =
            keys.sign(&signing_bytes(signed_at, &manifest_hash, &heads))?;
        Ok(Self {
            signed_at,
            manifest_hash,
            heads,
            key_version,
            signature,
        })
    }

    /// Check the anchor's own signature against the ring's public key.
    pub fn verify_signature(&self, keys: &KeyRing) -> CoreResult<()> {
        keys.verify_signature(
            self.key_version,
            &signing_bytes(self.signed_at, &self.manifest_hash, &self.heads),
            &self.signature,
        )
        .map_err(|e| Error::Crypto(format!("global checkpoint signature invalid: {e}")))
    }
}

/// SHA-256 (hex) of a map's canonical manifest bytes.
pub(crate) fn manifest_hash(map: &ShardMap) -> String {
    quipu_core::crypto::sha256_hex(&map.manifest_bytes())
}

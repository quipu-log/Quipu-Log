//! Tenant → shard routing.
//!
//! Two hard rules come straight from the design ([`docs/specs/horizontal-scaling`]):
//!
//! - A shard, once **frozen**, never takes another write. That is how the
//!   "single writer for the life of a chain" invariant survives resharding:
//!   we never move a record between chains, we only stop writing to old chains
//!   and start new ones.
//! - Routing is by **consistent hashing** over the *active* shards, so adding a
//!   shard remaps only a fraction of tenants instead of reshuffling everyone.
//!
//! Reads are different from writes: a tenant that was remapped by a reshard has
//! history on the shard that *used* to own it (now frozen). So a tenant-scoped
//! read targets the current active owner **plus every frozen shard**; only the
//! other active shards (which never held this tenant) can be pruned.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Identifier of one shard. Renders as `shard-0000` for on-disk roots.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ShardId(pub u32);

impl ShardId {
    /// Directory name for this shard's store root under the sharded layout.
    pub fn dir_name(&self) -> String {
        format!("shard-{:04}", self.0)
    }
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.dir_name())
    }
}

impl fmt::Debug for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShardId({})", self.0)
    }
}

/// Virtual nodes per active shard on the hash ring. Higher = smoother tenant
/// distribution at the cost of a larger ring; 64 keeps imbalance within a few
/// percent for a handful of shards while staying cheap to rebuild.
const VNODES_PER_SHARD: u32 = 64;

/// The routing table: which shards are writable, which are frozen, and the
/// consistent-hash ring used to map a tenant to its active owner.
///
/// This is the in-memory form of `root/shards.json`. It is rebuilt, never
/// mutated in place on disk: a reshard writes a fresh manifest with a temp +
/// rename so a crash mid-reshard can never leave a half-written ring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardMap {
    seed: u64,
    active: Vec<ShardId>,
    frozen: Vec<ShardId>,
    /// Sorted `(hash, shard)` ring over *active* shards only. Rebuilt from
    /// `active` whenever it changes; not serialized (derived state).
    #[serde(skip)]
    ring: Vec<(u64, ShardId)>,
}

impl ShardMap {
    /// A map over `n` active shards (ids `0..n`), no frozen shards. `n` must be
    /// at least 1; `n == 1` is the degenerate single-shard case that behaves
    /// exactly like an unsharded store.
    pub fn new(n: u32, seed: u64) -> Self {
        assert!(n >= 1, "a shard map needs at least one active shard");
        let active = (0..n).map(ShardId).collect();
        let mut m = Self {
            seed,
            active,
            frozen: Vec::new(),
            ring: Vec::new(),
        };
        m.rebuild_ring();
        m
    }

    /// Reconstruct a map from its persisted fields (active/frozen/seed). Use
    /// after deserializing `shards.json`, since the ring is derived state.
    pub fn from_parts(active: Vec<ShardId>, frozen: Vec<ShardId>, seed: u64) -> Self {
        assert!(
            !active.is_empty(),
            "a shard map needs at least one active shard"
        );
        let mut m = Self {
            seed,
            active,
            frozen,
            ring: Vec::new(),
        };
        m.rebuild_ring();
        m
    }

    fn rebuild_ring(&mut self) {
        let mut ring = Vec::with_capacity(self.active.len() * VNODES_PER_SHARD as usize);
        for shard in &self.active {
            for v in 0..VNODES_PER_SHARD {
                ring.push((self.hash(&(shard.0, v)), *shard));
            }
        }
        ring.sort_by_key(|(h, _)| *h);
        self.ring = ring;
    }

    fn hash<T: Hash>(&self, key: &T) -> u64 {
        let mut h = DefaultHasher::new();
        self.seed.hash(&mut h);
        key.hash(&mut h);
        h.finish()
    }

    /// The active shard that owns new writes for `tenant`. Frozen shards are
    /// never returned — that is the single-writer-for-life guarantee.
    pub fn route_write(&self, tenant: &str) -> ShardId {
        let h = self.hash(&tenant);
        // First ring point at or after `h`, wrapping to the front.
        match self.ring.binary_search_by_key(&h, |(rh, _)| *rh) {
            Ok(i) => self.ring[i].1,
            Err(i) if i < self.ring.len() => self.ring[i].1,
            Err(_) => self.ring[0].1, // wrap-around
        }
    }

    /// Shards a read must consult. With a tenant: its current active owner plus
    /// every frozen shard (a remapped tenant's old history lives on a frozen
    /// shard). Without a tenant: every shard, active and frozen.
    pub fn read_targets(&self, tenant: Option<&str>) -> Vec<ShardId> {
        match tenant {
            Some(t) => {
                let mut targets = Vec::with_capacity(1 + self.frozen.len());
                targets.push(self.route_write(t));
                for f in &self.frozen {
                    if !targets.contains(f) {
                        targets.push(*f);
                    }
                }
                targets
            }
            None => self.all_shards().collect(),
        }
    }

    /// Every shard, active first then frozen — for fan-out admin ops (verify,
    /// flush, retention) and tenant-less queries.
    pub fn all_shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.active.iter().chain(self.frozen.iter()).copied()
    }

    pub fn active(&self) -> &[ShardId] {
        &self.active
    }

    pub fn frozen(&self) -> &[ShardId] {
        &self.frozen
    }

    /// Stop writing to `shard`: move it from the active set to the frozen set
    /// and drop it off the write ring. Idempotent. After this, `route_write`
    /// never returns `shard`, but reads still reach it.
    pub fn freeze(&mut self, shard: ShardId) {
        if let Some(pos) = self.active.iter().position(|s| *s == shard) {
            assert!(
                self.active.len() > 1,
                "cannot freeze the last active shard — writes would have nowhere to go"
            );
            self.active.remove(pos);
            if !self.frozen.contains(&shard) {
                self.frozen.push(shard);
            }
            self.rebuild_ring();
        }
    }

    /// Canonical serialization of the routing manifest — the seed plus the
    /// sorted active and frozen shard sets. A cross-shard anchor signs the hash
    /// of these bytes (see [`crate::ShardRouter::global_checkpoint`]) so a
    /// silent map edit — a shard dropped, swapped, or un-frozen on disk — is
    /// detectable even when every surviving shard still verifies on its own.
    /// Stable across runs: sets are sorted, so the bytes do not depend on
    /// insertion order.
    pub fn manifest_bytes(&self) -> Vec<u8> {
        let mut active: Vec<u32> = self.active.iter().map(|s| s.0).collect();
        let mut frozen: Vec<u32> = self.frozen.iter().map(|s| s.0).collect();
        active.sort_unstable();
        frozen.sort_unstable();
        let mut out = Vec::with_capacity(32 + 4 * (active.len() + frozen.len()));
        out.extend_from_slice(b"quipu-shardmap-v1\0");
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&(active.len() as u32).to_le_bytes());
        for s in active {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out.extend_from_slice(&(frozen.len() as u32).to_le_bytes());
        for s in frozen {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// Bring a brand-new shard online for writes. Its store root must already
    /// exist and be empty. Remaps only the tenants whose ring position now
    /// falls on the new shard's virtual nodes.
    pub fn add_active(&mut self, shard: ShardId) {
        if !self.active.contains(&shard) && !self.frozen.contains(&shard) {
            self.active.push(shard);
            self.rebuild_ring();
        }
    }
}

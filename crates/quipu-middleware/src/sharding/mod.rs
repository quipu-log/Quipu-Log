//! Horizontal scaling by **sharded chains**.
//!
//! The store engine is single-writer by design: one thread owns one hash chain,
//! and that is what makes "this log wasn't altered" provable without cross-node
//! consensus. Sharding scales *out* without touching that invariant — it runs
//! **N independent stores**, each a full [`AuditPipeline`] with its own writer
//! thread, chain, registry, and signed checkpoints. Writes for a tenant are
//! routed to one owning shard; reads fan out and merge by timestamp.
//!
//! What scales:
//! - **Writes** — N writer threads instead of one; throughput grows with N.
//! - **Reads** — sealed segments are immutable, so they replicate freely to
//!   query nodes; a query fans out and [merges](fanout) per-shard results.
//!
//! What is preserved:
//! - **One writer per chain, for the life of the chain.** Resharding never
//!   moves a record; it [freezes](ShardMap::freeze) old shards and adds new
//!   ones ([`ShardMap`]).
//! - **Per-shard tamper-evidence.** Each shard keeps the full chain +
//!   checkpoint + anchor + [`verify_integrity`](ShardRouter::verify) story.
//!
//! See `docs/specs/horizontal-scaling/solution-design.md`.

mod anchor;
mod fanout;
mod shard_map;

pub use anchor::{GlobalCheckpoint, GlobalVerifyReport, ShardHead};
pub use fanout::{MergedPage, MultiCursor};
pub use shard_map::{ShardId, ShardMap};

use crate::event::AuditEvent;
use crate::permissions::Role;
use crate::pipeline::{AuditHandle, AuditPipeline, MiddlewareError, RedriveReport, VerifyReport};
use quipu_core::{
    AccessQuery, AccessRecord, CustomColumnDef, KeyRing, LogQuery, LogView, TargetSnapshot,
    TypeSchema,
};
use std::collections::BTreeMap;

struct ShardEntry {
    pipeline: AuditPipeline,
    handle: AuditHandle,
}

/// Owns the shards and routes operations across them. A single-shard router
/// (`ShardMap::new(1, _)`) behaves exactly like one [`AuditPipeline`].
pub struct ShardRouter {
    map: ShardMap,
    shards: BTreeMap<u32, ShardEntry>,
}

impl ShardRouter {
    /// Build a router from a routing map and the shards' pipelines. Every shard
    /// id named in `map` (active and frozen) must be present in `shards`, and
    /// vice versa.
    pub fn new(map: ShardMap, shards: Vec<(ShardId, AuditPipeline)>) -> Self {
        let shards = shards
            .into_iter()
            .map(|(id, pipeline)| {
                let handle = pipeline.handle();
                (id.0, ShardEntry { pipeline, handle })
            })
            .collect::<BTreeMap<_, _>>();

        debug_assert!(
            map.all_shards().all(|s| shards.contains_key(&s.0)),
            "every shard in the map must have a pipeline"
        );
        Self { map, shards }
    }

    /// The routing table (active/frozen sets, ring). Read-only; mutate through
    /// [`freeze`](Self::freeze) / [`add_shard`](Self::add_shard).
    pub fn map(&self) -> &ShardMap {
        &self.map
    }

    fn handle(&self, shard: ShardId) -> Result<&AuditHandle, MiddlewareError> {
        self.shards
            .get(&shard.0)
            .map(|e| &e.handle)
            .ok_or(MiddlewareError::WorkerGone)
    }

    /// Append an event to the shard that owns `tenant`. Frozen shards never
    /// receive writes, so this always targets an active shard.
    pub fn emit(
        &self,
        role: &Role,
        tenant: &str,
        event: AuditEvent,
    ) -> Result<ShardId, MiddlewareError> {
        let shard = self.map.route_write(tenant);
        self.handle(shard)?.emit(role, event)?;
        Ok(shard)
    }

    /// First page of a query. With `tenant`, only that tenant's owning shard
    /// (plus frozen shards) are consulted; without it, every shard. `q.limit`
    /// bounds the page; use [`query_page`](Self::query_page) to paginate.
    pub fn query(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
    ) -> Result<Vec<LogView>, MiddlewareError> {
        let limit = q.limit.unwrap_or(usize::MAX).min(100_000);
        Ok(self.query_page(role, tenant, q, None, limit)?.logs)
    }

    /// One page of a cross-shard query, merged by `(timestamp, log_id)`.
    /// Pass the previous page's [`MergedPage::next_cursor`] to continue.
    pub fn query_page(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
        cursor: Option<MultiCursor>,
        limit: usize,
    ) -> Result<MergedPage, MiddlewareError> {
        let targets = self.map.read_targets(tenant);
        let order = q.order;
        fanout::query_merged(
            &targets,
            order,
            limit,
            cursor,
            |shard, shard_cursor, lim| {
                let mut sq = q.clone();
                sq.cursor = shard_cursor;
                sq.limit = Some(lim);
                self.handle(shard)?.query_page(role, sq)
            },
        )
    }

    /// Count a query's matches across the relevant shards (summed).
    pub fn count(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
    ) -> Result<u64, MiddlewareError> {
        let mut total = 0;
        for shard in self.map.read_targets(tenant) {
            total += self.handle(shard)?.count(role, q.clone())?;
        }
        Ok(total)
    }

    /// Latest version of every entity of a type, across the tenant's shards
    /// (concatenated; an entity id is unique to the shard that owns it).
    pub fn list_entities(
        &self,
        role: &Role,
        tenant: Option<&str>,
        type_name: &str,
        include_deleted: bool,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        let mut out = Vec::new();
        for shard in self.map.read_targets(tenant) {
            out.extend(
                self.handle(shard)?
                    .list_entities(role, type_name, include_deleted)?,
            );
        }
        Ok(out)
    }

    /// Full version history of one entity (oldest first within each shard;
    /// after a reshard an id can span a frozen + an active shard).
    pub fn entity_history(
        &self,
        role: &Role,
        tenant: Option<&str>,
        type_name: &str,
        entity_id: &str,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        let mut out = Vec::new();
        for shard in self.map.read_targets(tenant) {
            out.extend(
                self.handle(shard)?
                    .entity_history(role, type_name, entity_id)?,
            );
        }
        Ok(out)
    }

    /// Schemas of all defined types (identical on every shard; read from the
    /// first available shard).
    pub fn entity_types(&self, role: &Role) -> Result<Vec<TypeSchema>, MiddlewareError> {
        let first = self
            .map
            .all_shards()
            .next()
            .ok_or(MiddlewareError::WorkerGone)?;
        self.handle(first)?.entity_types(role)
    }

    /// Read the meta-audit access log across all shards (concatenated).
    pub fn query_access(
        &self,
        role: &Role,
        q: AccessQuery,
    ) -> Result<Vec<AccessRecord>, MiddlewareError> {
        let mut out = Vec::new();
        for shard in self.map.all_shards() {
            out.extend(self.handle(shard)?.query_access(role, q.clone())?);
        }
        Ok(out)
    }

    /// Record a meta-audit access entry on every shard — for store-wide system
    /// actions (e.g. an auth reload) that aren't tied to one tenant.
    pub fn record_access_all(&self, rec: AccessRecord) {
        for shard in self.map.all_shards() {
            if let Ok(h) = self.handle(shard) {
                h.record_access(rec.clone());
            }
        }
    }

    /// Register a type on **every** shard — schemas are per-store, so a sharded
    /// deployment must define the type on each. Stops at the first failure.
    pub fn define_type(&self, role: &Role, schema: TypeSchema) -> Result<(), MiddlewareError> {
        for shard in self.map.all_shards() {
            self.handle(shard)?.define_type(role, schema.clone())?;
        }
        Ok(())
    }

    /// Register a custom log column on every shard.
    pub fn define_custom_column(
        &self,
        role: &Role,
        def: CustomColumnDef,
    ) -> Result<(), MiddlewareError> {
        for shard in self.map.all_shards() {
            self.handle(shard)?
                .define_custom_column(role, def.clone())?;
        }
        Ok(())
    }

    /// Replay parked DLQ events on every shard; returns the summed report.
    pub fn redrive_dlq(&self, role: &Role) -> Result<RedriveReport, MiddlewareError> {
        let mut total = RedriveReport::default();
        for shard in self.map.all_shards() {
            let r = self.handle(shard)?.redrive_dlq(role)?;
            total.replayed += r.replayed;
            total.requeued += r.requeued;
            total.quarantined_entries += r.quarantined_entries;
            total.quarantined_segments += r.quarantined_segments;
        }
        Ok(total)
    }

    /// Total parked DLQ entries across all shards.
    pub fn dlq_len(&self, role: &Role) -> Result<usize, MiddlewareError> {
        let mut total = 0;
        for shard in self.map.all_shards() {
            total += self.handle(shard)?.dlq_len(role)?;
        }
        Ok(total)
    }

    /// Flush every shard's writer (blocks until each queue drains).
    pub fn flush(&self) -> Result<(), MiddlewareError> {
        for shard in self.map.all_shards() {
            self.handle(shard)?.flush()?;
        }
        Ok(())
    }

    /// Run retention on every shard; returns the total segments dropped.
    pub fn apply_retention(&self, role: &Role) -> Result<usize, MiddlewareError> {
        let mut total = 0;
        for shard in self.map.all_shards() {
            total += self.handle(shard)?.apply_retention(role)?;
        }
        Ok(total)
    }

    /// Verify each shard independently. Every chain is its own; a break in one
    /// shard does not invalidate the others.
    pub fn verify(&self, role: &Role) -> Result<BTreeMap<ShardId, VerifyReport>, MiddlewareError> {
        let mut reports = BTreeMap::new();
        for shard in self.map.all_shards() {
            reports.insert(shard, self.handle(shard)?.verify_integrity(role)?);
        }
        Ok(reports)
    }

    /// Verify every shard and fold the results into one report: `ok` only if
    /// all shards are ok, counts summed, problems prefixed with their shard.
    pub fn verify_combined(&self, role: &Role) -> Result<VerifyReport, MiddlewareError> {
        let mut combined = VerifyReport {
            ok: true,
            segments_checked: 0,
            log_records: 0,
            problems: Vec::new(),
        };
        for (shard, r) in self.verify(role)? {
            combined.ok &= r.ok;
            combined.segments_checked += r.segments_checked;
            combined.log_records += r.log_records;
            combined
                .problems
                .extend(r.problems.into_iter().map(|p| format!("{shard}: {p}")));
        }
        Ok(combined)
    }

    /// **Option D — cross-shard checkpoint anchoring.** Pin every shard's
    /// latest checkpoint head plus the routing manifest under one signature.
    /// This is the *global integrity* glue: per-shard [`verify`](Self::verify)
    /// cannot see a whole shard being deleted, rolled back, or hidden by a map
    /// edit — every surviving shard still verifies — but a signed pin over the
    /// *set* of heads makes those detectable. Export the returned anchor to the
    /// same external trust domain the per-shard checkpoints use.
    ///
    /// Forces a fresh checkpoint on each shard, so `keys` (and every shard
    /// store) must hold an RSA signing key; a shard that cannot checkpoint is an
    /// error rather than a silently un-anchored gap. Re-anchor after a retention
    /// run — see the [`anchor`] module caveat.
    pub fn global_checkpoint(
        &self,
        role: &Role,
        keys: &KeyRing,
    ) -> Result<GlobalCheckpoint, MiddlewareError> {
        let heads = self.collect_heads(role)?;
        let manifest = anchor::manifest_hash(&self.map);
        GlobalCheckpoint::sign(keys, quipu_core::time::now_micros(), manifest, heads)
            .map_err(MiddlewareError::Core)
    }

    /// Verify a previously signed [`GlobalCheckpoint`] against the store as it
    /// stands now. Flags a bad signature, a changed shard manifest, a missing
    /// shard (deleted/detached), or a shard whose record count went backwards
    /// (rolled back / truncated). A clean run is `ok: true` with no problems.
    pub fn verify_global(
        &self,
        role: &Role,
        anchored: &GlobalCheckpoint,
        keys: &KeyRing,
    ) -> Result<GlobalVerifyReport, MiddlewareError> {
        let mut problems = Vec::new();
        if let Err(e) = anchored.verify_signature(keys) {
            // a forged/tampered anchor is itself the finding — stop here
            return Ok(GlobalVerifyReport {
                ok: false,
                problems: vec![e.to_string()],
            });
        }
        if anchor::manifest_hash(&self.map) != anchored.manifest_hash {
            problems.push(
                "shard manifest changed since the anchor was signed (a shard was added, \
                 removed, or the map was edited) — re-anchor after a legitimate reshard"
                    .into(),
            );
        }
        let current = self.collect_heads(role)?;
        let current_by_id: BTreeMap<u32, &ShardHead> =
            current.iter().map(|h| (h.shard.0, h)).collect();
        for anc in &anchored.heads {
            match current_by_id.get(&anc.shard.0) {
                None => problems.push(format!(
                    "{}: shard is missing — its chain was deleted or detached since the anchor",
                    anc.shard
                )),
                Some(cur) if cur.record_count < anc.record_count => problems.push(format!(
                    "{}: rolled back — {} records now, {} at anchor time \
                     (records were removed or the chain was truncated)",
                    anc.shard, cur.record_count, anc.record_count
                )),
                Some(_) => {}
            }
        }
        Ok(GlobalVerifyReport {
            ok: problems.is_empty(),
            problems,
        })
    }

    /// Force a checkpoint on every shard and collect the pinned heads (sorted by
    /// shard id). A shard with no checkpoint to pin (no signing key) is an error.
    fn collect_heads(&self, role: &Role) -> Result<Vec<ShardHead>, MiddlewareError> {
        let mut heads = Vec::new();
        for shard in self.map.all_shards() {
            let cp = self.handle(shard)?.checkpoint(role)?.ok_or_else(|| {
                MiddlewareError::Core(quipu_core::Error::Crypto(format!(
                    "{shard}: cannot anchor — shard holds no signing key, so it has no \
                     checkpoint head to pin"
                )))
            })?;
            heads.push(ShardHead {
                shard,
                chain_head_hex: cp.chain_head_hex(),
                record_count: cp.record_count,
            });
        }
        heads.sort_by_key(|h| h.shard.0);
        Ok(heads)
    }

    /// Per-shard metrics snapshots (queue depth, DLQ size, counters, latency).
    pub fn metrics(&self) -> BTreeMap<ShardId, crate::metrics::MetricsSnapshot> {
        self.shards
            .iter()
            .map(|(id, e)| (ShardId(*id), e.handle.metrics()))
            .collect()
    }

    /// Per-shard health snapshots (writer liveness, disk-full latch, low-disk).
    /// A sharded front folds these into one store-wide health verdict.
    pub fn health(&self) -> BTreeMap<ShardId, crate::health::HealthSnapshot> {
        self.shards
            .iter()
            .map(|(id, e)| (ShardId(*id), e.handle.health()))
            .collect()
    }

    /// A handle to one shard, for host code that needs a representative handle
    /// (e.g. shared health flags) without caring which shard. Shards are kept in
    /// id order, so this is the lowest-id shard. `None` only if there are none.
    pub fn representative_handle(&self) -> Option<AuditHandle> {
        self.shards.values().next().map(|e| e.handle.clone())
    }

    /// Reshard: stop writing to `shard`. Existing data stays put and stays
    /// readable; new writes for its tenants move to an active shard. Preserves
    /// the single-writer-for-life invariant (no record is ever moved).
    pub fn freeze(&mut self, shard: ShardId) {
        self.map.freeze(shard);
    }

    /// Reshard: bring a new, empty shard online for writes.
    pub fn add_shard(&mut self, shard: ShardId, pipeline: AuditPipeline) {
        let handle = pipeline.handle();
        self.shards.insert(shard.0, ShardEntry { pipeline, handle });
        self.map.add_active(shard);
    }

    /// Stop every shard's writer thread cleanly (final flush).
    pub fn shutdown(self) {
        for (_, entry) in self.shards {
            entry.pipeline.shutdown();
        }
    }
}

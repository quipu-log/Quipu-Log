# quipu-middleware

English | [한국어](README.ko.md)

The async layer over [`quipu-core`](../quipu-core/README.md). `quipu-core` is a synchronous, single-writer store; this crate is what you actually call from a running service. It owns the writer thread, keeps your request path non-blocking, and adds the pieces a real deployment needs: retries, a disk-backed dead-letter queue, permissions, an HTTP proxy layer, and — when one node isn't enough — a shard router.

If you're embedding Quipu-Log in a Rust service, this is your entry point. `quipu-server` is just this crate behind an HTTP API.

## What it gives you over the bare store

| concern | what this crate adds |
|---|---|
| **non-blocking writes** | `AuditPipeline` owns the store on a dedicated writer thread. `handle.emit()` is a bounded-channel enqueue — nanoseconds on the request path — never a disk write. |
| **durability under failure** | failed writes retry; events that exhaust retries park in a disk-backed DLQ that survives restarts (`redrive_dlq`); a `FallbackFn` hook catches the last-resort losses so you can page on them. |
| **permissions** | `PermissionPolicy` gates every `emit` / `query` / administer call by `Role`, deny- or allow-by-default. |
| **HTTP auditing** | `AuditLayer` is a `tower` Layer that records chosen endpoints automatically — no manual `emit` in handlers. |
| **observability** | `handle.metrics()` and `handle.health()` read lock-free atomics (queue depth, DLQ size, write latency, writer liveness, disk-full latch) without touching the writer thread. |
| **horizontal scale** | `ShardRouter` fronts N independent single-writer chains, routing writes by tenant and fanning queries out — see [Sharding](#sharding). |

## Quick start

The minimal embedded setup — open a store, start the pipeline, emit — is in the [root README's Quick start](../../README.md#quick-start). The shape:

```rust,no_run
use quipu_core::*;
use quipu_middleware::*;

let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* fallback hook */)?;
let handle = pipeline.handle();           // cheap, cloneable

handle.emit(&Role::new("svc"), event)?;   // non-blocking
```

`handle` is the thing you clone into every place that emits. The pipeline owns the store; nothing else touches it.

## The pieces

### Pipeline (`pipeline`)

`AuditPipeline::start` takes ownership of an `AuditStore` and spawns the writer thread. `PipelineConfig` sets the queue capacity and the retry schedule; the optional `FallbackFn` fires only when both the store *and* the DLQ fail to take an event — the one path where a record would otherwise be lost. `handle.flush()` blocks until everything queued is durable; `handle.redrive_dlq(&admin)` replays parked events (crash-safe, at-least-once, keeping each event's original occurrence time).

### Filters (`filter`)

A `FilterSet` runs your code around the audited request:

- **pre** — before the handler. Return a decision that exempts a request from auditing (health checks, static assets) before any work is done.
- **post** — after the response is known. Skip on status (e.g. drop 304s), or enrich the event with response-derived fields.

### Permissions (`permissions`)

`PermissionPolicy` maps a `Role` to a set of `Action`s (`Emit` / `Query` / `Administer`). One policy-wide switch sets the default for a role with no explicit grant: deny-by-default (an allowlist, the safe choice for multi-tenant or untrusted callers) or allow-by-default (a denylist). Every handle call carries the acting `Role` and is checked against the policy.

### HTTP layer (`layer`)

`AuditLayer` proxies a `tower` service per endpoint, captures request/response bodies up to a limit, derives target entities, and emits automatically. The full configuration — `EndpointRule`, `target_extractor`, body-capture limits, per-rule overrides — is documented in the [root README's "Recording from HTTP"](../../README.md#recording-from-http). `handle.emit()` still works alongside the layer for non-HTTP events (batch jobs, schedulers).

### Metrics & health (`metrics`, `health`)

`MetricsSnapshot` (queue depth, DLQ size, write/retry/park/loss counters, latency histogram) and `HealthSnapshot` (writer alive, disk-full latch, low-disk warning) are read from atomics off the write path, so polling them never contends with the writer. `quipu-server` exposes exactly these as Prometheus and `/v1/healthz`.

## Sharding

One pipeline is one writer thread on one store — the invariant that keeps each Merkle tree a single append-only line. To scale past that ceiling without breaking it, `ShardRouter` fronts **N independent pipelines**, each a complete single-writer tree + registry + checkpoints:

```rust,no_run
use quipu_middleware::{ShardMap, ShardRouter};

// N shards, hash seed pinned for stable tenant routing.
let map = ShardMap::new(4, 0x9e3779b97f4a7c15);
let shards = /* Vec<(ShardId, AuditPipeline)>, one pipeline per shard root */;
let router = ShardRouter::new(map, shards);

// Writes route by tenant to the tenant's owning shard.
router.emit(&role, "tenant-acme", event)?;

// Reads: with a tenant, only its shards; without, fan out across all,
// merged by (timestamp, log_id) with cursor pagination.
let page = router.query_page(&role, Some("tenant-acme"), q, None, 100)?;
```

Key properties (full model in [`docs/specs/horizontal-scaling`](../../docs/specs/horizontal-scaling/solution-design.md)):

- **Routing is consistent-hash by tenant.** A tenant's writes always land on one shard, so its tree never forks across shards.
- **No global order.** Cross-shard reads merge by `(timestamp_micros, log_id)`. An audit log rarely needs a single global sequence; per-shard order plus per-shard signed checkpoints is enough. Keep clocks sane (NTP).
- **Resharding is add-only.** Trees can't be rebalanced, so growth `freeze`s existing shards (read-only, still single-writer forever) and routes new writes to new shards. A tenant's history then spans its frozen and active shards; tenant-scoped reads cover both automatically.
- **Cross-shard integrity.** Per-shard `verify` catches tampering *within* a shard; `GlobalCheckpoint` / `verify_global` pin every shard's Merkle root + tree size plus the shard-map manifest under one signature, catching attacks on the shard *set* — whole-shard deletion, rollback (a smaller tree size), a rewrite (root changed at the same size), or manifest tampering. The tree size is monotonic, so a retention run no longer looks like a rollback.

`quipu-server` switches to the router automatically when its config has a `[shards]` section; single-store mode stays byte- and wire-compatible. See the [quipu-server README](../quipu-server/README.md).

## License

Apache-2.0. Part of [Quipu-Log](../../README.md).

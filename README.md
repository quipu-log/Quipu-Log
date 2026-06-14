<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/quipu-log-logo-dark.png">
    <img src="docs/logo/quipu-log-logo-light.png" alt="quipu-log — Tamper-evident audit log" width="440">
  </picture>
</p>

# Quipu-Log

[![CI](https://github.com/quipu-log/Quipu-Log/actions/workflows/ci.yml/badge.svg)](https://github.com/quipu-log/Quipu-Log/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](Cargo.toml)
[![crates.io](https://img.shields.io/crates/v/quipu-core.svg)](https://crates.io/crates/quipu-core)
[![docs.rs](https://img.shields.io/docsrs/quipu-core.svg)](https://docs.rs/quipu-core)

English | [한국어](README.ko.md)

**Audit logging for Rust services — record once, query the same history from any angle.** Tamper-evident, embedded in your process, no database.

Logs who did what, to which entity, through which API.

📖 **Deep dive:** [The Quipu-Log Book](https://quipu-log.github.io/quipu-log-textbook/) — a from-scratch guide to the internals: the filesystem storage engine, the Merkle integrity model, and searchable encryption.

## What Quipu-Log gives you

Quipu-Log does one thing — audit logging — and that focus buys you:

- **Record once, query from any angle.** Attach every entity related to a change as a target, and the same history comes back whichever related entity you start from ([more](#record-once-query-from-any-angle)).
- **Nothing to operate.** The store is one ordinary directory managed with `std::fs` — no daemon, no separate DB engine, no external dependency. The log embeds *inside* your service process rather than standing *beside* it.
- **Field-level, searchable encryption.** Each field picks its protection (plaintext / SHA-256 / keyed HMAC / RSA hybrid), and a blind index (exact / prefix / n-gram) lets you **search values whose plaintext never touched disk**. Find logs by SSN without storing the SSN in the clear.
- **Write-only deployment.** Start the server without the RSA private key and protected fields are stored as ciphertext it can't read itself. A fully compromised server still can't recover the plaintext.
- **Standard, vendor-neutral proofs.** The integrity backbone is an RFC 6962 (Certificate Transparency) Merkle tree. Inclusion and consistency proofs follow the RFC exactly, so a third party can verify your log with a checker written straight from the spec — not a scheme only this software understands.
- **History keeps its context.** Actors and targets are versioned entities, and every log pins the versions current when it was written. Rename a user today and last month's logs still render the old name — and still find it.
- **Writes don't wait on disk.** `emit` is non-blocking through an async pipeline with retries, a disk-backed DLQ, and a fallback hook you can wire to your pager. A `tower` layer captures HTTP requests with almost no code change.

## How it works

An **event**: an *actor* (user/service) did something (`method`, `url`, optional body) to one or more *targets*. Actors and targets are **entities** — typed records, one **registry** per type. A registry never overwrites; a field change appends a new immutable **version**, and each log row pins the versions current at write time. That pinning drives time-travel queries: old and new values both stay indexed.

```
your handler ──emit──▶ pipeline ─────────▶ store (append-only, Merkle-committed)
              (non-    (queue, retries,     ├── logs
              blocking) DLQ, fallback)      └── registries (versioned entities)
```

Your code holds a cloneable **handle**; a dedicated writer thread owns the store.

## Record once, query from any angle

When you log a create/update/delete, **attach every entity related to that change as a target.** Then later, whichever of those entities you start from, the related change history comes back in one query.

`targets` is a relation table, so one log row can point at many entities. Log a single document edit with the *document, author, project, and parent folder* all as targets, and:

- "every change to this document"
- "every change this user touched"
- "every change in this project"

all become the *same logs reached through different doors* — written once, queryable from many angles.

Because entities are versioned, a target's name can change later and **searching by the old name still surfaces that change.** A document that was `draft-v1` six months ago and is `final-report` now is found by either name, with its full history intact.

```rust
// Record: attach every entity related to the change as a target
handle.emit(&actor, AuditEvent::new(...)
    .target(doc_entity)
    .target(author_entity)
    .target(project_entity))?;

// Query: enter from any door — past values match too
handle.query(&auditor, LogQuery {
    targets: vec![
        TargetFilter::exact("document", "name", Value::Text("final-report".into())),
    ],
    ..Default::default()
})?;
```

Query quality comes down to **how completely you attach relations at write time.** With the HTTP layer, encode "which entities to derive from this request" once in `target_extractor`, and every request records them consistently without anyone having to remember.

## Quick start

```sh
cargo add quipu-core quipu-middleware
```

```rust
use quipu_core::*;
use quipu_middleware::*;

// 1. Open (or create) a store.
let root = std::path::PathBuf::from("/var/lib/myapp/audit");
let cfg = StoreConfig::new(&root)
    .retention(RetentionPolicy::days(90))
    .sync_policy(SyncPolicy::EveryN(32));
let mut store = AuditStore::open(cfg)?;

// 2. Register entity types (the defaults work without custom schemas).
if !store.has_type("default_actor") {
    store.define_type(default_actor_type())?;
    store.define_type(default_target_type())?;
}

// 3. Start the pipeline and keep a handle.
let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* fallback hook */)?;
let handle = pipeline.handle();

// 4. Emit events — non-blocking.
handle.emit(
    &Role::new("svc"),
    AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "billing-service"),
        "PUT",
        "/api/docs/42",
        Content::Text("saved".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new("42").text("name", "doc-42"),
    )),
)?;
```

Full runnable setup: [`examples/axum-demo`](examples/axum-demo). HTTP services usually record via the layer below instead of emitting by hand.

## Recording from HTTP

A `tower` layer fronts your routes: it selects endpoints, optionally captures bodies, and derives target entities.

```rust
let pipeline = AuditPipeline::start(store, root, permissions, PipelineConfig::default(),
    Some(Arc::new(|event, err| page_oncall(event, err))))?; // fallback
let layer = AuditLayer::new(pipeline.handle())
    .rules(vec![EndpointRule::prefix("/api/docs").method(Method::PUT)
        .capture_request().capture_response()        // bodies above the capture
        .capture_limit(1024 * 1024)                  //   limit proxy through uncaptured
        .target_extractor(|req, res, req_body, res_body| {
            /* rule-local target derivation (overrides the layer-wide one) */
            vec![]
        })])
    .filters(FilterSet::new()
        .pre(|req| /* runs before the handler: exempt health checks, ... */)
        .post(|req, res, event| /* runs after: skip 304s, enrich the event */))
    .target_extractor(|req, res, req_body, res_body| /* derive target entities */);
let app = Router::new().route(...).layer(layer);
```

`handle.emit(...)` still works alongside the layer for non-HTTP events (batch jobs, scripts, cron).

## Modeling your data

### Entity types

A log row carries `log_id`, `timestamp` (UTC µs), `actor`, `method`, `url`, `targets`, `content`, plus any custom columns you register (text/number/json, validated per write). Fields are defined per type:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

No custom schema needed? `default_actor` and `default_target` ship ready (the quick start registers them).

### Field protection

Per-field, default plaintext. No store-wide switch.

| level | searchable? | key? | notes |
|---|---|---|---|
| `Sha256` | exact match | none | One-way hash; query terms are hashed the same way. Low-entropy values (SSNs) can be brute-forced from disk — use `Hmac` for those. |
| `Hmac` | exact match | `KeyRing::with_hmac_key` | Keyed HMAC-SHA-256. Useless without the key. |
| `Rsa` | no (decrypt-scan) | RSA keypair | AES-256-GCM with RSA-OAEP key wrapping. Authenticated, so an in-place edit breaks decryption. |

Protection covers registry **fields only**. `entity_id`, the log's `method`/`url`/`content`, and custom columns are always plaintext (queries filter and render on them). Put sensitive values in protected fields, give entities opaque ids, and keep PII out of `content`.

### Blind indexes

Protection narrows search: hashed fields are exact-match only, RSA fields need a decrypt-scan. A blind index widens it:

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // exact match
    .search(FieldIndex::Ngram(3)),      // + substring match
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + prefix match up to 4 chars
```

At write time the plaintext is lowercased, tokenized, digested, and stored beside the record: whole value for `Exact`, first `1..=n` chars for `Prefix(n)`, n-char windows for `Ngram(n)`. Tokens use the field's own key, so an *outsider* can't brute-force them — but anyone holding that key (including a compromised server, which needs it to search) can dictionary-attack the digests of a **low-entropy** value and reconstruct it even without decrypting the field; `Ngram` is the worst here, since it rebuilds a value fragment by fragment. They also leak *structure* (which values share a prefix or fragment). So keep blind indexes — `Ngram` especially — off low-entropy PII. Per-field, no global switch.

### Schema evolution

Additive only: add fields, but don't remove one or change its kind/protection/index. Old values must stay searchable.

## Querying

```rust
let hits = handle.query(&Role::new("auditor"), LogQuery {
    targets: vec![          // several filters AND together
        // exact match, including past values (a renamed entity is still
        // found by its old name)
        TargetFilter::exact("default_target", "name", Value::Text("final-report".into())),
        // LIKE-style substring match
        TargetFilter::exact("default_target", "name", Value::Text("report".into())).contains(),
    ],
    method: Some("PUT".into()),
    ..Default::default()
})?;
```

Each hit returns the actor/target snapshots as recorded, plus an RFC 3339 UTC timestamp.

### Match operators

`exact`, `contains()`, `prefix()`, `exact_ci()` (case-insensitive exact). On plain fields all four work. On protected fields, `prefix()`/`exact_ci()` need the matching `FieldIndex` declared.

`contains()`:

- **With an `Ngram(n)` index:** matches by token digest, case-insensitive, no plaintext. RSA candidates are decrypted and verified (`StoreConfig::plaintext_cache(true)`); hashed fields can't verify, so false positives are possible — use `Rsa` for exact hits.
- **Without an index:** needs `plaintext_cache(true)` (in memory, never persisted). Off by default → the query is rejected.

### Snapshots

Queries run on a read snapshot (`handle.snapshot(&role)?`): it clones the in-memory registry indexes and scans on the caller's thread, never blocking writes.

```rust
handle.entity_types(&role)?;                            // all type schemas
handle.list_entities(&role, "default_target", false)?;  // latest version per entity
handle.entity_history(&role, "default_target", "doc-1")?; // every version, oldest first
```

## Server mode: one log for many services

`quipu-server` runs the same engine as a standalone daemon behind a token-authenticated HTTP/JSON API, so services in any language record and search in one place.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

Single-process store. Auth is deny-by-default, role grants per token. Write-only mode (start without the RSA private key) stores encrypted fields and returns them as ciphertext for clients to decrypt locally. Config, full HTTP API, and v1 limits: [quipu-server README](crates/quipu-server/README.md).

## Meta-audit: who read the audit log

Opt in to record every read and admin op (queries, registry browsing, DLQ redrives, retention runs, flushes, integrity checks, token reloads) in a separate **access log** with its own Merkle spine and retention window, covered by `verify_integrity`.

```rust
let cfg = StoreConfig::new("./audit-data")
    .access_log(true)                              // opt-in
    .access_retention(RetentionPolicy::days(90));  // independent window
```

Recording an access is a plain append (no query, so no self-reference loop). The parameter summary keeps a query's *shape* — fields, match mode, time range — but never term values, so protected-field plaintext never leaks in. Read back via `handle.query_access(&admin_role, AccessQuery::default())`, or `POST /v1/access/query` with the `administer` grant.

## What tamper-evidence covers

Quipu-Log makes tampering *evident*. The Merkle tree on its own catches accidental corruption (torn write, bit rot, truncated tail) and naive tampering (a record edited in place, a segment swapped out): `verify_integrity()` reports the first break. A third party can also verify independently — an inclusion proof shows a record is in the log, a consistency proof shows the history stayed append-only, both O(log n) against a published root.

Signed checkpoints plus external anchoring extend that to truncation and a full rebuild from scratch. Full threat model: [SECURITY.md](SECURITY.md).

## Scaling out: sharded trees

Each Merkle tree has one writer, so a single tree's throughput is a ceiling. To scale past it, shard — run N independent trees and route each tenant to one:

- **Writes scale by sharding.** Partition by tenant. Each shard is an independent single-writer tree + registry + checkpoints, so N shards give ~N× write throughput — until the shared device's fsync bandwidth saturates (PLP NVMe pushes that ceiling far out). You give up a single global order across shards (rarely needed for an audit log). `quipu-middleware`'s `ShardRouter` consistent-hashes writes to the owning shard, runs each shard's group commit in parallel, fans queries out merging by timestamp, and keeps a signed cross-shard anchor so tamper-evidence still spans every shard.
- **Reads scale by replication.** Sealed segments are immutable, so they copy to any number of read-replica query nodes; only the active tail lags.
- **Acceptance scales statelessly.** A stateless ingest front routes each request to its owning shard by `Idempotency-Key`.
- **Resharding is add-only.** Trees can't be rebalanced: growth freezes existing shards (read-only) and routes new writes to new shards by consistent hashing. No record moves; a tenant's history spans its old and current shards, and reads cover both. Freezing — read-only but still readable — is what preserves the single-writer-for-life guarantee.

```rust
use quipu_core::{AuditStore, StoreConfig, SyncPolicy, default_actor_type, default_target_type};
use quipu_middleware::{
    AuditPipeline, PermissionPolicy, PipelineConfig, ShardId, ShardMap, ShardRouter,
};

// One pipeline per shard, each rooted in its own directory.
fn shard_pipeline(dir: &std::path::Path) -> AuditPipeline {
    std::fs::create_dir_all(dir).unwrap();
    let mut store = AuditStore::open(
        StoreConfig::new(dir).sync_policy(SyncPolicy::EveryN(256)),
    ).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();
    AuditPipeline::start(
        store, dir.to_path_buf(),
        PermissionPolicy::allow_all(), PipelineConfig::default(), None,
    ).unwrap()
}

// Fixed seed — the routing ring derives from it, so persist it and never change it.
const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
let n = 8;
let shards = (0..n)
    .map(|i| (ShardId(i), shard_pipeline(&data_root.join(ShardId(i).dir_name()))))
    .collect();
let router = ShardRouter::new(ShardMap::new(n, SEED), shards);

router.emit(&role, tenant, event)?;     // routed to the tenant's owning shard
router.query(&role, Some(tenant), q)?;  // reads that tenant (active + frozen shards)
```

**Distribution is the caller's responsibility.** The router consistent-hashes whatever tenant key you pass and never rebalances by load — there is no "route to the least-busy shard." This is application-level partitioning, not dynamic load balancing. Sharding scales *across* tenants, not within one: an even spread comes from your *key design* — one key per tenant spreads tenants evenly (by count, not volume), while a finer `tenant:substream` key spreads a single hot tenant's writes across shards (at the cost of only ordering within a substream). Whoever sets the tenant — typically a trusted auth layer deriving it from the request identity, not raw client input — owns that choice.

Pick `n` to match write concurrency (~one shard per core is a sane start). The seed must stay constant and be persisted — the ring depends on it; after a restart, rebuild with `ShardMap::from_parts(active, frozen, seed)`. `ShardMap::new(1, seed)` is the degenerate single-shard case and behaves exactly like an unsharded store, so you can start at `n = 1` and grow later.

A single shard is one process: while it's down, audit trails to it stall. Surviving an outage is the sender's job — `quipu-client` provides idempotent retransmission (one record per `Idempotency-Key`), preserves each event's `occurred_at`, and spools to local disk through an outage. Recover a failed node by cold standby, not live failover. See [quipu-client](crates/quipu-client/README.md) and [cold-standby failover](crates/quipu-server/README.md#cold-standby-failover).

## Key management

Protect a field with `Hmac` or `Rsa` and you take on key management. For an audit log a lost key isn't a cold cache — it's records you can no longer read or search.

- **Rotation is cheap; re-keying is the exception.** `KeyRing` keys are versioned. Routine rotation adds a higher version for new writes while older versions stay loaded for old records. Run the offline `rekey` pass only after a key *leak*, to re-wrap RSA data so the leaked key can no longer read the store.
- **Keep old keys indefinitely.** Old RSA public keys verify old checkpoints; old HMAC keys match old search tokens. HMAC fields can't be re-keyed (one-way), so a leaked HMAC key means its digests are exposed.
- **A lost key is unrecoverable.** No escrow, no backdoor. Back the `KeyRing` up separately from the store and rehearse the restore.
- **Separate the signing key for anchoring.** Checkpoint signatures stop a key-holding insider only if the private key lives off the data node (separate host, HSM, or KMS).

Step-by-step rotation and re-key: [quipu-server README](crates/quipu-server/README.md#key-rotation).

## Operational notes

- **Permissions** — grant each role any of `Emit` / `Query` / `Administer`. One policy-wide switch sets the default for a role with no grants: deny-by-default or allow-by-default.
- **Retention** — `RetentionPolicy::days(90)` deletes whole sealed segments (one `unlink`, no rewrites); registries are kept so old history still renders. `.with_max_bytes(n)` adds a size cap (age OR size; active segment never dropped). Integrity still verifies afterward.
- **Durability** — `SyncPolicy::Always`, `EveryN(n)`, `EveryNOrInterval(n, dur)` (group commit: fsync after `n` appends *or* `dur` since the oldest unsynced append, whichever comes first), or `OsManaged`.
- **Dead-letter queue** — events that exhaust retries park on disk, survive restarts, and replay with `handle.redrive_dlq(&admin_role)` (crash-safe, at-least-once, original occurrence time kept).
- **Integrity audit** — `store.verify_integrity()` checks every record against its Merkle tree; `prove_inclusion` / `prove_consistency` issue third-party-checkable proofs.
- **Key rotation** — versioned `KeyRing` keys; highest active, older for reading. After a leak the offline `rekey` pass re-wraps RSA data and appends a signed re-key event. Full procedure: [quipu-server README](crates/quipu-server/README.md#key-rotation).
- **Backup** — sealed segments are immutable, so `rsync`/snapshot copies them while the daemon runs. `flush` first, then verify the copy with `verify_integrity()`.
- **Disk-full** — defined behavior. Housekeeping warns below 1 GiB or 10% free (configurable). An ENOSPC write skips retries, routes to DLQ/fallback, and sets a latch that clears on the next successful write or recovered space.
- **Observability** — writes reported via `tracing` and counted. `handle.metrics()` returns queue depth, DLQ size, write/retry/park/loss counters, and a latency histogram (lock-free). `quipu-server` exposes Prometheus on `GET /metrics` and health on `GET /v1/healthz`.
- **Export & SIEM** — `POST /v1/logs/export` dumps query hits as NDJSON. An opt-in syslog mirror (RFC 5424/UDP) forwards every written event, best-effort, never back-pressuring the write path.
- **Format versioning** — segment files start with a magic + version byte; layout changes ship as migrations.

## Performance

All figures below are **one Merkle tree, no sharding** — the throughput of a single writer. Sharding multiplies this (see [Scaling past one writer](#scaling-past-one-writer-tenant-sharding)). Write-path, `cargo bench -p quipu-middleware --bench write_path` (criterion 0.5). One actor, one target, small text payload. `flush()` waits for durability, so these are end-to-end figures. Apple M4, 16 GB RAM, NVMe SSD (APFS tempdir), macOS 26, rustc 1.96.0, release, single emitter thread:

| configuration | durable throughput |
|---|---|
| `SyncPolicy::OsManaged` (flush to page cache) | ~34,000 events/s |
| `SyncPolicy::EveryNOrInterval(1000, 20ms)` (group commit) | ~29,000 events/s |
| `SyncPolicy::EveryN(64)` (fsync every 64 appends) | ~3,200 events/s |

`EveryNOrInterval` is the throughput knob: batching the fsync over ~1000 appends (or a 20 ms window, whichever first) cuts fsync count ~16× and lands within ~85% of the page-cache ceiling while still fsyncing — a measured ~9× over the count-only `EveryN(64)`. The interval caps how long a durable-pending append waits under low load, which `EveryN` alone cannot bound.

Caller-side `emit()` latency, `EveryN(64)`, 32,768-slot queue, 200,000 events:

| percentile | latency |
|---|---|
| p50 | 42 ns |
| p99 | 16.3 ms |
| p99.9 | 19.3 ms |

p50 is a bounded-channel enqueue; the tail is backpressure (a full queue returns `QueueFull`). `OsManaged` removes the tail at the cost of trusting the OS page cache on power loss.

### Compared to immudb

Head-to-head against [immudb](https://github.com/codenotary/immudb)'s synced append, **matched on the group-commit knobs** (20 ms window, 1,000-op cap) and run in the **same `rust:1` Docker container** (Linux, tempdir on the container filesystem) immudb was benchmarked in — the same `write_path` / `EveryNOrInterval(1000, 20ms)` bench as above.

| metric | quipu `EveryNOrInterval(1000, 20ms)` | immudb `SyncedAppend` (matched) |
|---|---|---|
| durable throughput | **~163,000 /s** | ~38,800 /s |
| time / op | 6.14 ms / 1,000 events | 257.9 ms / 10,000 txn |
| mode | embedded (in-process) | embedded (in-process) |
| commit window | 20 ms | 20 ms |
| count cap | 1,000 | 1,000 (`MaxActiveTransactions`) |
| concurrency | single writer (1) | 1,000 goroutines |
| work per commit | multi-record append (log + relations + registry) + Merkle hash-tree leaf | multi-key append + AHT leaf (MVCC; secondary index built async) |
| relative | **4.2×** | 1.0× (baseline) |

This is an apples-to-apples comparison of the same durable-write primitive: both group-commit a multi-record durable append anchored in a tamper-evidence hash tree (quipu a Merkle spine, immudb its accumulate-hash-tree), and immudb's secondary index is built asynchronously, off this path. Matched on the group-commit knobs (20 ms / 1,000) in the same container, quipu sustains **~4.2×** immudb's durable write throughput. The two are different designs — quipu a single-writer append-only audit log, immudb a general MVCC transactional KV store — but on the durable-write path they share, quipu's Rust append is markedly faster.

A Merkle tree is single-writer, so the figures above are a per-tree ceiling. To scale past one tree, shard by tenant and run N in parallel — see [Scaling out: sharded trees](#scaling-out-sharded-trees).

## Workspace layout

| crate | what it is |
|---|---|
| [`quipu-core`](crates/quipu-core/README.md) | storage engine, typed registries, field encryption, retention, queries |
| [`quipu-middleware`](crates/quipu-middleware/README.md) | event pipeline (DLQ/fallback), pre/post filters, permissions, `tower` proxy layer, shard router |
| [`quipu-server`](crates/quipu-server/README.md) | standalone daemon: the same store behind a token-authenticated HTTP/JSON API |
| [`quipu-client`](crates/quipu-client/README.md) | reference client for the daemon: idempotent retransmission, backoff, opt-in disk spool |
| [`quipu-mcp`](crates/quipu-mcp/README.md) | Model Context Protocol server: exposes the store to an LLM agent (query / history / verify) |
| [`examples/axum-demo`](examples/axum-demo) | runnable axum integration |

## Running the demo and tests

```sh
cargo test                 # core + middleware test suites
cargo run -p axum-demo     # then: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## License

Apache-2.0

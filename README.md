# Quipu-Log

[![CI](https://github.com/draft-dhgo/Quipu-Log/actions/workflows/ci.yml/badge.svg)](https://github.com/draft-dhgo/Quipu-Log/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](Cargo.toml)
[![Status](https://img.shields.io/badge/status-pre--1.0-orange.svg)](CHANGELOG.md)

English | [한국어](README.ko.md)

**Tamper-evident audit logging for Rust services. Runs in your process — no database to set up.**

Quipu-Log answers questions like: *who changed this document last quarter, and what was it called back then?*

It logs who did what, to which entity, through which API. Each record is hash-chained to the one before it, so a silent edit shows up. And it stores what every entity looked like the moment you wrote the log. Rename a user today, and last month's logs still show — and still find — the old name.

## Why it exists

Most audit logging starts simple: serialize something to JSON, ship it somewhere. That holds up until your first real audit. Then three problems surface at once:

- Anyone with file access can edit the history, and nothing catches it.
- The names and values in old logs have gone stale — or were never captured.
- "Find every log about X" means grepping half-structured text.

Moving the logs into a database table fixes the third. The first two remain.

Quipu-Log treats all three as design requirements:

- **Tampering shows.** Storage is append-only. Every record carries a SHA-256 hash chained to the previous one, across file boundaries. `store.verify_integrity()` finds the first record edited in place, or the segment swapped out. A patched-up CRC won't hide it.
- **History keeps its context.** People and things are stored as versioned entities. Old logs render and match the values that were true when they were written.
- **No database to run — but key state to manage.** The store is a directory, managed with plain `std::fs`. No daemon, no external dependency, and a crash recovers by truncating the torn tail, the same way on every OS. What you *do* take on is keys: protect a field and you own its encryption keys, where a lost key means logs you can't read. That's the real operational cost here — see [Key management](#key-management).
- **Writes don't block your handler.** Events go through an async pipeline: retries, a disk-backed dead-letter queue, and a fallback hook you can wire to your pager.

## How it works

Each audit record is an **event**: an *actor* (a user, a service) did something (`method`, `url`, optional request/response body) to one or more *targets*.

Actors and targets aren't plain strings. They're **entities** — structured records with fields you define per **type**. Each type gets its own **registry** in the store.

A registry never overwrites. Change an entity's fields, and the registry appends a new immutable **version**. Each log row pins the versions that were current when it was written.

That pinning is what makes time-travel queries work. Old and new values both stay indexed, and each log shows the values it actually saw.

```
your handler ──emit──▶ pipeline ─────────▶ store (append-only, hash-chained)
              (non-    (queue, retries,     ├── logs
              blocking) DLQ, fallback)      └── registries (versioned entities)
```

Your code holds a cheap, cloneable **handle** to the pipeline. A dedicated writer thread owns the store and does the writing.

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

A full runnable setup is in [`examples/axum-demo`](examples/axum-demo). For HTTP services you usually don't emit by hand — see the next section.

## Recording from HTTP

The common setup puts a `tower` layer in front of your routes. It picks which endpoints to record, optionally captures bodies, and derives target entities from each request:

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

`handle.emit(...)` still works alongside the layer, for things that aren't HTTP requests: batch jobs, admin scripts, scheduled cleanups.

## Modeling your data

### Entity types

A log row carries `log_id`, `timestamp` (UTC microseconds), `actor`, `method`, `url`, `targets`, and `content`, plus any custom columns you register (text / number / json, validated on every write). `targets` is a relation table, so one log can point at many entities.

The real modeling is in the entity schemas. You set the fields per type:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

Don't need custom schemas? `default_actor` and `default_target` ship ready to use — that's what the quick start registers.

### Field protection

Each field picks its own protection level. The default is plaintext on disk. There's no store-wide switch on purpose: what to protect is a per-field decision.

| level | searchable? | key? | notes |
|---|---|---|---|
| `Sha256` | exact match | none | One-way hash; query terms are hashed the same way. Low-entropy values (SSNs) can be brute-forced from disk — use `Hmac` for those. |
| `Hmac` | exact match | `KeyRing::with_hmac_key` | Keyed HMAC-SHA-256. Useless without the key. |
| `Rsa` | no (decrypt-scan) | RSA keypair | AES-256-GCM with RSA-OAEP key wrapping. Authenticated, so an in-place edit breaks decryption. |

One rule to learn early: protection covers registry **fields only**. `entity_id`, the log's `method`/`url`/`content`, and custom columns are always plaintext — they're what queries filter and render on.

So put sensitive values in protected fields. Give entities opaque ids, not SSNs. Keep PII out of `content` — a captured request body is the easiest place to leak it.

### Blind indexes: searching what you encrypted

Protection narrows search. Hashed fields are exact-match only; RSA fields need a full decrypt-scan. A *blind index* widens it back:

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // exact match
    .search(FieldIndex::Ngram(3)),      // + substring match
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + prefix match up to 4 chars
```

Here's how. At write time the plaintext is still in hand. Quipu-Log lowercases it, digests the tokens, and stores them next to the record: the whole value for `Exact`, the first `1..=n` chars for `Prefix(n)`, n-char windows for `Ngram(n)`. Search survives restarts. The plaintext never touches disk.

The trade-off: token digests follow the field's own key (a keyed field gets keyed tokens), so they add no brute-force surface beyond what you already declared. But they do leak *structure* — which stored values share a prefix or a fragment. Declaring an index accepts that trade for that one field. That's why there's no global switch here either.

### Schema evolution

Redefining a type is additive only. New fields, yes. Removing a field, or changing its kind / protection / index, no. Allowing that would quietly break the promise that old values stay searchable.

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

Each hit comes back with the actor and target snapshots as they were recorded, plus an RFC 3339 UTC timestamp.

### Match operators

Besides `exact` and `contains()`, there are `prefix()` and `exact_ci()` (case-insensitive exact). On plain fields, all four just work. On protected fields, `prefix()` and `exact_ci()` need the matching `FieldIndex` declared — then they match with no false positives.

`contains()` is the subtle one:

- **With an `Ngram(n)` index:** terms of at least n chars match by token digest, case-insensitive, no plaintext involved. RSA candidates are then decrypted and verified (needs `StoreConfig::plaintext_cache(true)`). Hashed fields have no plaintext to verify against, so a hit means "has all the term's fragments" — false positives are possible. Use `Rsa` when hits must be exact.
- **Without an index:** `contains()` on a protected field needs `StoreConfig::plaintext_cache(true)`, which holds decrypted and written values in memory (never persisted; gone on restart). With the cache off — the default — the query is rejected, rather than quietly caching plaintexts you didn't ask for.

### Snapshots and browsing the registry

Queries run on a read snapshot (`handle.snapshot(&role)?`). Taking one just clones the small in-memory registry indexes, and the scan runs on the caller's thread — so a slow full-scan never blocks event writes.

```rust
handle.entity_types(&role)?;                            // all type schemas
handle.list_entities(&role, "default_target", false)?;  // latest version per entity
handle.entity_history(&role, "default_target", "doc-1")?; // every version, oldest first
```

## Server mode: one log for many services

Everything above runs *embedded* — the store lives inside your service. `quipu-server` runs the same engine as a standalone daemon behind a token-authenticated HTTP/JSON API, so services in any language can record and search audit logs in one place:

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

The store is still single-process; the daemon is that process. Auth is deny-by-default, with role grants per token.

The server can also run *write-only*. Start it without the RSA private key, and it stores encrypted fields but hands them back as ciphertext for clients to decrypt locally. A compromised server can't recover plaintext.

Config, the full HTTP API, and v1 limits are in the [quipu-server README](crates/quipu-server/README.md).

## Meta-audit: who read the audit log

In regulated settings, reading audit data is itself auditable. HIPAA expects a record of who viewed PHI — including viewing it through the audit trail. Opt in, and Quipu-Log records every read and admin operation against the store (queries, registry browsing, DLQ redrives, retention runs, flushes, integrity checks, token reloads) in a separate **access log**:

```rust
let cfg = StoreConfig::new("./audit-data")
    .access_log(true)                              // opt-in
    .access_retention(RetentionPolicy::days(90));  // independent window
```

Each record holds the actor (in server mode, the token's role), the operation, a parameter summary, the result count, and a timestamp. Two things hold by design:

- **No self-reference loop.** Recording an access is a plain append — it runs no query, so it can't spawn another access record. Reading the access log is recorded too (it's also an access), but exactly once per read. Growth is linear, never recursive.
- **Search terms stay out.** The parameter summary keeps the *shape* of a query — which fields, which match mode, what time range — but never the term values. Otherwise, searching an HMAC- or RSA-protected field would leak its plaintext into the access log and defeat the field protection.

Access records live in their own table (`root/access/`), with their own tamper-evidence chain, covered by `verify_integrity`. They also get their own retention window, so access records — usually kept shorter than the data they describe — age out on their own schedule without touching the main log.

To read them back: embedded, `handle.query_access(&admin_role, AccessQuery::default())`; in server mode, `POST /v1/access/query` with the `administer` grant.

## What tamper-evidence covers

Quipu-Log makes tampering *evident*; it does not make storage *immutable*. Knowing exactly where that line falls is the difference between a guarantee you have and one you only think you have.

The hash chain **on its own** catches:

- **Accidental corruption** — a torn write, bit rot, a truncated tail.
- **Naive tampering** — a record edited in place, or a whole segment swapped out. `verify_integrity()` reports the first break.

The hash chain on its own does **not** catch:

- **Truncation.** Delete the most recent records, or the whole active segment, and what remains still verifies end to end — it just ends sooner. Nothing inside the chain says how long it was supposed to be.
- **Full recomputation.** An attacker with write access to the store *and* knowledge of the format can edit a record and recompute every hash from that point on. The chain is unsalted SHA-256, so a rebuilt chain verifies clean.

What closes those two gaps is **signed checkpoints plus external anchoring**. Quipu-Log periodically signs the current chain head; you export that signature somewhere the writer can't reach. A later verification matches the live chain against the anchored checkpoints, so a shortened or rebuilt chain no longer agrees with a signature taken when the log was longer.

That guarantee holds only under two conditions — both your deployment's job, not the library's:

- **The anchor must leave the box.** A checkpoint signature sitting next to the data it protects gets rewritten alongside it. Send it elsewhere: another host, an append-only bucket, a timestamping or transparency service.
- **The signing key must not live with the data.** Anyone holding the checkpoint key can re-sign a rewritten chain. Anchoring stops an outside attacker and a disk-level actor; it stops a key-holding insider only if the key sits somewhere they don't control — see [Key management](#key-management).

The full scope — what's defended, what's deliberately out, what counts as a vulnerability — is in [SECURITY.md](SECURITY.md).

## Scaling out: sharded chains, not a distributed chain

There is one thing Quipu-Log won't do: spread a **single** hash chain across machines. Every record is chained to the one before it in a single line, and that line only holds if one writer owns it. Put one chain behind multiple writers and it forks; reconciling the forks needs consensus between nodes, and one bug in that consensus turns "this log wasn't altered" into "probably wasn't." That trade — availability bought with the project's whole reason to exist — is the one we refuse.

But "no distributed chain" is not "no horizontal scaling." The invariant that matters is **one writer per chain**, not **one chain total**. Keep that, and you scale on both axes:

- **Writes scale by sharding.** Partition the audit stream by tenant; each shard is an independent single-writer chain + registry + checkpoints — today's exact per-node guarantee, N times over. N shards = N writer threads ≈ N× write throughput. What you give up is a single global order across shards; an audit log rarely needs one (per-shard order + per-shard signed checkpoints is enough). `quipu-middleware`'s `ShardRouter` routes a tenant's writes to its owning shard and fans queries out, merging by timestamp.
- **Reads scale by replication.** Sealed segments are immutable, so they copy to any number of read-replica query nodes with no effect on integrity — only the active tail lags. That lifts the single-process read ceiling.
- **Acceptance scales statelessly.** A stateless ingest front behind a load balancer takes requests and routes them to the owning shard by `Idempotency-Key` (already implemented) — request intake scales horizontally while each chain keeps its single writer.
- **Resharding is add-only.** Chains are append-only and can't be rebalanced, so growth freezes existing shards (read-only, forever single-writer) and routes new writes to new shards via consistent hashing. No record ever moves; a tenant's history simply spans its old (frozen) and current (active) shards, and reads cover both.

The full model — shard key, ordering, resharding, read topology — is in [`docs/specs/horizontal-scaling`](docs/specs/horizontal-scaling/solution-design.md).

### Availability of a single shard

A shard is still one process. **When it's down — daemon dead, or write queue full — every calling service's audit trail to that shard stalls in the meantime.** For an audit log, a missing record can't be filled in later, and that gap is itself a compliance problem.

So surviving an outage is the sender's job, and the server backs it two ways.

- **Sending the same request twice still records it once.** When a sender gets no response, it can't tell success from failure, so it resends. The server remembers a unique id on each request (`Idempotency-Key`), so a resend of one it already took doesn't create a second record.
- **A late event keeps its real timestamp.** Each event carries the time the action actually happened (`occurred_at`). Whether it's retried or buffered on disk and sent minutes later, the log records when it happened — not when it finally arrived.

`quipu-client` is the reference sender: idempotent retransmission, exponential backoff with jitter, and an opt-in local disk spool that rides out an outage and replays when the daemon returns. It has no HTTP dependency — you plug in your own HTTP library through a one-method trait. See its [README](crates/quipu-client/README.md).

For planned downtime or a failed node, recover by **cold standby**, not live failover. Sealed segments are immutable, so they copy safely anytime; only the active segment and registry tail need a `flush` (or a clean shutdown) first. Bring the daemon up on the standby host against the copied root — it takes the lock, truncates any torn tail, and is writable again. Restart time depends on the *active* segment, not the whole store. The step-by-step is in the [quipu-server README](crates/quipu-server/README.md#cold-standby-failover).

## Key management

"No database" is true. "No operational state" is not. The moment you protect a field with `Hmac` or `Rsa`, you take on key management — and for an audit log a lost key isn't a cold cache, it's records you can no longer read or search.

- **Rotation is cheap; re-keying is the exception.** `KeyRing` keys are versioned. Routine rotation only adds a higher version: it signs and encrypts new writes while older versions stay loaded, so old records keep decrypting and matching. You run the offline `rekey` pass only after a key *leak*, to re-wrap existing RSA data under a fresh key so the leaked one can no longer read the store.
- **Keep old keys, indefinitely.** Old RSA *public* keys verify old checkpoints; old HMAC keys match old search tokens. Drop them and verification and search break — quietly. HMAC fields can't be re-keyed at all (one-way, no plaintext retained), so a leaked HMAC key means its existing digests must be treated as exposed.
- **A lost key is unrecoverable.** There is no escrow and no backdoor. Lose the RSA private key and every field encrypted under it is gone — ciphertext with no way back. Back the `KeyRing` up separately from the store, and rehearse the restore.
- **For anchoring to mean anything, separate the signing key.** Checkpoint signatures defend against a key-holding insider *only* if the private key doesn't sit on the node holding the data: a separate signing host, an HSM, or a KMS. Co-locate it and anchoring drops back to a check against outsiders. (Same point as [What tamper-evidence covers](#what-tamper-evidence-covers), from the operator's side.)

Step-by-step rotation and re-key procedures: [quipu-server README](crates/quipu-server/README.md#key-rotation).

## Operational notes

- **Permissions** — grant each role any of `Emit` / `Query` / `Administer`. One policy-wide switch sets what a role with no grants gets: deny-by-default (an allowlist) or allow-by-default (a denylist).
- **Retention** — `RetentionPolicy::days(90)` drops old data by deleting whole sealed segments: one `unlink`, no rewrites. Registries are kept, so old history still renders. Add `.with_max_bytes(n)` for a size cap; age and size combine as OR, and the active segment is never dropped, so the cap is a target, not a hard ceiling. Integrity still verifies afterward.
- **Durability** — `SyncPolicy::Always` (fsync every write), `EveryN(n)`, or `OsManaged`.
- **Dead-letter queue** — events that exhaust their retries are parked on disk, survive restarts, and replay with `handle.redrive_dlq(&admin_role)`. Redrive is crash-safe and at-least-once; replayed logs keep their original occurrence time.
- **Integrity audit** — `store.verify_integrity()` walks every hash chain and reports the first record edited in place or segment swapped out.
- **Key rotation** — keys in the `KeyRing` are versioned; the highest version is active, older ones stay for reading, so rotating never drops old records from search. Routine rotation just adds a higher version. After a key leak, an offline `rekey` pass re-wraps RSA data under the new key — the leaked key can no longer read the store — and appends a signed re-key event so `verify_integrity()` tells an audited re-key from a silent rewrite. (HMAC fields are one-way and can't be re-keyed, so keep old HMAC keys.) Full procedure: [quipu-server README](crates/quipu-server/README.md#key-rotation).
- **Backup** — sealed segments are immutable, so `rsync` or a snapshot copies them safely while the daemon runs. `flush` first to settle the active tail for a clean point-in-time copy, then verify the restored copy with `verify_integrity()`.
- **Disk-full** — defined behavior, not luck. Housekeeping warns early (below 1 GiB or 10% free, configurable). An ENOSPC write skips retries and routes straight to DLQ/fallback, and sets a disk-full latch that clears when a write succeeds or space recovers.
- **Observability** — every write is reported via `tracing` and counted. `handle.metrics()` returns queue depth, DLQ size, write/retry/park/loss counters, and a latency histogram, read from atomics without touching the writer thread. `quipu-server` exposes the same as Prometheus on `GET /metrics` and a health verdict on `GET /v1/healthz`.
- **Export & SIEM** — `POST /v1/logs/export` dumps query hits as NDJSON for auditor handoff and SIEM ingest. An opt-in syslog mirror (RFC 5424/UDP) forwards every written event; it's best-effort and never back-pressures the write path.
- **Format versioning** — segment files start with a magic + version byte, so layout changes ship as migrations, not misreads.

## Performance

Write-path numbers from `cargo bench -p quipu-middleware --bench write_path` (criterion 0.5). Each event carries one actor, one target, and a small text payload. `flush()` waits until everything queued is written, so these are end-to-end figures, not channel speed.

Apple M4, 16 GB RAM, internal NVMe SSD, macOS 15, rustc 1.96.0, release build, single emitter thread:

| configuration | durable throughput |
|---|---|
| `SyncPolicy::OsManaged` (flush to page cache) | ~56,000 events/s |
| `SyncPolicy::EveryN(64)` (fsync every 64 appends) | ~4,800 events/s |

Caller-side `emit()` latency with `EveryN(64)` and a 32,768-slot queue, over 200,000 events:

| percentile | latency |
|---|---|
| p50 | 42 ns |
| p99 | 10.7 ms |
| p99.9 | 11.6 ms |

The p50 is just a bounded-channel enqueue — the audited request path normally pays nanoseconds. The tail is backpressure, not disk time on the caller: when fsync stalls the writer long enough to fill the queue, `emit` returns `QueueFull` and the benchmark retries after 50 µs. Size the queue and sync policy for your burst profile; with `OsManaged` the tail disappears, at the cost of trusting the OS page cache on power loss.

### Scale and its limits

Those are throughput figures, not capacity. Two ceilings matter as data accumulates:

- **One writer, one process.** A single thread owns the store — that's what keeps the hash chain a single unbroken line ([why](#scaling-out-sharded-chains-not-a-distributed-chain)). The numbers above are that thread's ceiling; you scale a node by batching and queue sizing, not by adding writers, and past one node you shard by tenant, not replicate. Plan capacity around a sustained single-writer rate, with retention bounding how much history a node carries.
- **Queries full-scan; the registry index is in memory.** A query scans log segments, and the registry's entity indexes live in RAM (a snapshot clones them, off the write path). Comfortable for millions of records; at hundreds of millions a full-scan query is seconds rather than milliseconds, and the in-memory indexes grow with your distinct-entity count, so the working set has to fit. Keep it bounded: lean on retention, always constrain queries by time range, and add a blind index only on fields you actually search. There's no secondary index over log rows yet — for ad-hoc analytics at that scale, export ([`POST /v1/logs/export`](#operational-notes)) into a dedicated search or warehouse system rather than scanning live.

Robustness gets its own tests: `fuzz/` has libFuzzer targets for the segment parser and DLQ redrive, and `crates/quipu-middleware/tests/` has a concurrent stress test (emit + flush + retention + query, full chain verification after) and a SIGKILL crash-injection test. Every PR runs a short fuzz smoke; long runs happen in nightly CI.

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

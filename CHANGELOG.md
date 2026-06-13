# Changelog

All notable changes to the Quipu-Log workspace are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates
version together under [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Compatibility policy

Three contracts carry from one release to the next; they are what "audit data
written by an old version still reads, verifies, and redrives on a new one" is
made of. Breaking any of them is a major-version change.

- **On-disk segment format.** Segment frames begin with a magic + version byte,
  so a layout change ships as a migration the reader recognises, never a
  silent misread. Records are bincode, which is **not** self-describing: adding
  or reordering a struct field changes the encoding, so any change to a
  persisted struct (`AuditLog`, `RegistryRecord`, `TargetRelation`,
  checkpoint/meta payloads) requires a format-version bump and a read path for
  the old shape. New `RegistryRecord` fields use `#[serde(default)]` so existing
  records still deserialize.
- **Dead-letter queue format.** Parked events are stored as serialized
  `AuditEvent`. The same bincode caveat applies: a field added to `AuditEvent`
  must stay backward-readable, or events parked by an older binary become
  unredrivable after upgrade. Redrive is at-least-once and keeps each event's
  original `occurred_at`; `required` custom columns are not enforced
  retroactively, so old parked events always stay redrivable.
- **HTTP API (`quipu-server`).** The `/v1/*` surface is versioned in the path.
  Backward-incompatible request/response changes go to `/v2`, not a silent edit
  of `/v1`. The `Idempotency-Key` window's in-memory nature is part of the
  contract, not an implementation detail (see the server README).

The deeper rationale and worked examples live in the project wiki under
`암묵지/Quipu-Log 디스크 포맷 진화`.

### MSRV

Minimum supported Rust version is **1.89** (the store guards its root with
`std::fs::File::try_lock`, stabilized there). An MSRV increase is a breaking
change and gets a major-version bump with a changelog note.

## [Unreleased]

### Added
- `quipu-mcp`: Model Context Protocol server exposing the audit store to an LLM
  agent — `query_logs`, `get_entity_history`, `verify_store_integrity` tools
  over `quipu-server`'s HTTP API (single-writer lock makes embedding
  impractical), plus a scoped access-token issuer. Std-only plaintext HTTP
  client; no new dependencies.
- `quipu-server`: `POST /v1/logs/export` (newline-delimited JSON for auditor
  handoff / SIEM ingest), `GET /v1/openapi.json` (OpenAPI 3.1 spec), and an
  opt-in `sink` section that mirrors written events to syslog (RFC 5424/UDP).
- `quipu-middleware`: `SinkFn` hook — a post-write mirror point for SIEM
  forwarding, fired on durable write only.
- `quipu-client`: reference client for `quipu-server` — idempotent
  retransmission, exponential backoff with full jitter, and an opt-in
  CRC-framed local disk spool that rides out a server outage and replays on
  recovery. Transport-agnostic (no HTTP dependency; adapt via the `Transport`
  trait).
- `quipu-server`: `Idempotency-Key` duplicate detection on `POST /v1/logs`;
  documented single-node availability scope and cold-standby failover
  procedure.
- `quipu-server`: direct TLS termination (rustls), hashed/expiring bearer
  tokens with `SIGHUP` hot-reload, per-token concurrent-query cap.
- `quipu-server`: integrity verification endpoint (`POST /v1/admin/verify`) and
  optional periodic background verification.
- `quipu-core`: signed integrity checkpoints with an external-anchor hook.
- crates.io publishing metadata across the workspace: MSRV, keywords,
  categories, `docs.rs` config, and this changelog.

## [0.1.0]

Initial workspace: `quipu-core` (embedded storage engine), `quipu-middleware`
(async pipeline, DLQ, filters, permissions, tower layer), `quipu-server`
(standalone HTTP daemon).

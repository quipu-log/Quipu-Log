# quipu-core

English | [한국어](README.ko.md)

The embedded storage and query core of [Quipu-Log](../../README.md):
append-only hash-chained segments, versioned entity registries, field-level
protection, retention, and time-travel queries. The async pipeline and HTTP
proxy live in `quipu-middleware` / `quipu-server`; this crate is the
synchronous engine underneath.

## Signed integrity checkpoints

The per-record hash chain catches partial tampering — a record rewritten in
place, a segment swapped out or reordered. It cannot catch a **full rewrite**:
an insider with unrestricted disk access can delete every segment and replay a
self-consistent chain from scratch, and nothing left inside the store
contradicts the forgery.

Checkpoints close that gap. A checkpoint pins the state of the log chain —

| field | meaning |
|---|---|
| `created_at` | UTC micros at signing time |
| `segment_seq` | logs segment that was active at checkpoint time |
| `record_count` | log records on disk (decreases after retention) |
| `chain_head` | chain value of the newest log record |
| `signature` | RSA PKCS#1 v1.5 / SHA-256 over the fields above |

— and appends it to `checkpoints.log` at the store root. Segment files are
untouched: a store that never checkpoints stays byte-identical on disk.

### When checkpoints are written

- **On segment seal.** A seal is the moment a chain prefix becomes immutable,
  and its frequency is bounded by `max_segment_bytes` — unlike the flush/sync
  path, which would put an RSA signing operation on the every-N-appends hot
  path.
- **After a retention purge.** The previous latest checkpoint may point into a
  segment retention just unlinked; re-checkpointing keeps verification
  independent of legitimately deleted records.
- **On demand** via `AuditStore::checkpoint()` — e.g. from a scheduler, or
  before a backup.

### Verification

`verify_integrity()` runs the existing chain checks, then, if checkpoints
exist:

1. every checkpoint signature is verified with the RSA public key;
2. the **latest** checkpoint's `chain_head` must still exist in the log chain
   (as a stored record chain value or a segment seed).

A rewritten chain cannot reproduce the checkpointed head without the original
records, and a truncated tail loses it — both now fail verification. Only the
latest head is matched because older heads may live in segments retention has
legitimately removed; every count-reducing operation writes a fresh
checkpoint, so the latest one never depends on purged data.

### Write-only deployments

Signing needs the RSA **private** key. A log-producing service configured with
only the public key (the recommended split — it can encrypt fields but never
read them back) cannot sign, so checkpointing is **silently disabled** there:
`checkpoint()` returns `Ok(None)`, segment seals skip the step, no
`checkpoints.log` is created, and `verify_integrity()` simply has no
checkpoints to check. This is a deliberate availability decision, not an
error. Run checkpointing where the private key lives, or accept chain-only
tamper evidence on write-only nodes.

### External anchoring

A checkpoint inside the store still shares the store's fate: the scheme
assumes the insider does not hold the signing key, and a key-holding insider
could re-sign a rewritten chain. The anchor hook exports each checkpoint to a
trust domain the insider cannot rewrite:

```rust
let cfg = StoreConfig::new("/var/audit")
    .keys(keys)
    .anchor(|cp| {
        // ship (created_at, cp.chain_head_hex()) anywhere outside the host:
        // another machine, a ticket, a transparency log, a printed report
    });
```

The hook runs synchronously right after each checkpoint is persisted. Errors
and panics inside it are swallowed — availability of the write path outranks
anchoring, so delivery guarantees (queueing, retries) are the hook's job.
Comparing the anchored heads against `checkpoints.log` later proves the
checkpoint file itself was not rewritten.

### Threat model summary

| attack | caught by |
|---|---|
| record edited in place (even with fixed CRC) | hash chain |
| segment removed / reordered / replaced | cross-segment seeds |
| full delete-and-rewrite of the chain | latest checkpoint head |
| newest records truncated | latest checkpoint head |
| checkpoint file forged or edited | RSA signature |
| checkpoint file rewritten by the key holder | external anchor comparison |

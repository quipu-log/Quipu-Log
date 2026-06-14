# quipu-core

English | [한국어](README.ko.md)

The embedded storage and query core of [Quipu-Log](../../README.md): append-only segments backed by an RFC 6962 Merkle history tree, versioned entity registries, field-level protection, retention, and time-travel queries. This crate is the synchronous engine. The async pipeline and HTTP proxy live in `quipu-middleware` and `quipu-server`.

## Integrity: a Merkle history tree

Every record's leaf hash (`SHA-256(0x00 || payload)`) is appended to a **Merkle spine** — a retention-independent file (`merkle.spine`) per table whose root commits to every record ever appended (RFC 6962 history tree; `node = SHA-256(0x01 || left || right)`). The root subsumes a hash chain's tamper-evidence — a record edited in place no longer hashes to its spine leaf, and removing or reordering a segment changes the root — and adds something a chain can't give: **independent, third-party verification** in O(log n).

- **Inclusion proof** — "record E is committed to root R" with an audit path, verifiable without the rest of the log and without trusting the operator.
- **Consistency proof** — "the tree of size *m* is a prefix of the tree of size *n*", i.e. the history in between is append-only: nothing was edited or removed.

The spine holds only hashes (no payloads), so it is never purged by retention — which is what lets the root and every proof survive after the underlying records age out. Segment frames carry just `[len][crc][ts][payload]`; the CRC catches accidental corruption, the spine catches tampering.

```rust
let proof = store.prove_inclusion(log_id)?;           // O(log n) audit path
let root  = store.merkle_root();                       // the value an anchor pins
assert!(quipu_core::merkle::verify_inclusion(
    &proof.leaf, proof.leaf_index as usize,
    proof.tree_size as usize, &proof.path, &root));

let c = store.prove_consistency(earlier_size)?;        // append-only between sizes
```

## Signed integrity checkpoints

The spine proves *partial* tampering and append-only history, but not a **full rewrite**: an insider with disk access can delete the spine and every segment and replay a self-consistent tree from scratch. Checkpoints close that gap by pinning the tree under a signature:

| field | meaning |
|---|---|
| `created_at` | UTC micros at signing time |
| `segment_seq` | logs segment that was active at checkpoint time |
| `record_count` | log records on disk (decreases after retention) |
| `tree_size` | total records ever appended — the Merkle tree size (monotonic) |
| `merkle_root` | Merkle root over the first `tree_size` leaves |
| `signature` | RSA PKCS#1 v1.5 / SHA-256 over the fields above |

It appends that to `checkpoints.log` at the store root. Segment files aren't touched, so a store that never checkpoints stays byte-identical on disk.

### When checkpoints are written

- **On segment seal.** A seal is when a prefix becomes immutable. Its frequency is bounded by `max_segment_bytes` — unlike the flush/sync path, which would put an RSA signing operation on the every-N-appends hot path.
- **After a retention purge.** Re-checkpointing keeps verification independent of legitimately deleted records.
- **On demand** via `AuditStore::checkpoint()` — from a scheduler, or before a backup.

### Verification

`verify_integrity()` re-derives each surviving record's leaf against the spine, then, if checkpoints exist:

1. verifies every checkpoint signature with the RSA public key;
2. confirms the **latest** checkpoint's `merkle_root` is consistent with the current tree — identical when `tree_size` matches, otherwise via a consistency proof.

The spine is never purged, so the current tree is always an extension of any honest checkpoint. A rewritten tree can't reproduce the checkpointed root; a truncated tail makes the current `tree_size` smaller than the checkpoint's. Both fail verification.

### Write-only deployments

Signing needs the RSA **private** key. A log-producing service configured with only the public key (the recommended split — it can encrypt fields but never read them back) can't sign, so checkpointing is **silently disabled** there. `checkpoint()` returns `Ok(None)`, segment seals skip the step, no `checkpoints.log` is created, and `verify_integrity()` simply has no checkpoints to check.

This is a deliberate choice, not an error: write-path availability comes first. Run checkpointing where the private key lives, or accept spine-only tamper evidence on write-only nodes. (The Merkle root and proofs still work without a key — only the *signed* anchor needs one.)

### External anchoring

A checkpoint inside the store still shares the store's fate. The scheme assumes the insider doesn't hold the signing key — a key-holding insider could re-sign a rewritten tree. The anchor hook exports each checkpoint somewhere the insider can't rewrite:

```rust
let cfg = StoreConfig::new("/var/audit")
    .keys(keys)
    .anchor(|cp| {
        // ship (created_at, cp.tree_size, cp.merkle_root_hex()) anywhere outside
        // the host: another machine, a ticket, a transparency log, a printed report
    });
```

The hook runs synchronously right after each checkpoint is persisted. Errors and panics inside it are swallowed — write-path availability outranks anchoring, so delivery guarantees (queueing, retries) are the hook's job. Comparing the anchored roots against `checkpoints.log` later proves the checkpoint file itself wasn't rewritten — and anyone holding an anchored `(tree_size, root)` can demand a consistency proof against the live store.

### Threat model summary

| attack | caught by |
|---|---|
| record edited in place (even with fixed CRC) | Merkle spine (leaf mismatch) |
| segment removed / reordered / replaced | Merkle root changes |
| full delete-and-rewrite of the tree | latest checkpoint root |
| newest records truncated | latest checkpoint `tree_size` / consistency proof |
| checkpoint file forged or edited | RSA signature |
| checkpoint file rewritten by the key holder | external anchor comparison |
| operator hides/forges a record from a third party | **inclusion proof against the anchored root** |
| operator silently edits past history | **consistency proof against an anchored root** |

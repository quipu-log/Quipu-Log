//! Signed integrity checkpoints and external anchoring.

use quipu_core::*;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// One RSA keypair (as PEM) shared by every test — 2048-bit generation is the
/// slow part, not the point of these tests.
fn pems() -> &'static (String, String) {
    static PEMS: OnceLock<(String, String)> = OnceLock::new();
    PEMS.get_or_init(|| {
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (private_pem, public_pem)
    })
}

fn signing_keys() -> KeyRing {
    KeyRing::new().with_private_pem(&pems().0).unwrap()
}

fn write_only_keys() -> KeyRing {
    KeyRing::new().with_public_pem(&pems().1).unwrap()
}

fn small_segment_cfg(root: &std::path::Path, keys: KeyRing) -> StoreConfig {
    StoreConfig::new(root)
        .keys(keys)
        .sync_policy(SyncPolicy::OsManaged)
        .max_segment_bytes(512) // roll (and thus checkpoint) every few appends
}

fn open_store(cfg: StoreConfig) -> AuditStore {
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn append_n(store: &mut AuditStore, n: usize) {
    append_n_at(store, n, None);
}

fn append_n_at(store: &mut AuditStore, n: usize, occurred_at: Option<u64>) {
    for i in 0..n {
        let actor = EntityInput::new("user-1").text("name", "alice");
        let args = (
            "default_actor",
            &actor,
            "POST",
            format!("/api/items/{i}"),
            Content::Text("padding-padding-padding-padding".into()),
        );
        match occurred_at {
            Some(ts) => store
                .append_at(
                    ts,
                    args.0,
                    args.1,
                    args.2,
                    &args.3,
                    args.4,
                    &[],
                    BTreeMap::new(),
                )
                .unwrap(),
            None => store
                .append(
                    args.0,
                    args.1,
                    args.2,
                    &args.3,
                    args.4,
                    &[],
                    BTreeMap::new(),
                )
                .unwrap(),
        };
    }
}

#[test]
fn checkpoints_are_written_on_seal_signed_and_verified() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(small_segment_cfg(dir.path(), signing_keys()));
    append_n(&mut store, 30);

    let cps = store.checkpoints().unwrap();
    assert!(
        !cps.is_empty(),
        "segment seals must have produced checkpoints"
    );
    for cp in &cps {
        cp.verify(&signing_keys()).unwrap();
    }
    // counts and segment seqs grow monotonically along the file
    for pair in cps.windows(2) {
        assert!(pair[0].record_count <= pair[1].record_count);
        assert!(pair[0].segment_seq <= pair[1].segment_seq);
    }

    // a manual checkpoint pins the current head and verification passes
    let cp = store.checkpoint().unwrap().expect("private key present");
    assert_eq!(cp.record_count, 30);
    store.verify_integrity().unwrap();

    // signature verification needs only the public key
    cp.verify(&write_only_keys()).unwrap();
}

#[test]
fn write_only_configuration_silently_skips_checkpointing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(small_segment_cfg(dir.path(), write_only_keys()));
    append_n(&mut store, 30); // seals several segments — no errors
    store.sync().unwrap();

    assert_eq!(store.checkpoint().unwrap(), None, "no private key -> skip");
    assert!(store.checkpoints().unwrap().is_empty());
    assert!(
        !dir.path().join("checkpoints.log").exists(),
        "no checkpoint file is ever created"
    );
    store.verify_integrity().unwrap();
}

#[test]
fn full_chain_rewrite_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(small_segment_cfg(dir.path(), signing_keys()));
        append_n(&mut store, 20);
        store.checkpoint().unwrap().unwrap();
    }

    // the insider wipes the log segments and replays a fresh, internally
    // consistent chain of the same shape — every per-record check passes.
    // The insider holds the disk but NOT the signing key (the premise of the
    // whole scheme: with the key they could simply re-sign new checkpoints),
    // so the replay runs under a public-key-only ring.
    std::fs::remove_dir_all(dir.path().join("logs")).unwrap();
    {
        let mut store = open_store(small_segment_cfg(dir.path(), write_only_keys()));
        append_n(&mut store, 20);
        store.sync().unwrap();
    }

    // verification needs only the public key
    let mut store = open_store(small_segment_cfg(dir.path(), write_only_keys()));
    let err = store.verify_integrity().unwrap_err();
    assert!(
        err.to_string().contains("checkpoint"),
        "rewrite must be caught by the checkpoint, got: {err}"
    );
}

#[test]
fn tail_truncation_after_checkpoint_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(small_segment_cfg(dir.path(), signing_keys()));
        append_n(&mut store, 20);
        store.checkpoint().unwrap().unwrap();
    }
    // delete the newest (active) segment — the surviving prefix is a valid
    // chain, but the checkpointed head is gone with the tail
    let newest = std::fs::read_dir(dir.path().join("logs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    std::fs::remove_file(newest).unwrap();

    let mut store = open_store(small_segment_cfg(dir.path(), signing_keys()));
    assert!(store.verify_integrity().is_err());
}

#[test]
fn forged_checkpoint_fails_signature_verification() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(small_segment_cfg(dir.path(), signing_keys()));
    append_n(&mut store, 20);
    store.checkpoint().unwrap().unwrap();
    store.verify_integrity().unwrap();

    // the insider edits a recorded checkpoint (e.g. to shrink the count)
    let path = dir.path().join("checkpoints.log");
    let tampered = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"record_count\":20", "\"record_count\":2");
    std::fs::write(&path, tampered).unwrap();

    let err = store.verify_integrity().unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
}

#[test]
fn anchor_hook_receives_checkpoints_and_panics_are_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Checkpoint>();
    let tx = Mutex::new(tx);
    let cfg = small_segment_cfg(dir.path(), signing_keys())
        .anchor(move |cp| tx.lock().unwrap().send(cp.clone()).unwrap());
    let mut store = open_store(cfg);

    append_n(&mut store, 30); // rolls segments -> automatic checkpoints
    let manual = store.checkpoint().unwrap().unwrap();

    let received: Vec<Checkpoint> = rx.try_iter().collect();
    assert_eq!(received, store.checkpoints().unwrap());
    assert_eq!(received.last(), Some(&manual));

    // a panicking anchor must not break the write path or checkpointing
    drop(store);
    let cfg = small_segment_cfg(dir.path(), signing_keys()).anchor(|_| panic!("anchor down"));
    let mut store = open_store(cfg);
    append_n(&mut store, 30);
    store.checkpoint().unwrap().unwrap();
    store.verify_integrity().unwrap();
}

#[test]
fn retention_purge_keeps_chain_and_checkpoints_verifiable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = small_segment_cfg(dir.path(), signing_keys()).retention(RetentionPolicy::days(7));
    let mut store = open_store(cfg);

    let old = quipu_core::time::now_micros() - 30 * 86_400 * 1_000_000;
    append_n_at(&mut store, 40, Some(old)); // several sealed, expired segments
    append_n(&mut store, 5); // fresh records in the active segment
    let before = store.checkpoints().unwrap().last().unwrap().record_count;

    let dropped = store.apply_retention().unwrap();
    assert!(dropped > 0, "expired segments must be unlinked");

    // chain verification and checkpoint verification both still hold
    store.verify_integrity().unwrap();

    // the purge itself wrote a fresh checkpoint reflecting the deletion, so
    // verification never depends on records retention removed
    let after = store.checkpoints().unwrap().last().unwrap().record_count;
    assert!(
        after < before,
        "purge must be reflected: {after} < {before}"
    );

    // and the store keeps working + verifying across reopen
    drop(store);
    let cfg = small_segment_cfg(dir.path(), signing_keys()).retention(RetentionPolicy::days(7));
    let mut store = open_store(cfg);
    append_n(&mut store, 5);
    store.verify_integrity().unwrap();
}

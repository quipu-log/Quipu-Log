//! End-to-end Merkle proof API: a third party verifies inclusion and
//! consistency against the store's signed root, without the rest of the log.

use quipu_core::merkle::{verify_consistency, verify_inclusion};
use quipu_core::*;
use std::collections::BTreeMap;

fn open_store(root: &std::path::Path) -> AuditStore {
    let cfg = StoreConfig::new(root)
        .sync_policy(SyncPolicy::OsManaged)
        .keys(KeyRing::generate_ephemeral(2048).unwrap());
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store
}

fn actor() -> EntityInput {
    EntityInput::new("user-1").text("name", "alice")
}

fn append(store: &mut AuditStore, i: usize) -> Uid {
    store
        .append(
            "default_actor",
            &actor(),
            "POST",
            &format!("/api/x/{i}"),
            Content::Text(format!("event-{i}")),
            &[],
            BTreeMap::new(),
        )
        .unwrap()
}

#[test]
fn inclusion_proofs_verify_against_the_signed_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    let ids: Vec<Uid> = (0..50).map(|i| append(&mut store, i)).collect();
    store.sync().unwrap();

    let root = store.merkle_root();
    let size = store.tree_size();
    assert_eq!(size, 50);

    // every record proves inclusion against the current root
    for id in &ids {
        let p = store.prove_inclusion(*id).unwrap();
        assert!(
            verify_inclusion(
                &p.leaf,
                p.leaf_index as usize,
                p.tree_size as usize,
                &p.path,
                &root
            ),
            "inclusion proof for {id} must verify"
        );
    }

    // a proof against the wrong root is rejected
    let p = store.prove_inclusion(ids[0]).unwrap();
    let mut bad_root = root;
    bad_root[0] ^= 0xff;
    assert!(!verify_inclusion(
        &p.leaf,
        p.leaf_index as usize,
        p.tree_size as usize,
        &p.path,
        &bad_root
    ));

    // an unknown id has no proof
    assert!(store.prove_inclusion(Uid::generate()).is_err());
}

#[test]
fn consistency_proof_links_a_checkpoint_to_the_present() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    for i in 0..20 {
        append(&mut store, i);
    }
    store.sync().unwrap();

    // an auditor records the checkpoint (size + root) now...
    let cp = store.checkpoint().unwrap().unwrap();
    assert_eq!(cp.tree_size, 20);

    // ...the log keeps growing...
    for i in 20..60 {
        append(&mut store, i);
    }
    store.sync().unwrap();
    let now_root = store.merkle_root();
    let now_size = store.tree_size();

    // ...and the auditor proves the checkpointed state was preserved, not
    // rewritten, with only an O(log n) proof.
    let proof = store.prove_consistency(cp.tree_size).unwrap();
    assert!(verify_consistency(
        cp.tree_size as usize,
        now_size as usize,
        &cp.merkle_root,
        &now_root,
        &proof.path
    ));
}

#[test]
fn proofs_and_root_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (root, size, id);
    {
        let mut store = open_store(dir.path());
        let ids: Vec<Uid> = (0..30).map(|i| append(&mut store, i)).collect();
        store.sync().unwrap();
        root = store.merkle_root();
        size = store.tree_size();
        id = ids[7];
    }
    // a fresh process rebuilds the same root from disk and issues a valid proof
    let mut store = open_store(dir.path());
    assert_eq!(store.tree_size(), size);
    assert_eq!(store.merkle_root(), root);
    let p = store.prove_inclusion(id).unwrap();
    assert!(verify_inclusion(
        &p.leaf,
        p.leaf_index as usize,
        p.tree_size as usize,
        &p.path,
        &root
    ));
}

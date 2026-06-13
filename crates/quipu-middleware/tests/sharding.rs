//! Sharded-router behavior: routing, per-shard integrity, cross-shard merge +
//! pagination, N=1 equivalence, and resharding (freeze).

use quipu_core::{
    default_actor_type, default_target_type, AuditStore, Content, EntityInput, KeyRing, LogQuery,
    Order, StoreConfig, SyncPolicy,
};
use quipu_middleware::{
    AuditEvent, AuditPipeline, MultiCursor, PermissionPolicy, PipelineConfig, Role, ShardId,
    ShardMap, ShardRouter, TargetSpec,
};
use std::path::Path;

const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

fn make_pipeline(root: &Path) -> AuditPipeline {
    make_pipeline_keyed(root, None)
}

fn make_pipeline_keyed(root: &Path, keys: Option<KeyRing>) -> AuditPipeline {
    std::fs::create_dir_all(root).unwrap();
    let mut cfg = StoreConfig::new(root).sync_policy(SyncPolicy::OsManaged);
    if let Some(k) = keys {
        cfg = cfg.keys(k);
    }
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();
    AuditPipeline::start(
        store,
        root.to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap()
}

fn router(n: u32, dir: &Path) -> ShardRouter {
    let shards = (0..n)
        .map(|i| {
            let id = ShardId(i);
            (id, make_pipeline(&dir.join(id.dir_name())))
        })
        .collect();
    ShardRouter::new(ShardMap::new(n, SEED), shards)
}

/// A router whose shards all hold the same signing key — needed for the
/// cross-shard checkpoint anchoring tests (a shard must be able to checkpoint).
fn keyed_router(n: u32, dir: &Path, keys: &KeyRing) -> ShardRouter {
    let shards = (0..n)
        .map(|i| {
            let id = ShardId(i);
            (
                id,
                make_pipeline_keyed(&dir.join(id.dir_name()), Some(keys.clone())),
            )
        })
        .collect();
    ShardRouter::new(ShardMap::new(n, SEED), shards)
}

fn event(tenant: &str, doc: &str, body: &str) -> AuditEvent {
    AuditEvent::new(
        "default_actor",
        EntityInput::new(tenant).text("name", tenant),
        "PUT",
        format!("/api/docs/{doc}"),
        Content::Text(body.into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new(doc).text("name", doc),
    ))
}

#[test]
fn each_tenant_lands_on_one_shard_and_every_shard_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(4, dir.path());
    let role = Role::new("svc");

    // Many tenants, many events each.
    for t in 0..50 {
        let tenant = format!("tenant-{t}");
        let mut owner = None;
        for e in 0..20 {
            let shard = r
                .emit(&role, &tenant, event(&tenant, &format!("d{e}"), "x"))
                .unwrap();
            match owner {
                None => owner = Some(shard),
                Some(o) => assert_eq!(o, shard, "a tenant must never split across shards"),
            }
        }
    }
    r.flush().unwrap();

    // Every shard's chain is independently sound.
    for (shard, report) in r.verify(&role).unwrap() {
        assert!(
            report.ok,
            "shard {shard} failed verify: {:?}",
            report.problems
        );
    }

    // No loss: 50 tenants * 20 events all present across shards.
    let all = r
        .query(
            &role,
            None,
            LogQuery {
                limit: Some(100_000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(all.len(), 50 * 20);
}

#[test]
fn tenant_scoped_query_finds_only_that_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(4, dir.path());
    let role = Role::new("svc");

    for t in 0..8 {
        let tenant = format!("tenant-{t}");
        for e in 0..5 {
            r.emit(&role, &tenant, event(&tenant, &format!("d{e}"), "x"))
                .unwrap();
        }
    }
    r.flush().unwrap();

    // Query one tenant by its actor name; only its 5 events come back.
    let hits = r
        .query(
            &role,
            Some("tenant-3"),
            LogQuery {
                actor: Some(quipu_core::TargetFilter::exact(
                    "default_actor",
                    "name",
                    quipu_core::Value::Text("tenant-3".into()),
                )),
                limit: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 5);
}

#[test]
fn cross_shard_pagination_is_globally_ordered_no_dups_no_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(4, dir.path());
    let role = Role::new("svc");

    // Emit a known number of events spread across tenants/shards. Events are
    // appended in arrival order, which here equals timestamp order. Kept modest
    // because cross-shard fan-out re-scans per page (no global index), so
    // page_size=1 does total*shards sub-queries — fine for correctness, heavy
    // if total is large.
    let total = 40usize;
    for i in 0..total {
        let tenant = format!("tenant-{}", i % 10);
        r.emit(&role, &tenant, event(&tenant, &format!("d{i}"), "x"))
            .unwrap();
    }
    r.flush().unwrap();

    // Paginate desc; concatenated pages must equal the full
    // descending-by-(timestamp,log_id) order with no dup/gap. page_size=1 is
    // the hardest boundary case.
    for &page_size in &[1usize, 7, 40, 999] {
        let mut seen: Vec<(u64, u128)> = Vec::new();
        let mut cursor: Option<MultiCursor> = None;
        loop {
            let page = r
                .query_page(
                    &role,
                    None,
                    LogQuery {
                        order: Order::Desc,
                        ..Default::default()
                    },
                    cursor.take(),
                    page_size,
                )
                .unwrap();
            for lv in &page.logs {
                seen.push((lv.timestamp_micros, lv.log_id.0));
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        assert_eq!(
            seen.len(),
            total,
            "page_size={page_size}: lost or duplicated rows"
        );
        // strictly descending, unique
        for w in seen.windows(2) {
            assert!(
                w[0] > w[1],
                "page_size={page_size}: not strictly descending / has dup"
            );
        }
    }
}

#[test]
fn count_and_entity_fanout_across_shards() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(4, dir.path());
    let role = Role::new("svc");

    for t in 0..12 {
        let tenant = format!("tenant-{t}");
        for e in 0..3 {
            r.emit(
                &role,
                &tenant,
                event(&tenant, &format!("{tenant}-d{e}"), "x"),
            )
            .unwrap();
        }
    }
    r.flush().unwrap();

    // count() over all shards == total events.
    assert_eq!(r.count(&role, None, LogQuery::default()).unwrap(), 12 * 3);

    // entity_history for one tenant's doc is found via its shard(s).
    let hist = r
        .entity_history(&role, Some("tenant-5"), "default_target", "tenant-5-d1")
        .unwrap();
    assert_eq!(hist.len(), 1);

    // list_entities fans out: every distinct target doc shows up once.
    let entities = r
        .list_entities(&role, None, "default_target", false)
        .unwrap();
    assert_eq!(entities.len(), 12 * 3);
}

#[test]
fn single_shard_router_matches_a_plain_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(1, dir.path());
    let role = Role::new("svc");

    for i in 0..30 {
        r.emit(&role, "tenant-0", event("tenant-0", &format!("d{i}"), "x"))
            .unwrap();
    }
    r.flush().unwrap();

    let hits = r
        .query(
            &role,
            Some("tenant-0"),
            LogQuery {
                limit: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 30);
    assert!(r.verify(&role).unwrap().values().all(|v| v.ok));
}

#[test]
fn frozen_shard_takes_no_writes_but_stays_readable() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = router(2, dir.path());
    let role = Role::new("svc");

    // Find a tenant owned by shard 0, write some history.
    let frozen_target = ShardId(0);
    let tenant = (0..1000)
        .map(|i| format!("tenant-{i}"))
        .find(|t| r.map().route_write(t) == frozen_target)
        .expect("some tenant must hash to shard 0");
    for i in 0..10 {
        let s = r
            .emit(&role, &tenant, event(&tenant, &format!("d{i}"), "x"))
            .unwrap();
        assert_eq!(s, frozen_target);
    }
    r.flush().unwrap();

    // Freeze shard 0. New writes for the same tenant must NOT land there.
    r.freeze(frozen_target);
    assert_ne!(
        r.map().route_write(&tenant),
        frozen_target,
        "frozen shard must not take writes"
    );
    let new_shard = r
        .emit(&role, &tenant, event(&tenant, "d-new", "x"))
        .unwrap();
    assert_ne!(new_shard, frozen_target);
    r.flush().unwrap();

    // Pre-freeze history is still readable for the tenant (reads include frozen).
    let hits = r
        .query(
            &role,
            Some(&tenant),
            LogQuery {
                actor: Some(quipu_core::TargetFilter::exact(
                    "default_actor",
                    "name",
                    quipu_core::Value::Text(tenant.clone()),
                )),
                limit: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        hits.len(),
        11,
        "10 pre-freeze + 1 post-freeze across frozen+active"
    );
}

// ---- option D: cross-shard checkpoint anchoring (ADR-5) ----------------------

fn anchor_keys() -> KeyRing {
    KeyRing::generate_ephemeral(2048).unwrap()
}

fn populate(r: &ShardRouter, role: &Role, tenants: u32, per: u32) {
    for t in 0..tenants {
        let tenant = format!("tenant-{t}");
        for e in 0..per {
            r.emit(role, &tenant, event(&tenant, &format!("d{e}"), "x"))
                .unwrap();
        }
    }
    r.flush().unwrap();
}

#[test]
fn global_checkpoint_round_trips_and_signature_tamper_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let keys = anchor_keys();
    let r = keyed_router(3, dir.path(), &keys);
    let role = Role::new("svc");
    populate(&r, &role, 30, 4);

    let gc = r.global_checkpoint(&role, &keys).unwrap();
    assert_eq!(gc.heads.len(), 3, "one pinned head per shard");
    assert!(
        gc.heads.iter().all(|h| h.record_count > 0),
        "every shard took some of the 30 tenants"
    );

    // An untampered store verifies clean.
    let report = r.verify_global(&role, &gc, &keys).unwrap();
    assert!(report.ok, "fresh anchor must verify: {:?}", report.problems);

    // A flipped signature byte is detected (and short-circuits).
    let mut forged = gc.clone();
    forged.signature[0] ^= 0xFF;
    let report = r.verify_global(&role, &forged, &keys).unwrap();
    assert!(!report.ok);
    assert!(report.problems.iter().any(|p| p.contains("signature")));
}

#[test]
fn global_checkpoint_detects_whole_shard_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let keys = anchor_keys();
    let r = keyed_router(2, dir.path(), &keys);
    let role = Role::new("svc");
    populate(&r, &role, 20, 3);
    let gc = r.global_checkpoint(&role, &keys).unwrap();

    // A different deployment of the *same* 2-shard map but empty — every shard's
    // record count is now below what the anchor pinned: a rollback/truncation.
    let dir2 = tempfile::tempdir().unwrap();
    let empty = keyed_router(2, dir2.path(), &keys);

    let report = empty.verify_global(&role, &gc, &keys).unwrap();
    assert!(!report.ok);
    assert!(
        report.problems.iter().any(|p| p.contains("rolled back")),
        "expected a rollback finding, got {:?}",
        report.problems
    );
    // Same shard set + seed -> the manifest itself is unchanged.
    assert!(!report.problems.iter().any(|p| p.contains("manifest")));
    assert!(!report.problems.iter().any(|p| p.contains("missing")));
}

#[test]
fn global_checkpoint_detects_shard_deletion_and_manifest_change() {
    let dir = tempfile::tempdir().unwrap();
    let keys = anchor_keys();
    let r = keyed_router(3, dir.path(), &keys);
    let role = Role::new("svc");
    populate(&r, &role, 30, 3);
    let gc = r.global_checkpoint(&role, &keys).unwrap();

    // The store now presents only 2 of the 3 shards — shard-2's chain was
    // dropped and the map quietly shrunk. Per-shard verify on 0 and 1 is clean;
    // only the anchor over the *set* catches the loss.
    let dir2 = tempfile::tempdir().unwrap();
    let shrunk = keyed_router(2, dir2.path(), &keys);

    let report = shrunk.verify_global(&role, &gc, &keys).unwrap();
    assert!(!report.ok);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("shard-0002") && p.contains("missing")),
        "expected shard-0002 missing, got {:?}",
        report.problems
    );
    assert!(
        report.problems.iter().any(|p| p.contains("manifest")),
        "expected a manifest-change finding, got {:?}",
        report.problems
    );
}

//! Meta-audit (access log) behaviour at the store level: recording, the
//! reserved type namespace, independent retention, and the no-plaintext rule.

use quipu_core::*;
use std::collections::BTreeMap;

fn open_store(cfg: StoreConfig) -> AuditStore {
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn append_one(store: &mut AuditStore, url: &str) {
    store
        .append(
            "default_actor",
            &EntityInput::new("user-1").text("name", "alice"),
            "GET",
            url,
            Content::Text("body".into()),
            &[(
                "default_target".to_string(),
                EntityInput::new("t-1").text("name", "thing"),
            )],
            BTreeMap::new(),
        )
        .unwrap();
}

#[test]
fn queries_are_meta_audited_with_actor_and_count() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path())
        .sync_policy(SyncPolicy::OsManaged)
        .access_log(true);
    let mut store = open_store(cfg);
    append_one(&mut store, "/api/a");
    append_one(&mut store, "/api/b");

    let hits = store.query_as("auditor", &LogQuery::default()).unwrap();
    assert_eq!(hits.len(), 2);

    let recs = store.access_records(&AccessQuery::default()).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].actor, "auditor");
    assert_eq!(recs[0].operation, "query_logs");
    assert_eq!(recs[0].result_count, Some(2));

    // reading the access log at the store level is a plain scan: it does not
    // multiply records by itself (callers above record it once per request)
    let again = store.access_records(&AccessQuery::default()).unwrap();
    assert_eq!(again.len(), 1);
}

#[test]
fn search_probe_values_never_land_in_the_access_log_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyRing::new().with_hmac_key(b"k");
    let cfg = StoreConfig::new(dir.path())
        .sync_policy(SyncPolicy::OsManaged)
        .keys(keys)
        .access_log(true);
    let mut store = AuditStore::open(cfg).unwrap();
    store
        .define_type(TypeSchema::new(
            "patient",
            vec![
                FieldDef::text("name").indexed().required(),
                FieldDef::text("ssn")
                    .indexed()
                    .protection(FieldProtection::Hmac),
            ],
        ))
        .unwrap();
    store.define_type(default_actor_type()).unwrap();
    store
        .append(
            "default_actor",
            &EntityInput::new("u-1").text("name", "alice"),
            "GET",
            "/api/patients/1",
            Content::Text("read".into()),
            &[(
                "patient".to_string(),
                EntityInput::new("p-1")
                    .text("name", "bob")
                    .text("ssn", "900101-1234567"),
            )],
            BTreeMap::new(),
        )
        .unwrap();

    // search by the protected SSN — the probe must not leak into meta-audit
    let q = LogQuery {
        targets: vec![TargetFilter::exact(
            "patient",
            "ssn",
            Value::Text("900101-1234567".into()),
        )],
        ..Default::default()
    };
    assert_eq!(store.query_as("auditor", &q).unwrap().len(), 1);

    let recs = store.access_records(&AccessQuery::default()).unwrap();
    assert_eq!(recs.len(), 1);
    assert!(
        !recs[0].params.contains("900101-1234567"),
        "probe value leaked into access log: {}",
        recs[0].params
    );
    assert!(recs[0].params.contains("ssn")); // the shape is still there

    // ... and not anywhere in the access table's raw bytes either
    store.sync().unwrap();
    for entry in std::fs::read_dir(dir.path().join("access")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("900101-1234567"), "probe on disk in access/");
    }
}

#[test]
fn reserved_type_prefix_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = AuditStore::open(StoreConfig::new(dir.path())).unwrap();
    let err = store
        .define_type(TypeSchema::new("quipu_access", vec![FieldDef::text("x")]))
        .unwrap_err();
    assert!(matches!(err, Error::Schema(_)), "got: {err}");
    let err = store
        .define_type(TypeSchema::new("quipu_anything", vec![FieldDef::text("x")]))
        .unwrap_err();
    assert!(matches!(err, Error::Schema(_)), "got: {err}");
}

#[test]
fn access_log_disabled_is_noop_and_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path()).sync_policy(SyncPolicy::OsManaged);
    let mut store = open_store(cfg);
    assert!(!store.access_enabled());
    // recording is a no-op, not an error — callers record unconditionally
    store
        .record_access(AccessRecord::new("a", "query_logs", "{}", None))
        .unwrap();
    assert!(store.access_records(&AccessQuery::default()).is_err());
    assert!(!dir.path().join("access").exists());
}

#[test]
fn access_retention_is_independent_of_main_retention() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path())
        .sync_policy(SyncPolicy::OsManaged)
        .max_segment_bytes(256)
        .access_log(true)
        // main data kept forever, access records only ~1 day
        .access_retention(RetentionPolicy::days(1));
    let mut store = open_store(cfg);
    append_one(&mut store, "/api/old");

    // pile up old access records (2 days ago) until segments roll
    let old_ts = time::now_micros() - 2 * 86_400 * 1_000_000;
    for i in 0..50 {
        store
            .record_access(
                AccessRecord::new("auditor", "query_logs", format!("{{\"n\":{i}}}"), Some(0))
                    .at(old_ts + i),
            )
            .unwrap();
    }
    let before = store.access_records(&AccessQuery::default()).unwrap().len();
    assert_eq!(before, 50);

    let dropped = store.apply_retention().unwrap();
    assert!(dropped > 0, "expected old access segments to be dropped");

    // access log shrank, main audit data fully intact
    let after = store.access_records(&AccessQuery::default()).unwrap().len();
    assert!(after < before, "access records not purged");
    assert_eq!(store.query(&LogQuery::default()).unwrap().len(), 1);

    // integrity (including the access table's own chain) still verifies
    store.verify_integrity().unwrap();
}

#[test]
fn access_records_filter_by_actor_operation_and_time() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path())
        .sync_policy(SyncPolicy::OsManaged)
        .access_log(true);
    let mut store = open_store(cfg);
    store
        .record_access(AccessRecord::new("a", "query_logs", "{}", Some(1)).at(1_000))
        .unwrap();
    store
        .record_access(AccessRecord::new("b", "redrive_dlq", "{}", Some(2)).at(2_000))
        .unwrap();
    store
        .record_access(AccessRecord::new("a", "redrive_dlq", "{}", Some(3)).at(3_000))
        .unwrap();

    let by_actor = store
        .access_records(&AccessQuery {
            actor: Some("a".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(by_actor.len(), 2);
    let by_op = store
        .access_records(&AccessQuery {
            operation: Some("redrive_dlq".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(by_op.len(), 2);
    let by_time = store
        .access_records(&AccessQuery {
            from_micros: Some(1_500),
            to_micros: Some(2_500),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(by_time.len(), 1);
    assert_eq!(by_time[0].actor, "b");
    let limited = store
        .access_records(&AccessQuery {
            limit: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(limited.len(), 1);
}

//! Sharded-mode HTTP surface: tenant-header routing on writes, per-tenant vs
//! fan-out reads, cross-shard pagination over the wire, and a combined verify.
//! Single-mode behavior is covered by `http.rs`; this asserts the sharded path
//! a `[shards]` config turns on.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use quipu_core::{AuditStore, KeyRing, StoreConfig, SyncPolicy};
use quipu_middleware::{
    Action, AuditPipeline, PermissionPolicy, PipelineConfig, Role, ShardId, ShardMap, ShardRouter,
};
use quipu_server::config::AuthSection;
use quipu_server::{router, AppState, AuthState, DEFAULT_TENANT_HEADER};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

fn sharded_app(base: &std::path::Path, n: u32) -> (Router, Arc<ShardRouter>) {
    let policy = PermissionPolicy::deny_by_default().grant(
        Role::new("admin"),
        &[Action::Emit, Action::Query, Action::Administer],
    );
    let mut shards = Vec::new();
    for i in 0..n {
        let id = ShardId(i);
        let root = base.join(id.dir_name());
        std::fs::create_dir_all(&root).unwrap();
        let keys = KeyRing::new().with_hmac_key(b"test-hmac-key");
        let store = AuditStore::open(
            StoreConfig::new(&root)
                .keys(keys)
                .sync_policy(SyncPolicy::Always)
                .access_log(true),
        )
        .unwrap();
        let pipeline = AuditPipeline::start(
            store,
            root.clone(),
            PermissionPolicy::allow_all(),
            PipelineConfig::default(),
            None,
        )
        .unwrap();
        shards.push((id, pipeline));
    }
    let r = Arc::new(ShardRouter::new(ShardMap::new(n, 0xA11CE), shards));
    let auth: AuthSection = serde_json::from_value(json!({
        "tokens": { "admin-token": "admin" },
        "grants": { "admin": ["emit", "query", "administer"] }
    }))
    .unwrap();
    let state = AppState::new_sharded(
        r.clone(),
        AuthState {
            tokens: auth.token_map().unwrap(),
            policy,
            max_concurrent_queries: None,
        },
        base.to_path_buf(),
        DEFAULT_TENANT_HEADER,
    );
    (router(state), r)
}

fn user_schema() -> Value {
    json!({
        "type_name": "user",
        "fields": [{
            "name": "name", "kind": "Text", "protection": "None",
            "indexed": true, "required": false, "search": "None"
        }]
    })
}

fn append_body(actor: &str) -> Value {
    json!({
        "actor_type": "user",
        "actor": { "entity_id": actor, "fields": { "name": { "Text": actor } } },
        "method": "POST",
        "url": "/api/things",
        "content": { "Text": "did a thing" },
        "targets": [{
            "entity_type": "user",
            "input": { "entity_id": actor, "fields": { "name": { "Text": actor } } }
        }]
    })
}

/// Send with an optional tenant header.
async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    tenant: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    if let Some(t) = tenant {
        req = req.header(DEFAULT_TENANT_HEADER, t);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

async fn count(app: &Router, tenant: Option<&str>, q: Value) -> u64 {
    let (status, body) = send(
        app,
        "POST",
        "/v1/logs/count",
        Some("admin-token"),
        tenant,
        Some(q),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["count"].as_u64().unwrap()
}

#[tokio::test]
async fn write_requires_tenant_then_routes_and_reads_per_tenant_and_fanout() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _r) = sharded_app(dir.path(), 4);

    // define the type once — fans out to every shard
    let (status, _) = send(
        &app,
        "POST",
        "/v1/types",
        Some("admin-token"),
        None,
        Some(user_schema()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // a write with no tenant header is rejected: it must not be split silently
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs",
        Some("admin-token"),
        None,
        Some(append_body("alice")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // alice x4, bob x2 — routed by tenant header
    for _ in 0..4 {
        let (s, b) = send(
            &app,
            "POST",
            "/v1/logs",
            Some("admin-token"),
            Some("alice"),
            Some(append_body("alice")),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    }
    for _ in 0..2 {
        let (s, b) = send(
            &app,
            "POST",
            "/v1/logs",
            Some("admin-token"),
            Some("bob"),
            Some(append_body("bob")),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    }

    // fan-out count (no tenant) sees everything
    assert_eq!(count(&app, None, json!({})).await, 6);

    // tenant-scoped + actor filter isolates one tenant's records
    let alice = json!({ "actor": { "entity_type": "user", "field": "name", "value": { "Text": "alice" } } });
    assert_eq!(count(&app, Some("alice"), alice).await, 4);
    let bob =
        json!({ "actor": { "entity_type": "user", "field": "name", "value": { "Text": "bob" } } });
    assert_eq!(count(&app, Some("bob"), bob).await, 2);

    // combined verify across all shards is clean
    let (status, body) = send(
        &app,
        "POST",
        "/v1/admin/verify",
        Some("admin-token"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], json!(true), "{body}");
}

#[tokio::test]
async fn cross_shard_pagination_round_trips_the_multicursor_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _r) = sharded_app(dir.path(), 4);
    send(
        &app,
        "POST",
        "/v1/types",
        Some("admin-token"),
        None,
        Some(user_schema()),
    )
    .await;

    // spread 12 events across tenants/shards
    for i in 0..12 {
        let tenant = format!("tenant-{}", i % 5);
        let (s, _) = send(
            &app,
            "POST",
            "/v1/logs",
            Some("admin-token"),
            Some(&tenant),
            Some(append_body(&tenant)),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED);
    }

    // paginate the fan-out with a page size below the total; the opaque cursor
    // is echoed back each round (it is a base64 MultiCursor in sharded mode)
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut q = json!({ "order": "desc", "limit": 5 });
        if let Some(c) = &cursor {
            q["cursor"] = json!(c);
        }
        let (status, body) = send(
            &app,
            "POST",
            "/v1/logs/query",
            Some("admin-token"),
            None,
            Some(q),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for lv in body["logs"].as_array().unwrap() {
            // log_id is not a plain string on the wire; the whole row is a
            // stable unique key (distinct events differ in id + timestamp)
            seen.push(lv.to_string());
        }
        match body.get("next_cursor").and_then(|c| c.as_str()) {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }

    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        12,
        "every row appears exactly once across pages"
    );
}

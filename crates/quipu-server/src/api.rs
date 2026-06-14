use crate::auth::{role_for, AuthState};
use crate::config::ServerConfig;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use quipu_core::{
    Content, CustomColumnDef, EntityInput, LogQuery, LogView, QueryPage, TargetSnapshot,
    TypeSchema, Uid, Value,
};
use quipu_middleware::{
    disk_usage, AccessQuery, AccessRecord, Action, AuditEvent, AuditHandle, ConsistencyResponse,
    DiskUsage, HealthSnapshot, InclusionResponse, MetricsSnapshot, MiddlewareError, MultiCursor,
    Role, ShardRouter, TargetSpec, VerifyReport,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct AppState {
    /// A representative shard handle. In single-store mode it *is* the store; in
    /// sharded mode it is the lowest-id shard, kept for the shared health flags
    /// the disk-full tests drive. All data operations go through the helpers
    /// (which route via [`router`](Self::router) when present), never this field
    /// directly.
    pub handle: AuditHandle,
    /// `Some` in sharded mode — every emit/query/admin op routes through it.
    /// `None` in single-store mode, where [`handle`](Self::handle) is used
    /// directly (byte- and wire-compatible with the unsharded server).
    router: Option<Arc<ShardRouter>>,
    /// Tenant id header (sharded mode). Required on writes, optional on reads.
    tenant_header: Arc<str>,
    /// Store root directory — health probes write here, `/metrics` sizes it.
    /// In sharded mode this is the base that contains every `shard-NNNN`.
    store_root: Arc<PathBuf>,
    /// Hot-reloadable auth view (tokens + grants + query cap). All
    /// permission gating happens here at the HTTP layer — the pipeline runs
    /// `allow_all` in this binary precisely so a SIGHUP reload of this field
    /// is the single source of truth.
    auth: Arc<RwLock<AuthState>>,
    /// Per-token-hash query semaphores, created lazily; cleared on reload so
    /// a changed cap takes effect (in-flight permits stay on the old
    /// semaphores and just drain out).
    query_slots: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// True while an integrity verification runs. Verification is a
    /// full-store scan on the writer thread, so the endpoint and the periodic
    /// task share this guard to keep it to one pass at a time.
    verify_running: Arc<AtomicBool>,
    /// Completed verification passes since startup (endpoint + periodic) —
    /// an observability counter, also what tests poll.
    verify_runs: Arc<AtomicU64>,
    /// Recently seen `Idempotency-Key` values for `POST /v1/logs`. A client
    /// that times out cannot tell "queued" from "lost", so its retransmission
    /// of the same event must not become a second audit record — this window
    /// is what absorbs that duplicate. In-memory by design: see
    /// [`DedupWindow`] for the trade-off.
    dedup: Arc<Mutex<DedupWindow>>,
}

/// Default capacity of the idempotency-key window (see [`DedupWindow`]).
pub const DEFAULT_IDEMPOTENCY_WINDOW: usize = 65_536;

/// Fixed-capacity, insertion-ordered set of recently accepted idempotency
/// keys. Deliberately **in-memory**: persisting every key would put a
/// durable write on the append path *before* the event is even queued, for a
/// duplicate class that only exists across a client retransmission window
/// (seconds to minutes). The cost of that choice is precise and documented:
/// a server restart forgets the window, so a retransmission that straddles a
/// restart can be recorded twice — duplicates are bounded to that case, and
/// both copies carry the same client-set `occurred_at`, so they are
/// detectable after the fact.
struct DedupWindow {
    capacity: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl DedupWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `key`. Returns `false` if it was already in the window (a
    /// duplicate), `true` if it is new. Oldest keys are evicted at capacity.
    fn insert(&mut self, key: &str) -> bool {
        if self.capacity == 0 {
            return true; // dedup disabled
        }
        if self.seen.contains(key) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(key.to_string());
        self.order.push_back(key.to_string());
        true
    }

    /// Forget `key` — used when the enqueue behind it failed, so the
    /// client's retry is not misread as a duplicate.
    fn remove(&mut self, key: &str) {
        if self.seen.remove(key) {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
    }
}

/// One reserved unit of a token's concurrent-query budget.
pub enum QuerySlot {
    /// No `max_concurrent_queries` configured.
    Unlimited,
    /// Slot held until the permit drops.
    Acquired(OwnedSemaphorePermit),
    /// Budget exhausted — the HTTP layer answers 429.
    Busy,
}

/// Default tenant-id header for sharded mode (`config.shards.tenant_header`).
pub const DEFAULT_TENANT_HEADER: &str = "x-quipu-tenant";

impl AppState {
    pub fn new(handle: AuditHandle, auth: AuthState, store_root: PathBuf) -> Self {
        Self {
            handle,
            router: None,
            tenant_header: Arc::from(DEFAULT_TENANT_HEADER),
            store_root: Arc::new(store_root),
            auth: Arc::new(RwLock::new(auth)),
            query_slots: Arc::new(Mutex::new(HashMap::new())),
            verify_running: Arc::new(AtomicBool::new(false)),
            verify_runs: Arc::new(AtomicU64::new(0)),
            dedup: Arc::new(Mutex::new(DedupWindow::new(DEFAULT_IDEMPOTENCY_WINDOW))),
        }
    }

    /// Sharded mode: route every operation through `router`. `store_root` is the
    /// base directory holding the `shard-NNNN` stores (health probe + sizing).
    /// `tenant_header` names the request header that carries the tenant id.
    pub fn new_sharded(
        router: Arc<ShardRouter>,
        auth: AuthState,
        store_root: PathBuf,
        tenant_header: impl Into<String>,
    ) -> Self {
        let handle = router
            .representative_handle()
            .expect("a sharded router has at least one shard");
        Self {
            handle,
            router: Some(router),
            tenant_header: Arc::from(tenant_header.into().to_ascii_lowercase().as_str()),
            store_root: Arc::new(store_root),
            auth: Arc::new(RwLock::new(auth)),
            query_slots: Arc::new(Mutex::new(HashMap::new())),
            verify_running: Arc::new(AtomicBool::new(false)),
            verify_runs: Arc::new(AtomicU64::new(0)),
            dedup: Arc::new(Mutex::new(DedupWindow::new(DEFAULT_IDEMPOTENCY_WINDOW))),
        }
    }

    /// `true` in sharded mode (writes then require a tenant id).
    pub fn is_sharded(&self) -> bool {
        self.router.is_some()
    }

    /// Resize the idempotency-key window (config `idempotency.window`).
    /// `0` disables duplicate detection entirely. Call before the state is
    /// cloned into the router.
    pub fn idempotency_window(self, capacity: usize) -> Self {
        *self.dedup.lock().unwrap() = DedupWindow::new(capacity);
        self
    }

    /// Claim the single verification slot. `None` while a verification is
    /// already running (the HTTP layer answers 409); the slot frees itself
    /// when the returned guard drops. Public so tests can occupy it
    /// deterministically.
    pub fn try_begin_verify(&self) -> Option<VerifyGuard> {
        self.verify_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| VerifyGuard(self.verify_running.clone()))
    }

    /// Verification passes completed since startup (endpoint + periodic).
    pub fn verify_runs(&self) -> u64 {
        self.verify_runs.load(Ordering::Acquire)
    }

    /// Re-read `path` and swap in its `auth` section. On any error (I/O,
    /// parse, bad token hash) the previous auth state stays in force — a
    /// botched edit must not lock everyone out of a running server.
    pub fn reload_auth(&self, path: &std::path::Path) -> std::io::Result<()> {
        let cfg = ServerConfig::load(path)?;
        let next = cfg.auth_state()?;
        let mut auth = self.auth.write().unwrap();
        // hash-level diff doubles as the issue/revoke audit trail in the
        // server log, without ever logging token material
        let added = next
            .tokens
            .hashes()
            .filter(|h| !auth.tokens.contains_hash(h))
            .count();
        let removed = auth
            .tokens
            .hashes()
            .filter(|h| !next.tokens.contains_hash(h))
            .count();
        if next.max_concurrent_queries != auth.max_concurrent_queries {
            self.query_slots.lock().unwrap().clear();
        }
        *auth = next;
        tracing::info!(
            tokens_added = added,
            tokens_removed = removed,
            "auth section reloaded"
        );
        // token issue/revoke is admin activity worth a meta-audit record too
        // (no bearer token behind a SIGHUP — the actor is the host system).
        // In sharded mode it is store-wide, so it lands on every shard.
        self.record_access_op(AccessRecord::new(
            "system",
            "auth_reload",
            serde_json::json!({ "tokens_added": added, "tokens_removed": removed }).to_string(),
            None,
        ));
        Ok(())
    }

    /// Reserve one of the token's concurrent-query slots, keyed by the
    /// token's SHA-256 hex (see [`crate::auth::sha256_hex`]). Public so tests can occupy
    /// a slot deterministically.
    pub fn query_slot(&self, token_hash: &str) -> QuerySlot {
        let limit = self.auth.read().unwrap().max_concurrent_queries;
        let Some(limit) = limit else {
            return QuerySlot::Unlimited;
        };
        let semaphore = self
            .query_slots
            .lock()
            .unwrap()
            .entry(token_hash.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(limit as usize)))
            .clone();
        match semaphore.try_acquire_owned() {
            Ok(permit) => QuerySlot::Acquired(permit),
            Err(_) => QuerySlot::Busy,
        }
    }
}

/// The claimed verification slot (see [`AppState::try_begin_verify`]);
/// dropping it lets the next verification start.
pub struct VerifyGuard(Arc<AtomicBool>);

impl Drop for VerifyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Backend routing: every handler reaches the store through these, so the
/// single-store and sharded paths differ in exactly one place. In single mode
/// they delegate to the one [`AuditHandle`] (today's behavior, byte- and
/// wire-compatible); in sharded mode they route by tenant through the
/// [`ShardRouter`] and fan reads out across shards.
impl AppState {
    /// Tenant id from the configured header — `None` if absent/blank. Only
    /// meaningful in sharded mode; single mode ignores it.
    fn tenant(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(self.tenant_header.as_ref())
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn emit_event(
        &self,
        role: &Role,
        tenant: Option<&str>,
        event: AuditEvent,
    ) -> Result<(), MiddlewareError> {
        match &self.router {
            Some(r) => r.emit(role, tenant.unwrap_or_default(), event).map(|_| ()),
            None => self.handle.emit(role, event),
        }
    }

    /// Fire-and-forget meta-audit record. In sharded mode this is a store-wide
    /// action (e.g. an admin flush / auth reload) so it lands on every shard.
    fn record_access_op(&self, rec: AccessRecord) {
        match &self.router {
            Some(r) => r.record_access_all(rec),
            None => self.handle.record_access(rec),
        }
    }

    fn query_page_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
    ) -> Result<QueryPage, MiddlewareError> {
        match &self.router {
            None => self.handle.query_page(role, q),
            Some(r) => {
                // the wire cursor is an opaque MultiCursor (base64) in sharded
                // mode; decode it, run the fan-out, re-encode for the next page
                let cursor = q.cursor.as_deref().and_then(MultiCursor::decode);
                let limit = q.limit.unwrap_or(usize::MAX).min(100_000);
                let mut sub = q.clone();
                sub.cursor = None;
                let merged = r.query_page(role, tenant, sub, cursor, limit)?;
                Ok(QueryPage {
                    logs: merged.logs,
                    next_cursor: merged.next_cursor.map(|c| c.encode()),
                    segments_scanned: merged.segments_scanned,
                })
            }
        }
    }

    fn query_all_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
    ) -> Result<Vec<LogView>, MiddlewareError> {
        match &self.router {
            None => self.handle.query(role, q),
            Some(r) => r.query(role, tenant, q),
        }
    }

    fn count_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        q: LogQuery,
    ) -> Result<u64, MiddlewareError> {
        match &self.router {
            None => self.handle.count(role, q),
            Some(r) => r.count(role, tenant, q),
        }
    }

    fn list_entities_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        type_name: String,
        include_deleted: bool,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        match &self.router {
            None => self.handle.list_entities(role, type_name, include_deleted),
            Some(r) => r.list_entities(role, tenant, &type_name, include_deleted),
        }
    }

    fn entity_history_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        type_name: String,
        entity_id: String,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        match &self.router {
            None => self.handle.entity_history(role, type_name, entity_id),
            Some(r) => r.entity_history(role, tenant, &type_name, &entity_id),
        }
    }

    fn entity_types_op(&self, role: &Role) -> Result<Vec<TypeSchema>, MiddlewareError> {
        match &self.router {
            None => self.handle.entity_types(role),
            Some(r) => r.entity_types(role),
        }
    }

    fn define_type_op(&self, role: &Role, schema: TypeSchema) -> Result<(), MiddlewareError> {
        match &self.router {
            None => self.handle.define_type(role, schema),
            Some(r) => r.define_type(role, schema),
        }
    }

    fn define_column_op(&self, role: &Role, def: CustomColumnDef) -> Result<(), MiddlewareError> {
        match &self.router {
            None => self.handle.define_custom_column(role, def),
            Some(r) => r.define_custom_column(role, def),
        }
    }

    fn query_access_op(
        &self,
        role: &Role,
        q: AccessQuery,
    ) -> Result<Vec<AccessRecord>, MiddlewareError> {
        match &self.router {
            None => self.handle.query_access(role, q),
            Some(r) => r.query_access(role, q),
        }
    }

    fn flush_op(&self) -> Result<(), MiddlewareError> {
        match &self.router {
            Some(r) => r.flush(),
            None => self.handle.flush(),
        }
    }

    fn redrive_op(&self, role: &Role) -> Result<quipu_middleware::RedriveReport, MiddlewareError> {
        match &self.router {
            None => self.handle.redrive_dlq(role),
            Some(r) => r.redrive_dlq(role),
        }
    }

    fn retention_op(&self, role: &Role) -> Result<usize, MiddlewareError> {
        match &self.router {
            None => self.handle.apply_retention(role),
            Some(r) => r.apply_retention(role),
        }
    }

    fn dlq_len_op(&self, role: &Role) -> Result<usize, MiddlewareError> {
        match &self.router {
            None => self.handle.dlq_len(role),
            Some(r) => r.dlq_len(role),
        }
    }

    fn verify_op(&self, role: &Role) -> Result<VerifyReport, MiddlewareError> {
        match &self.router {
            None => self.handle.verify_integrity(role),
            Some(r) => r.verify_combined(role),
        }
    }

    /// Store-wide health: the writer is alive only if *every* shard's is; the
    /// disk-full and low-disk flags trip if *any* shard reports them.
    fn health_op(&self) -> HealthSnapshot {
        match &self.router {
            None => self.handle.health(),
            Some(r) => {
                let per = r.health();
                let mut it = per.values();
                let Some(first) = it.next().cloned() else {
                    return self.handle.health();
                };
                per.values().fold(
                    HealthSnapshot {
                        writer_alive: true,
                        disk_full: false,
                        low_disk: false,
                        thresholds: first.thresholds,
                    },
                    |acc, h| HealthSnapshot {
                        writer_alive: acc.writer_alive && h.writer_alive,
                        disk_full: acc.disk_full || h.disk_full,
                        low_disk: acc.low_disk || h.low_disk,
                        thresholds: acc.thresholds,
                    },
                )
            }
        }
    }

    /// Store-wide metrics: per-shard counters summed, latency histograms merged.
    fn metrics_op(&self) -> MetricsSnapshot {
        match &self.router {
            None => self.handle.metrics(),
            Some(r) => aggregate_metrics(r.metrics().into_values()),
        }
    }

    fn prove_inclusion_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        log_id: Uid,
    ) -> Result<InclusionResponse, MiddlewareError> {
        match &self.router {
            None => self.handle.prove_inclusion(role, log_id),
            Some(r) => r.prove_inclusion(role, tenant, log_id),
        }
    }

    fn prove_consistency_op(
        &self,
        role: &Role,
        tenant: Option<&str>,
        first_size: u64,
    ) -> Result<ConsistencyResponse, MiddlewareError> {
        match &self.router {
            None => self.handle.prove_consistency(role, first_size),
            Some(r) => r.prove_consistency(role, tenant.unwrap_or_default(), first_size),
        }
    }
}

/// Sum a set of per-shard metrics snapshots into one store-wide snapshot. The
/// zero base comes from a fresh `PipelineMetrics` so the latency histogram's
/// bucket bounds are correct even with zero shards.
fn aggregate_metrics(shards: impl Iterator<Item = MetricsSnapshot>) -> MetricsSnapshot {
    let mut out = quipu_middleware::PipelineMetrics::default().snapshot();
    for s in shards {
        out.queue_depth += s.queue_depth;
        out.dlq_entries += s.dlq_entries;
        out.writes_ok += s.writes_ok;
        out.write_retries += s.write_retries;
        out.writes_parked += s.writes_parked;
        out.events_lost += s.events_lost;
        out.emit_rejected_queue_full += s.emit_rejected_queue_full;
        out.emit_rejected_disk_full += s.emit_rejected_disk_full;
        out.write_latency.count += s.write_latency.count;
        out.write_latency.sum_seconds += s.write_latency.sum_seconds;
        for (i, (_, c)) in s.write_latency.buckets.iter().enumerate() {
            out.write_latency.buckets[i].1 += c;
        }
    }
    out
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/types", post(define_type).get(list_types))
        .route("/v1/columns", post(define_column))
        .route("/v1/openapi.json", get(openapi_json))
        .route("/v1/logs", post(append_log))
        .route("/v1/logs/query", post(query_logs))
        .route("/v1/logs/count", post(count_logs))
        .route("/v1/logs/export", post(export_logs))
        .route("/v1/entities/{type_name}", get(list_entities))
        .route(
            "/v1/entities/{type_name}/{entity_id}/history",
            get(entity_history),
        )
        .route("/v1/access/query", post(query_access))
        .route("/v1/proof/inclusion/{log_id}", get(proof_inclusion))
        .route("/v1/proof/consistency", get(proof_consistency))
        .route("/v1/admin/flush", post(admin_flush))
        .route("/v1/admin/redrive", post(admin_redrive))
        .route("/v1/admin/retention", post(admin_retention))
        .route("/v1/admin/dlq", get(admin_dlq))
        .route("/v1/admin/verify", post(admin_verify))
        .with_state(state)
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<MiddlewareError> for ApiError {
    fn from(e: MiddlewareError) -> Self {
        let status = match &e {
            MiddlewareError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            // the event is handed back inside the error; the HTTP client's
            // retry (after backoff) is the equivalent of re-emitting it
            MiddlewareError::QueueFull(_) => StatusCode::SERVICE_UNAVAILABLE,
            // persistent until space is freed — retrying immediately is
            // pointless, so a distinct status the client can back off on
            MiddlewareError::DiskFull(_) => StatusCode::INSUFFICIENT_STORAGE,
            MiddlewareError::WorkerGone => StatusCode::INTERNAL_SERVER_ERROR,
            MiddlewareError::Core(core) => match core {
                quipu_core::Error::Schema(_)
                | quipu_core::Error::Crypto(_)
                | quipu_core::Error::InvalidCursor(_) => StatusCode::BAD_REQUEST,
                quipu_core::Error::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        ApiError {
            status,
            message: e.to_string(),
        }
    }
}

fn unauthorized() -> ApiError {
    ApiError {
        status: StatusCode::UNAUTHORIZED,
        message: "missing or unknown bearer token".into(),
    }
}

fn internal(msg: impl Into<String>) -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: msg.into(),
    }
}

struct Caller {
    role: Role,
    /// SHA-256 hex of the presented token — the per-token rate-limit key.
    token_hash: String,
}

impl AppState {
    /// Authenticate the bearer token (existence + expiry) and check the
    /// role's grant in one step, against the current (possibly reloaded)
    /// auth state.
    fn authorize(&self, headers: &HeaderMap, action: Action) -> Result<Caller, ApiError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before 1970")
            .as_secs();
        let auth = self.auth.read().unwrap();
        let (role, token_hash) = role_for(headers, &auth.tokens, now).ok_or_else(unauthorized)?;
        if !auth.policy.is_allowed(&role, action) {
            return Err(MiddlewareError::PermissionDenied { role, action }.into());
        }
        Ok(Caller { role, token_hash })
    }
}

/// Run a handle call that blocks on the writer thread (or scans segments) off
/// the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, MiddlewareError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(format!("worker task failed: {e}")))?
        .map_err(ApiError::from)
}

// ---- health ------------------------------------------------------------------

/// `GET /v1/healthz` — unauthenticated, JSON
/// `{"status": "ok"|"degraded"|"unhealthy", "reasons": [...]}`.
///
/// - `unhealthy` (HTTP 503): the writer thread is dead, the disk-full latch
///   is set, or a probe write into the store root fails — appends are not
///   being persisted.
/// - `degraded` (HTTP 200): writes still work but free disk space is below
///   the configured thresholds (act now, before it becomes 503).
/// - `ok` (HTTP 200).
///
/// (Pre-observability versions answered plain-text `ok` unconditionally;
/// monitors matching on the body must switch to the status code or JSON.)
async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let snapshot = state.health_op();
    let root = state.store_root.clone();
    // the probe write and statvfs touch the filesystem: off the async runtime
    let report = tokio::task::spawn_blocking(move || evaluate_health(&snapshot, &root)).await;
    match report {
        Ok(report) => report.into_response_parts(),
        Err(e) => {
            HealthReport::unhealthy(format!("health check task failed: {e}")).into_response_parts()
        }
    }
}

/// Outcome of one health evaluation (separated from the handler so tests can
/// drive it with synthetic snapshots).
pub struct HealthReport {
    pub status: &'static str,
    pub reasons: Vec<String>,
}

impl HealthReport {
    fn unhealthy(reason: String) -> Self {
        Self {
            status: "unhealthy",
            reasons: vec![reason],
        }
    }

    fn into_response_parts(self) -> (StatusCode, Json<serde_json::Value>) {
        let code = if self.status == "unhealthy" {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            // degraded stays 200: load balancers must not eject an instance
            // that is still persisting events — the body carries the warning
            StatusCode::OK
        };
        (
            code,
            Json(serde_json::json!({ "status": self.status, "reasons": self.reasons })),
        )
    }
}

/// Combine the pipeline's health flags with live filesystem checks:
/// writer liveness and the disk-full latch from the snapshot, plus a probe
/// write into the store root (is the directory actually writable *now*?) and
/// a fresh statvfs against the configured thresholds.
pub fn evaluate_health(snapshot: &HealthSnapshot, store_root: &FsPath) -> HealthReport {
    let mut reasons = Vec::new();
    let mut unhealthy = false;
    let mut degraded = false;
    if !snapshot.writer_alive {
        unhealthy = true;
        reasons.push("audit writer thread is not running".into());
    }
    if snapshot.disk_full {
        unhealthy = true;
        reasons.push("store disk is full (writes are failing with ENOSPC)".into());
    }
    if let Err(e) = probe_write(store_root) {
        unhealthy = true;
        reasons.push(format!("store root is not writable: {e}"));
    }
    match disk_usage(store_root) {
        Ok(usage) => {
            if snapshot.thresholds.is_low(&usage) {
                degraded = true;
                reasons.push(format!(
                    "free disk space low: {} of {} bytes free (thresholds: {} bytes / {:.0}%)",
                    usage.free_bytes,
                    usage.total_bytes,
                    snapshot.thresholds.min_free_bytes,
                    snapshot.thresholds.min_free_ratio * 100.0
                ));
            }
        }
        // measurement unsupported/failed: fall back to the writer's last
        // housekeeping verdict instead of crying wolf
        Err(_) => {
            if snapshot.low_disk {
                degraded = true;
                reasons.push("free disk space low (reported by pipeline housekeeping)".into());
            }
        }
    }
    let status = if unhealthy {
        "unhealthy"
    } else if degraded {
        "degraded"
    } else {
        "ok"
    };
    HealthReport { status, reasons }
}

/// Create, write, fsync and remove a small probe file in the store root —
/// the most direct answer to "can the store still take bytes?".
fn probe_write(store_root: &FsPath) -> std::io::Result<()> {
    let path = store_root.join(".healthz-probe");
    let result = (|| {
        let mut f = std::fs::File::create(&path)?;
        std::io::Write::write_all(&mut f, b"probe")?;
        f.sync_all()
    })();
    let _ = std::fs::remove_file(&path); // best effort either way
    result
}

// ---- metrics -----------------------------------------------------------------

/// `GET /metrics` — Prometheus text exposition of the pipeline counters plus
/// store/disk gauges. Requires a bearer token with `Administer`, like the
/// other operational endpoints (point Prometheus at it with
/// `authorization: { credentials: <token> }`).
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    state.authorize(&headers, Action::Administer)?;
    let snapshot = state.metrics_op();
    let health = state.health_op();
    let verify_runs = state.verify_runs();
    let root = state.store_root.clone();
    // dir walk + statvfs: off the async runtime
    let body = tokio::task::spawn_blocking(move || {
        let store_bytes = dir_size(&root);
        let disk = disk_usage(&root).ok();
        render_prometheus(&snapshot, &health, store_bytes, disk, verify_runs)
    })
    .await
    .map_err(|e| internal(format!("metrics task failed: {e}")))?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response())
}

/// Total bytes of all files under `root` (the whole store: logs, relations,
/// registries, meta, checkpoints, DLQ). Unreadable entries count as 0 — a
/// metric scrape must not fail over a transient unlink race.
fn dir_size(root: &FsPath) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            total += dir_size(&path);
        } else {
            total += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

/// Hand-rolled Prometheus text format (v0.0.4) — the counter set is small
/// and fixed, so a real metrics framework would be all dependency and no
/// benefit.
pub fn render_prometheus(
    m: &MetricsSnapshot,
    h: &HealthSnapshot,
    store_bytes: u64,
    disk: Option<DiskUsage>,
    verify_runs: u64,
) -> String {
    fn metric_into(out: &mut String, name: &str, kind: &str, help: &str, value: String) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        let _ = writeln!(out, "{name} {value}");
    }
    let mut out = String::with_capacity(2048);
    let metric = metric_into;
    metric(
        &mut out,
        "quipu_queue_depth",
        "gauge",
        "Audit events enqueued but not yet picked up by the writer thread.",
        m.queue_depth.to_string(),
    );
    metric(
        &mut out,
        "quipu_dlq_entries",
        "gauge",
        "Events currently parked in the dead-letter queue.",
        m.dlq_entries.to_string(),
    );
    metric(
        &mut out,
        "quipu_writes_ok_total",
        "counter",
        "Events durably appended to the store.",
        m.writes_ok.to_string(),
    );
    metric(
        &mut out,
        "quipu_write_retries_total",
        "counter",
        "Failed write attempts that were retried.",
        m.write_retries.to_string(),
    );
    metric(
        &mut out,
        "quipu_writes_parked_total",
        "counter",
        "Events that exhausted retries (or hit disk-full) and went to the DLQ.",
        m.writes_parked.to_string(),
    );
    metric(
        &mut out,
        "quipu_events_lost_total",
        "counter",
        "Events lost outright: store and DLQ both failed (fallback hook only).",
        m.events_lost.to_string(),
    );
    let _ = writeln!(
        out,
        "# HELP quipu_emit_rejected_total Emits rejected at the caller, by reason.\n\
         # TYPE quipu_emit_rejected_total counter\n\
         quipu_emit_rejected_total{{reason=\"queue_full\"}} {}\n\
         quipu_emit_rejected_total{{reason=\"disk_full\"}} {}",
        m.emit_rejected_queue_full, m.emit_rejected_disk_full
    );
    let _ = writeln!(
        out,
        "# HELP quipu_write_latency_seconds Wall time to durably persist one event (including retries).\n\
         # TYPE quipu_write_latency_seconds histogram"
    );
    for (bound, count) in &m.write_latency.buckets {
        let _ = writeln!(
            out,
            "quipu_write_latency_seconds_bucket{{le=\"{bound}\"}} {count}"
        );
    }
    let _ = writeln!(
        out,
        "quipu_write_latency_seconds_bucket{{le=\"+Inf\"}} {}\n\
         quipu_write_latency_seconds_sum {}\n\
         quipu_write_latency_seconds_count {}",
        m.write_latency.count, m.write_latency.sum_seconds, m.write_latency.count
    );
    metric(
        &mut out,
        "quipu_store_bytes",
        "gauge",
        "Total bytes on disk under the store root (all tables, registries, DLQ).",
        store_bytes.to_string(),
    );
    if let Some(d) = disk {
        metric(
            &mut out,
            "quipu_disk_free_bytes",
            "gauge",
            "Free bytes on the filesystem holding the store root.",
            d.free_bytes.to_string(),
        );
        metric(
            &mut out,
            "quipu_disk_total_bytes",
            "gauge",
            "Size of the filesystem holding the store root.",
            d.total_bytes.to_string(),
        );
    }
    metric(
        &mut out,
        "quipu_writer_alive",
        "gauge",
        "1 while the audit writer thread is running.",
        u8::from(h.writer_alive).to_string(),
    );
    metric(
        &mut out,
        "quipu_disk_full",
        "gauge",
        "1 while the ENOSPC latch is set (writes failing for lack of space).",
        u8::from(h.disk_full).to_string(),
    );
    metric(
        &mut out,
        "quipu_disk_low",
        "gauge",
        "1 while free disk space is below the warning thresholds.",
        u8::from(h.low_disk).to_string(),
    );
    metric(
        &mut out,
        "quipu_verify_runs_total",
        "counter",
        "Completed integrity verification passes since startup.",
        verify_runs.to_string(),
    );
    out
}

// ---- schema ----------------------------------------------------------------

async fn define_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(schema): Json<TypeSchema>,
) -> Result<StatusCode, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    blocking(move || st.define_type_op(&role, schema)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TypeSchema>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let st = state.clone();
    Ok(Json(blocking(move || st.entity_types_op(&role)).await?))
}

async fn define_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(def): Json<CustomColumnDef>,
) -> Result<StatusCode, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    blocking(move || st.define_column_op(&role, def)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- logs --------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendRequest {
    /// UTC-micros event time; defaults to "now" on the server. Senders that
    /// queue/retry should set it so the log records when the action happened.
    occurred_at: Option<u64>,
    actor_type: String,
    actor: EntityInput,
    method: String,
    url: String,
    content: Content,
    #[serde(default)]
    targets: Vec<TargetSpec>,
    #[serde(default)]
    custom: BTreeMap<String, Value>,
}

/// Header carrying the client-generated idempotency key (any opaque string,
/// 1–128 visible-ASCII chars; a UUIDv4 is the recommended shape).
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";

/// Extract and validate the optional `Idempotency-Key` header.
fn idempotency_key(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(raw) = headers.get(IDEMPOTENCY_HEADER) else {
        return Ok(None);
    };
    let bad = |msg: &str| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: format!("{IDEMPOTENCY_HEADER}: {msg}"),
    };
    let key = raw
        .to_str()
        .map_err(|_| bad("must be visible ASCII"))?
        .trim();
    if key.is_empty() || key.len() > 128 {
        return Err(bad("must be 1-128 characters"));
    }
    if !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(bad("must be visible ASCII without spaces"));
    }
    Ok(Some(key.to_string()))
}

async fn append_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AppendRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let role = state.authorize(&headers, Action::Emit)?.role;
    // in sharded mode a write must name its tenant so it lands on exactly one
    // chain — silently picking a shard would split a tenant across chains
    let tenant = state.tenant(&headers);
    if state.is_sharded() && tenant.is_none() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "{} header is required on writes in sharded mode",
                state.tenant_header.as_ref()
            ),
        });
    }
    // duplicate detection happens *before* the enqueue: a retransmitted key
    // is acknowledged as already-accepted (202 "duplicate") and never becomes
    // a second audit record. The insert reserves the key; a failed enqueue
    // releases it below so the client's next retry isn't misread.
    let idem = idempotency_key(&headers)?;
    if let Some(key) = &idem {
        if !state.dedup.lock().unwrap().insert(key) {
            return Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "status": "duplicate" })),
            ));
        }
    }
    let mut event = AuditEvent::new(req.actor_type, req.actor, req.method, req.url, req.content);
    if let Some(at) = req.occurred_at {
        event.occurred_at = at;
    }
    event.targets = req.targets;
    event.custom = req.custom;
    // enqueue only — 202: durability is the pipeline's job (retries + DLQ)
    if let Err(e) = state.emit_event(&role, tenant.as_deref(), event) {
        if let Some(key) = &idem {
            state.dedup.lock().unwrap().remove(key);
        }
        return Err(e.into());
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "queued" })),
    ))
}

/// One page of matches, newest-first by default. The request body is a
/// `LogQuery`: `limit` is the page size, `order` is `"desc"`/`"asc"`, and
/// `cursor` continues from a previous response's `next_cursor` (opaque —
/// send it back verbatim with an otherwise identical query). The response is
/// `{ "logs": [...], "next_cursor": "...", "segments_scanned": n }`;
/// `next_cursor` is absent on the final page.
async fn query_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<LogQuery>,
) -> Result<Json<quipu_core::QueryPage>, ApiError> {
    let caller = state.authorize(&headers, Action::Query)?;
    // a query may still scan many segments — hold one of the token's slots
    // for the whole scan so a single token cannot monopolise the blocking pool
    let _slot = match state.query_slot(&caller.token_hash) {
        QuerySlot::Busy => {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "too many concurrent queries for this token".into(),
            })
        }
        slot => slot,
    };
    let role = caller.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    // the scan runs on the snapshot in the blocking pool; appends keep flowing.
    // with a tenant it hits one shard's fast path; without, it fans out + merges
    Ok(Json(
        blocking(move || st.query_page_op(&role, tenant.as_deref(), q)).await?,
    ))
}

/// Total number of matches for a `LogQuery`, without rendering (no registry
/// resolution, no decryption). `limit`/`cursor`/`order` in the body are
/// ignored. Response: `{ "count": n }`.
async fn count_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<LogQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let caller = state.authorize(&headers, Action::Query)?;
    let _slot = match state.query_slot(&caller.token_hash) {
        QuerySlot::Busy => {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "too many concurrent queries for this token".into(),
            })
        }
        slot => slot,
    };
    let role = caller.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    let n = blocking(move || st.count_op(&role, tenant.as_deref(), q)).await?;
    Ok(Json(serde_json::json!({ "count": n })))
}

// ---- meta-audit (access log) ---------------------------------------------------

/// Read the meta-audit access log: who queried/administered the audit store,
/// when, with what parameter shapes and result counts. Requires the
/// `administer` grant (access records reveal who searched what). Only
/// available when `store.access_log` is enabled in the config (400
/// otherwise). This read is itself recorded — one `query_access` record per
/// call, never more (the recording is an append, not a query).
async fn query_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<AccessQuery>,
) -> Result<Json<Vec<AccessRecord>>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    Ok(Json(blocking(move || st.query_access_op(&role, q)).await?))
}

// ---- merkle proofs -------------------------------------------------------------

/// Lowercase-hex a byte slice (proof fields go out as hex so the JSON stays
/// inspectable and matches the hex roots an anchor exports).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Inclusion proof for a log id: proves the record is committed to the current
/// Merkle root, in O(log n), without the rest of the log. Requires the `query`
/// grant. In sharded mode pass the tenant header so the owning shard is found.
/// Response: `{ log_id, leaf_index, tree_size, leaf, audit_path: [..], merkle_root }`
/// — verify it with the published RFC 6962 algorithm against `merkle_root`.
async fn proof_inclusion(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(log_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    // accept the decimal u128 form a query returns, or 32-char hex
    let id = log_id
        .parse::<u128>()
        .ok()
        .map(Uid)
        .or_else(|| Uid::from_hex(&log_id))
        .ok_or_else(|| ApiError {
            status: StatusCode::BAD_REQUEST,
            message: format!("'{log_id}' is not a valid log id"),
        })?;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    let r = blocking(move || st.prove_inclusion_op(&role, tenant.as_deref(), id)).await?;
    Ok(Json(serde_json::json!({
        "log_id": log_id,
        "leaf_index": r.proof.leaf_index,
        "tree_size": r.proof.tree_size,
        "leaf": hex(&r.proof.leaf),
        "audit_path": r.proof.path.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "merkle_root": hex(&r.root),
    })))
}

#[derive(Deserialize)]
struct ConsistencyParams {
    /// The earlier tree size to prove the current tree extends (typically a
    /// checkpoint's `tree_size` an auditor holds).
    from: u64,
}

/// Consistency proof from an earlier tree size (`?from=`) to the current tree:
/// proves the history in between is append-only — nothing was edited or removed.
/// Requires the `query` grant. In sharded mode the tenant header selects the
/// shard (proofs are per-shard). Response:
/// `{ first_size, second_size, proof: [..], merkle_root }`.
async fn proof_consistency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ConsistencyParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    let from = params.from;
    let r = blocking(move || st.prove_consistency_op(&role, tenant.as_deref(), from)).await?;
    Ok(Json(serde_json::json!({
        "first_size": r.proof.first_size,
        "second_size": r.proof.second_size,
        "proof": r.proof.path.iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "merkle_root": hex(&r.root),
    })))
}

/// Export matching logs as newline-delimited JSON (`application/x-ndjson`) —
/// one [`quipu_core::LogView`] per line, the format auditors and SIEM ingest
/// pipelines expect. Same query body, permission, and per-token slot as
/// `/v1/logs/query`; the difference is only the response framing. Protected
/// fields obey the same key boundary as a query: a server without the RSA
/// private key exports them as ciphertext for the holder to decrypt.
async fn export_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<LogQuery>,
) -> Result<Response, ApiError> {
    let caller = state.authorize(&headers, Action::Query)?;
    let _slot = match state.query_slot(&caller.token_hash) {
        QuerySlot::Busy => {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "too many concurrent queries for this token".into(),
            })
        }
        slot => slot,
    };
    let role = caller.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    let views = blocking(move || st.query_all_op(&role, tenant.as_deref(), q)).await?;
    // serialize off the snapshot into one line per record; a record that fails
    // to serialize aborts the export rather than emitting a truncated line
    let mut body = String::new();
    for view in &views {
        let line = serde_json::to_string(view).map_err(|e| internal(e.to_string()))?;
        body.push_str(&line);
        body.push('\n');
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    )
        .into_response())
}

/// Serve the OpenAPI 3.1 description of this API (the static spec shipped with
/// the crate). Unauthenticated on purpose — it is an interface description, not
/// data — and the one endpoint a client developer hits first.
async fn openapi_json() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        include_str!("../openapi.json"),
    )
        .into_response()
}

// ---- registry browsing -------------------------------------------------------

#[derive(Deserialize)]
struct ListParams {
    #[serde(default)]
    include_deleted: bool,
}

async fn list_entities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(type_name): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<quipu_core::TargetSnapshot>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    Ok(Json(
        blocking(move || {
            st.list_entities_op(&role, tenant.as_deref(), type_name, params.include_deleted)
        })
        .await?,
    ))
}

async fn entity_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((type_name, entity_id)): Path<(String, String)>,
) -> Result<Json<Vec<quipu_core::TargetSnapshot>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let tenant = state.tenant(&headers);
    let st = state.clone();
    Ok(Json(
        blocking(move || st.entity_history_op(&role, tenant.as_deref(), type_name, entity_id))
            .await?,
    ))
}

// ---- admin ---------------------------------------------------------------------

async fn admin_flush(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    blocking(move || st.flush_op()).await?;
    // flush() takes no role (it is also the pipeline's internal barrier), so
    // the HTTP layer records the admin action itself (on every shard in
    // sharded mode — flush is store-wide)
    state.record_access_op(AccessRecord::new(&role.0, "flush", "{}", None));
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_redrive(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    let report = blocking(move || st.redrive_op(&role)).await?;
    Ok(Json(serde_json::json!({
        "redriven": report.replayed,
        "requeued": report.requeued,
        "quarantined_entries": report.quarantined_entries,
        "quarantined_segments": report.quarantined_segments,
    })))
}

async fn admin_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    let n = blocking(move || st.retention_op(&role)).await?;
    Ok(Json(serde_json::json!({ "segments_dropped": n })))
}

async fn admin_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let st = state.clone();
    let n = blocking(move || st.dlq_len_op(&role)).await?;
    Ok(Json(serde_json::json!({ "parked": n })))
}

/// Verify the store's tamper-evidence hash chains. A found chain break is a
/// *successful* verification: 200 with `"ok": false` and the problem listed —
/// only "could not verify at all" is an error status. At most one
/// verification runs at a time (shared with the periodic task); a second
/// request gets 409 and should retry later.
async fn admin_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VerifyReport>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let Some(guard) = state.try_begin_verify() else {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            message: "an integrity verification is already running".into(),
        });
    };
    let st = state.clone();
    // full-store scan: run it in the blocking pool, holding the guard until
    // the scan finishes (every shard, sequentially, in sharded mode)
    let report = blocking(move || {
        let _running = guard;
        st.verify_op(&role)
    })
    .await?;
    state.verify_runs.fetch_add(1, Ordering::AcqRel);
    Ok(Json(report))
}

/// Background verification loop (config section `verify`): one pass at
/// startup, then one per `interval`. A pass that finds a chain break — or
/// cannot run — logs at `error`; that log line is the alerting hook. Skips a
/// tick (at `warn`) when a verification is already running.
pub fn spawn_periodic_verify(state: AppState, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // the pipeline behind AppState enforces nothing (the HTTP layer
        // does), so this internal identity is only a label in error messages
        let role = Role::new("periodic-verify");
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(guard) = state.try_begin_verify() else {
                tracing::warn!("periodic verify skipped: a verification is already running");
                continue;
            };
            let st = state.clone();
            let role = role.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _running = guard;
                st.verify_op(&role)
            })
            .await;
            match result {
                Ok(Ok(report)) => {
                    state.verify_runs.fetch_add(1, Ordering::AcqRel);
                    if report.ok {
                        tracing::info!(
                            segments = report.segments_checked,
                            log_records = report.log_records,
                            "periodic integrity verification passed"
                        );
                    } else {
                        tracing::error!(
                            problems = ?report.problems,
                            segments = report.segments_checked,
                            "integrity verification FAILED — the store shows tampering or corruption"
                        );
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "periodic integrity verification could not run")
                }
                Err(e) => tracing::error!(error = %e, "periodic verify task panicked"),
            }
        }
    })
}

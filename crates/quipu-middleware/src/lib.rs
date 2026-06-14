//! # quipu-middleware
//!
//! Async audit-logging middleware on top of [`quipu_core`]:
//!
//! - [`pipeline`]: event-driven, non-blocking writer with retries, a
//!   disk-backed dead-letter queue and a programmable fallback hook
//! - [`filter`]: programmable pre/post filters that can exempt requests from
//!   auditing or enrich events after the response is known
//! - [`permissions`]: who may emit and who may query audit logs
//! - [`layer`]: a `tower` Layer that proxies HTTP services per endpoint and
//!   emits audit events automatically
//! - [`metrics`] / [`health`]: lock-free pipeline counters (queue depth, DLQ
//!   size, write latency, ...) and health flags (writer liveness, disk-full
//!   latch, low-disk warning), readable from any handle clone without
//!   touching the writer thread
//!
//! # Quick start
//!
//! This is the README quick start, kept here as a `no_run` doctest so it can't
//! drift from the real API — `cargo test --doc -p quipu-middleware` compiles it.
//!
//! ```no_run
//! use quipu_core::*;
//! use quipu_middleware::*;
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! // 1. Open (or create) a store.
//! let root = std::path::PathBuf::from("/var/lib/myapp/audit");
//! let cfg = StoreConfig::new(&root)
//!     .retention(RetentionPolicy::days(90))
//!     .sync_policy(SyncPolicy::EveryN(32));
//! let mut store = AuditStore::open(cfg)?;
//!
//! // 2. Register entity types (the defaults work without custom schemas).
//! if !store.has_type("default_actor") {
//!     store.define_type(default_actor_type())?;
//!     store.define_type(default_target_type())?;
//! }
//!
//! // 3. Start the pipeline and keep a cheap, cloneable handle.
//! let pipeline = AuditPipeline::start(
//!     store, root, PermissionPolicy::allow_all(),
//!     PipelineConfig::default(), None /* fallback hook */)?;
//! let handle = pipeline.handle();
//!
//! // 4. Emit events — non-blocking.
//! handle.emit(
//!     &Role::new("svc"),
//!     AuditEvent::new(
//!         "default_actor",
//!         EntityInput::new("svc-1").text("name", "billing-service"),
//!         "PUT",
//!         "/api/docs/42",
//!         Content::Text("saved".into()),
//!     )
//!     .target(TargetSpec::new(
//!         "default_target",
//!         EntityInput::new("42").text("name", "doc-42"),
//!     )),
//! )?;
//! # Ok(())
//! # }
//! ```

pub mod event;
pub mod filter;
pub mod health;
pub mod layer;
pub mod metrics;
pub mod permissions;
pub mod pipeline;
pub mod sharding;

pub use event::{AuditEvent, TargetSpec};
pub use filter::{FilterDecision, FilterSet, PostFilter, PreFilter, RequestInfo, ResponseInfo};
pub use health::{disk_usage, DiskThresholds, DiskUsage, HealthSnapshot, HealthState};
pub use layer::{ActorExtractor, AuditLayer, AuditService, EndpointRule, TargetExtractor};
pub use metrics::{LatencySnapshot, MetricsSnapshot, PipelineMetrics};
pub use permissions::{Action, PermissionPolicy, Role};
pub use pipeline::{
    AuditHandle, AuditPipeline, ConsistencyResponse, DlqEntry, FallbackFn, InclusionResponse,
    MiddlewareError, PipelineConfig, RedriveReport, SinkFn, VerifyReport,
};
pub use quipu_core::{AccessQuery, AccessRecord};
pub use sharding::{
    GlobalCheckpoint, GlobalVerifyReport, MergedPage, MultiCursor, ShardHead, ShardId, ShardMap,
    ShardRouter,
};

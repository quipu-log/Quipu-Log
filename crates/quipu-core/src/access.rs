//! Meta-audit ("access log"): records of *reads and administrative actions
//! against the audit store itself* — who queried what, who ran a redrive or a
//! retention pass. In regulated environments (HIPAA access reports, financial
//! audit-trail reviews) the act of looking at audit data is itself auditable.
//!
//! Design notes:
//!
//! - Access records live in their **own append-only table** (`root/access/`),
//!   not in the main log table. That keeps their retention independent
//!   (retention drops whole segments per table, so mixing record kinds in one
//!   table would make per-kind retention impossible) and keeps the main hash
//!   chain / checkpoint machinery untouched. The access table carries its own
//!   tamper-evidence chain and is covered by
//!   [`crate::AuditStore::verify_integrity`].
//! - **No self-reference loop**: recording an access is a plain table append —
//!   it never goes through a query path, so it can never trigger another
//!   access record. Querying the access log *is* an access and is recorded
//!   (exactly one record per query), but that recording again is just an
//!   append: growth is strictly one record per externally-initiated
//!   operation, never recursive.
//! - **Search probe values are never recorded.** A query summary (see
//!   [`summarize_log_query`]) keeps the *shape* of the query — which fields
//!   were filtered, in which mode, over which time range — but drops filter
//!   values and custom-column values. Otherwise a search against an
//!   HMAC/RSA-protected field would leak its probe plaintext into the access
//!   log, defeating the field protection.

use crate::id::Uid;
use crate::query::LogQuery;
use serde::{Deserialize, Serialize};

/// Entity-type names starting with this prefix are reserved for quipu's own
/// internal record kinds (e.g. [`ACCESS_TYPE`]) and cannot be defined via
/// [`crate::AuditStore::define_type`].
pub const RESERVED_TYPE_PREFIX: &str = "quipu_";

/// The reserved type name under which meta-audit records are kept.
pub const ACCESS_TYPE: &str = "quipu_access";

/// One meta-audit row: a single read or administrative operation against the
/// audit store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub id: Uid,
    /// UTC-micros when the operation ran.
    pub timestamp: u64,
    /// Who performed the operation. In server mode this is the bearer
    /// token's role; in embedded mode the host-supplied identity (or
    /// `"local"` for direct [`crate::AuditStore::query`] calls).
    pub actor: String,
    /// What was done: `query_logs`, `list_entities`, `entity_history`,
    /// `query_access`, `redrive_dlq`, `apply_retention`, `flush`, `dlq_len`,
    /// `verify`, `auth_reload`, ...
    pub operation: String,
    /// Sanitized parameter summary (JSON). Never contains search probe
    /// values or custom-column values — see [`summarize_log_query`].
    pub params: String,
    /// How many rows/items the operation returned or affected, if countable.
    pub result_count: Option<u64>,
}

impl AccessRecord {
    pub fn new(
        actor: impl Into<String>,
        operation: impl Into<String>,
        params: impl Into<String>,
        result_count: Option<u64>,
    ) -> Self {
        Self {
            id: Uid::generate(),
            timestamp: crate::time::now_micros(),
            actor: actor.into(),
            operation: operation.into(),
            params: params.into(),
            result_count,
        }
    }

    /// Override the record's timestamp (UTC micros) — for hosts that record
    /// after the fact, and for retention tests.
    pub fn at(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Filter for reading the access log back. All set conditions are AND-ed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessQuery {
    /// Inclusive UTC-micros range.
    pub from_micros: Option<u64>,
    pub to_micros: Option<u64>,
    /// Exact actor match.
    pub actor: Option<String>,
    /// Exact operation match.
    pub operation: Option<String>,
    pub limit: Option<usize>,
}

impl AccessQuery {
    pub fn matches(&self, rec: &AccessRecord) -> bool {
        if self.from_micros.is_some_and(|from| rec.timestamp < from) {
            return false;
        }
        if self.to_micros.is_some_and(|to| rec.timestamp > to) {
            return false;
        }
        if self.actor.as_ref().is_some_and(|a| *a != rec.actor) {
            return false;
        }
        if self
            .operation
            .as_ref()
            .is_some_and(|op| *op != rec.operation)
        {
            return false;
        }
        true
    }
}

/// Render a [`LogQuery`] as a JSON summary that is safe to persist in the
/// access log: filter *shapes* (entity type, field name, match mode,
/// include_past) are kept, filter *values* and custom-column values are
/// dropped (only custom keys survive). Method and url_prefix are kept as-is —
/// both are plaintext columns of the main log already.
pub fn summarize_log_query(q: &LogQuery) -> String {
    fn filter_shape(f: &crate::query::TargetFilter) -> serde_json::Value {
        serde_json::json!({
            "entity_type": f.entity_type,
            "field": f.field,
            "mode": f.mode,
            "include_past": f.include_past,
        })
    }
    let mut out = serde_json::Map::new();
    if let Some(v) = q.from_micros {
        out.insert("from_micros".into(), v.into());
    }
    if let Some(v) = q.to_micros {
        out.insert("to_micros".into(), v.into());
    }
    if let Some(v) = &q.method {
        out.insert("method".into(), v.clone().into());
    }
    if let Some(v) = &q.url_prefix {
        out.insert("url_prefix".into(), v.clone().into());
    }
    if let Some(f) = &q.actor {
        out.insert("actor_filter".into(), filter_shape(f));
    }
    if !q.targets.is_empty() {
        out.insert(
            "target_filters".into(),
            q.targets.iter().map(filter_shape).collect(),
        );
    }
    if !q.custom.is_empty() {
        out.insert(
            "custom_keys".into(),
            q.custom.keys().cloned().collect::<Vec<_>>().into(),
        );
    }
    if let Some(v) = q.limit {
        out.insert("limit".into(), v.into());
    }
    serde_json::Value::Object(out).to_string()
}

/// Render an [`AccessQuery`] as a JSON summary. Access-query parameters carry
/// no protected material (actor names and operation names are stored
/// plaintext in the access log anyway), so they are recorded verbatim.
pub fn summarize_access_query(q: &AccessQuery) -> String {
    let mut out = serde_json::Map::new();
    if let Some(v) = q.from_micros {
        out.insert("from_micros".into(), v.into());
    }
    if let Some(v) = q.to_micros {
        out.insert("to_micros".into(), v.into());
    }
    if let Some(v) = &q.actor {
        out.insert("actor".into(), v.clone().into());
    }
    if let Some(v) = &q.operation {
        out.insert("operation".into(), v.clone().into());
    }
    if let Some(v) = q.limit {
        out.insert("limit".into(), v.into());
    }
    serde_json::Value::Object(out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Value;
    use crate::query::TargetFilter;

    #[test]
    fn summary_never_contains_probe_values() {
        let q = LogQuery {
            actor: Some(TargetFilter::exact(
                "user",
                "name",
                Value::Text("SECRET-ACTOR".into()),
            )),
            targets: vec![
                TargetFilter::exact("patient", "ssn", Value::Text("SECRET-123".into())).contains(),
            ],
            custom: [("note".to_string(), Value::Text("SECRET-NOTE".into()))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let s = summarize_log_query(&q);
        assert!(!s.contains("SECRET-123"), "target probe leaked: {s}");
        assert!(!s.contains("SECRET-ACTOR"), "actor probe leaked: {s}");
        assert!(!s.contains("SECRET-NOTE"), "custom value leaked: {s}");
        // the shape survives
        assert!(s.contains("patient"));
        assert!(s.contains("ssn"));
        assert!(s.contains("contains"));
        assert!(s.contains("note"));
    }
}

//! The seam between the MCP tools and the audit store behind them.
//!
//! The tools never touch a store directly; they call a [`Backend`]. The
//! shipped backend ([`crate::HttpBackend`]) is an HTTP client for
//! `quipu-server`, but the trait keeps the protocol layer testable against a
//! mock and documents exactly what an "audit auditor" agent is allowed to do —
//! read and verify, never append or administer.

use serde_json::Value;

/// Why a backend call failed, in the terms the tool layer needs: a message to
/// surface to the agent, and whether retrying could help (so a tool can say
/// "the audit server is unreachable, try again" instead of "your query is
/// wrong").
#[derive(Debug, Clone)]
pub struct BackendError {
    pub message: String,
    pub retryable: bool,
}

impl BackendError {
    pub fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub type BackendResult = Result<Value, BackendError>;

/// The read-only audit operations exposed to an agent. Each returns the raw
/// JSON the audit store produced, which the tool layer forwards verbatim — the
/// MCP server adds no interpretation of its own, so the agent reasons over the
/// store's actual answer.
///
/// Note what is *absent*: there is no append and no admin (flush/redrive/
/// retention). An MCP token is scoped to `query` (plus `administer` only if you
/// want `verify_store_integrity`); the agent can read and check the ledger, not
/// change it.
pub trait Backend: Send + Sync {
    /// Run a `LogQuery` (the same JSON body as `POST /v1/logs/query`) and
    /// return the matching `[LogView]`.
    fn query_logs(&self, query: &Value) -> BackendResult;

    /// Full version history of one entity, oldest first
    /// (`GET /v1/entities/{type}/{id}/history`).
    fn entity_history(&self, entity_type: &str, entity_id: &str) -> BackendResult;

    /// Verify the store's tamper-evidence hash chains
    /// (`POST /v1/admin/verify`) and return the report.
    fn verify_integrity(&self) -> BackendResult;
}

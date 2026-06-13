//! The three tools the agent sees, their JSON schemas, and dispatch to the
//! [`Backend`].
//!
//! Tool *failures* are reported the MCP way — a normal `tools/call` result with
//! `isError: true` and a human-readable message — not as JSON-RPC protocol
//! errors. The agent is meant to read "the audit server rejected this query
//! because ..." and adjust, the same way it would read any tool's error text.

use crate::backend::{Backend, BackendResult};
use serde_json::{json, Value};

pub const QUERY_LOGS: &str = "query_logs";
pub const GET_ENTITY_HISTORY: &str = "get_entity_history";
pub const VERIFY_STORE_INTEGRITY: &str = "verify_store_integrity";

/// The `tools/list` payload: name, description, and input JSON Schema for each
/// tool. Descriptions are written for the *model* — they say when to reach for
/// the tool and what the shape of the answer is.
pub fn tool_defs() -> Value {
    json!([
        {
            "name": QUERY_LOGS,
            "description": "Search the audit log. Pass a LogQuery object; every field is optional and set fields are AND-ed (an empty object {} returns the most recent events up to `limit`). Use this to answer questions like 'who accessed document 42 last week' or 'show failed logins for user alice'. Returns an array of LogView rows: each is the recorded action plus the actor/target as they were at the time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "object",
                        "description": "A LogQuery. Useful fields: from_micros/to_micros (UTC microseconds), actor_type, method, url, limit, and targets (a list of {entity_type, field, value, mode} filters, mode one of exact/exact_ci/prefix/contains). Values are tagged: {\"Text\":\"...\"}, {\"Number\":1.5}, or {\"Json\":\"...\"}.",
                        "additionalProperties": true
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        },
        {
            "name": GET_ENTITY_HISTORY,
            "description": "Retrieve the full version history of one entity (a user, document, account, ...), oldest first. Use this to see how an entity's recorded attributes changed over time — renames, field edits, deletion. Returns an array of TargetSnapshot versions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_type": { "type": "string", "description": "The registered type name, e.g. 'user' or 'document'." },
                    "entity_id": { "type": "string", "description": "The entity's stable external id." }
                },
                "required": ["entity_type", "entity_id"],
                "additionalProperties": false
            }
        },
        {
            "name": VERIFY_STORE_INTEGRITY,
            "description": "Verify the audit store's tamper-evidence hash chains and return the report. Use this to answer 'has the audit log been altered?'. A report with ok:false lists the first detected break (a record edited in place or a segment removed/swapped); ok:true means every chain checked out.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        }
    ])
}

/// Dispatch one `tools/call`. Returns the MCP result object (`content` +
/// optional `isError`), never a protocol error: an unknown tool or a backend
/// failure both come back as `isError: true` text the agent can read.
pub fn call(backend: &dyn Backend, name: &str, arguments: &Value) -> Value {
    let result: Result<BackendResult, String> = match name {
        QUERY_LOGS => {
            let query = arguments.get("query").cloned().unwrap_or(json!({}));
            Ok(backend.query_logs(&query))
        }
        GET_ENTITY_HISTORY => {
            match (
                arguments.get("entity_type").and_then(Value::as_str),
                arguments.get("entity_id").and_then(Value::as_str),
            ) {
                (Some(t), Some(id)) => Ok(backend.entity_history(t, id)),
                _ => Err("get_entity_history requires string 'entity_type' and 'entity_id'".into()),
            }
        }
        VERIFY_STORE_INTEGRITY => Ok(backend.verify_integrity()),
        other => Err(format!("unknown tool '{other}'")),
    };

    match result {
        // bad arguments before the call even happened
        Err(msg) => error_result(&msg),
        // the backend ran; format success or its error
        Ok(Ok(value)) => ok_result(&value),
        Ok(Err(e)) => {
            let hint = if e.retryable {
                " (transient — the audit server may be unreachable or busy; retrying may help)"
            } else {
                ""
            };
            error_result(&format!("{e}{hint}"))
        }
    }
}

fn ok_result(value: &Value) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    json!({ "content": [{ "type": "text", "text": text }] })
}

fn error_result(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendError, BackendResult};
    use std::sync::Mutex;

    struct MockBackend {
        last_query: Mutex<Option<Value>>,
        reply: BackendResult,
    }
    impl MockBackend {
        fn ok(reply: Value) -> Self {
            Self {
                last_query: Mutex::new(None),
                reply: Ok(reply),
            }
        }
        fn err(e: BackendError) -> Self {
            Self {
                last_query: Mutex::new(None),
                reply: Err(e),
            }
        }
    }
    impl Backend for MockBackend {
        fn query_logs(&self, query: &Value) -> BackendResult {
            *self.last_query.lock().unwrap() = Some(query.clone());
            self.reply.clone()
        }
        fn entity_history(&self, _t: &str, _id: &str) -> BackendResult {
            self.reply.clone()
        }
        fn verify_integrity(&self) -> BackendResult {
            self.reply.clone()
        }
    }

    #[test]
    fn query_logs_forwards_query_and_wraps_result() {
        let backend = MockBackend::ok(json!([{ "url": "/x" }]));
        let out = call(
            &backend,
            QUERY_LOGS,
            &json!({ "query": { "method": "POST" } }),
        );
        assert!(out.get("isError").is_none());
        assert_eq!(
            *backend.last_query.lock().unwrap(),
            Some(json!({ "method": "POST" }))
        );
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("/x"));
    }

    #[test]
    fn missing_args_is_tool_error_not_panic() {
        let backend = MockBackend::ok(json!([]));
        let out = call(
            &backend,
            GET_ENTITY_HISTORY,
            &json!({ "entity_type": "user" }),
        );
        assert_eq!(out["isError"], json!(true));
    }

    #[test]
    fn unknown_tool_is_tool_error() {
        let backend = MockBackend::ok(json!([]));
        let out = call(&backend, "drop_table", &json!({}));
        assert_eq!(out["isError"], json!(true));
        assert!(out["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));
    }

    #[test]
    fn backend_error_surfaces_with_retry_hint() {
        let backend = MockBackend::err(BackendError::retryable("queue full"));
        let out = call(&backend, VERIFY_STORE_INTEGRITY, &json!({}));
        assert_eq!(out["isError"], json!(true));
        assert!(out["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("transient"));
    }
}

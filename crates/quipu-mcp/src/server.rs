//! The MCP server: JSON-RPC 2.0 dispatch and the newline-delimited stdio loop.
//!
//! MCP's stdio transport is one JSON-RPC message per line on stdin, one
//! response per line on stdout. [`Server::handle_line`] is the whole protocol
//! as a pure function — parse, dispatch, return an optional response line — so
//! the conversation is testable without spawning a process or wiring real
//! stdio. [`Server::run_stdio`] is the thin loop around it.

use crate::backend::Backend;
use crate::tools;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// The MCP protocol version this server speaks (the revision it was written
/// against). Echoed back in `initialize`.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC error codes used here (a subset of the standard set).
mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
}

/// An MCP server over some [`Backend`]. Cheap to construct; one per stdio
/// session.
pub struct Server<B: Backend> {
    backend: B,
}

impl<B: Backend> Server<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Handle one line of input. Returns the response line to write back, or
    /// `None` for a notification (no `id`) or a blank line — neither gets a
    /// reply, per JSON-RPC.
    pub fn handle_line(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(error_response(Value::Null, codes::PARSE_ERROR, "parse error")),
        };
        let id = msg.get("id").cloned();
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            return id.map(|id| error_response(id, codes::INVALID_REQUEST, "missing method"));
        };
        // a request without an id is a notification: act on it, never reply
        let is_notification = id.is_none();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        let outcome = self.dispatch(method, &params);
        match (is_notification, outcome) {
            (true, _) => None,
            (false, Ok(result)) => Some(ok_response(id.unwrap(), result)),
            (false, Err((code, message))) => Some(error_response(id.unwrap(), code, &message)),
        }
    }

    /// Map a method name to its result (or a JSON-RPC error).
    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "quipu-mcp", "version": env!("CARGO_PKG_VERSION") }
            })),
            // lifecycle notifications we simply accept
            "notifications/initialized" | "notifications/cancelled" => Ok(Value::Null),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools::tool_defs() })),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or((codes::INVALID_PARAMS, "tools/call requires 'name'".to_string()))?;
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                Ok(tools::call(&self.backend, name, &arguments))
            }
            other => Err((codes::METHOD_NOT_FOUND, format!("unknown method '{other}'"))),
        }
    }

    /// Run the stdio loop until stdin closes. One request per line in, one
    /// response per line out, flushed each time so the client sees replies
    /// promptly.
    pub fn run_stdio(
        &self,
        input: impl BufRead,
        mut output: impl Write,
    ) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if let Some(response) = self.handle_line(&line) {
                output.write_all(response.as_bytes())?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }
}

fn ok_response(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

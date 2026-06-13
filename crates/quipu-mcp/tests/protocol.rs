//! The MCP conversation end to end against a mock backend: initialize,
//! tools/list, tools/call (success and error), notifications, and JSON-RPC
//! error paths.

use quipu_mcp::backend::{Backend, BackendError, BackendResult};
use quipu_mcp::server::PROTOCOL_VERSION;
use quipu_mcp::Server;
use serde_json::{json, Value};

struct StubBackend;
impl Backend for StubBackend {
    fn query_logs(&self, query: &Value) -> BackendResult {
        // echo back something that proves the query was forwarded
        Ok(json!([{ "echoed_method": query.get("method") }]))
    }
    fn entity_history(&self, t: &str, id: &str) -> BackendResult {
        Ok(json!([{ "type": t, "id": id, "version": 0 }]))
    }
    fn verify_integrity(&self) -> BackendResult {
        Err(BackendError::fatal("private key required"))
    }
}

fn server() -> Server<StubBackend> {
    Server::new(StubBackend)
}

fn reply(s: &Server<StubBackend>, msg: Value) -> Value {
    let line = s
        .handle_line(&msg.to_string())
        .expect("expected a response");
    serde_json::from_str(&line).unwrap()
}

#[test]
fn initialize_advertises_tools_capability() {
    let r = reply(
        &server(),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {} } }),
    );
    assert_eq!(r["id"], 1);
    assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert!(r["result"]["capabilities"]["tools"].is_object());
    assert_eq!(r["result"]["serverInfo"]["name"], "quipu-mcp");
}

#[test]
fn initialized_notification_gets_no_reply() {
    assert!(server()
        .handle_line(
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string()
        )
        .is_none());
}

#[test]
fn tools_list_returns_the_three_tools() {
    let r = reply(
        &server(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let names: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["query_logs", "get_entity_history", "verify_store_integrity"]
    );
    // each tool carries an inputSchema object
    for tool in r["result"]["tools"].as_array().unwrap() {
        assert!(tool["inputSchema"]["type"] == "object");
    }
}

#[test]
fn tools_call_query_logs_forwards_and_returns_text_content() {
    let r = reply(
        &server(),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "query_logs", "arguments": { "query": { "method": "POST" } } } }),
    );
    assert!(r["result"].get("isError").is_none());
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("POST"), "forwarded query echoed back: {text}");
}

#[test]
fn tools_call_backend_error_is_tool_error_not_protocol_error() {
    let r = reply(
        &server(),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "verify_store_integrity", "arguments": {} } }),
    );
    // protocol-level success, tool-level error
    assert!(r.get("error").is_none());
    assert_eq!(r["result"]["isError"], json!(true));
    assert!(r["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("private key"));
}

#[test]
fn unknown_method_is_jsonrpc_method_not_found() {
    let r = reply(
        &server(),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "do/everything" }),
    );
    assert_eq!(r["error"]["code"], -32601);
}

#[test]
fn malformed_line_is_parse_error() {
    let line = server().handle_line("{ not json").unwrap();
    let r: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(r["error"]["code"], -32700);
}

#[test]
fn stdio_loop_processes_a_session() {
    use std::io::Cursor;
    let input = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }).to_string(),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
    ]
    .join("\n");
    let mut out = Vec::new();
    server().run_stdio(Cursor::new(input), &mut out).unwrap();
    let lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
    // two requests get one response each; the notification gets none
    assert_eq!(lines.len(), 2);
    let init: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["id"], 1);
    let list: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(list["id"], 2);
    assert!(list["result"]["tools"].is_array());
}

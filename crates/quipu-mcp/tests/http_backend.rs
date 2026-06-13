//! The std-only HTTP backend against a real socket: a canned-response TCP
//! server stands in for quipu-server, so we exercise actual request formatting
//! and response parsing without the network or the daemon.

use quipu_mcp::backend::Backend;
use quipu_mcp::HttpBackend;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

/// Accept one connection, capture the raw request, and reply with `response`.
/// Returns the address to point the backend at and a handle yielding the
/// captured request bytes.
fn canned_server(response: &'static [u8]) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        // read until we have headers + body; the client sends Connection: close
        // but we just read what's buffered for the request, then reply
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        sock.write_all(response).unwrap();
        request
    });
    (addr, handle)
}

#[test]
fn query_logs_sends_bearer_and_parses_array() {
    let (addr, server) =
        canned_server(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n[{\"url\":\"/api/x\"}]\n\n\n");
    let backend = HttpBackend::new(addr, "agent-token");
    let out = backend
        .query_logs(&serde_json::json!({ "method": "POST" }))
        .unwrap();

    let request = server.join().unwrap();
    assert!(
        request.starts_with("POST /v1/logs/query HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains("Authorization: Bearer agent-token"),
        "{request}"
    );
    assert!(
        request.contains("Content-Type: application/json"),
        "{request}"
    );
    assert!(
        request.contains("\"method\":\"POST\""),
        "body forwarded: {request}"
    );
    assert_eq!(out[0]["url"], "/api/x");
}

#[test]
fn entity_history_is_a_get_with_encoded_path() {
    let (addr, server) = canned_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]");
    let backend = HttpBackend::new(addr, "t");
    let out = backend.entity_history("document", "doc/42").unwrap();
    let request = server.join().unwrap();
    assert!(
        request.starts_with("GET /v1/entities/document/doc%2F42/history HTTP/1.1"),
        "{request}"
    );
    assert!(out.as_array().unwrap().is_empty());
}

#[test]
fn http_400_is_a_fatal_error_with_server_message() {
    let (addr, server) = canned_server(
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\n{\"error\":\"bad query body\"}",
    );
    let backend = HttpBackend::new(addr, "t");
    let err = backend.query_logs(&serde_json::json!({})).unwrap_err();
    server.join().unwrap();
    assert!(!err.retryable);
    assert_eq!(err.message, "bad query body");
}

#[test]
fn http_503_is_retryable() {
    let (addr, server) = canned_server(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 22\r\n\r\n{\"error\":\"queue full\"}",
    );
    let backend = HttpBackend::new(addr, "t");
    let err = backend.verify_integrity().unwrap_err();
    server.join().unwrap();
    assert!(err.retryable);
}

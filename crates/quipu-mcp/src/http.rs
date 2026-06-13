//! [`HttpBackend`]: the shipped [`Backend`], an HTTP/1.1 client for
//! `quipu-server`.
//!
//! It is intentionally **std-only and plaintext** — a few dozen lines over
//! `TcpStream`, no HTTP crate, no TLS. The MCP server is meant to run
//! co-located with `quipu-server` (same host or same trusted network segment),
//! talking to its plain-HTTP listener; for a remote or untrusted leg, front it
//! with a TLS-terminating sidecar rather than teaching this client TLS. That
//! keeps the agent-facing component tiny and its dependency surface (a place an
//! audit system least wants surprises) almost nil.
//!
//! Requests use `Connection: close` and read to EOF, so there is no
//! keep-alive/chunked-decoding machinery to get subtly wrong; each tool call is
//! one short-lived connection, which is the right shape for an interactive
//! agent issuing occasional queries.

use crate::backend::{Backend, BackendError, BackendResult};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// HTTP client for one `quipu-server`, carrying the bearer token every request
/// presents. The token's role is what bounds the agent (query, and optionally
/// administer for verify) — see the crate README's scope design.
pub struct HttpBackend {
    /// `host:port` of the server's plain-HTTP listener.
    addr: String,
    token: String,
    timeout: Duration,
}

impl HttpBackend {
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            token: token.into(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// One request/response over a fresh connection. `body` is JSON for a POST,
    /// `None` for a GET. Returns the parsed JSON body on a 2xx, else a
    /// [`BackendError`] classified by status.
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> BackendResult {
        let mut stream = TcpStream::connect(&self.addr)
            .map_err(|e| BackendError::retryable(format!("cannot reach audit server: {e}")))?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n",
            host = self.addr,
            token = self.token,
        );
        if let Some(b) = body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }

        stream
            .write_all(req.as_bytes())
            .map_err(|e| BackendError::retryable(format!("write to audit server failed: {e}")))?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| BackendError::retryable(format!("read from audit server failed: {e}")))?;

        let (status, body_bytes) = parse_response(&raw)
            .ok_or_else(|| BackendError::retryable("malformed HTTP response from audit server"))?;
        classify(status, body_bytes)
    }
}

/// Map an HTTP status + body onto the backend contract. The classification
/// mirrors the server's documented status meanings and the retry split in
/// `quipu-client`'s `Transport`.
fn classify(status: u16, body: &[u8]) -> BackendResult {
    let parse_body = || -> Value {
        if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(body).unwrap_or(Value::Null)
        }
    };
    // a server error body is {"error": "..."}; surface it when present
    let server_msg = || -> String {
        parse_body()
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"))
    };
    match status {
        200..=299 => Ok(parse_body()),
        // queue full / busy / gateway / unreachable upstream — try again
        408 | 429 | 502 | 503 | 504 => Err(BackendError::retryable(server_msg())),
        // a verification already running: retryable (it will free up)
        409 => Err(BackendError::retryable(server_msg())),
        // bad request, auth, not found, other 5xx: the agent must change
        // something (or an operator must) — retrying as-is won't help
        _ => Err(BackendError::fatal(server_msg())),
    }
}

/// Split a raw HTTP response into (status code, body bytes). Returns `None` if
/// the status line or header/body separator is missing.
fn parse_response(raw: &[u8]) -> Option<(u16, &[u8])> {
    let sep = find_subslice(raw, b"\r\n\r\n")?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];
    let first_line_end = find_subslice(head, b"\r\n").unwrap_or(head.len());
    let status_line = std::str::from_utf8(&head[..first_line_end]).ok()?;
    // "HTTP/1.1 200 OK" -> 200
    let code = status_line.split_whitespace().nth(1)?.parse().ok()?;
    Some((code, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Percent-encode one path segment (entity type/id can contain arbitrary
/// characters; a `/` or space would otherwise break the request line).
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Backend for HttpBackend {
    fn query_logs(&self, query: &Value) -> BackendResult {
        let body = serde_json::to_string(query).map_err(|e| BackendError::fatal(e.to_string()))?;
        self.request("POST", "/v1/logs/query", Some(&body))
    }

    fn entity_history(&self, entity_type: &str, entity_id: &str) -> BackendResult {
        let path = format!(
            "/v1/entities/{}/{}/history",
            encode_segment(entity_type),
            encode_segment(entity_id)
        );
        self.request("GET", &path, None)
    }

    fn verify_integrity(&self) -> BackendResult {
        self.request("POST", "/v1/admin/verify", None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"[]");
    }

    #[test]
    fn classify_splits_retryable_from_fatal() {
        assert!(classify(200, b"[]").is_ok());
        assert!(classify(503, br#"{"error":"queue full"}"#).unwrap_err().retryable);
        assert!(classify(409, b"{}").unwrap_err().retryable);
        let fatal = classify(400, br#"{"error":"bad query"}"#).unwrap_err();
        assert!(!fatal.retryable);
        assert_eq!(fatal.message, "bad query");
        assert!(!classify(401, b"").unwrap_err().retryable);
    }

    #[test]
    fn encode_segment_escapes_separators() {
        assert_eq!(encode_segment("doc/42"), "doc%2F42");
        assert_eq!(encode_segment("a b"), "a%20b");
        assert_eq!(encode_segment("normal-id_1"), "normal-id_1");
    }
}

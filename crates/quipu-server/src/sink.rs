//! SIEM forwarding: mirror each durably-written audit event to a syslog
//! collector over UDP (RFC 5424).
//!
//! This is the one sink the daemon ships, because syslog is the lowest common
//! denominator every SIEM ingests and it needs no dependency beyond
//! `std::net::UdpSocket`. A webhook or Kafka sink is the same shape — a
//! [`quipu_middleware::SinkFn`] closure — and embedded users can supply one
//! directly; the daemon does not bundle an HTTP client just for this.
//!
//! Design constraints come from where the hook fires (the writer thread, in
//! line with persistence — see [`quipu_middleware::SinkFn`]):
//!
//! - **Never block the writer.** The closure only does a non-blocking
//!   `try_send` onto a bounded channel; a dedicated thread owns the socket and
//!   does the actual `send_to`. A slow or dead collector cannot back-pressure
//!   audit writes.
//! - **Drop, don't stall, on overload.** If the channel is full the line is
//!   dropped and counted. Mirroring is best-effort by definition — the store
//!   is the system of record, the SIEM is a copy — so a forwarding backlog must
//!   never threaten the write path.
//! - **Mirror metadata, not payloads.** The line carries who/what/when
//!   (actor, method, url, targets, custom keys), not the event `content`, which
//!   may be large or hold protected values. The store keeps the full record;
//!   the SIEM gets the audit-trail skeleton.

use quipu_middleware::{AuditEvent, SinkFn};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::Arc;

/// RFC 5424 facility 13 ("log audit"), severity 6 ("informational"):
/// `PRI = facility * 8 + severity`.
const SYSLOG_PRI: u8 = 13 * 8 + 6;

/// A running syslog forwarder. Hold it for the lifetime of the server; its
/// background thread drains the queue until the [`SinkFn`] (and this handle)
/// are dropped.
pub struct SyslogSink {
    sink: SinkFn,
    dropped: Arc<AtomicU64>,
}

impl SyslogSink {
    /// Bind a UDP socket and spawn the sender thread. `collector` is the
    /// syslog server's `host:port` (e.g. `10.0.0.5:514`); `app_name` is the
    /// RFC 5424 APP-NAME tag. `queue_capacity` bounds the in-flight backlog —
    /// past it, lines are dropped (and counted) rather than blocking the audit
    /// writer.
    pub fn new(
        collector: &str,
        app_name: &str,
        queue_capacity: usize,
    ) -> std::io::Result<Self> {
        // bind to an ephemeral local port; connect so every send_to targets
        // the collector and the kernel can report unreachable early
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(collector)?;
        let hostname = hostname();
        let app_name = sanitize_tag(app_name);

        let (tx, rx) = sync_channel::<String>(queue_capacity);
        std::thread::Builder::new()
            .name("audit-syslog".into())
            .spawn(move || {
                // best-effort: a send error (collector down) drops the line;
                // the next one will try again, the store stays authoritative
                while let Ok(line) = rx.recv() {
                    if let Err(e) = socket.send(line.as_bytes()) {
                        tracing::debug!(error = %e, "syslog mirror send failed (dropped)");
                    }
                }
            })?;

        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_for_closure = dropped.clone();
        let sink: SinkFn = Arc::new(move |event: &AuditEvent, log_id| {
            let line = format_5424(SYSLOG_PRI, &hostname, &app_name, event, log_id);
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    let n = dropped_for_closure.fetch_add(1, Ordering::Relaxed) + 1;
                    // log sparsely so a backlog does not itself flood the log
                    if n.is_power_of_two() {
                        tracing::warn!(dropped_total = n, "syslog mirror backlog full; dropping");
                    }
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        });
        Ok(Self { sink, dropped })
    }

    /// The hook to install in [`quipu_middleware::PipelineConfig::sink`].
    pub fn sink(&self) -> SinkFn {
        self.sink.clone()
    }

    /// Lines dropped so far because the queue was full (observability).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Build one RFC 5424 line:
/// `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`, where MSG is a
/// compact JSON summary of the event. STRUCTURED-DATA is `-` (none).
fn format_5424(pri: u8, hostname: &str, app_name: &str, event: &AuditEvent, log_id: quipu_core::Uid) -> String {
    let ts = rfc3339_micros(event.occurred_at);
    let procid = std::process::id();
    let summary = serde_json::json!({
        "log_id": log_id.to_string(),
        "actor_type": event.actor_type,
        "actor": event.actor.entity_id,
        "method": event.method,
        "url": event.url,
        "targets": event
            .targets
            .iter()
            .map(|t| serde_json::json!({ "type": t.entity_type, "id": t.input.entity_id }))
            .collect::<Vec<_>>(),
        "custom_keys": event.custom.keys().collect::<Vec<_>>(),
    });
    // MSGID "audit"; structured-data absent ("-")
    format!("<{pri}>1 {ts} {hostname} {app_name} {procid} audit - {summary}")
}

/// UTC RFC 3339 with microseconds from a unix-micros timestamp, without pulling
/// in a date crate. Days-from-civil is the standard Howard Hinnant algorithm.
fn rfc3339_micros(unix_micros: u64) -> String {
    let secs = (unix_micros / 1_000_000) as i64;
    let micros = unix_micros % 1_000_000;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{micros:06}Z")
}

/// Convert days since the unix epoch to (year, month, day). Hinnant's
/// `civil_from_days`, valid for the full proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Local hostname for the syslog HOSTNAME field; `-` (the RFC 5424 nil value)
/// when it cannot be read.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| sanitize_tag(&h))
        .unwrap_or_else(|| "-".to_string())
}

/// RFC 5424 fields are printable ASCII without spaces; replace anything else so
/// a stray byte cannot split the line into two syslog frames.
fn sanitize_tag(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(48)
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quipu_core::{Content, EntityInput, Uid};

    #[test]
    fn rfc3339_is_correct() {
        // 2026-06-13T00:00:00Z = 1_780_704_000 s (verified against date -u)
        assert_eq!(rfc3339_micros(1_781_308_800_000_000), "2026-06-13T00:00:00.000000Z");
        assert_eq!(rfc3339_micros(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            rfc3339_micros(1_781_308_800_000_000 + 123_456),
            "2026-06-13T00:00:00.123456Z"
        );
    }

    #[test]
    fn line_is_well_formed_5424() {
        let mut event = AuditEvent::new(
            "user",
            EntityInput::new("alice"),
            "POST",
            "/v1/transfer",
            Content::Text("secret body".into()),
        );
        event.occurred_at = 1_781_308_800_000_000;
        let line = format_5424(SYSLOG_PRI, "host1", "quipu", &event, Uid(0));
        assert!(line.starts_with("<110>1 2026-06-13T00:00:00.000000Z host1 quipu "));
        assert!(line.contains(" audit - "));
        // metadata mirrored, payload not
        assert!(line.contains("\"actor\":\"alice\""));
        assert!(line.contains("\"method\":\"POST\""));
        assert!(!line.contains("secret body"));
    }

    #[test]
    fn sanitize_strips_spaces_and_controls() {
        assert_eq!(sanitize_tag("my host\n"), "myhost");
        assert_eq!(sanitize_tag(""), "-");
        assert_eq!(sanitize_tag("   "), "-");
    }
}

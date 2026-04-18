//! Structured event logging for DRIFT, inspired by qlog
//! (the IETF structured-logging format for QUIC).
//!
//! Every transport-level event — packets sent/received,
//! handshakes, rekeys, congestion state changes, path
//! validations — gets one line of newline-delimited JSON
//! written to a configured file. The format is intentionally
//! simple enough to post-process with `jq` or stream into a
//! visualizer. We don't try to match the IETF qlog schema
//! byte-for-byte; that's overkill for a DRIFT-specific tool.
//! What we DO preserve is qlog's core shape:
//!
//!   `{"time": <ms_since_start>, "category": "...",
//!     "event": "...", "data": {...}}`
//!
//! so existing qlog muscle memory (and most qlog-adjacent
//! tooling) still reads clean.
//!
//! Enable via `TransportConfig::qlog_path = Some(path)`.
//! Disabled by default; writing to disk is opt-in.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

/// Minimal JSON value type. We avoid pulling in `serde_json`
/// as a dependency — the event schema is small and the
/// writer below hand-serializes. Strings are escaped for
/// `"` and `\`; the DRIFT transport only ever emits ASCII
/// peer ids (hex-style) and simple numeric data, so this is
/// enough.
#[derive(Debug, Clone, Copy)]
pub(crate) enum QlogValue<'a> {
    Str(&'a str),
    U64(u64),
    #[allow(dead_code)]
    I64(i64),
    Bool(bool),
}

/// Writer state. One instance per transport when qlog is
/// enabled. Lives behind a `Mutex` because the writer can be
/// hit from multiple background tasks concurrently.
pub(crate) struct QlogWriter {
    file: Mutex<File>,
    started_at: Instant,
}

impl QlogWriter {
    /// Open (or create + truncate) the target path. Writes a
    /// qlog header line with the current time origin so
    /// readers can align traces.
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let writer = Self {
            file: Mutex::new(file),
            started_at: Instant::now(),
        };
        writer.log_raw(
            "qlog",
            "trace_start",
            &[("version", QlogValue::Str("drift-v1"))],
        );
        Ok(writer)
    }

    /// Emit a single event. Swallows write errors — if disk
    /// is full, the network path continues to function.
    pub(crate) fn log_raw(&self, category: &str, event: &str, fields: &[(&str, QlogValue<'_>)]) {
        let ms = self.started_at.elapsed().as_micros() as u64;
        let mut line = String::with_capacity(256);
        line.push('{');
        write_kv(&mut line, "time", QlogValue::U64(ms));
        line.push(',');
        write_kv(&mut line, "category", QlogValue::Str(category));
        line.push(',');
        write_kv(&mut line, "event", QlogValue::Str(event));
        if !fields.is_empty() {
            line.push_str(",\"data\":{");
            for (i, (k, v)) in fields.iter().enumerate() {
                if i > 0 {
                    line.push(',');
                }
                write_kv(&mut line, k, *v);
            }
            line.push('}');
        }
        line.push('}');
        line.push('\n');

        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// Convenience: a packet send event.
    pub(crate) fn log_packet_sent(&self, packet_type: &str, dst: &str, size: usize, seq: u32) {
        self.log_raw(
            "transport",
            "packet_sent",
            &[
                ("type", QlogValue::Str(packet_type)),
                ("dst", QlogValue::Str(dst)),
                ("size", QlogValue::U64(size as u64)),
                ("seq", QlogValue::U64(seq as u64)),
            ],
        );
    }

    /// Convenience: a packet receive event.
    pub(crate) fn log_packet_received(&self, packet_type: &str, src: &str, size: usize, seq: u32) {
        self.log_raw(
            "transport",
            "packet_received",
            &[
                ("type", QlogValue::Str(packet_type)),
                ("src", QlogValue::Str(src)),
                ("size", QlogValue::U64(size as u64)),
                ("seq", QlogValue::U64(seq as u64)),
            ],
        );
    }

    /// Handshake completion event.
    pub(crate) fn log_handshake_complete(&self, peer: &str, resumption: bool) {
        self.log_raw(
            "transport",
            "handshake_complete",
            &[
                ("peer", QlogValue::Str(peer)),
                ("resumption", QlogValue::Bool(resumption)),
            ],
        );
    }

    /// State-change events — e.g., rekey, path migration.
    #[allow(dead_code)]
    pub(crate) fn log_state_change(&self, what: &str, peer: &str) {
        self.log_raw("transport", what, &[("peer", QlogValue::Str(peer))]);
    }
}

fn write_kv(out: &mut String, k: &str, v: QlogValue<'_>) {
    out.push('"');
    escape_into(out, k);
    out.push('"');
    out.push(':');
    match v {
        QlogValue::Str(s) => {
            out.push('"');
            escape_into(out, s);
            out.push('"');
        }
        QlogValue::U64(n) => out.push_str(&n.to_string()),
        QlogValue::I64(n) => out.push_str(&n.to_string()),
        QlogValue::Bool(b) => out.push_str(if b { "true" } else { "false" }),
    }
}

fn escape_into(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn emits_valid_ndjson() {
        let tmp = std::env::temp_dir().join("drift_qlog_test.jsonl");
        let w = QlogWriter::open(&tmp).unwrap();
        w.log_packet_sent("Data", "127.0.0.1:9999", 128, 42);
        w.log_handshake_complete("abcd1234", true);
        w.log_raw(
            "transport",
            "custom",
            &[
                ("foo", QlogValue::Str("bar\nbaz")),
                ("num", QlogValue::I64(-7)),
            ],
        );
        drop(w);

        let mut contents = String::new();
        File::open(&tmp)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // trace_start + 3 user events = 4
        assert_eq!(lines.len(), 4);
        for line in &lines {
            // Every line must start with { and end with }
            assert!(line.starts_with('{') && line.ends_with('}'));
            // Every line must have "time" and "category".
            assert!(line.contains("\"time\":"));
            assert!(line.contains("\"category\":"));
        }
        // Escaping: \n inside a string must be escaped.
        assert!(contents.contains("bar\\nbaz"));
        let _ = std::fs::remove_file(&tmp);
    }
}

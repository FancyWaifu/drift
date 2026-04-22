//! Unified report shape. Every protocol/workload combination
//! emits the same JSON object, with `null` for fields that
//! don't apply. Makes `run.sh` parsing trivial — no per-protocol
//! schema to track.

use serde::Serialize;

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub protocol: String,
    pub workload: String,

    // Handshake: cold connect → first byte acked.
    pub handshake_us: Option<u64>,

    // Throughput: bytes moved / duration.
    pub bytes_moved: Option<u64>,
    pub duration_s: Option<f64>,
    pub throughput_mbps: Option<f64>,

    // RTT: ping-pong distribution across `rtt_iters` samples.
    pub rtt_samples: Option<usize>,
    pub rtt_min_us: Option<u64>,
    pub rtt_p50_us: Option<u64>,
    pub rtt_p95_us: Option<u64>,
    pub rtt_p99_us: Option<u64>,
    pub rtt_max_us: Option<u64>,
}

impl Report {
    pub fn new(protocol: &str, workload: &str) -> Self {
        Self {
            protocol: protocol.to_string(),
            workload: workload.to_string(),
            ..Default::default()
        }
    }
}

/// Summarize a set of RTT samples into min/p50/p95/p99/max (µs).
/// `samples` is mutated (sorted) for the quantile lookups.
pub fn summarize_rtts(samples: &mut [u128], report: &mut Report) {
    if samples.is_empty() {
        return;
    }
    samples.sort_unstable();
    let pct = |p: f64| -> u64 {
        let idx = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[idx] as u64
    };
    report.rtt_samples = Some(samples.len());
    report.rtt_min_us = Some(samples[0] as u64);
    report.rtt_p50_us = Some(pct(0.50));
    report.rtt_p95_us = Some(pct(0.95));
    report.rtt_p99_us = Some(pct(0.99));
    report.rtt_max_us = Some(samples[samples.len() - 1] as u64);
}

//! Adapter probing for `via_bridges_auto` measured ranking.
//!
//! The static `via_bridges_auto` expansion produces a 9-entry
//! candidate list in a default order (`udp` first, `dns` last).
//! That default is just a guess — the actual best-fit adapter
//! depends on the network. On corporate Wi-Fi, UDP is dead and
//! `h2s://` wins. On home Wi-Fi, `udp://` is fastest. On a
//! satellite link, the longer-RTT wires might win. Hardcoding
//! the order means the daemon picks the wrong wire on
//! ~half of real-world networks.
//!
//! This module measures each candidate at startup, ranks them
//! by handshake time, and hands the ranked list to the
//! supervisor for runtime failover. The handshake-time metric
//! is a proxy for "this wire is responsive on this network" —
//! a slow handshake captures high latency, blocked return
//! traffic (timeout-then-establish), and crypto overhead all
//! at once. It doesn't capture steady-state throughput; that
//! would require an echo-back probe target the bridge doesn't
//! offer. Throughput-aware ranking is a future enhancement
//! once federated peers can echo (or once we add a small
//! per-bridge "probe-echo" endpoint).
//!
//! Why drift-vpn-side, not drift-core: adapter registration is
//! drift-core's job (any inventory::submit! anywhere produces
//! a new registered scheme — QR codes, BLE, serial, anything),
//! but *measurement* is application-policy. Different apps want
//! different metrics (latency-sensitive vs throughput-sensitive
//! vs stealth-sensitive). Keeping the measurement layer here
//! lets each tool define its own policy without bloating
//! drift-core.

use std::sync::Arc;
use std::time::{Duration, Instant};

use drift::Transport;
use drift_core::PeerId;
use tracing::{debug, info, warn};

/// One per-bridge measurement. Sorted by `handshake_time`
/// ascending in the ranked output; failed entries (unreachable
/// or unestablished within `PROBE_DEADLINE`) sort last with
/// `handshake_time = None`.
#[derive(Debug, Clone)]
pub struct AdapterMeasurement {
    /// Original spec string from `via_bridges_auto` expansion
    /// or `via_bridges`. Used as the key into `bridge_handles`
    /// and as the failover-supervisor's display string.
    pub spec: String,
    /// Pre-registered bridge `PeerId` (handle into the
    /// transport's peer table).
    pub bridge_pid: PeerId,
    /// Time from probe-start to `peer_is_established` =
    /// true. `None` if the bridge didn't establish within
    /// `PROBE_DEADLINE`.
    pub handshake_time: Option<Duration>,
}

/// Max time we'll wait for a bridge handshake. 8 s leaves room
/// for one full cookie-path retry on a noisy WAN; anything
/// slower than that we treat as unavailable for this startup.
/// The supervisor re-probes during operation, so a wire that's
/// slow to first-handshake but reliable later doesn't stay
/// excluded forever.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(8);

/// Poll interval for `peer_is_established`. 50 ms gives ms-level
/// precision in the measured handshake time without spinning
/// the runtime.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Probe a list of pre-registered bridges in parallel; return
/// measurements sorted by handshake time ascending.
///
/// Caller has already done `connect_federate` for each
/// `(spec, bridge_pid)` so the transport's peer table contains
/// each bridge in `Pending` state with the handshake in flight.
/// All we do here is wait + time + sort.
///
/// The probes run as concurrent tokio tasks; total wall-clock
/// time is bounded by `PROBE_DEADLINE` (≈ 8 s), not N ×
/// per-probe time.
pub async fn probe_and_rank(
    transport: Arc<Transport>,
    candidates: Vec<(String, PeerId)>,
) -> Vec<AdapterMeasurement> {
    let total = candidates.len();
    info!(
        candidates = total,
        deadline_secs = PROBE_DEADLINE.as_secs(),
        "adapter probe starting (parallel handshake-time measurement)"
    );

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(total);
    for (spec, bridge_pid) in candidates {
        let t = transport.clone();
        tasks.push(tokio::spawn(async move {
            let measure_started = Instant::now();
            let deadline = measure_started + PROBE_DEADLINE;
            loop {
                if t.peer_is_established(&bridge_pid).await {
                    let elapsed = measure_started.elapsed();
                    return AdapterMeasurement {
                        spec,
                        bridge_pid,
                        handshake_time: Some(elapsed),
                    };
                }
                if Instant::now() >= deadline {
                    return AdapterMeasurement {
                        spec,
                        bridge_pid,
                        handshake_time: None,
                    };
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }));
    }

    let mut results = Vec::with_capacity(total);
    for task in tasks {
        match task.await {
            Ok(m) => results.push(m),
            Err(e) => warn!(error = ?e, "adapter probe task panicked"),
        }
    }

    // Sort: established first (by ascending handshake time);
    // failed last (preserving the original input order among
    // failed entries so the operator can still see the
    // default-best fallback they configured).
    results.sort_by(|a, b| match (a.handshake_time, b.handshake_time) {
        (Some(ta), Some(tb)) => ta.cmp(&tb),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let total_elapsed = started.elapsed();
    let succeeded = results.iter().filter(|m| m.handshake_time.is_some()).count();
    info!(
        candidates = total,
        succeeded,
        failed = total - succeeded,
        wall_clock_ms = total_elapsed.as_millis() as u64,
        "adapter probe complete; ranked"
    );
    for (idx, m) in results.iter().enumerate() {
        match m.handshake_time {
            Some(t) => debug!(
                rank = idx,
                spec = %m.spec,
                handshake_ms = t.as_millis() as u64,
                "ranked"
            ),
            None => debug!(
                rank = idx,
                spec = %m.spec,
                "unreachable within probe deadline"
            ),
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_deadline_under_typical_supervisor_tick() {
        // The supervisor reacts on ~10 s ticks; the probe must
        // finish well under that so startup feels fast.
        assert!(PROBE_DEADLINE.as_secs() <= 10);
    }

    #[test]
    fn measurement_ordering_established_before_failed() {
        let mut v = vec![
            AdapterMeasurement {
                spec: "fail-a".into(),
                bridge_pid: [0u8; 8],
                handshake_time: None,
            },
            AdapterMeasurement {
                spec: "slow".into(),
                bridge_pid: [1u8; 8],
                handshake_time: Some(Duration::from_secs(3)),
            },
            AdapterMeasurement {
                spec: "fail-b".into(),
                bridge_pid: [2u8; 8],
                handshake_time: None,
            },
            AdapterMeasurement {
                spec: "fast".into(),
                bridge_pid: [3u8; 8],
                handshake_time: Some(Duration::from_millis(80)),
            },
        ];
        v.sort_by(|a, b| match (a.handshake_time, b.handshake_time) {
            (Some(ta), Some(tb)) => ta.cmp(&tb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        assert_eq!(v[0].spec, "fast", "fastest established first");
        assert_eq!(v[1].spec, "slow", "next-fastest second");
        assert!(
            v[2].handshake_time.is_none() && v[3].handshake_time.is_none(),
            "failed entries land at the end: {:?}",
            v
        );
    }
}

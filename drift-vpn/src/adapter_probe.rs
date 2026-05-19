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

use anyhow::Context;
use drift::{Direction, Transport};
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
    /// Bridge `PeerId` (handle into the transport's peer
    /// table). Filled by `register_and_probe` after the
    /// register step succeeds; remains `[0u8; 8]` if register
    /// failed (which also sets `handshake_time = None`).
    pub bridge_pid: PeerId,
    /// Bridge's 32-byte X25519 pubkey, parsed from `spec`.
    /// Caller passes this to `Transport::add_federated_peer`
    /// as the `target_bridge_pub` argument.
    pub bridge_pub: [u8; 32],
    /// Time from probe-start (before connect) to
    /// `peer_is_established = true`. Includes connect +
    /// crypto + handshake. `None` if the bridge didn't
    /// establish within `PROBE_DEADLINE` OR if the register
    /// step itself failed.
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

/// Register + probe each bridge spec in parallel; return
/// measurements sorted by total time-to-Established ascending.
///
/// Each task runs `connect_federate` (or the UDP equivalent)
/// AND the establishment poll inside the same wall-clock
/// window, so the measurement captures the real cost: connect
/// + crypto + handshake round-trips. The previous design
/// registered bridges sequentially before probing — and on a
/// LAN where handshakes complete in 5-10 ms each, all 9 had
/// reached Established before the probe loop even ran. The
/// resulting `wall_clock_ms=0` ranking was meaningless.
///
/// Returns: `Vec<AdapterMeasurement>` sorted by handshake time
/// ascending. Caller treats failed entries (`handshake_time =
/// None`) as available-but-unranked; the supervisor uses them
/// as last-resort fallbacks.
///
/// Side effect: populates the transport's peer table with one
/// federation-style entry per bridge. Caller reads each
/// measurement's `bridge_pid` and uses it as the
/// `via_bridge` argument to `Transport::add_federated_peer`
/// for the actual VPN peer.
pub async fn register_and_probe(
    transport: Arc<Transport>,
    specs: Vec<String>,
) -> Vec<AdapterMeasurement> {
    let total = specs.len();
    info!(
        candidates = total,
        deadline_secs = PROBE_DEADLINE.as_secs(),
        "adapter probe starting (parallel register + handshake-time measurement)"
    );

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(total);
    for spec in specs {
        let t = transport.clone();
        tasks.push(tokio::spawn(async move {
            // Per-task clock: includes the register call AND
            // the wait-for-Established. This is the metric
            // that actually captures adapter cost on the
            // current network.
            let measure_started = Instant::now();
            let bridge_pid = match register_one(&t, &spec).await {
                Ok((pid, _pub)) => pid,
                Err(e) => {
                    debug!(spec = %spec, error = %e, "bridge register failed");
                    return AdapterMeasurement {
                        spec,
                        bridge_pid: [0u8; 8],
                        bridge_pub: [0u8; 32],
                        handshake_time: None,
                    };
                }
            };
            let bridge_pub = match crate::config::parse_bridge_spec(&spec) {
                Ok((_, pk)) => pk,
                Err(_) => [0u8; 32], // unreachable: register_one would have failed first
            };
            let deadline = measure_started + PROBE_DEADLINE;
            loop {
                if t.peer_is_established(&bridge_pid).await {
                    return AdapterMeasurement {
                        spec,
                        bridge_pid,
                        bridge_pub,
                        handshake_time: Some(measure_started.elapsed()),
                    };
                }
                if Instant::now() >= deadline {
                    return AdapterMeasurement {
                        spec,
                        bridge_pid,
                        bridge_pub,
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
    // failed last (preserving relative input order among failed
    // entries so operators still see configured fallbacks).
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
            Some(t) => info!(
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

/// Register one bridge spec via the appropriate scheme:
/// `add_peer` (+ HELLO kick) for UDP, `connect_federate` for
/// stream-based schemes. Returns the bridge's `PeerId` and the
/// raw pubkey for the caller to track.
async fn register_one(
    transport: &Transport,
    spec: &str,
) -> anyhow::Result<(PeerId, [u8; 32])> {
    let (url, bridge_pub) = crate::config::parse_bridge_spec(spec)
        .context("parsing bridge spec")?;
    let scheme = url.split("://").next().unwrap_or("");
    let bridge_pid = if scheme == "udp" {
        let addr = crate::daemon::resolve_endpoint(&url)
            .await
            .with_context(|| format!("resolving {}", url))?;
        let pid = transport
            .add_peer(bridge_pub, addr, Direction::Initiator)
            .await
            .with_context(|| format!("add_peer({})", url))?;
        // UDP add_peer doesn't initiate handshake on its own;
        // send_data does. Trigger HELLO immediately so the
        // measure window covers the round-trip.
        let _ = transport.send_data(&pid, b".", 0, 0).await;
        pid
    } else {
        transport
            .connect_federate(&url, bridge_pub)
            .await
            .with_context(|| format!("connect_federate({})", url))?
    };
    Ok((bridge_pid, bridge_pub))
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
                bridge_pub: [0u8; 32],
                handshake_time: None,
            },
            AdapterMeasurement {
                spec: "slow".into(),
                bridge_pid: [1u8; 8],
                bridge_pub: [1u8; 32],
                handshake_time: Some(Duration::from_secs(3)),
            },
            AdapterMeasurement {
                spec: "fail-b".into(),
                bridge_pid: [2u8; 8],
                bridge_pub: [2u8; 32],
                handshake_time: None,
            },
            AdapterMeasurement {
                spec: "fast".into(),
                bridge_pid: [3u8; 8],
                bridge_pub: [3u8; 32],
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

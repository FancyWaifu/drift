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

/// When measured handshake times are within this window of each
/// other, treat them as a tie and fall back to scheme priority
/// (see `scheme_default_rank`). Without this, two healthy wires
/// that finish within typical network jitter (~30 ms on home
/// Wi-Fi to a remote WAN bridge) get ranked by noise. The first
/// live run on home Wi-Fi clustered all 9 healthy wires in a
/// 32 ms band; DNS came out on top by 2 ms despite being the
/// worst steady-state wire. 250 ms is "wider than jitter,
/// narrower than a meaningful adapter difference."
const TIE_BREAK_WINDOW: Duration = Duration::from_millis(250);

/// Scheme priority used to break ties within `TIE_BREAK_WINDOW`.
/// Lower number = better. The order reflects steady-state cost
/// (header overhead, framing, crypto cost on top of TLS, etc.)
/// — *not* handshake-time. UDP and webtransport are cheapest;
/// dns is the most expensive per-byte and exists only as a
/// stealth/last-resort fallback.
fn scheme_default_rank(spec: &str) -> u8 {
    let scheme = spec.split("://").next().unwrap_or("");
    match scheme {
        "udp" => 0,
        "webtransport" => 1,
        "h2s" => 2,
        "tls" => 3,
        "h2" => 4,
        "ws" => 5,
        "tcp" => 6,
        "http" => 7,
        "dns" => 8,
        _ => 100,
    }
}

/// Register + probe each bridge spec in parallel; return
/// measurements sorted by total time-to-Established ascending.
///
/// Each task runs `connect_federate` (or the UDP equivalent)
/// AND the establishment poll inside the same wall-clock
/// window, so the measurement captures the real cost: connect
/// plus crypto and handshake round-trips. The previous design
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

    // Rank: established first, failed last.
    //
    // For established entries we want a non-noisy ordering. On
    // a healthy network all wires cluster within tens of ms
    // (the bottleneck is the bridge's response latency, not the
    // adapter), so raw handshake-time ordering is dominated by
    // jitter — DNS can "win" on home Wi-Fi by 2 ms despite
    // being the worst steady-state wire.
    //
    // Strategy: bucket established entries into tiers, where a
    // tier contains all wires within TIE_BREAK_WINDOW of the
    // tier's fastest member. Within each tier, sort by
    // scheme_default_rank (UDP cheap → DNS expensive). Across
    // tiers, ordering follows tier-min time (faster tier first).
    //
    // A pairwise sort_by would be non-transitive (a within b's
    // window, b within c's window, but a outside c's window
    // forms a cycle), so we bucket explicitly.
    let (mut established, failed): (Vec<_>, Vec<_>) = results
        .into_iter()
        .partition(|m| m.handshake_time.is_some());
    established.sort_by_key(|m| m.handshake_time.unwrap());
    let mut tiered: Vec<AdapterMeasurement> = Vec::with_capacity(established.len());
    let mut i = 0;
    while i < established.len() {
        let tier_min = established[i].handshake_time.unwrap();
        let mut j = i;
        while j < established.len()
            && established[j].handshake_time.unwrap() - tier_min <= TIE_BREAK_WINDOW
        {
            j += 1;
        }
        let tier = &mut established[i..j];
        tier.sort_by_key(|m| scheme_default_rank(&m.spec));
        tiered.extend_from_slice(tier);
        i = j;
    }
    let mut results = tiered;
    results.extend(failed);

    let total_elapsed = started.elapsed();
    let succeeded = results
        .iter()
        .filter(|m| m.handshake_time.is_some())
        .count();
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
async fn register_one(transport: &Transport, spec: &str) -> anyhow::Result<(PeerId, [u8; 32])> {
    let (url, bridge_pub) =
        crate::config::parse_bridge_spec(spec).context("parsing bridge spec")?;
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

    /// Helper: apply the same tier-sort logic the live probe uses,
    /// without spinning up a Transport.
    fn rank(measurements: Vec<AdapterMeasurement>) -> Vec<AdapterMeasurement> {
        let (mut established, failed): (Vec<_>, Vec<_>) = measurements
            .into_iter()
            .partition(|m| m.handshake_time.is_some());
        established.sort_by_key(|m| m.handshake_time.unwrap());
        let mut tiered: Vec<AdapterMeasurement> = Vec::with_capacity(established.len());
        let mut i = 0;
        while i < established.len() {
            let tier_min = established[i].handshake_time.unwrap();
            let mut j = i;
            while j < established.len()
                && established[j].handshake_time.unwrap() - tier_min <= TIE_BREAK_WINDOW
            {
                j += 1;
            }
            let tier = &mut established[i..j];
            tier.sort_by_key(|m| scheme_default_rank(&m.spec));
            tiered.extend_from_slice(tier);
            i = j;
        }
        let mut out = tiered;
        out.extend(failed);
        out
    }

    fn m(spec: &str, ms: Option<u64>) -> AdapterMeasurement {
        AdapterMeasurement {
            spec: spec.into(),
            bridge_pid: [0u8; 8],
            bridge_pub: [0u8; 32],
            handshake_time: ms.map(Duration::from_millis),
        }
    }

    #[test]
    fn ranking_established_before_failed() {
        let v = rank(vec![
            m("fail-a://x", None),
            m("udp://x", Some(3000)),
            m("fail-b://x", None),
            m("udp://y", Some(80)),
        ]);
        assert_eq!(v[0].spec, "udp://y", "fastest established first");
        assert_eq!(v[1].spec, "udp://x", "next-fastest second");
        assert!(
            v[2].handshake_time.is_none() && v[3].handshake_time.is_none(),
            "failed entries land at the end: {:?}",
            v
        );
    }

    #[test]
    fn tie_break_picks_udp_over_dns_when_clustered() {
        // Reproduces the live home-Wi-Fi observation: 9 wires
        // cluster within ~30 ms because the bottleneck is the
        // bridge's cold-start latency, not the adapter. Without
        // tie-break, DNS "wins" by jitter. With tie-break, UDP
        // wins as it should.
        let v = rank(vec![
            m("dns://x", Some(2015)),
            m("udp://x", Some(2015)),
            m("tcp://x", Some(2020)),
            m("http://x", Some(2031)),
            m("h2://x", Some(2031)),
            m("tls://x", Some(2031)),
            m("ws://x", Some(2032)),
            m("h2s://x", Some(2047)),
            m("webtransport://x", Some(2047)),
        ]);
        assert_eq!(v[0].spec, "udp://x", "UDP wins the tie-break");
        assert_eq!(v[1].spec, "webtransport://x", "webtransport second");
        assert_eq!(v[2].spec, "h2s://x", "h2s third");
        assert_eq!(v[8].spec, "dns://x", "DNS sorts last in the tier");
    }

    #[test]
    fn outside_window_measurement_dominates() {
        // If a wire is meaningfully slower (e.g. corporate
        // network where TLS takes 5 s and UDP times out), the
        // measurement should dominate — we don't want the
        // tie-break to mask real adapter differences.
        let v = rank(vec![
            m("tls://x", Some(5000)),
            m("udp://x", None), // timed out
            m("h2s://x", Some(1200)),
            m("ws://x", Some(800)),
        ]);
        assert_eq!(v[0].spec, "ws://x", "actually-fastest established");
        assert_eq!(v[1].spec, "h2s://x");
        assert_eq!(v[2].spec, "tls://x");
        assert_eq!(v[3].spec, "udp://x", "timed-out drops to last");
    }

    #[test]
    fn tier_chaining_does_not_overreach() {
        // Three wires at 0/200/450 ms with TIE_BREAK_WINDOW=250.
        // Without bucketing-by-tier-min, the algorithm could
        // chain all three into one tier (each within 250 of its
        // neighbor). We want 0/200 in tier A and 450 alone in
        // tier B, because 450-0 > 250.
        let v = rank(vec![
            m("dns://x", Some(0)),
            m("tcp://x", Some(200)),
            m("udp://x", Some(450)),
        ]);
        // Tier A (0..=200): tcp beats dns by scheme priority.
        assert_eq!(v[0].spec, "tcp://x");
        assert_eq!(v[1].spec, "dns://x");
        // Tier B: udp alone, even though it has best scheme rank.
        assert_eq!(v[2].spec, "udp://x");
    }
}

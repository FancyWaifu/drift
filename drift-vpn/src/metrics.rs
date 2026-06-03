//! Per-daemon counters. Cheap atomics — incremented from hot
//! paths (tun read/write, send_data drops) and from the
//! supervisor (failover events, restarts). Read by the status
//! subcommand for operator-facing observability.
//!
//! Everything here is monotonic. The status command snapshots
//! the values at a point in time; rate computations belong to
//! the consumer (Prometheus / `watch -n1`).

use std::sync::atomic::{AtomicU64, Ordering};

/// Why a packet got dropped on the inbound (drift → tun) path.
/// Each cause has its own counter so an operator looking at
/// "rpfilter drops" can tell the difference between "I have a
/// misconfigured peer" and "I'm being attacked."
#[derive(Default)]
pub(crate) struct RpFilterCounters {
    /// `src_is_valid` returned false because the peer table
    /// has the peer but its `allowed_ips` doesn't cover the
    /// claimed source. This is almost always a config mismatch
    /// (peer's tun IP differs from what we listed). Less
    /// commonly: an attacker who controls the peer's identity
    /// but is using a different source IP.
    pub config_mismatch: AtomicU64,
    /// The DRIFT transport routed a packet to us but our
    /// route table doesn't have a peer for it. Happens at
    /// startup before all peers are registered, or for
    /// mesh-forwarded traffic from peers-of-peers we don't
    /// directly know.
    pub unknown_peer: AtomicU64,
    /// L3 parse failed (truncated header, unknown version).
    /// Usually noise from broken senders, but excessive
    /// counts mean someone's spraying garbage at us.
    pub parse_failed: AtomicU64,
}

/// All daemon-level counters. Cheap to construct (no heap
/// per field) and cheap to bump (relaxed atomics).
#[derive(Default)]
pub(crate) struct DaemonMetrics {
    // --- TUN device path (drift → tun) ---
    /// Packets successfully written to the tun device.
    pub tun_writes: AtomicU64,
    /// Bytes successfully written to the tun.
    pub tun_bytes_written: AtomicU64,
    /// `tun_w.write_all` returned an error. The most common
    /// cause is the kernel queue being full, which usually
    /// means an app on the host is too slow to drain.
    pub tun_write_errs: AtomicU64,

    // --- Egress path (tun → drift) ---
    /// Packets successfully passed to send_data.
    pub send_data_ok: AtomicU64,
    /// `send_data` returned an error. Logged with the size
    /// hint so an operator can see if it's MTU-related.
    pub send_data_errs: AtomicU64,
    /// Outbound packets that didn't match any peer's
    /// allowed_ips and got dropped at the routing layer.
    pub no_route_drops: AtomicU64,

    // --- Reverse-path filter (inbound) ---
    pub rpfilter: RpFilterCounters,

    // --- Failover supervisor ---
    /// Total times any peer failed over to a new endpoint.
    pub failover_commits_total: AtomicU64,
    /// Failovers that landed on a UDP endpoint. Sum across
    /// all peers.
    pub failover_to_udp: AtomicU64,
    /// Failovers that landed on a TCP endpoint.
    pub failover_to_tcp: AtomicU64,
    /// Failovers that landed on TLS / WS / HTTP / Onion (any
    /// non-UDP/TCP scheme). Pivot point for v0.5 cross-scheme.
    pub failover_to_other: AtomicU64,
    /// Times the supervisor's path-probe rounds all timed out
    /// and we fell back to `restart_handshake`. High count =
    /// path-probe machinery isn't getting through; the
    /// configured endpoints might be entirely wrong.
    pub failover_restarts: AtomicU64,
    /// Times the supervisor decided NOT to fail over because
    /// it was inside the post-commit hold window. Useful as
    /// "is hysteresis being exercised."
    pub failover_hold_skipped: AtomicU64,
}

impl DaemonMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the failover scheme bucket. Called once per
    /// committed failover with the destination URL.
    pub fn note_failover_to(&self, url: &str) {
        self.failover_commits_total.fetch_add(1, Ordering::Relaxed);
        let scheme_end = url.find("://").unwrap_or(url.len());
        match &url[..scheme_end] {
            "udp" => self.failover_to_udp.fetch_add(1, Ordering::Relaxed),
            "tcp" => self.failover_to_tcp.fetch_add(1, Ordering::Relaxed),
            _ => self.failover_to_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Snapshot all counters as a plain owned struct, suitable
    /// for serialization to the status subcommand or a metrics
    /// scrape. Cheap — just N atomic loads.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        MetricsSnapshot {
            tun_writes: load(&self.tun_writes),
            tun_bytes_written: load(&self.tun_bytes_written),
            tun_write_errs: load(&self.tun_write_errs),
            send_data_ok: load(&self.send_data_ok),
            send_data_errs: load(&self.send_data_errs),
            no_route_drops: load(&self.no_route_drops),
            rpfilter_config_mismatch: load(&self.rpfilter.config_mismatch),
            rpfilter_unknown_peer: load(&self.rpfilter.unknown_peer),
            rpfilter_parse_failed: load(&self.rpfilter.parse_failed),
            failover_commits_total: load(&self.failover_commits_total),
            failover_to_udp: load(&self.failover_to_udp),
            failover_to_tcp: load(&self.failover_to_tcp),
            failover_to_other: load(&self.failover_to_other),
            failover_restarts: load(&self.failover_restarts),
            failover_hold_skipped: load(&self.failover_hold_skipped),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct MetricsSnapshot {
    pub tun_writes: u64,
    pub tun_bytes_written: u64,
    pub tun_write_errs: u64,
    pub send_data_ok: u64,
    pub send_data_errs: u64,
    pub no_route_drops: u64,
    pub rpfilter_config_mismatch: u64,
    pub rpfilter_unknown_peer: u64,
    pub rpfilter_parse_failed: u64,
    pub failover_commits_total: u64,
    pub failover_to_udp: u64,
    pub failover_to_tcp: u64,
    pub failover_to_other: u64,
    pub failover_restarts: u64,
    pub failover_hold_skipped: u64,
}

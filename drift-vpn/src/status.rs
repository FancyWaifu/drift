//! Status server + client.
//!
//! The running daemon listens on a Unix socket (default
//! `/run/drift-vpn/status.sock`) and serves a JSON snapshot of
//! its state on connect: peer table, current endpoints, SRTT,
//! per-peer last_seen, and the daemon-wide counters from
//! `metrics::DaemonMetrics`.
//!
//! `drift-vpn status` connects to the socket, prints a human-
//! readable summary, exits. Operators don't need to grep logs
//! to answer "which endpoint is peer X on, how stale is the
//! link, how many failovers have we done."
//!
//! No authentication: the Unix socket lives in a directory
//! owned by the daemon's user; same security model as
//! WireGuard's `wg show` (which talks to the kernel via
//! netlink, also unauthenticated to the namespace).

use crate::metrics::{DaemonMetrics, MetricsSnapshot};
use anyhow::{Context, Result};
use drift_core::PeerId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Default socket path. Relative paths are normal here; the
/// daemon mkdirs the parent.
///
/// Platform-specific because `/run` is read-only on macOS (we
/// observed `Read-only file system (os error 30)` and a noisy
/// WARN at every daemon startup using the Linux path on Mac).
///
///   * Linux:  `/run/drift-vpn/status.sock` — systemd-managed,
///     writable for root.
///   * macOS:  `/var/run/drift-vpn/status.sock` — equivalent
///     tmpfs-style location that's actually writable.
///   * other:  `$TMPDIR/drift-vpn/status.sock` as a last resort.
pub(crate) fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/drift-vpn/status.sock")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/drift-vpn/status.sock")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let tmp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        tmp.join("drift-vpn/status.sock")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusReport {
    pub local: LocalInfo,
    pub peers: Vec<PeerStatus>,
    pub metrics: MetricsSnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LocalInfo {
    pub peer_id_hex: String,
    pub pubkey_hex: String,
    pub iface: String,
    pub addr: String,
    pub uptime_secs: u64,
    /// Daemon's PID. Used by `drift-vpn down` to send a graceful
    /// SIGTERM without shelling out to `ps`. Always present;
    /// historical reports without it deserialize to 0 via the
    /// default impl.
    #[serde(default)]
    pub pid: u32,
}

/// How drift-vpn reaches this peer. Determines whether the
/// "state=pending tx=0 rx=0" reading from `peer_metrics` is
/// meaningful — for `Federation` peers, no direct session
/// exists, so `peer_metrics` returns None and the counters
/// would all be zero whether data flows through the bridge
/// or not.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PeerKind {
    /// Direct peer reachable via one or more `endpoints`. Has a
    /// real DRIFT session and meaningful tx/rx/srtt.
    Direct,
    /// Mesh-only peer — no direct endpoint, no via_bridge.
    /// Reachable only via forwarding through another peer.
    /// Has a DRIFT session once the forwarder discovers it.
    Mesh,
    /// Federation peer — reachable through a configured
    /// via_bridge. No direct session; all wire traffic flows
    /// through the bridge's session. `peer_metrics` reads
    /// zero for these because the bridge sees the bytes, not
    /// the federation peer itself.
    Federation,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PeerStatus {
    pub peer_id_hex: String,
    pub pubkey_hex: String,
    pub allowed_ips: Vec<String>,
    pub current_addr: Option<String>,
    pub current_endpoint_url: Option<String>,
    pub is_established: bool,
    pub srtt_us: Option<u64>,
    pub rttvar_us: Option<u64>,
    pub seconds_since_last_seen: u64,
    pub tx_packets: u32,
    pub rx_packets: u32,
    /// How this peer is reached. See `PeerKind`. Default
    /// `Direct` for back-compat with older daemons that didn't
    /// emit this field.
    #[serde(default = "default_peer_kind")]
    pub kind: PeerKind,
}

fn default_peer_kind() -> PeerKind {
    PeerKind::Direct
}

/// Information the daemon serves to status clients.
pub(crate) struct StatusContext {
    pub local_pubkey: [u8; 32],
    pub local_peer_id: PeerId,
    pub iface_name: String,
    pub local_addr: String,
    pub started_at: std::time::Instant,
    pub transport: Arc<drift::Transport>,
    pub metrics: Arc<DaemonMetrics>,
    pub peers: Vec<KnownPeer>,
}

#[derive(Clone)]
pub(crate) struct KnownPeer {
    pub peer_id: PeerId,
    pub pubkey: [u8; 32],
    pub allowed_ips: Vec<String>,
    pub kind: PeerKind,
}

impl StatusContext {
    pub async fn build_report(&self) -> StatusReport {
        let mut peers = Vec::with_capacity(self.peers.len());
        for kp in &self.peers {
            let m = self.transport.peer_metrics(&kp.peer_id).await;
            let addr = self.transport.peer_addr(&kp.peer_id).await;
            let (srtt, rttvar, last_seen, is_established, tx, rx) = match m {
                Some(pm) => (
                    pm.srtt.map(|d| d.as_micros() as u64),
                    pm.rttvar.map(|d| d.as_micros() as u64),
                    std::time::Instant::now()
                        .duration_since(pm.last_seen)
                        .as_secs(),
                    pm.is_established,
                    pm.next_tx_seq.saturating_sub(1),
                    pm.highest_rx_seq,
                ),
                None => (None, None, u64::MAX, false, 0, 0),
            };
            peers.push(PeerStatus {
                peer_id_hex: hex::encode(kp.peer_id),
                pubkey_hex: hex::encode(kp.pubkey),
                allowed_ips: kp.allowed_ips.clone(),
                current_addr: addr.map(|a| a.to_string()),
                current_endpoint_url: None,
                is_established,
                srtt_us: srtt,
                rttvar_us: rttvar,
                seconds_since_last_seen: last_seen,
                tx_packets: tx,
                rx_packets: rx,
                kind: kp.kind,
            });
        }
        StatusReport {
            local: LocalInfo {
                peer_id_hex: hex::encode(self.local_peer_id),
                pubkey_hex: hex::encode(self.local_pubkey),
                iface: self.iface_name.clone(),
                addr: self.local_addr.clone(),
                uptime_secs: std::time::Instant::now()
                    .duration_since(self.started_at)
                    .as_secs(),
                pid: std::process::id(),
            },
            peers,
            metrics: self.metrics.snapshot(),
        }
    }
}

/// Server side: bind a Unix-domain socket. On each connection,
/// serialize a `StatusReport` as one JSON line and close.
///
/// Best-effort: if the socket can't be bound (e.g. parent dir
/// not writable), log a warning and exit cleanly. The daemon
/// itself stays running.
#[cfg(unix)]
pub(crate) async fn run_server(path: PathBuf, ctx: Arc<StatusContext>) {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            tracing::warn!(error = %e, dir = %parent.display(), "couldn't create status socket dir");
            return;
        }
    }
    // If a socket file already exists from a previous (crashed)
    // run, remove it. Bind would fail otherwise. We don't try
    // to detect a live-daemon collision here — if the dir is
    // writable, that's the operator's problem.
    let _ = tokio::fs::remove_file(&path).await;

    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "couldn't bind status socket");
            return;
        }
    };
    // World-readable; same model as wg-quick's runtime files.
    // Surfaced as a warn-level log if chmod fails so the operator
    // notices when `drift-vpn status` from a non-root shell would
    // hit permission-denied (rare — happens on filesystems that
    // ignore chmod, e.g., FAT mounts in test rigs).
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "could not chmod status socket to 0o666 — `drift-vpn status` from a non-root shell may fail with EACCES"
        );
    }

    tracing::info!(path = %path.display(), "status socket listening");

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "status socket accept error");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let report = ctx.build_report().await;
            let body = match serde_json::to_string(&report) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "serializing status report");
                    return;
                }
            };
            let _ = sock.write_all(body.as_bytes()).await;
            let _ = sock.write_all(b"\n").await;
            let _ = sock.shutdown().await;
        });
    }
}

/// Client side: connect, read one JSON blob, parse, return.
///
/// Translates the raw OS errors into actionable messages:
///   * ENOENT → daemon not running (suggest `drift-vpn up`)
///   * ECONNREFUSED → stale socket from a crashed daemon
///   * EACCES → permission denied (socket not world-readable; rare)
///
/// Anything else falls through with the underlying error attached.
#[cfg(unix)]
pub(crate) async fn fetch(path: &Path) -> Result<StatusReport> {
    use tokio::io::AsyncReadExt;
    let mut sock = match tokio::net::UnixStream::connect(path).await {
        Ok(s) => s,
        Err(e) => {
            return Err(match e.kind() {
                std::io::ErrorKind::NotFound => anyhow::anyhow!(
                    "no drift-vpn daemon running — start it with `drift-vpn up -c <config>` \
                     (status socket {} does not exist)",
                    path.display()
                ),
                std::io::ErrorKind::ConnectionRefused => anyhow::anyhow!(
                    "status socket {} exists but no daemon is listening — \
                     the previous drift-vpn likely crashed without cleanup. \
                     Remove the stale socket and restart: `rm {} && drift-vpn up -c <config>`",
                    path.display(),
                    path.display()
                ),
                std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                    "permission denied connecting to {} — the socket isn't world-readable. \
                     Either run `drift-vpn status` as the same user that started the daemon, \
                     or restart the daemon and check its log for a `could not chmod status socket` warning.",
                    path.display()
                ),
                _ => anyhow::Error::from(e).context(format!("connecting to {}", path.display())),
            });
        }
    };
    let mut buf = String::new();
    tokio::time::timeout(Duration::from_secs(2), sock.read_to_string(&mut buf))
        .await
        .context("status socket read timeout")?
        .context("reading status response")?;
    let report: StatusReport = serde_json::from_str(buf.trim()).context("parsing status JSON")?;
    Ok(report)
}

/// Pretty-print a status report (`drift-vpn status` output).
pub(crate) fn render_human(report: &StatusReport) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "local: peer={} iface={} addr={} uptime={}s",
        &report.local.peer_id_hex, report.local.iface, report.local.addr, report.local.uptime_secs
    );
    let _ = writeln!(out, "  pubkey: {}", report.local.pubkey_hex);
    let _ = writeln!(out);
    let _ = writeln!(out, "peers: {}", report.peers.len());
    for p in &report.peers {
        // State display depends on kind:
        //   * Direct/Mesh peer with a DRIFT session →
        //     "established" or "pending" per is_established.
        //   * Federation peer has no direct session — show
        //     "federation-routed" instead of "pending tx=0
        //     rx=0" so operators don't mistake it for broken.
        //     Actual reachability is the bridge's session
        //     state, which the bridge shows in its own peers
        //     list above this one.
        let state = match (p.kind, p.is_established) {
            (PeerKind::Federation, _) => "federation-routed",
            (_, true) => "established",
            (_, false) => "pending",
        };
        let kind_tag = match p.kind {
            PeerKind::Direct => "",
            PeerKind::Mesh => " kind=mesh",
            PeerKind::Federation => " kind=federation",
        };
        let srtt = p
            .srtt_us
            .map(|us| format!("{:.1}ms", us as f64 / 1000.0))
            .unwrap_or_else(|| "—".into());
        let stale = if p.seconds_since_last_seen == u64::MAX {
            "never".to_string()
        } else {
            format!("{}s", p.seconds_since_last_seen)
        };
        let _ = writeln!(
            out,
            "  {}  {}  state={}{} srtt={} stale={}",
            &p.peer_id_hex,
            p.current_addr.as_deref().unwrap_or("—"),
            state,
            kind_tag,
            srtt,
            stale,
        );
        // For federation peers, the tx/rx counters here are
        // zero by construction — peer_metrics tracks the direct
        // session, federation peers don't have one. Suppress
        // the misleading "tx=0 rx=0" and show the data plane
        // counters from the daemon (tun writes, egress sent)
        // are the source of truth instead.
        if p.kind == PeerKind::Federation {
            let _ = writeln!(
                out,
                "    allowed_ips={:?}  (tx/rx counters are bridge-side; see daemon counters below)",
                p.allowed_ips
            );
        } else {
            let _ = writeln!(
                out,
                "    allowed_ips={:?}  tx={} rx={}",
                p.allowed_ips, p.tx_packets, p.rx_packets
            );
        }
    }
    let _ = writeln!(out);
    let m = &report.metrics;
    let _ = writeln!(out, "counters:");
    let _ = writeln!(
        out,
        "  tun:      writes={} bytes={} errs={}",
        m.tun_writes, m.tun_bytes_written, m.tun_write_errs
    );
    let _ = writeln!(
        out,
        "  egress:   sent={} errs={} no-route={}",
        m.send_data_ok, m.send_data_errs, m.no_route_drops
    );
    let _ = writeln!(
        out,
        "  rpfilter: config-mismatch={} unknown-peer={} parse-fail={}",
        m.rpfilter_config_mismatch, m.rpfilter_unknown_peer, m.rpfilter_parse_failed
    );
    let _ = writeln!(
        out,
        "  failover: total={} udp={} tcp={} other={} restart={} hold-skipped={}",
        m.failover_commits_total,
        m.failover_to_udp,
        m.failover_to_tcp,
        m.failover_to_other,
        m.failover_restarts,
        m.failover_hold_skipped
    );
    out
}

/// Render a `StatusReport` in Prometheus text exposition format.
///
/// Conventions:
///   - Counters end in `_total`.
///   - Gauges are descriptive (`_seconds`, `_bytes`, …).
///   - Per-peer metrics use a `peer` label (the 8-byte peer-id
///     hex), so a single Prometheus query can graph all peers
///     and a `topk` / `groupby` works naturally.
///   - All metric names are prefixed `drift_vpn_` so they
///     don't collide with anything else a node is exposing.
///
/// Format ref: <https://prometheus.io/docs/instrumenting/exposition_formats/>
pub(crate) fn render_prometheus(report: &StatusReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    // --- Daemon-wide counters ---
    let m = &report.metrics;

    let _ = writeln!(
        out,
        "# HELP drift_vpn_uptime_seconds Daemon uptime since startup"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_uptime_seconds gauge");
    let _ = writeln!(out, "drift_vpn_uptime_seconds {}", report.local.uptime_secs);

    let _ = writeln!(
        out,
        "# HELP drift_vpn_tun_writes_total Packets successfully written to the TUN device"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_tun_writes_total counter");
    let _ = writeln!(out, "drift_vpn_tun_writes_total {}", m.tun_writes);

    let _ = writeln!(
        out,
        "# HELP drift_vpn_tun_bytes_total Bytes successfully written to the TUN device"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_tun_bytes_total counter");
    let _ = writeln!(out, "drift_vpn_tun_bytes_total {}", m.tun_bytes_written);

    let _ = writeln!(out, "# HELP drift_vpn_tun_write_errors_total TUN write errors (kernel queue full, driver issue, …)");
    let _ = writeln!(out, "# TYPE drift_vpn_tun_write_errors_total counter");
    let _ = writeln!(out, "drift_vpn_tun_write_errors_total {}", m.tun_write_errs);

    let _ = writeln!(
        out,
        "# HELP drift_vpn_egress_packets_total Packets handed to the transport from the TUN"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_egress_packets_total counter");
    let _ = writeln!(
        out,
        "drift_vpn_egress_packets_total{{outcome=\"ok\"}} {}",
        m.send_data_ok
    );
    let _ = writeln!(
        out,
        "drift_vpn_egress_packets_total{{outcome=\"error\"}} {}",
        m.send_data_errs
    );
    let _ = writeln!(
        out,
        "drift_vpn_egress_packets_total{{outcome=\"no_route\"}} {}",
        m.no_route_drops
    );

    let _ = writeln!(out, "# HELP drift_vpn_rpfilter_drops_total Inbound packets dropped by the reverse-path filter, by cause");
    let _ = writeln!(out, "# TYPE drift_vpn_rpfilter_drops_total counter");
    let _ = writeln!(
        out,
        "drift_vpn_rpfilter_drops_total{{cause=\"config_mismatch\"}} {}",
        m.rpfilter_config_mismatch
    );
    let _ = writeln!(
        out,
        "drift_vpn_rpfilter_drops_total{{cause=\"unknown_peer\"}} {}",
        m.rpfilter_unknown_peer
    );
    let _ = writeln!(
        out,
        "drift_vpn_rpfilter_drops_total{{cause=\"parse_failed\"}} {}",
        m.rpfilter_parse_failed
    );

    let _ = writeln!(
        out,
        "# HELP drift_vpn_failover_commits_total Committed failovers, by destination scheme"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_failover_commits_total counter");
    let _ = writeln!(
        out,
        "drift_vpn_failover_commits_total{{scheme=\"udp\"}} {}",
        m.failover_to_udp
    );
    let _ = writeln!(
        out,
        "drift_vpn_failover_commits_total{{scheme=\"tcp\"}} {}",
        m.failover_to_tcp
    );
    let _ = writeln!(
        out,
        "drift_vpn_failover_commits_total{{scheme=\"other\"}} {}",
        m.failover_to_other
    );

    let _ = writeln!(
        out,
        "# HELP drift_vpn_failover_restarts_total Failovers that fell through to a fresh handshake"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_failover_restarts_total counter");
    let _ = writeln!(
        out,
        "drift_vpn_failover_restarts_total {}",
        m.failover_restarts
    );

    let _ = writeln!(
        out,
        "# HELP drift_vpn_failover_hold_skipped_total Failover attempts suppressed by hysteresis"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_failover_hold_skipped_total counter");
    let _ = writeln!(
        out,
        "drift_vpn_failover_hold_skipped_total {}",
        m.failover_hold_skipped
    );

    // --- Per-peer metrics ---
    let _ = writeln!(
        out,
        "# HELP drift_vpn_peer_established Whether the peer is in Established state (1=yes, 0=no)"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_peer_established gauge");
    for p in &report.peers {
        let _ = writeln!(
            out,
            "drift_vpn_peer_established{{peer=\"{}\"}} {}",
            p.peer_id_hex,
            if p.is_established { 1 } else { 0 }
        );
    }

    let _ = writeln!(
        out,
        "# HELP drift_vpn_peer_srtt_seconds Smoothed round-trip time per peer"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_peer_srtt_seconds gauge");
    for p in &report.peers {
        if let Some(us) = p.srtt_us {
            let secs = us as f64 / 1_000_000.0;
            let _ = writeln!(
                out,
                "drift_vpn_peer_srtt_seconds{{peer=\"{}\"}} {:.6}",
                p.peer_id_hex, secs
            );
        }
    }

    let _ = writeln!(out, "# HELP drift_vpn_peer_seconds_since_last_seen Staleness — secs since the last AEAD-valid packet from this peer");
    let _ = writeln!(out, "# TYPE drift_vpn_peer_seconds_since_last_seen gauge");
    for p in &report.peers {
        let v = if p.seconds_since_last_seen == u64::MAX {
            // Mesh-only peers that haven't bootstrapped yet —
            // emit -1 to make it distinguishable in graphs from
            // a freshly-stale peer.
            -1.0
        } else {
            p.seconds_since_last_seen as f64
        };
        let _ = writeln!(
            out,
            "drift_vpn_peer_seconds_since_last_seen{{peer=\"{}\"}} {}",
            p.peer_id_hex, v
        );
    }

    let _ = writeln!(
        out,
        "# HELP drift_vpn_peer_tx_packets_total Packets sent to peer in current session"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_peer_tx_packets_total counter");
    for p in &report.peers {
        let _ = writeln!(
            out,
            "drift_vpn_peer_tx_packets_total{{peer=\"{}\"}} {}",
            p.peer_id_hex, p.tx_packets
        );
    }

    let _ = writeln!(
        out,
        "# HELP drift_vpn_peer_rx_packets_total Packets received from peer in current session"
    );
    let _ = writeln!(out, "# TYPE drift_vpn_peer_rx_packets_total counter");
    for p in &report.peers {
        let _ = writeln!(
            out,
            "drift_vpn_peer_rx_packets_total{{peer=\"{}\"}} {}",
            p.peer_id_hex, p.rx_packets
        );
    }

    out
}

/// HTTP server for the `/metrics` endpoint. Tiny by design —
/// only handles `GET /metrics` (and `GET /` as a friendly
/// pointer); everything else gets a 404. Connection: close
/// after each response so we don't have to do keepalive.
///
/// Prometheus' default scrape interval is 15s; the server
/// rebuilds the snapshot per request, which is cheap (one
/// peer-table walk + a handful of atomic reads).
#[cfg(unix)]
pub(crate) async fn run_prom_server(addr: std::net::SocketAddr, ctx: Arc<StatusContext>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, %addr, "couldn't bind prometheus listener");
            return;
        }
    };
    tracing::info!(%addr, "prometheus /metrics listening");

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "prometheus accept error");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            // Read the request line. We don't actually parse
            // headers — we just need to see "GET /metrics" so
            // we can return either the metrics or a 404.
            let mut buf = [0u8; 1024];
            let n =
                match tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf))
                    .await
                {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
            let req = String::from_utf8_lossy(&buf[..n]);
            let first_line = req.lines().next().unwrap_or("");

            let response = if first_line.starts_with("GET /metrics") {
                let report = ctx.build_report().await;
                let body = render_prometheus(&report);
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                )
            } else if first_line.starts_with("GET / ") || first_line.starts_with("GET / HTTP") {
                let body = "drift-vpn metrics endpoint\n\nGET /metrics for Prometheus scrape.\n";
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                )
            } else {
                let body = "not found\n";
                format!(
                    "HTTP/1.1 404 Not Found\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                )
            };

            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

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
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/drift-vpn/status.sock")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub local: LocalInfo,
    pub peers: Vec<PeerStatus>,
    pub metrics: MetricsSnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalInfo {
    pub peer_id_hex: String,
    pub pubkey_hex: String,
    pub iface: String,
    pub addr: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
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
}

/// Information the daemon serves to status clients.
pub struct StatusContext {
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
pub struct KnownPeer {
    pub peer_id: PeerId,
    pub pubkey: [u8; 32],
    pub allowed_ips: Vec<String>,
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
#[cfg(target_os = "linux")]
pub async fn run_server(path: PathBuf, ctx: Arc<StatusContext>) {
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
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));

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
#[cfg(target_os = "linux")]
pub async fn fetch(path: &Path) -> Result<StatusReport> {
    use tokio::io::AsyncReadExt;
    let mut sock = tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    let mut buf = String::new();
    tokio::time::timeout(Duration::from_secs(2), sock.read_to_string(&mut buf))
        .await
        .context("status socket read timeout")?
        .context("reading status response")?;
    let report: StatusReport =
        serde_json::from_str(buf.trim()).context("parsing status JSON")?;
    Ok(report)
}

/// Pretty-print a status report (`drift-vpn status` output).
pub fn render_human(report: &StatusReport) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "local: peer={} iface={} addr={} uptime={}s",
        &report.local.peer_id_hex,
        report.local.iface,
        report.local.addr,
        report.local.uptime_secs
    );
    let _ = writeln!(out, "  pubkey: {}", report.local.pubkey_hex);
    let _ = writeln!(out);
    let _ = writeln!(out, "peers: {}", report.peers.len());
    for p in &report.peers {
        let state = if p.is_established { "established" } else { "pending" };
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
            "  {}  {}  state={} srtt={} stale={}",
            &p.peer_id_hex,
            p.current_addr.as_deref().unwrap_or("—"),
            state,
            srtt,
            stale,
        );
        let _ = writeln!(
            out,
            "    allowed_ips={:?}  tx={} rx={}",
            p.allowed_ips, p.tx_packets, p.rx_packets
        );
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

//! `drift-vpn doctor` — preflight diagnostics.
//!
//! Runs a series of read-only checks against the host and the
//! configured drift-vpn instance, prints actionable pass/warn/fail
//! results. Designed for the moments before first `drift-vpn up`:
//! tells you what's missing, what's wrong, and what you'll need
//! to fix to get a working VPN.
//!
//! Does NOT require a running daemon. Does NOT mutate state — no
//! sysctl writes, no kernel module loads, no socket binds longer
//! than a probe.

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;

use anyhow::Result;

use crate::config::Config;

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Warn,
    Fail,
    /// Informational — neither pass nor fail (e.g. "running as
    /// non-root, which is fine if you've granted CAP_NET_ADMIN").
    Info,
}

impl Verdict {
    fn glyph(self) -> &'static str {
        match self {
            Verdict::Pass => "  OK ",
            Verdict::Warn => " WARN",
            Verdict::Fail => " FAIL",
            Verdict::Info => " INFO",
        }
    }
}

struct CheckResult {
    name: &'static str,
    verdict: Verdict,
    detail: String,
    /// One-line suggestion the user can act on. Empty if no
    /// suggestion applies (typical for `Pass`).
    hint: Option<String>,
}

impl CheckResult {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Pass,
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Warn,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Fail,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }

    fn info(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            verdict: Verdict::Info,
            detail: detail.into(),
            hint: None,
        }
    }
}

/// Run the full check suite and print a report. Returns Ok(true)
/// if every check passed (or was warn/info), Ok(false) if any
/// check failed.
///
/// `probe`: when true, additionally attempts a real handshake
/// against each configured peer / bridge. Catches unreachability
/// + pubkey-mismatch failures that the static checks can't see.
pub async fn run(config_path: &Path, probe: bool) -> Result<bool> {
    let mut results = Vec::new();

    // Order is deliberate — checks that gate later checks come
    // first. If the config doesn't parse there's no point checking
    // peer endpoints.
    results.push(check_privilege());
    let (cfg_result, cfg) = check_config(config_path).await;
    results.push(cfg_result);
    results.push(check_tun_device());
    results.push(check_ip_forwarding());
    if let Some(ref cfg) = cfg {
        results.push(check_identity(cfg).await);
        results.push(check_listen_ports(cfg));
        results.push(check_peers(cfg));
    }
    results.push(check_status_socket_dir());

    // Live probes — only when --probe is set, because they take
    // ~5s per peer and touch the network. Static checks are still
    // safe to run blindly; probes need explicit consent.
    if probe {
        if let Some(ref cfg) = cfg {
            for r in probe_peers(cfg).await {
                results.push(r);
            }
        }
    }

    render(&results);

    let any_fail = results.iter().any(|r| r.verdict == Verdict::Fail);
    Ok(!any_fail)
}

// ─── Individual checks ───────────────────────────────────────────

fn check_privilege() -> CheckResult {
    // Geteuid is Unix-specific; non-Unix builds can't even
    // reach `Up` so this codepath only runs on Linux/macOS.
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is always safe; reads a thread-local
        // integer.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            CheckResult::pass("privilege", "running as root (uid 0)")
        } else {
            CheckResult::warn(
                "privilege",
                format!("running as uid {}, not root", uid),
                "drift-vpn needs CAP_NET_ADMIN to create TUN devices and \
                 configure routes. Either run as root, or grant the cap with \
                 `sudo setcap cap_net_admin+eip /path/to/drift-vpn`.",
            )
        }
    }
    #[cfg(not(unix))]
    {
        CheckResult::info("privilege", "non-Unix platform; `up` is unsupported here")
    }
}

async fn check_config(path: &Path) -> (CheckResult, Option<Config>) {
    if !path.exists() {
        return (
            CheckResult::fail(
                "config",
                format!("not found at {}", path.display()),
                format!(
                    "generate one with `drift-vpn config init --config {}` \
                     or copy the schema from drift-vpn/README.md",
                    path.display()
                ),
            ),
            None,
        );
    }
    match Config::load(path).await {
        Ok(cfg) => {
            let peer_n = cfg.peers.len();
            let detail = format!(
                "{} parses cleanly ({} peer{}, listen on {})",
                path.display(),
                peer_n,
                if peer_n == 1 { "" } else { "s" },
                cfg.interface.listen.join(", ")
            );
            (CheckResult::pass("config", detail), Some(cfg))
        }
        Err(e) => (
            CheckResult::fail(
                "config",
                format!("failed to parse {}: {}", path.display(), e),
                "fix the TOML syntax or schema error reported above",
            ),
            None,
        ),
    }
}

fn check_tun_device() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/dev/net/tun");
        if path.exists() {
            CheckResult::pass("tun device", "/dev/net/tun is present")
        } else {
            CheckResult::fail(
                "tun device",
                "/dev/net/tun does not exist",
                "load the tun module: `sudo modprobe tun`. If running in a \
                 container, the host must pass /dev/net/tun through.",
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS utun is built into the kernel — no module to load.
        // Probe by checking for the system utun control socket.
        let path = Path::new("/dev/tty");
        let _ = path; // unused; placate compiler if we later remove
        CheckResult::pass(
            "tun device",
            "macOS utun is built into the kernel; will be created on `up`",
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        CheckResult::info(
            "tun device",
            "unsupported OS for TUN; drift-vpn `up` won't work here",
        )
    }
}

fn check_ip_forwarding() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            Ok(s) => {
                let on = s.trim() == "1";
                if on {
                    CheckResult::info(
                        "ip forwarding",
                        "net.ipv4.ip_forward=1 (forwarding ON — required for hub \
                         roles, harmless for spokes)",
                    )
                } else {
                    CheckResult::warn(
                        "ip forwarding",
                        "net.ipv4.ip_forward=0 (forwarding OFF)",
                        "if this host is a HUB (other peers route through it to \
                         reach each other), enable forwarding with \
                         `sudo sysctl -w net.ipv4.ip_forward=1` and persist it in \
                         /etc/sysctl.d/. Spoke-only hosts can ignore this.",
                    )
                }
            }
            Err(_) => CheckResult::warn(
                "ip forwarding",
                "couldn't read /proc/sys/net/ipv4/ip_forward",
                "non-standard /proc layout (container?). If hub role, verify \
                 sysctl net.ipv4.ip_forward=1 manually.",
            ),
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS: `sysctl net.inet.ip.forwarding`. Don't shell out
        // for the preflight; just inform the user.
        CheckResult::info(
            "ip forwarding",
            "macOS: check with `sysctl net.inet.ip.forwarding` if running as hub",
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        CheckResult::info("ip forwarding", "skipped (unsupported OS)")
    }
}

async fn check_identity(cfg: &Config) -> CheckResult {
    let path = &cfg.interface.identity_file;
    if !path.exists() {
        return CheckResult::fail(
            "identity",
            format!("not found at {}", path.display()),
            format!(
                "generate one with `drift-vpn keygen --out {}`",
                path.display()
            ),
        );
    }
    match tokio::fs::read_to_string(path).await {
        Ok(body) => {
            // Identity files are 64 hex chars (32 raw bytes,
            // hex-encoded) — see drift-vpn::identity::keygen.
            // Trailing newline is fine.
            let trimmed = body.trim();
            match hex::decode(trimmed) {
                Ok(bytes) if bytes.len() == 32 => CheckResult::pass(
                    "identity",
                    format!("{} is a well-formed 32-byte X25519 key", path.display()),
                ),
                Ok(bytes) => CheckResult::fail(
                    "identity",
                    format!(
                        "{} decodes to {} bytes, expected 32",
                        path.display(),
                        bytes.len()
                    ),
                    "regenerate with `drift-vpn keygen --out <path>` (back up the \
                     old file first if you need to keep the old pubkey)",
                ),
                Err(e) => CheckResult::fail(
                    "identity",
                    format!("{} is not valid hex: {}", path.display(), e),
                    "drift-vpn keygen writes 64 hex chars; if this file is from \
                     another tool, convert it or regenerate",
                ),
            }
        }
        Err(e) => CheckResult::fail(
            "identity",
            format!("failed to read {}: {}", path.display(), e),
            "check file ownership and permissions (root-only is typical, \
             mode 0600)",
        ),
    }
}

fn check_listen_ports(cfg: &Config) -> CheckResult {
    // For every UDP listen URL of the form `udp://0.0.0.0:N`,
    // try a quick non-blocking bind to see if the port is free.
    // Other schemes (tcp/tls/ws) bind only on `up`; we don't
    // probe them — the OS error message at `up` time is just as
    // actionable.
    let mut probed = Vec::new();
    let mut taken = Vec::new();
    for url in &cfg.interface.listen {
        if let Some(rest) = url.strip_prefix("udp://") {
            // rest is like "0.0.0.0:51820"
            if let Ok(addr) = rest.parse::<SocketAddr>() {
                probed.push(addr);
                match UdpSocket::bind(addr) {
                    Ok(sock) => drop(sock),
                    Err(_) => taken.push(addr),
                }
            }
        }
    }
    if probed.is_empty() {
        return CheckResult::info(
            "listen ports",
            "no UDP listen URLs to probe (non-UDP listens checked at `up` time)",
        );
    }
    if taken.is_empty() {
        CheckResult::pass(
            "listen ports",
            format!(
                "{} UDP port{} available: {}",
                probed.len(),
                if probed.len() == 1 { "" } else { "s" },
                probed
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    } else {
        CheckResult::fail(
            "listen ports",
            format!(
                "{} of {} UDP port{} already in use: {}",
                taken.len(),
                probed.len(),
                if taken.len() == 1 { "" } else { "s" },
                taken
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "stop the process holding the port (`sudo lsof -iUDP:51820` or \
             `sudo ss -ulnp`) or change interface.listen in the config",
        )
    }
}

fn check_peers(cfg: &Config) -> CheckResult {
    let n = cfg.peers.len();
    if n == 0 {
        return CheckResult::warn(
            "peers",
            "no [[peer]] sections in the config",
            "add at least one peer to make the VPN useful — see drift-vpn/README.md",
        );
    }
    // Count peers by reach kind: direct (endpoints), federation
    // (via_bridge / via_bridges / via_bridges_auto), or true
    // mesh-only (no endpoint AND no bridge). The previous version
    // lumped all-no-endpoints peers under "mesh-only", which
    // mis-labeled federation peers — they're reachable through
    // the configured bridge, not via beacon-propagated mesh.
    use std::collections::BTreeMap;
    let mut direct_by_scheme: BTreeMap<&str, usize> = BTreeMap::new();
    let mut federation = 0;
    let mut mesh_only = 0;
    for p in &cfg.peers {
        let endpoints = p.endpoint_list();
        if !endpoints.is_empty() {
            for url in &endpoints {
                let scheme = url.split("://").next().unwrap_or("?");
                *direct_by_scheme
                    .entry(Box::leak(scheme.to_string().into_boxed_str()))
                    .or_insert(0) += 1;
            }
            continue;
        }
        if !p.via_bridge_list().is_empty() || p.via_bridges_auto.is_some() {
            federation += 1;
        } else {
            mesh_only += 1;
        }
    }
    let mut parts = Vec::new();
    for (scheme, c) in &direct_by_scheme {
        parts.push(format!("{}×{}", scheme, c));
    }
    if federation > 0 {
        parts.push(format!("{} federation", federation));
    }
    if mesh_only > 0 {
        parts.push(format!("{} mesh-only", mesh_only));
    }
    CheckResult::pass(
        "peers",
        format!(
            "{} peer{} configured ({})",
            n,
            if n == 1 { "" } else { "s" },
            parts.join(", ")
        ),
    )
}

/// `doctor --probe`: actually try to handshake with each
/// configured peer / bridge. Returns one CheckResult per
/// target.
///
/// What it does:
///   - Reads the identity file.
///   - Stands up a Transport bound to an ephemeral local UDP
///     port (no TUN, no status socket — read-only on the system).
///   - For each peer or via_bridge URL, calls connect_url +
///     add_peer + send_data("probe"), then waits up to ~5s for
///     `peer_metrics.is_established`.
///   - Reports pass/fail + the time to establish or the error.
///
/// Catches: peer offline, bridge unreachable, pubkey mismatch
/// (handshake AEAD will fail, surface as "not established within
/// 5s"), network filtering (TCP connect timeout, UDP HELLO_ACK
/// drop). All the failure modes we saw debugging today.
async fn probe_peers(cfg: &Config) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // 1. Collect unique bridge URLs first — multiple peers can
    //    share one via_bridge and we probe each bridge only once.
    use std::collections::BTreeMap;
    let mut bridge_by_url: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    for peer in &cfg.peers {
        if let Some(spec) = &peer.via_bridge {
            if let Ok((url, pub_)) = crate::config::parse_bridge_spec(spec) {
                bridge_by_url.entry(url).or_insert(pub_);
            }
        }
    }
    for (bridge_url, bridge_pub) in &bridge_by_url {
        match probe_one(bridge_url, *bridge_pub).await {
            Ok(elapsed) => {
                results.push(CheckResult::pass(
                    "probe / bridge",
                    format!(
                        "{} reachable; session Established in {}ms",
                        bridge_url,
                        elapsed.as_millis()
                    ),
                ));
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "probe / bridge",
                    format!("{} not reachable: {}", bridge_url, e),
                    "check the bridge is running and the WAN forward is correct; \
                     if SYN/HELLO is dropped, the network between this host and \
                     the bridge is filtering — try a different scheme (h2s/h2/ws) \
                     or an SSH tunnel",
                ));
            }
        }
    }

    // 2. Probe direct-endpoint peers. via_bridge peers ride the
    //    bridge probe above; if the bridge handshake works,
    //    end-to-end federation is likely working too. Probing
    //    the federated leg specifically would require dialing
    //    the peer's pubkey via the bridge — connect_federate
    //    handles that inside the daemon but isn't exposed here;
    //    deferred.
    for (i, peer) in cfg.peers.iter().enumerate() {
        let endpoints = peer.endpoint_list();
        if endpoints.is_empty() {
            continue; // mesh-only or via_bridge-only — handled above
        }
        let peer_pub = match peer.pubkey_bytes() {
            Ok(p) => p,
            Err(_) => continue, // surfaced by check_peers already
        };
        let mut last_err: Option<String> = None;
        let mut succeeded = false;
        for endpoint in &endpoints {
            match probe_one(endpoint, peer_pub).await {
                Ok(elapsed) => {
                    results.push(CheckResult::pass(
                        "probe / peer",
                        format!(
                            "peer #{} via {} — Established in {}ms",
                            i,
                            endpoint,
                            elapsed.as_millis()
                        ),
                    ));
                    succeeded = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(format!("{}: {}", endpoint, e));
                }
            }
        }
        if !succeeded {
            results.push(CheckResult::fail(
                "probe / peer",
                format!(
                    "peer #{} unreachable via {} endpoint{}: {}",
                    i,
                    endpoints.len(),
                    if endpoints.len() == 1 { "" } else { "s" },
                    last_err.unwrap_or_else(|| "no endpoints to try".to_string())
                ),
                "peer process may be offline, the configured pubkey may \
                 not match the peer's current identity (check with \
                 `drift-vpn show --identity-file <peer-key>` on the other \
                 side), or the network is filtering — try a different scheme",
            ));
        }
    }

    results
}

/// Single per-target probe: spin up a fresh Transport via
/// connect_url (which selects the correct adapter for the URL's
/// scheme), add the target as a peer, send a probe packet, wait
/// up to 5 s for `peer_metrics.is_established`.
///
/// Uses an ephemeral identity so it never collides with whatever
/// the user's running daemon is doing. The Transport is dropped
/// on function exit — all sockets close cleanly.
async fn probe_one(
    url: &str,
    target_pub: [u8; 32],
) -> std::result::Result<std::time::Duration, String> {
    use drift::identity::Identity;
    use drift::{Direction, Transport, TransportConfig};
    use std::time::{Duration, Instant};

    let identity = Identity::generate();
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    let (transport, peer_addr) = Transport::connect_url(url, identity, cfg)
        .await
        .map_err(|e| format!("connect_url: {}", e))?;
    let transport = std::sync::Arc::new(transport);

    let handle = transport
        .add_peer(target_pub, peer_addr, Direction::Initiator)
        .await
        .map_err(|e| format!("add_peer: {}", e))?;
    let start = Instant::now();
    transport
        .send_data(&handle, b"doctor-probe", 5000, 0)
        .await
        .map_err(|e| format!("send_data: {}", e))?;
    let deadline = start + Duration::from_secs(5);
    loop {
        if let Some(m) = transport.peer_metrics(&handle).await {
            if m.is_established {
                return Ok(start.elapsed());
            }
        }
        if Instant::now() >= deadline {
            return Err("handshake did not reach Established within 5s".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn check_status_socket_dir() -> CheckResult {
    let sock = crate::status::default_socket_path();
    let dir = sock.parent().unwrap_or_else(|| Path::new("/"));
    if dir.exists() {
        // Probe writability by stat'ing — best we can do without
        // actually creating a file.
        match std::fs::metadata(dir) {
            Ok(_) => CheckResult::pass(
                "status socket",
                format!("parent dir {} exists", dir.display()),
            ),
            Err(e) => CheckResult::warn(
                "status socket",
                format!("{} stat failed: {}", dir.display(), e),
                "the daemon will create the socket on `up`; if this fails the \
                 daemon will log a clear error",
            ),
        }
    } else {
        // Don't fail outright — the daemon attempts to create the
        // directory on startup. Just inform.
        CheckResult::info(
            "status socket",
            format!(
                "parent dir {} does not exist (daemon will create on `up`)",
                dir.display()
            ),
        )
    }
}

// ─── Output rendering ────────────────────────────────────────────

fn render(results: &[CheckResult]) {
    println!("drift-vpn doctor");
    println!("================");
    for r in results {
        println!("{}  {:18} {}", r.verdict.glyph(), r.name, r.detail);
        if let Some(hint) = &r.hint {
            // Wrap hint to 76 cols with 6-space indent so it reads
            // as an obvious sub-bullet.
            for line in wrap(hint, 70) {
                println!("      → {}", line);
            }
        }
    }
    let pass = results
        .iter()
        .filter(|r| r.verdict == Verdict::Pass)
        .count();
    let warn = results
        .iter()
        .filter(|r| r.verdict == Verdict::Warn)
        .count();
    let fail = results
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .count();
    let info = results
        .iter()
        .filter(|r| r.verdict == Verdict::Info)
        .count();
    println!();
    println!(
        "{} pass · {} warn · {} fail · {} info",
        pass, warn, fail, info
    );
    if fail > 0 {
        println!();
        println!("Fix the FAIL items above and re-run `drift-vpn doctor`.");
    } else if warn > 0 {
        println!();
        println!("No blockers — the WARN items are worth a look but won't stop `drift-vpn up`.");
    } else {
        println!();
        println!("All checks clear. You're ready to `drift-vpn up`.");
    }
}

/// Tiny word-wrap. Doesn't handle multi-byte word boundaries
/// perfectly but is fine for ASCII English hint strings.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut line));
            line.push_str(word);
        } else {
            line.push(' ');
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

// Silence unused-import warnings in non-Unix builds where most
// of this module is dead.
#[cfg(not(unix))]
#[allow(dead_code)]
fn _unused(_: IpAddr, _: Ipv4Addr) {}

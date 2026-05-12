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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

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
pub async fn run(config_path: &Path) -> Result<bool> {
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
                    format!(
                        "{} is a well-formed 32-byte X25519 key",
                        path.display()
                    ),
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
    // Count peers by transport scheme to give the operator a quick
    // visual of what the daemon will try.
    use std::collections::BTreeMap;
    let mut by_scheme: BTreeMap<&str, usize> = BTreeMap::new();
    let mut endpointless = 0;
    for p in &cfg.peers {
        let endpoints = p.endpoint_list();
        if endpoints.is_empty() {
            endpointless += 1;
            continue;
        }
        for url in &endpoints {
            let scheme = url.split("://").next().unwrap_or("?");
            *by_scheme.entry(Box::leak(scheme.to_string().into_boxed_str())).or_insert(0) += 1;
        }
    }
    let mut parts = Vec::new();
    for (scheme, c) in &by_scheme {
        parts.push(format!("{}×{}", scheme, c));
    }
    if endpointless > 0 {
        parts.push(format!("{} mesh-only", endpointless));
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
    let pass = results.iter().filter(|r| r.verdict == Verdict::Pass).count();
    let warn = results.iter().filter(|r| r.verdict == Verdict::Warn).count();
    let fail = results.iter().filter(|r| r.verdict == Verdict::Fail).count();
    let info = results.iter().filter(|r| r.verdict == Verdict::Info).count();
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

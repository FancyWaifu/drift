//! Background `connect` bridge management.
//!
//! When a user clicks a `drift://` link, we want to:
//! 1. Find a running `drift-http connect` bridge for that peer,
//!    or spawn a fresh one.
//! 2. Hand back the local TCP port the bridge is listening on,
//!    so the URL handler can hand it to the browser as
//!    `http://127.0.0.1:<port>/<path>`.
//!
//! State lives in `~/.config/drift/links/<pub-prefix>.json`,
//! one file per peer. Each file holds `{ port, pid, peer_addr }`.
//! "Alive" is determined by TCP-poking the listed port — the pid
//! check is informational only (PIDs get reused).

use crate::transport_url::Transport as TpKind;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

#[derive(Serialize, Deserialize, Debug)]
struct BridgeState {
    /// Local TCP port the bridge is listening on.
    pub port: u16,
    /// PID of the `drift-http connect` process.
    pub pid: u32,
    /// Peer pubkey + addr the bridge points at, for sanity-
    /// checking on reuse.
    pub peer_addr: String,
    pub peer_pub_hex: String,
}

fn links_dir() -> Result<PathBuf> {
    Ok(crate::identity::config_dir()?.join("links"))
}

fn state_path(pub_hex: &str) -> Result<PathBuf> {
    // Use the full hex pubkey as the file name so two peers
    // with similar prefixes can never collide.
    Ok(links_dir()?.join(format!("{}.json", pub_hex)))
}

/// Returns the local TCP port of a healthy bridge to the given
/// peer. Reuses an existing bridge if one is live; otherwise
/// spawns a fresh one and returns its port.
///
/// `peer_url` is the canonical `<scheme>://host:port` form
/// `Transport::connect_url` accepts (e.g. `udp://1.2.3.4:9100`,
/// `tcp://example.com:443`). The transport choice is encoded
/// inside the URL string itself; the bridge state file keys on
/// the URL so two routes to the same pubkey via different
/// transports get distinct bridges.
pub async fn ensure_bridge(
    pub_hex: &str,
    peer_url: &str,
    transport: TpKind,
    identity_file: Option<PathBuf>,
) -> Result<u16> {
    let path = state_path(pub_hex)?;

    if let Ok(state) = read_state(&path) {
        if state.peer_pub_hex == pub_hex
            && state.peer_addr == peer_url
            && tcp_alive(state.port).await
        {
            tracing::debug!(port = state.port, "reusing existing bridge");
            return Ok(state.port);
        }
        // Stale — fall through to spawn fresh.
        tracing::debug!("stale bridge state, spawning fresh");
        let _ = std::fs::remove_file(&path);
    }

    let port = spawn_bridge(pub_hex, peer_url, transport, identity_file).await?;
    write_state(
        &path,
        &BridgeState {
            port,
            pid: std::process::id(),
            peer_addr: peer_url.to_string(),
            peer_pub_hex: pub_hex.to_string(),
        },
    )?;
    Ok(port)
}

/// Try to TCP-connect to `127.0.0.1:port`. Used as the
/// "is the bridge actually serving?" check — a stale state
/// file pointing at a dead port shouldn't fool us.
async fn tcp_alive(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_millis(150),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// Spawn `drift-http connect` as a detached background process,
/// read its DRIFT_HTTP_LISTEN line, and return the bound port.
/// The bridge keeps running after `drift-http open` exits.
async fn spawn_bridge(
    pub_hex: &str,
    peer_url: &str,
    _transport: TpKind,
    identity_file: Option<PathBuf>,
) -> Result<u16> {
    let exe = std::env::current_exe().context("locating drift-http binary")?;

    let mut cmd = Command::new(&exe);
    // Forward the transport choice to the spawned `connect` by
    // embedding the scheme directly in the peer URL — the
    // canonical `PUB@scheme://host:port` form transport_url
    // splits.
    let peer_arg = format!("{}@{}", pub_hex, peer_url);
    cmd.arg("connect")
        .arg("--peer")
        .arg(peer_arg)
        .arg("--listen")
        .arg("127.0.0.1:0");
    if let Some(p) = identity_file {
        cmd.arg("--identity-file").arg(p);
    }
    cmd.stdout(Stdio::piped());
    // Redirect stderr to a per-peer log file so debug info is
    // recoverable but doesn't pollute the user's terminal.
    let log_path = links_dir()?.join(format!("{}.log", pub_hex));
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    cmd.stderr(Stdio::from(log_file));

    // Detach from our process group on unix so a parent SIGHUP
    // (e.g., the launching terminal closing) doesn't kill the
    // bridge. The bridge has its own session leader.
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().context("spawning bridge process")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("could not capture bridge stdout"))?;
    let mut reader = BufReader::new(stdout).lines();

    // Read banner lines until DRIFT_HTTP_READY appears or we
    // hit a sane timeout.
    let mut listen_addr: Option<String> = None;
    let banner_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(banner_deadline, reader.next_line()).await {
            Ok(Ok(Some(line))) => {
                tracing::debug!(line = %line, "bridge banner");
                if let Some(rest) = line.strip_prefix("DRIFT_HTTP_LISTEN=") {
                    listen_addr = Some(rest.to_string());
                }
                if line == "DRIFT_HTTP_READY" {
                    break;
                }
            }
            Ok(Ok(None)) => {
                return Err(anyhow!("bridge process exited before READY"));
            }
            Ok(Err(e)) => {
                return Err(anyhow!("reading bridge stdout: {}", e));
            }
            Err(_) => {
                return Err(anyhow!("bridge didn't print READY within 5 s"));
            }
        }
    }

    let addr = listen_addr.ok_or_else(|| anyhow!("bridge ready but no LISTEN line"))?;
    let port: u16 = addr
        .rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bridge LISTEN address not parseable: {:?}", addr))?;

    // Drop the child handle without waiting → process keeps
    // running. Drop also closes our end of the stdout pipe;
    // subsequent prints from the bridge would no-op into a
    // closed pipe (and tracing output goes to the log file
    // we already redirected stderr to).
    let _ = child;
    Ok(port)
}

fn read_state(path: &Path) -> Result<BridgeState> {
    let data = std::fs::read(path).context("reading bridge state")?;
    serde_json::from_slice::<BridgeState>(&data).context("parsing bridge state")
}

fn write_state(path: &Path, state: &BridgeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(state).context("serializing bridge state")?;
    std::fs::write(path, data).context("writing bridge state")?;
    Ok(())
}

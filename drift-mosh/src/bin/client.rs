//! drift-mosh-client — connects to a drift-mosh-server and
//! proxies the local terminal ↔ remote pty.
//!
//! Flow:
//! 1. Parse `--server-pub <hex>` and `--server-addr <ip:port>`.
//! 2. Bind a DRIFT transport on an ephemeral port.
//! 3. Open a stream to the server (this is the "pty" stream
//!    by convention — server accepts first stream as pty).
//! 4. Open a second stream: control channel.
//! 5. Put the local terminal into raw mode, capture stdin +
//!    SIGWINCH.
//! 6. Pipe bytes both ways until the user exits (Ctrl+D
//!    typically causes the remote shell to close the pty,
//!    which closes the stream, which exits).
//!
//! On exit we restore the terminal even if panicking, so the
//! user doesn't have to `stty sane` to get their shell back.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use drift_mosh::{Ctrl, PTY_CHUNK_SIZE};
use futures_util::StreamExt;
use signal_hook::consts::signal::SIGWINCH;
use signal_hook_tokio::Signals;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "drift-mosh-client", about = "Local side of drift-mosh")]
struct Cli {
    /// Hex-encoded 32-byte server public key (pinning value —
    /// lifted verbatim from the server's startup banner).
    #[clap(long)]
    server_pub: String,

    /// Server address in `ip:port` form (from the server's
    /// startup banner).
    #[clap(long)]
    server_addr: String,
}

/// RAII guard that puts the terminal into raw mode on
/// construction and restores cooked mode on drop. Key for
/// survival: if the client panics, Drop still runs and the
/// user doesn't lose their terminal.
struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("could not enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_mosh=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let pub_bytes = hex::decode(&cli.server_pub).context("--server-pub is not valid hex")?;
    if pub_bytes.len() != 32 {
        return Err(anyhow!("--server-pub must be 32 bytes, got {}", pub_bytes.len()));
    }
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&pub_bytes);
    let server_addr: SocketAddr = cli.server_addr.parse().context("--server-addr invalid")?;

    // Fresh identity every run — the server accepts any peer
    // so we don't need a persistent client key. Persistent keys
    // would matter for resumption; MVP doesn't need that yet.
    let identity = Identity::generate();

    let transport = Arc::new(
        Transport::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap(), identity)
            .await
            .context("DRIFT transport bind failed")?,
    );

    let server_peer = transport
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .context("add_peer failed")?;

    let mgr = StreamManager::bind(transport.clone()).await;

    // Open the two streams in the same order the server accepts.
    let pty_stream = Arc::new(
        mgr.open(server_peer)
            .await
            .context("opening pty stream failed")?,
    );
    let ctrl_stream = Arc::new(
        mgr.open(server_peer)
            .await
            .context("opening control stream failed")?,
    );

    // Send initial window size so the server's pty starts at
    // the right dimensions. Without this the shell launches
    // with the default 40x100 and full-screen programs draw
    // at the wrong size until the first resize.
    //
    // `size()` can return (0, 0) on some terminal setups
    // (notably when stdout was reopened or under certain
    // expect/screen wrappers). Treat zeros as "unknown" and
    // fall back to 80×24 — matches what most terminal apps
    // do when TIOCGWINSZ is unavailable.
    let (cols, rows) = match size() {
        Ok((c, r)) if c > 0 && r > 0 => (c, r),
        _ => (80, 24),
    };
    let initial_resize = bincode::serialize(&Ctrl::Resize { rows, cols })?;
    ctrl_stream.send(&initial_resize).await?;

    // Enter raw mode LAST so if anything above fails the user's
    // terminal is untouched.
    let _raw_guard = RawModeGuard::enter()?;

    // stdin → pty stream. stdin is a blocking fd; we use a
    // dedicated OS thread feeding a channel, same pattern as
    // the server's pty reader.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = vec![0u8; PTY_CHUNK_SIZE];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdin_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Server bytes → stdout. stdout is NOT in the pty stream
    // path — we use regular tokio stdout writes.
    let mut stdout = tokio::io::stdout();

    // Spawn all three concurrent loops.

    // A. stdin → pty_stream
    let pty_a = pty_stream.clone();
    let task_a = tokio::spawn(async move {
        while let Some(chunk) = stdin_rx.recv().await {
            if let Err(e) = pty_a.send(&chunk).await {
                tracing::warn!(error = ?e, "stdin→server send failed");
                break;
            }
        }
    });

    // B. pty_stream → stdout
    let pty_b = pty_stream.clone();
    let task_b = tokio::spawn(async move {
        loop {
            let chunk = match pty_b.recv().await {
                Some(c) => c,
                None => break,
            };
            if stdout.write_all(&chunk).await.is_err() {
                break;
            }
            if stdout.flush().await.is_err() {
                break;
            }
        }
    });

    // C. SIGWINCH → resize control messages
    let ctrl_c = ctrl_stream.clone();
    let mut signals = Signals::new([SIGWINCH]).context("registering SIGWINCH failed")?;
    let task_c = tokio::spawn(async move {
        while let Some(sig) = signals.next().await {
            if sig != SIGWINCH {
                continue;
            }
            let (cols, rows) = match size() {
                Ok((c, r)) if c > 0 && r > 0 => (c, r),
                _ => continue,
            };
            let msg = match bincode::serialize(&Ctrl::Resize { rows, cols }) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let _ = ctrl_c.send(&msg).await;
        }
    });

    // First loop to finish ends the session. Usually B
    // (pty → stdout) finishes first when the remote shell
    // exits.
    tokio::select! {
        _ = task_a => {}
        _ = task_b => {}
        _ = task_c => {}
    }

    // Best-effort polite goodbye. If the server's already gone
    // this silently fails — that's fine.
    let bye = bincode::serialize(&Ctrl::Bye).unwrap_or_default();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        ctrl_stream.send(&bye),
    )
    .await;

    // RawModeGuard's Drop restores the terminal here.
    Ok(())
}

// Silence the unused-import warnings — tokio's AsyncRead/Write
// traits are brought in for their method resolution on stdout.
#[allow(unused_imports)]
use {AsyncReadExt as _, AsyncWriteExt as _};

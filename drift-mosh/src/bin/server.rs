//! drift-mosh-server — spawns a shell in a PTY and exposes it
//! over a DRIFT stream session.
//!
//! Startup flow:
//! 1. Generate an identity (or load from `--identity-file`).
//! 2. Bind DRIFT on the configured address.
//! 3. Print `peer_id = ...`, `pub = ...`, `addr = ...` to
//!    stdout. A wrapper (or the user) pastes those into the
//!    client command line.
//! 4. Enable `accept_any_peer` so the first client that
//!    handshakes with the right pubkey gets in.
//! 5. Accept the first inbound stream: that's our pty stream.
//! 6. Wait for the second stream: control channel.
//! 7. Spawn a shell in a pty. Pipe pty ↔ DRIFT streams until
//!    either side closes.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Transport, TransportConfig};
use drift_mosh::{Ctrl, PTY_CHUNK_SIZE};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "drift-mosh-server", about = "Remote side of drift-mosh")]
struct Cli {
    /// UDP address to bind on. Use 0.0.0.0:0 for a kernel-
    /// assigned ephemeral port.
    #[clap(long, default_value = "0.0.0.0:0")]
    bind: String,

    /// Shell to spawn. Defaults to `$SHELL`, falling back to
    /// `/bin/sh`.
    #[clap(long)]
    shell: Option<String>,

    /// Identity file (32-byte secret, hex-encoded). If absent,
    /// generates a fresh identity on startup.
    #[clap(long)]
    identity_file: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_mosh=info".into()),
        )
        .with_writer(std::io::stderr) // keep stdout clean for startup banner
        .init();

    let cli = Cli::parse();

    let identity = match &cli.identity_file {
        Some(path) => {
            let hex_str = std::fs::read_to_string(path)
                .with_context(|| format!("reading identity from {}", path))?;
            let bytes = hex::decode(hex_str.trim())
                .with_context(|| "identity file is not valid hex")?;
            if bytes.len() != 32 {
                return Err(anyhow!("identity must be exactly 32 bytes, got {}", bytes.len()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Identity::from_secret_bytes(seed)
        }
        None => Identity::generate(),
    };

    let pub_hex: String = identity.public_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    let peer_id_hex: String = identity.peer_id().iter().map(|b| format!("{:02x}", b)).collect();

    // accept_any_peer: the server has no pre-shared list of
    // clients. Whoever handshakes with this server's pubkey
    // gets through. Clients authenticate the server by pinning
    // its pubkey in their connect argv.
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    let bind_addr: SocketAddr = cli.bind.parse().context("invalid --bind address")?;
    let transport = Arc::new(
        Transport::bind_with_config(bind_addr, identity, cfg)
            .await
            .context("DRIFT transport bind failed")?,
    );
    let local_addr = transport.local_addr()?;

    // Print the handshake info to stdout. The client uses these
    // two fields (pub + addr) to connect. We keep the format
    // stable so a wrapper script can parse it.
    println!("drift-mosh-server ready");
    println!("pub = {}", pub_hex);
    println!("peer_id = {}", peer_id_hex);
    println!("addr = {}", local_addr);
    println!("(paste into client: --server-pub {} --server-addr {})", pub_hex, local_addr);
    // Flush so the client doesn't hit a stdout buffer when
    // we're launched under SSH.
    use std::io::Write;
    std::io::stdout().flush().ok();

    // Stream manager on top of the transport.
    let mgr = StreamManager::bind(transport.clone()).await;

    // Accept two streams from the client: first = pty, second
    // = control. The order is a convention both sides agree
    // on; no in-band negotiation needed.
    let pty_stream = mgr
        .accept()
        .await
        .ok_or_else(|| anyhow!("stream manager closed before accepting pty stream"))?;
    tracing::info!("pty stream accepted");

    let ctrl_stream = mgr
        .accept()
        .await
        .ok_or_else(|| anyhow!("stream manager closed before accepting control stream"))?;
    tracing::info!("control stream accepted");

    // Spawn the shell in a pty. portable-pty gives us the
    // master handle + a Child we need to keep alive.
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("openpty failed")?;

    let shell = cli
        .shell
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".into());
    let mut cmd = CommandBuilder::new(&shell);
    // Run the shell as a login shell — gives the user a fresh
    // environment, same as SSH's default.
    cmd.env("TERM", "xterm-256color");
    let _child = pair.slave.spawn_command(cmd).context("failed to spawn shell")?;
    drop(pair.slave);
    tracing::info!(shell = %shell, "spawned shell in pty");

    let pty_master = pair.master;

    // portable-pty gives us a blocking Read + Write. We wrap
    // them in tokio's `spawn_blocking` for reads and shuttle
    // bytes through channels. This is the least-bad way to
    // mix blocking fd I/O with a tokio app.
    let pty_reader = pty_master.try_clone_reader().context("clone pty reader")?;
    let mut pty_writer = pty_master.take_writer().context("take pty writer")?;

    // pty → tokio: blocking read thread feeds an unbounded
    // channel.
    let (pty_tx, mut pty_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut reader = pty_reader;
        let mut buf = vec![0u8; PTY_CHUNK_SIZE];
        loop {
            use std::io::Read;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "pty read error");
                    break;
                }
            }
        }
        tracing::info!("pty reader thread exiting");
    });

    // pty_tx is now held only by the thread above; when it
    // drops (on EOF), pty_rx.recv() returns None.

    // Three concurrent tasks:
    //   A. Read pty_rx, write to pty_stream (server → client).
    //   B. Read pty_stream, write to pty (client → server).
    //   C. Read ctrl_stream, handle Ctrl messages (resize, bye).
    let pty_stream = Arc::new(pty_stream);

    // A: pty → client
    let pty_stream_a = pty_stream.clone();
    let task_a = tokio::spawn(async move {
        while let Some(chunk) = pty_rx.recv().await {
            if let Err(e) = pty_stream_a.send(&chunk).await {
                tracing::warn!(error = ?e, "pty→client send failed; exiting");
                break;
            }
        }
        tracing::info!("pty→client task done");
    });

    // B: client → pty (blocking writes go through spawn_blocking).
    let pty_stream_b = pty_stream.clone();
    let task_b = tokio::spawn(async move {
        loop {
            let chunk = match pty_stream_b.recv().await {
                Some(c) => c,
                None => break,
            };
            let writer = &mut pty_writer;
            let res = tokio::task::block_in_place(|| {
                use std::io::Write;
                writer.write_all(&chunk).and_then(|_| writer.flush())
            });
            if let Err(e) = res {
                tracing::warn!(error = %e, "pty write failed; exiting");
                break;
            }
        }
        tracing::info!("client→pty task done");
    });

    // C: control messages
    let ctrl_stream_c = Arc::new(ctrl_stream);
    let pty_master_resize = pty_master;
    let task_c = tokio::spawn(async move {
        loop {
            let msg = match ctrl_stream_c.recv().await {
                Some(m) => m,
                None => break,
            };
            let ctrl: Ctrl = match bincode::deserialize(&msg) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "bad control message; ignoring");
                    continue;
                }
            };
            match ctrl {
                Ctrl::Resize { rows, cols } => {
                    if let Err(e) = pty_master_resize.resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    }) {
                        tracing::warn!(error = %e, "pty resize failed");
                    } else {
                        tracing::info!(rows, cols, "pty resized");
                    }
                }
                Ctrl::Bye => {
                    tracing::info!("client sent Bye, exiting");
                    break;
                }
            }
        }
        tracing::info!("ctrl task done");
    });

    // Wait for any of the three to finish — the session's over.
    tokio::select! {
        _ = task_a => {}
        _ = task_b => {}
        _ = task_c => {}
    }
    tracing::info!("server shutting down");
    // `_child` dropped here → shell process cleaned up by
    // portable-pty's Drop impl.
    Ok(())
}

// Squash the warning: tokio's `AsyncReadExt` / `AsyncWriteExt`
// aren't used here but imported-for-consistency elsewhere.
#[allow(dead_code)]
fn _type_aliases() -> (tokio::io::Stdin, tokio::io::Stdout) {
    unreachable!()
}
// Silence the unused-import warning in a stable way.
#[allow(unused_imports)]
use {AsyncReadExt as _, AsyncWriteExt as _};

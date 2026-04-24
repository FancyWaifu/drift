//! drift-mosh-server: mobile-shell remote endpoint on DRIFT.
//!
//! Session lifecycle:
//! 1. Bind DRIFT, print the startup banner to stdout so the
//!    `drift-mosh` launcher (or a human) can hand the pubkey
//!    and address to the client.
//! 2. Loop accepting stream pairs from clients. Each client
//!    opens two streams in order: pty-stream (raw bytes both
//!    ways), then ctrl-stream (bincode-encoded `Ctrl` msgs).
//! 3. On the control stream, receive `Ctrl::Attach { session_id }`.
//!    Look up the session by the client's `peer_id` (stable
//!    across reconnects because it's a BLAKE2b-truncated hash
//!    of the client's pubkey — the whole identity-first idea).
//!    * If we have that session AND the supplied id matches
//!      what we minted for this peer: reattach — re-wire streams,
//!      reply with scrollback.
//!    * Otherwise: mint a fresh session, spawn a shell.
//! 4. Pipe pty ↔ streams until the client disconnects.
//! 5. When the client disconnects, mark the session detached
//!    but keep the pty alive. A background sweep evicts
//!    sessions that stay detached past `keepalive_secs`.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use drift::identity::Identity;
use drift::streams::{Stream, StreamManager};
use drift::{Transport, TransportConfig};
use drift_mosh::{BannerLine, Config, Ctrl, Scrollback, PTY_CHUNK_SIZE, SCROLLBACK_BYTES};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

type PeerId = [u8; 8];
type SessionId = [u8; 16];

#[derive(Parser)]
#[command(name = "drift-mosh-server", about = "Remote side of drift-mosh")]
struct Cli {
    #[clap(long)]
    bind: Option<String>,

    #[clap(long)]
    shell: Option<String>,

    #[clap(long)]
    identity_file: Option<String>,

    #[clap(long)]
    keepalive_secs: Option<u64>,
}

/// One attached shell session. `last_detached = None` means a
/// client is actively connected; `Some(t)` means they left at
/// time `t` and we're waiting for them to come back.
struct Session {
    id: SessionId,
    /// Kept alive so portable-pty's Drop doesn't kill the shell.
    /// `Option` so we can `.take()` it when evicting.
    pty_master: Option<Box<dyn MasterPty + Send>>,
    /// Bytes written BY the pty (pty → client). Session
    /// workers drain this; when no client is attached, an
    /// unattended-drain task routes the bytes into scrollback.
    pty_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// Keystrokes the CURRENT attached client wants to send
    /// to the shell. Rewired on reattach.
    pty_tx: mpsc::UnboundedSender<Vec<u8>>,
    scrollback: Arc<Mutex<Scrollback>>,
    last_detached: Option<Instant>,
    /// Bumped when the client detaches, so the "unattended
    /// drain" task knows to absorb bytes into scrollback
    /// until a new client attaches.
    attached: Arc<std::sync::atomic::AtomicBool>,
    /// Cancel handle for the currently-attached session_worker,
    /// if one is running. When a new client (re)connects with
    /// the same peer_id, we fire this so the old worker tears
    /// down promptly — otherwise we'd race with the stale
    /// worker still holding the pty master.
    worker_cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    let config = Config::load().unwrap_or_default();
    let keepalive_secs = cli.keepalive_secs.unwrap_or(config.keepalive_secs);
    let bind_addr: String = cli.bind.unwrap_or(config.bind_addr);
    let shell = cli
        .shell
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".into());

    let identity = load_identity(cli.identity_file.as_deref())?;
    let pub_bytes = identity.public_bytes();
    let pub_hex: String = pub_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let peer_id_hex: String =
        identity.peer_id().iter().map(|b| format!("{:02x}", b)).collect();

    let tcfg = TransportConfig {
        // Auth model: client pins our pubkey (--server-pub).
        // Server accepts any client that successfully
        // handshakes.
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let bind_sock: SocketAddr = bind_addr.parse().context("invalid --bind address")?;
    let transport = Arc::new(
        Transport::bind_with_config(bind_sock, identity, tcfg)
            .await
            .context("DRIFT transport bind failed")?,
    );
    let local_addr = transport.local_addr()?;

    // Banner: one key=value per line, parseable by the
    // `drift-mosh` launcher.
    println!("{}{}", BannerLine::Pub.prefix(), pub_hex);
    println!("{}{}", BannerLine::PeerId.prefix(), peer_id_hex);
    println!("{}{}", BannerLine::Addr.prefix(), local_addr);
    println!("{}", BannerLine::Ready.prefix());
    use std::io::Write;
    std::io::stdout().flush().ok();
    tracing::info!(addr = %local_addr, keepalive_secs, "drift-mosh-server ready");

    let mgr = StreamManager::bind(transport.clone()).await;

    let sessions: Arc<Mutex<HashMap<PeerId, Session>>> = Arc::new(Mutex::new(HashMap::new()));

    // Background sweep: evict sessions left idle past
    // keepalive_secs.
    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let mut map = sessions.lock().await;
                let before = map.len();
                map.retain(|peer, s| match s.last_detached {
                    Some(t) if now.duration_since(t) >= Duration::from_secs(keepalive_secs) => {
                        tracing::info!(
                            peer = ?peer,
                            "evicting session after {}s idle",
                            keepalive_secs
                        );
                        false
                    }
                    _ => true,
                });
                if before != map.len() {
                    tracing::info!("session count: {} → {}", before, map.len());
                }
            }
        });
    }

    // Accept stream pairs. Each connecting client opens two
    // in order (pty, then ctrl). We dispatch to session_worker.
    loop {
        let pty_stream = match mgr.accept().await {
            Some(s) => s,
            None => {
                tracing::info!("stream manager closed; exiting accept loop");
                break;
            }
        };
        let ctrl_stream = match mgr.accept().await {
            Some(s) => s,
            None => break,
        };
        let peer_id = pty_stream.peer();
        tracing::info!(peer = ?peer_id, "new stream pair");

        let sessions = sessions.clone();
        let shell = shell.clone();
        tokio::spawn(async move {
            if let Err(e) = session_worker(sessions, peer_id, pty_stream, ctrl_stream, &shell).await
            {
                tracing::warn!(error = ?e, peer = ?peer_id, "session worker exited with error");
            }
        });
    }

    Ok(())
}

async fn session_worker(
    sessions: Arc<Mutex<HashMap<PeerId, Session>>>,
    peer_id: PeerId,
    pty_stream: Stream,
    ctrl_stream: Stream,
    shell: &str,
) -> Result<()> {
    // ── Step 1: receive the client's Attach message. ──
    //
    // It's the first message on the control stream. Client
    // sends a random session_id on a fresh session, or the
    // previously-remembered session_id on reconnect.
    let first = ctrl_stream
        .recv()
        .await
        .ok_or_else(|| anyhow!("client hung up before sending Attach"))?;
    let attach: Ctrl =
        bincode::deserialize(&first).context("first control msg isn't a valid Ctrl")?;
    let client_session_id = match attach {
        Ctrl::Attach { session_id } => session_id,
        other => return Err(anyhow!("expected Attach, got {:?}", other)),
    };

    // ── Step 2: is it a reattach? ──
    //
    // Take the session out of the map (so we own it). If an
    // older worker for this peer_id is still running on stale
    // streams (e.g. the client died rudely and DRIFT hasn't
    // timed out yet), fire its cancel so it releases the
    // session promptly.
    let mut reattaching = false;
    let taken: Option<Session> = {
        let mut map = sessions.lock().await;
        map.remove(&peer_id).map(|mut s| {
            // Fire the old worker's cancel (if any) so it
            // releases the session promptly instead of waiting
            // for its (possibly dead) streams to notice.
            if let Some(cancel) = s.worker_cancel.take() {
                let _ = cancel.send(());
            }
            s
        })
    };
    // If we evicted an old session, wait briefly for its
    // worker to release the pty master before proceeding.
    // The resize-task-owned master needs to return to
    // `session.pty_master` before we can use it.
    let mut existing = if let Some(s) = taken {
        // Poll up to ~500 ms for the master to be returned.
        for _ in 0..50 {
            if s.pty_master.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if s.pty_master.is_none() {
            tracing::warn!(peer = ?peer_id, "old worker didn't release pty master; restarting");
            None
        } else if s.id == client_session_id {
            tracing::info!(peer = ?peer_id, "reattaching existing session");
            reattaching = true;
            Some(s)
        } else {
            tracing::info!(peer = ?peer_id, "session_id mismatch — starting fresh");
            drop(s);
            None
        }
    } else {
        None
    };
    let mut session = match existing.take() {
        Some(s) => s,
        None => build_session(shell).context("failed to spawn shell")?,
    };

    // Mark it attached BEFORE we send AttachAck so no bytes
    // race into scrollback while the client is listening.
    session
        .attached
        .store(true, std::sync::atomic::Ordering::Release);
    session.last_detached = None;

    // ── Step 3: send AttachAck with scrollback. ──
    let scrollback_bytes = {
        let s = session.scrollback.lock().await;
        s.replay()
    };
    let ack = Ctrl::AttachAck {
        session_id: session.id,
        reattach_ok: reattaching,
        scrollback: scrollback_bytes,
    };
    let ack_bytes = bincode::serialize(&ack)?;
    ctrl_stream.send(&ack_bytes).await?;

    // Install our worker's cancel handle so a future reconnect
    // can evict us. Do this AFTER sending AttachAck so the
    // client's reattach request is definitively live.
    let (worker_cancel_tx, worker_cancel_rx) = tokio::sync::oneshot::channel::<()>();
    session.worker_cancel = Some(worker_cancel_tx);

    // ── Step 4: run the live pipes until client detaches. ──
    //
    // Three concurrent tasks, same shape as the MVP:
    //   A. pty → client  (pty_rx → pty_stream.send)
    //   B. client → pty  (pty_stream.recv → pty_tx)
    //   C. control       (ctrl_stream.recv → Ctrl handling)
    //
    // Any one of them finishing ends the live session; we
    // detach rather than kill so the client can come back.
    let pty_stream = Arc::new(pty_stream);
    let ctrl_stream = Arc::new(ctrl_stream);

    let (detach_tx, mut detach_rx) = mpsc::unbounded_channel::<&'static str>();

    // A: pty → client
    let pty_rx = session.pty_rx.clone();
    let scrollback_a = session.scrollback.clone();
    let pty_stream_a = pty_stream.clone();
    let detach_a = detach_tx.clone();
    let attached_a = session.attached.clone();
    let task_a = tokio::spawn(async move {
        loop {
            let chunk_opt = {
                let mut rx = pty_rx.lock().await;
                rx.recv().await
            };
            let chunk = match chunk_opt {
                Some(c) => c,
                None => {
                    let _ = detach_a.send("pty_eof");
                    break;
                }
            };
            // Always scrollback-buffer, even when attached,
            // so reattaches after transient disconnects have
            // fresh context.
            {
                let mut sb = scrollback_a.lock().await;
                sb.push(&chunk);
            }
            if !attached_a.load(std::sync::atomic::Ordering::Acquire) {
                continue;
            }
            if let Err(e) = pty_stream_a.send(&chunk).await {
                tracing::debug!(error = ?e, "pty→client send failed; detaching");
                let _ = detach_a.send("send_fail");
                break;
            }
        }
    });

    // B: client → pty
    let pty_tx = session.pty_tx.clone();
    let pty_stream_b = pty_stream.clone();
    let detach_b = detach_tx.clone();
    let task_b = tokio::spawn(async move {
        loop {
            match pty_stream_b.recv().await {
                Some(chunk) => {
                    if pty_tx.send(chunk).is_err() {
                        let _ = detach_b.send("pty_writer_closed");
                        break;
                    }
                }
                None => {
                    let _ = detach_b.send("pty_stream_recv_none");
                    break;
                }
            }
        }
    });

    // C: control — resize + bye
    let ctrl_stream_c = ctrl_stream.clone();
    // We need the master pty for .resize(); stash a clone-ish
    // handle. portable-pty doesn't let us clone master, but
    // we hold the box in `session.pty_master` and access via
    // the session. We'll keep the session locked via a
    // dedicated resize channel instead.
    let (resize_tx, mut resize_rx) = mpsc::unbounded_channel::<(u16, u16)>();
    let detach_c = detach_tx.clone();
    let task_c = tokio::spawn(async move {
        loop {
            match ctrl_stream_c.recv().await {
                Some(bytes) => {
                    let msg: Ctrl = match bincode::deserialize(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    match msg {
                        Ctrl::Resize { rows, cols } => {
                            let _ = resize_tx.send((rows, cols));
                        }
                        Ctrl::Bye => {
                            let _ = detach_c.send("bye");
                            break;
                        }
                        _ => {} // ignore re-Attaches, unknown variants
                    }
                }
                None => {
                    let _ = detach_c.send("ctrl_recv_none");
                    break;
                }
            }
        }
    });

    // Resize applier: owns the pty master. When the select!
    // below fires, this task is dropped — pty master goes
    // back into the session via the return path below.
    let pty_master_for_resize = session
        .pty_master
        .take()
        .expect("session always has master");
    let (resize_cancel_tx, mut resize_cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let resize_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some((rows, cols)) = resize_rx.recv() => {
                    if let Err(e) = pty_master_for_resize.resize(PtySize {
                        rows, cols, pixel_width: 0, pixel_height: 0,
                    }) {
                        tracing::warn!(error = %e, "pty resize failed");
                    }
                }
                _ = &mut resize_cancel_rx => break,
            }
        }
        pty_master_for_resize  // returned so main can store it back
    });

    // Wait for any reason to detach — either a live task
    // finished (stream eof, ctrl Bye, etc.) or a new worker
    // fired the cancel.
    let reason = tokio::select! {
        r = detach_rx.recv() => r.unwrap_or("channel_closed"),
        _ = worker_cancel_rx => "evicted_by_new_worker",
    };
    tracing::info!(peer = ?peer_id, reason, "client detaching");

    // Tear down the live tasks; session state persists.
    task_a.abort();
    task_b.abort();
    task_c.abort();
    let _ = resize_cancel_tx.send(());
    let master_back = resize_task.await.ok();

    session.attached.store(false, std::sync::atomic::Ordering::Release);
    session.last_detached = Some(Instant::now());
    if let Some(m) = master_back {
        session.pty_master = Some(m);
    }

    // Re-insert the session into the map so a reattach can
    // find it.
    sessions.lock().await.insert(peer_id, session);
    Ok(())
}

/// Spawn a fresh shell in a pty, set up the pty↔channel
/// bridges, return the Session handle.
fn build_session(shell: &str) -> Result<Session> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("openpty")?;

    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    let _child = pair.slave.spawn_command(cmd).context("spawn shell")?;
    // Drop the slave side — we only need the master handle.
    drop(pair.slave);
    // Leak the Child into the thread that owns the pty reader
    // so it doesn't get reaped until the shell exits naturally.
    std::mem::forget(_child);

    let reader = pair.master.try_clone_reader().context("clone pty reader")?;
    let writer = pair.master.take_writer().context("take pty writer")?;

    // pty → channel (blocking read in dedicated thread)
    let (pty_to_client_tx, pty_to_client_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let _reader_handle = std::thread::spawn(move || {
        let mut reader = reader;
        let mut buf = vec![0u8; PTY_CHUNK_SIZE];
        loop {
            use std::io::Read;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_to_client_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // channel → pty (blocking writes via blocking thread)
    let (keystroke_tx, mut keystroke_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut writer = writer;
        use std::io::Write;
        // Block-read from the tokio channel via its blocking
        // handle. We're not inside a tokio runtime here so
        // we use `blocking_recv` which is designed for exactly
        // this fd-bridging pattern.
        while let Some(chunk) = keystroke_rx.blocking_recv() {
            if writer.write_all(&chunk).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let mut session_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut session_id);

    Ok(Session {
        id: session_id,
        pty_master: Some(pair.master),
        pty_rx: Arc::new(Mutex::new(pty_to_client_rx)),
        pty_tx: keystroke_tx,
        scrollback: Arc::new(Mutex::new(Scrollback::new(SCROLLBACK_BYTES))),
        last_detached: None,
        attached: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        worker_cancel: None,
    })
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_mosh=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
}

fn load_identity(file: Option<&str>) -> Result<Identity> {
    match file {
        Some(path) => {
            let hex_str = std::fs::read_to_string(path)
                .with_context(|| format!("reading identity {}", path))?;
            let bytes = hex::decode(hex_str.trim())
                .context("identity file is not hex")?;
            if bytes.len() != 32 {
                return Err(anyhow!("identity must be 32 bytes, got {}", bytes.len()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Identity::from_secret_bytes(seed))
        }
        None => {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            Ok(Identity::from_secret_bytes(seed))
        }
    }
}

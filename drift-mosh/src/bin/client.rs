//! drift-mosh-client — local end of a drift-mosh session.
//!
//! Lifecycle:
//! 1. Load (or create) the persistent client identity from
//!    `$CONFIG_DIR/drift-mosh/client.key`. Persistent so the
//!    server recognizes us across reconnects.
//! 2. Bind DRIFT, open pty + ctrl streams to the server.
//! 3. Send `Ctrl::Attach { session_id }`. Session id comes
//!    from `--session-id` (written by a previous successful
//!    connect) or all-zeros for a fresh session.
//! 4. Wait for `Ctrl::AttachAck`. Replay scrollback bytes to
//!    stdout before entering raw mode — the screen "wakes up"
//!    showing exactly what the user left. Print the
//!    session_id from the ack to stdout so a wrapper script
//!    can save it for next time.
//! 5. Raw mode + stream loops until the remote side closes.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use drift_mosh::{ClientKey, Ctrl, PTY_CHUNK_SIZE};
use futures_util::StreamExt;
use signal_hook::consts::signal::SIGWINCH;
use signal_hook_tokio::Signals;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Parser)]
#[command(name = "drift-mosh-client", about = "Local side of drift-mosh")]
struct Cli {
    /// Server pubkey (hex). Optional if `--server-addr` is a
    /// petname registered in the local contacts file — the
    /// launcher resolves the name to pubkey + addr together.
    #[clap(long)]
    server_pub: Option<String>,

    /// Either a petname registered in `~/.config/drift/contacts.toml`
    /// (e.g. `bob-laptop`) or a `host:port` / scheme-prefixed
    /// address. Petnames take priority: if a contact matches,
    /// its pubkey + address are used.
    #[clap(long)]
    server_addr: String,

    /// Hex-encoded 16-byte session id from a previous connect.
    /// Omit for a fresh session. The `drift-mosh` launcher
    /// manages this automatically via the sessions file.
    #[clap(long)]
    session_id: Option<String>,

    /// Path to the client identity file. Defaults to
    /// `$CONFIG_DIR/drift-mosh/client.key`; the launcher lets
    /// the default work out-of-the-box.
    #[clap(long)]
    identity_file: Option<String>,

    /// Local address to bind. Default `0.0.0.0:0` (any
    /// interface, ephemeral port). Useful for testing across
    /// multiple loopback addresses or pinning a specific NIC.
    #[clap(long, default_value = "0.0.0.0:0")]
    bind: String,
}

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

    if let Err(e) = run().await {
        // Make errors readable. anyhow's chain prints nicely
        // with `:#` — gives cause context.
        eprintln!("drift-mosh: {:#}", e);
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let session_id = parse_session_id(cli.session_id.as_deref())?;

    // Resolve `--server-addr`: it can be either a petname
    // saved in `$CONFIG_DIR/drift/contacts.toml` (e.g.
    // `bob-laptop`) or a literal `host:port` / scheme-
    // prefixed URL. Petnames take priority — if the user
    // typed `bob-laptop` and a contact exists, use that
    // contact's pubkey + addr regardless of whether
    // `--server-pub` was passed.
    let (server_pub, server_addr_with_scheme) =
        resolve_target(&cli.server_addr, cli.server_pub.as_deref())?;

    // Identity: either explicit --identity-file, or the
    // persistent default at $CONFIG_DIR/drift-mosh/client.key.
    let identity = match &cli.identity_file {
        Some(p) => load_identity_from_file(p)?,
        None => ClientKey::load_or_create()
            .context("loading or creating persistent client identity")?,
    };

    // `--bind` is an unused legacy flag retained for old scripts.
    let _ = &cli.bind;
    let (transport, server_addr) =
        Transport::connect_url(&server_addr_with_scheme, identity, TransportConfig::default())
            .await
            .with_context(|| format!("connecting to {}", server_addr_with_scheme))?;
    let transport = Arc::new(transport);

    let server_peer = transport
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .context("failed to register server peer (is the address right?)")?;

    let mgr = StreamManager::bind(transport.clone()).await;

    // Server accepts streams in order: pty first, ctrl second.
    // Open in the same order. Use generous timeouts — the
    // first open needs the handshake to complete, which can
    // take ~1 RTT + crypto.
    let pty_stream = Arc::new(
        tokio::time::timeout(std::time::Duration::from_secs(10), mgr.open(server_peer))
            .await
            .map_err(|_| anyhow!("server didn't respond within 10 s — is --server-addr reachable?"))?
            .context("opening pty stream")?,
    );
    let ctrl_stream = Arc::new(
        tokio::time::timeout(std::time::Duration::from_secs(5), mgr.open(server_peer))
            .await
            .map_err(|_| anyhow!("couldn't open control stream"))?
            .context("opening control stream")?,
    );

    // Attach handshake. We include our self-name (loaded from
    // the shared `~/.config/drift/self-name`) so the server
    // can record us in its contacts file under that petname.
    // Hearsay only — the server still authenticates us by
    // pubkey via DRIFT.
    let our_name = drift::contacts::self_name::load().ok().flatten();
    let attach = Ctrl::Attach {
        session_id,
        name: our_name,
    };
    ctrl_stream.send(&bincode::serialize(&attach)?).await?;

    let ack_bytes = tokio::time::timeout(std::time::Duration::from_secs(5), ctrl_stream.recv())
        .await
        .map_err(|_| anyhow!("no AttachAck from server within 5 s"))?
        .ok_or_else(|| anyhow!("server closed control stream before AttachAck"))?;
    let ack: Ctrl = bincode::deserialize(&ack_bytes).context("decoding AttachAck")?;
    let (got_session_id, reattach_ok, scrollback, server_name) = match ack {
        Ctrl::AttachAck {
            session_id,
            reattach_ok,
            scrollback,
            name,
        } => (session_id, reattach_ok, scrollback, name),
        other => return Err(anyhow!("unexpected first reply from server: {:?}", other)),
    };

    // Auto-record the server in our local contacts under the
    // petname it advertised (or `peer-<pubkey-prefix>` if it
    // didn't advertise one). Best-effort: contacts I/O failure
    // never breaks the session.
    if let Ok(mut book) = drift::contacts::Contacts::load_default() {
        if book
            .record(server_pub, server_addr, server_name.as_deref())
            .is_ok()
        {
            let _ = book.save();
        }
    }

    // Machine-parseable line on stdout so the launcher can
    // persist the session id. Written BEFORE raw mode so it
    // shows up on a proper line.
    let sid_hex: String = got_session_id.iter().map(|b| format!("{:02x}", b)).collect();
    println!("DRIFT_MOSH_SESSION_ID={}", sid_hex);
    if reattach_ok {
        println!("DRIFT_MOSH_REATTACH=yes");
    }
    use std::io::Write;
    std::io::stdout().flush().ok();

    // Initial window size → server.
    let (cols, rows) = match size() {
        Ok((c, r)) if c > 0 && r > 0 => (c, r),
        _ => (80, 24),
    };
    ctrl_stream
        .send(&bincode::serialize(&Ctrl::Resize { rows, cols })?)
        .await?;

    // Enter raw mode last, so any error above leaves the
    // terminal in cooked mode.
    let _raw = RawModeGuard::enter()?;

    // Replay scrollback bytes to stdout so the user sees
    // their previous screen content on reattach.
    if !scrollback.is_empty() {
        let mut out = tokio::io::stdout();
        out.write_all(&scrollback).await?;
        out.flush().await?;
    }

    // Three live loops.
    // A. stdin → pty_stream (keystrokes)
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

    let pty_a = pty_stream.clone();
    let task_a = tokio::spawn(async move {
        while let Some(chunk) = stdin_rx.recv().await {
            if pty_a.send(&chunk).await.is_err() {
                break;
            }
        }
    });

    // B. pty_stream → stdout (shell output)
    //
    // Coalesce: when the server emits a flurry of small chunks
    // (very common during prompt redraws / escape sequences),
    // the old code did one write+flush per chunk — many syscalls
    // and a perceptible stutter on each redraw. Instead, after
    // the first chunk arrives, opportunistically drain anything
    // already queued, concatenate, write once, flush once. This
    // changes nothing semantically (DRIFT already delivers in
    // order on a stream) but cuts the syscall count to roughly
    // one per server burst rather than one per chunk.
    let pty_b = pty_stream.clone();
    let task_b = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut batch: Vec<u8> = Vec::with_capacity(PTY_CHUNK_SIZE * 4);
        loop {
            let first = match pty_b.recv().await {
                Some(c) => c,
                None => break,
            };
            batch.clear();
            batch.extend_from_slice(&first);
            // Soak up everything else that's already ready
            // without ever blocking. The Stream::try_recv path
            // returns immediately when the queue is empty, so we
            // exit the inner loop and write what we have.
            while let Some(more) = pty_b.try_recv().await {
                batch.extend_from_slice(&more);
                if batch.len() >= PTY_CHUNK_SIZE * 16 {
                    // Hard cap so a runaway server can't make us
                    // hold off rendering forever during a flood.
                    break;
                }
            }
            if stdout.write_all(&batch).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    // C. SIGWINCH → Ctrl::Resize on ctrl_stream
    let ctrl_c = ctrl_stream.clone();
    let mut signals = Signals::new([SIGWINCH]).context("registering SIGWINCH")?;
    let task_c = tokio::spawn(async move {
        while let Some(_sig) = signals.next().await {
            let (cols, rows) = match size() {
                Ok((c, r)) if c > 0 && r > 0 => (c, r),
                _ => continue,
            };
            if let Ok(bytes) = bincode::serialize(&Ctrl::Resize { rows, cols }) {
                let _ = ctrl_c.send(&bytes).await;
            }
        }
    });

    // First one done ends the session.
    tokio::select! {
        _ = task_a => {}
        _ = task_b => {}
        _ = task_c => {}
    }

    // Polite goodbye so the server knows we're leaving
    // voluntarily (and records last_detached, etc).
    if let Ok(bytes) = bincode::serialize(&Ctrl::Bye) {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            ctrl_stream.send(&bytes),
        )
        .await;
    }

    Ok(())
}

fn parse_server_pub(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim())
        .with_context(|| format!("--server-pub {:?} isn't valid hex", hex_str))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "--server-pub must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Resolve `--server-addr` into (pubkey, connect-URL).
///
/// Priority:
///   1. If `--server-addr` matches a contact in
///      `~/.config/drift/contacts.toml`, use that contact's
///      pubkey + saved address. `--server-pub` is ignored.
///   2. Otherwise treat `--server-addr` as a literal address
///      (bare `host:port` or scheme-prefixed) and require
///      `--server-pub` for the pubkey.
fn resolve_target(server_addr_arg: &str, server_pub_arg: Option<&str>) -> Result<([u8; 32], String)> {
    if let Ok(book) = drift::contacts::Contacts::load_default() {
        if let Some(contact) = book.resolve(server_addr_arg) {
            let pub_bytes = drift::contacts::parse_pubkey_hex(&contact.pubkey)?;
            // Saved address — fall back to udp:// if it lacks
            // a scheme (older entries from before multi-
            // transport support).
            let url = if contact.address.contains("://") {
                contact.address.clone()
            } else {
                format!("udp://{}", contact.address)
            };
            return Ok((pub_bytes, url));
        }
    }
    let pub_str = server_pub_arg.ok_or_else(|| {
        anyhow!(
            "--server-pub is required when --server-addr is a literal address \
             (no contact named {:?} found in {})",
            server_addr_arg,
            drift::contacts::Contacts::default_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<no config dir>".into())
        )
    })?;
    let pub_bytes = parse_server_pub(pub_str)?;
    let url = if server_addr_arg.contains("://") {
        server_addr_arg.to_string()
    } else {
        format!("udp://{}", server_addr_arg)
    };
    Ok((pub_bytes, url))
}

fn parse_session_id(opt: Option<&str>) -> Result<[u8; 16]> {
    let hex_str = match opt {
        None => return Ok([0u8; 16]),
        Some(s) => s.trim(),
    };
    if hex_str.is_empty() {
        return Ok([0u8; 16]);
    }
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("--session-id {:?} isn't valid hex", hex_str))?;
    if bytes.len() != 16 {
        return Err(anyhow!(
            "--session-id must be 16 bytes (32 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_identity_from_file(path: &str) -> Result<Identity> {
    let hex_str = std::fs::read_to_string(path)
        .with_context(|| format!("reading identity from {}", path))?;
    let bytes = hex::decode(hex_str.trim())
        .context("identity file isn't valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("identity must be 32 bytes; got {}", bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Identity::from_secret_bytes(seed))
}

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

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use drift_mosh::{ClientKey, Ctrl, PTY_CHUNK_SIZE};
use futures_util::StreamExt;
use rand::RngCore;
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
    ///
    /// Optional: when omitted, the server's pubkey is looked up
    /// in drift.toml; the entry's `endpoints` provide the dial
    /// address, or `via_bridge` provides a federation route.
    #[clap(long)]
    server_addr: Option<String>,

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

    /// Reach the server via a federated bridge instead of a
    /// direct UDP/TCP/WS connection. Format:
    /// `<url>@<bridge-pubkey-hex>`. When set:
    ///   * `--server-addr` is ignored for connection (we
    ///     connect to the bridge instead).
    ///   * `--target-bridge` must also be set — that's the
    ///     pubkey of the bridge the SERVER is connected to.
    ///   * `--server-pub` is still required (the server's
    ///     identity pubkey, used for end-to-end addressing).
    #[clap(long)]
    bridge: Option<String>,

    /// Pubkey of the bridge the server is connected to.
    /// Required when `--bridge` is set; ignored otherwise.
    #[clap(long)]
    target_bridge: Option<String>,

    /// Look the server up by its drift.toml `[hosts.<name>]`
    /// entry. Resolves both the pubkey and the route
    /// (`endpoints` for direct dial, `via_bridge` for federated
    /// dial) in one go. Lets you replace the
    /// `--server-pub <hex> --bridge <url>@<hex>
    /// --target-bridge <hex>` triplet with a single short name.
    ///
    /// Mutually exclusive with `--server-pub`, `--server-addr`,
    /// `--bridge`, and `--target-bridge` — when `--host` is set,
    /// drift.toml is the sole source of truth.
    #[clap(long)]
    host: Option<String>,

    /// Non-interactive mode: run this shell command on the
    /// server, print its output, then exit. Skips raw-mode
    /// terminal handling so it works from scripts / CI / piped
    /// stdin. The remote shell sees `<cmd>\nexit\n`; we drain
    /// the pty stream until the shell session ends (or
    /// `--exec-timeout` seconds elapse with no further output).
    #[clap(long)]
    exec: Option<String>,

    /// Maximum quiet period (seconds) after the last byte of
    /// output before we conclude the `--exec` command is done.
    /// Only meaningful with `--exec`.
    #[clap(long, default_value = "3")]
    exec_timeout: u64,

    /// How long to wait for the server's `AttachAck` reply after
    /// sending the attach control frame.
    ///
    /// 5 s is fine on direct sessions and on triangle-scale (≤3
    /// bridges) federation. Larger federation meshes can need
    /// more — first-time attach via federation goes
    /// client→bridge-A → (federation forward) → bridge-B → server,
    /// and on Docker Desktop / macOS or on bridges with many
    /// federation peers, the cumulative latency on the
    /// reverse-path setup occasionally exceeds 5 s. Bumping this
    /// to 15-20 s gives federation cold-start enough headroom
    /// without changing steady-state behavior (once the path is
    /// warm, AttachAcks arrive in <100 ms).
    #[clap(long, default_value = "5")]
    attach_timeout_secs: u64,
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
    let mut cli = Cli::parse();
    let session_id = parse_session_id(cli.session_id.as_deref())?;

    // Phase 0 of target resolution: petname → drift.toml host
    // lookup. When `--host <name>` is set, the entry's pubkey
    // populates `--server-pub` and the entry's route populates
    // either `--server-addr` (direct) or `--bridge` +
    // `--target-bridge` (federated). Subsequent phases then run
    // as if the operator had typed those flags explicitly. The
    // operator-set flags take precedence — `--host` rejects
    // when it would silently override.
    if let Some(host_name) = cli.host.as_deref() {
        if cli.server_pub.is_some()
            || cli.server_addr.is_some()
            || cli.bridge.is_some()
            || cli.target_bridge.is_some()
        {
            bail!(
                "--host {} is mutually exclusive with --server-pub, --server-addr, \
                 --bridge, and --target-bridge. Remove the redundant flag or drop \
                 --host.",
                host_name
            );
        }
        let (pubkey_hex, dial) = resolve_host_by_name(host_name)?;
        cli.server_pub = Some(pubkey_hex);
        match dial {
            InventoryDial::Direct(addr) => {
                cli.server_addr = Some(addr);
            }
            InventoryDial::Bridged {
                bridge_spec,
                target_bridge_pub_hex,
            } => {
                cli.bridge = Some(bridge_spec);
                cli.target_bridge = Some(target_bridge_pub_hex);
            }
        }
    }

    // Phase 1 of target resolution: inventory-driven discovery.
    //
    // If the operator passed only `--server-pub` (no
    // `--server-addr` and no `--bridge`), look up the target in
    // drift.toml and synthesize whichever flag chain we need.
    // This is the "zero-config" identity-first promise — the user
    // gives us a pubkey and the inventory tells us how to route.
    //
    //   * `hosts[X].endpoints = [...]`  → direct dial; populate
    //     `--server-addr` with the first endpoint.
    //   * `hosts[X].via_bridge = <Y>`   → federation; populate
    //     `--bridge` with bridge Y's first endpoint plus its
    //     pubkey, and `--target-bridge` with Y's pubkey.
    //
    // Best-effort: any inventory-load error falls through to the
    // existing resolve_target / explicit-flag path so users who
    // never set up drift.toml see the same UX as before.
    if cli.server_addr.is_none() && cli.bridge.is_none() {
        if let Some(server_pub_hex) = cli.server_pub.as_deref() {
            match resolve_from_inventory(server_pub_hex) {
                Ok(InventoryDial::Direct(addr)) => {
                    cli.server_addr = Some(addr);
                }
                Ok(InventoryDial::Bridged {
                    bridge_spec,
                    target_bridge_pub_hex,
                }) => {
                    cli.bridge = Some(bridge_spec);
                    cli.target_bridge = Some(target_bridge_pub_hex);
                }
                Err(e) => {
                    return Err(e.context(
                        "no --server-addr or --bridge given and the inventory lookup didn't resolve a route",
                    ));
                }
            }
        } else {
            bail!(
                "need either --server-addr, --bridge, or --server-pub (with a drift.toml entry)"
            );
        }
    }

    // Resolve `--server-addr`: it can be either a petname
    // saved in `$CONFIG_DIR/drift/contacts.toml` (e.g.
    // `bob-laptop`) or a literal `host:port` / scheme-
    // prefixed URL. Petnames take priority — if the user
    // typed `bob-laptop` and a contact exists, use that
    // contact's pubkey + addr regardless of whether
    // `--server-pub` was passed.
    //
    // In federated mode, `--server-addr` may still be None at
    // this point — the bridge URL stands in for it. Pass an
    // empty string so the existing helper short-circuits to the
    // `--server-pub`-required branch.
    let (server_pub, server_addr_with_scheme) = resolve_target(
        cli.server_addr.as_deref().unwrap_or(""),
        cli.server_pub.as_deref(),
    )?;

    // Identity: either explicit --identity-file, or the
    // persistent default at $CONFIG_DIR/drift-mosh/client.key.
    let identity = match &cli.identity_file {
        Some(p) => load_identity_from_file(p)?,
        None => ClientKey::load_or_create()
            .context("loading or creating persistent client identity")?,
    };

    // `--bind` is an unused legacy flag retained for old scripts.
    let _ = &cli.bind;

    // Two paths:
    //
    //   * Direct — connect_url to server_addr, add_peer(server_pub).
    //     Original behavior.
    //   * Federated — connect_url to bridge, add_peer(bridge_pub),
    //     warmup, then add_federated_peer(server_pub) so subsequent
    //     send_data on `server_peer` transparently rides through
    //     the bridge.
    let (transport, server_peer) = if let Some(bridge_spec) = cli.bridge.as_deref() {
        let target_bridge_hex = cli.target_bridge.as_deref().ok_or_else(|| {
            anyhow!("--bridge requires --target-bridge (the server's bridge pubkey)")
        })?;
        let (bridge_url, bridge_pub_hex) = bridge_spec
            .split_once('@')
            .ok_or_else(|| anyhow!("--bridge expected <url>@<pubkey-hex>"))?;
        let bridge_pub = decode_hex32(bridge_pub_hex)
            .context("--bridge pubkey")?;
        let target_bridge_pub = decode_hex32(target_bridge_hex)
            .context("--target-bridge pubkey")?;
        let (t, bridge_addr) = Transport::connect_url(
            bridge_url,
            identity,
            TransportConfig::default(),
        )
        .await
        .with_context(|| format!("connecting to bridge {}", bridge_url))?;
        let t = Arc::new(t);
        let bridge_handle = t
            .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
            .await
            .context("add_peer(bridge) failed")?;
        // Warmup byte to kick the HELLO with the local bridge.
        // add_peer alone never initiates a handshake — send_data
        // does. The first session we need for federation is the
        // client↔bridge one (federated peers ride on top of it).
        let _ = t.send_data(&bridge_handle, b".", 0, 0).await;
        // Wait briefly for the bridge HELLO/HELLO_ACK round-trip.
        // Without this, the immediate `mgr.open(server_peer)`
        // below would race the bridge handshake and fail with
        // `UnknownPeer` from send_typed (which requires the
        // bridge to be Established before it can carry a
        // Federated envelope).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        // Register presence with our local bridge so the server's
        // reply path can find us. Without this, the bridge can't
        // announce us in its FederationDirectory (announces only
        // include clients with valid presence tickets), AND remote
        // bridges hitting our local bridge with FindPeer queries
        // won't get a PeerHere reply (handle_find_peer also gates
        // on ticket existence). 60 s is plenty for a typical
        // dial-reply round-trip; long-lived clients should refresh.
        if let Err(e) = t.register_presence_to(&bridge_handle, 60_000).await {
            // Non-fatal: register_presence_to can fail transiently
            // (e.g. if the bridge HELLO hasn't fully completed).
            // The dial still works for the OUTBOUND direction; the
            // reply path may need FindPeer fallback.
            eprintln!(
                "drift-mosh: warning: presence registration with \
                 bridge failed ({e}); replies may take longer to \
                 route until proactive announces converge"
            );
        }
        let server_peer = t
            .add_federated_peer(server_pub, bridge_handle, target_bridge_pub)
            .await
            .context("add_federated_peer(server) failed")?;
        (t, server_peer)
    } else {
        let (t, server_addr) = Transport::connect_url(
            &server_addr_with_scheme,
            identity,
            TransportConfig::default(),
        )
        .await
        .with_context(|| format!("connecting to {}", server_addr_with_scheme))?;
        let t = Arc::new(t);
        let p = t
            .add_peer(server_pub, server_addr, Direction::Initiator)
            .await
            .context("failed to register server peer (is the address right?)")?;
        (t, p)
    };

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

    let ack_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(cli.attach_timeout_secs),
        ctrl_stream.recv(),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "no AttachAck from server within {} s",
            cli.attach_timeout_secs
        )
    })?
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
    // never breaks the session. Skipped for federated mode —
    // contacts store host:port addresses and a federated server
    // doesn't have one (it's reachable only via its bridge).
    if cli.bridge.is_none() {
        if let Ok(mut book) = drift::contacts::Contacts::load_default() {
            let server_addr: std::net::SocketAddr =
                server_addr_with_scheme
                    .splitn(2, "://")
                    .nth(1)
                    .unwrap_or(&server_addr_with_scheme)
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            if book
                .record(server_pub, server_addr, server_name.as_deref())
                .is_ok()
            {
                let _ = book.save();
            }
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

    // ─── Non-interactive `--exec` short-circuit ───────────────
    //
    // For test harnesses and CI: pump a single command into the
    // remote pty, drain the output, exit. Skips raw mode / stdin
    // reader / SIGWINCH wiring entirely. The remote shell sees:
    //
    //   <cmd>\n
    //   exit\n
    //
    // which makes /bin/sh run the command and then quit. We
    // drain pty_stream until the stream closes (server shut
    // down the pty after the shell exited) or until
    // `--exec-timeout` seconds pass with no new bytes.
    if let Some(cmd) = cli.exec.as_deref() {
        // Tell the server about a sane terminal size so output
        // wraps cleanly. We never enter raw mode locally, but
        // the remote shell still respects window-size hints.
        let _ = ctrl_stream
            .send(&bincode::serialize(&Ctrl::Resize {
                rows: 24,
                cols: 200,
            })?)
            .await;

        // Send the command. Two writes (cmd, then `exit`) so the
        // shell parses them as separate lines without buffering
        // tricks.
        let mut to_send = cmd.as_bytes().to_vec();
        to_send.push(b'\n');
        pty_stream.send(&to_send).await?;

        // Forward local stdin to the remote shell if stdin is not
        // a TTY (i.e., piped or redirected). This is what lets
        // `cat script.sh | drift-mosh-client --exec sh` push a
        // script as input to the remote command. When local stdin
        // closes, send Ctrl-D (EOT) so the remote command sees
        // end-of-input and finishes its own read loop.
        //
        // Skipped when stdin is a TTY — a human at the terminal
        // doesn't have anything useful to pipe through; their
        // session is interactive (use the no-`--exec` mode for
        // that).
        if !is_stdin_tty() {
            let pty_for_stdin = pty_stream.clone();
            let stdin_pump = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut buf = [0u8; 1024];
                let mut stdin = std::io::stdin().lock();
                let mut bytes = Vec::with_capacity(4096);
                while let Ok(n) = stdin.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                }
                bytes
            });
            if let Ok(bytes) = stdin_pump.await {
                if !bytes.is_empty() {
                    let _ = pty_for_stdin.send(&bytes).await;
                }
            }
            // Newline before Ctrl-D so any unterminated line
            // flushes to the remote command first.
            let _ = pty_for_stdin.send(b"\n\x04").await;
        }

        // Brief pause so the shell processes the command before
        // we send `exit`. Without this, on some shells the two
        // lines can get clobbered if they arrive in the same
        // read syscall.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let _ = pty_stream.send(b"exit\n").await;

        // Drain pty output to stdout until quiet period elapses
        // or stream closes.
        use std::io::Write;
        let quiet_window =
            std::time::Duration::from_secs(cli.exec_timeout);
        loop {
            match tokio::time::timeout(quiet_window, pty_stream.recv()).await {
                Ok(Some(chunk)) => {
                    std::io::stdout().write_all(&chunk).ok();
                    std::io::stdout().flush().ok();
                }
                Ok(None) | Err(_) => break,
            }
        }

        // Polite goodbye.
        if let Ok(bytes) = bincode::serialize(&Ctrl::Bye) {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                ctrl_stream.send(&bytes),
            )
            .await;
        }
        return Ok(());
    }

    // ─── Interactive path ─────────────────────────────────────

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

/// Output of the drift.toml-based discovery step. Either we found
/// a direct endpoint or we found a federation route.
enum InventoryDial {
    Direct(String),
    Bridged {
        /// `<url>@<pubkey-hex>` as expected by `--bridge`.
        bridge_spec: String,
        /// The bridge's pubkey in hex, as expected by `--target-bridge`.
        target_bridge_pub_hex: String,
    },
}

/// Look up `server_pub_hex` in drift.toml's `[hosts.…]` entries.
/// Returns a `Direct` dial if the host listens (`endpoints`), a
/// `Bridged` dial if it's reachable through a specific `via_bridge`,
/// or falls back to the inventory's `default_bridge` (dialing
/// through it with the UNKNOWN_BRIDGE_PUB sentinel so the bridge
/// resolves via its peer directory) when the host isn't in the
/// inventory or has no explicit route.
fn resolve_from_inventory(server_pub_hex: &str) -> Result<InventoryDial> {
    let path = drift_config::io::default_path()
        .context("resolving the default drift.toml path")?;
    if !path.exists() {
        bail!(
            "no drift.toml at {}; either pass --server-addr explicitly \
             or run `drift-config init` and `drift-config peer add` first",
            path.display()
        );
    }
    let doc = drift_config::io::read(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let needle = server_pub_hex.trim().to_lowercase();

    // Find the host with this pubkey (if any). Case-insensitive
    // on the pubkey field because drift.toml stores it lowercased
    // but CLI users sometimes paste uppercase from `drift info`.
    let host_entry = doc
        .hosts
        .iter()
        .find(|(_, h)| h.pubkey.to_lowercase() == needle);

    // Direct dial wins when the target listens — fewer hops, no
    // bridge operator in the middle.
    if let Some((_, host)) = host_entry {
        if let Some(ep) = host.endpoints.first() {
            return Ok(InventoryDial::Direct(ep.clone()));
        }
        // Specific via_bridge wins over the inventory's
        // default_bridge — operator told us exactly where this
        // host lives, so respect that.
        if let Some(via) = host.via_bridge.as_deref() {
            return resolve_via_bridge(&doc, via, &path);
        }
    }

    // Fall back to the inventory's `default_bridge` when neither
    // the host nor its `via_bridge` is set. We dial the default
    // bridge and let it resolve via its peer directory.
    if let Some(default_bridge_pub_hex) = doc.default_bridge.as_deref() {
        return resolve_via_default_bridge(&doc, default_bridge_pub_hex, &path);
    }

    if host_entry.is_none() {
        bail!(
            "no host in {} has pubkey {}; either add it with \
             `drift-config peer add <name> --pubkey {} --endpoint <url>` \
             (or --via-bridge <bridge-pubkey>), or set a \
             `default_bridge` in drift.toml so we can fall back \
             to its directory.",
            path.display(),
            needle,
            needle
        );
    }
    bail!(
        "host with pubkey {} has neither `endpoints` nor \
         `via_bridge` in {}, and no `default_bridge` is set as \
         a fallback. Set one with \
         `drift-config peer rm <name>` then re-add with \
         --endpoint or --via-bridge.",
        needle,
        path.display(),
    );
}

/// Look the host up by its drift.toml entry name (e.g.
/// `router-mosh`) and return `(pubkey_hex, dial)`. Used by the
/// `--host <name>` flag. Direct dial wins over `via_bridge`, same
/// as `resolve_from_inventory`'s policy.
///
/// Errors when:
///   - drift.toml doesn't exist
///   - `[hosts.<name>]` is missing
///   - the entry has no `endpoints` AND no `via_bridge`
fn resolve_host_by_name(host_name: &str) -> Result<(String, InventoryDial)> {
    let path = drift_config::io::default_path()
        .context("resolving the default drift.toml path")?;
    if !path.exists() {
        bail!(
            "no drift.toml at {}; either run `drift-config init` + \
             `drift-config peer add {} --pubkey <hex> --endpoint <url>` \
             (or --via-bridge <bridge-pubkey>), or drop --host {} and \
             pass the flags explicitly.",
            path.display(),
            host_name,
            host_name,
        );
    }
    let doc = drift_config::io::read(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let host = doc.hosts.get(host_name).ok_or_else(|| {
        anyhow!(
            "no host named {:?} in {}. Add it with `drift-config peer add {} \
             --pubkey <hex> --endpoint <url>` (or --via-bridge <bridge-pubkey>).",
            host_name,
            path.display(),
            host_name,
        )
    })?;
    let pubkey_hex = host.pubkey.to_lowercase();
    if let Some(ep) = host.endpoints.first() {
        return Ok((pubkey_hex, InventoryDial::Direct(ep.clone())));
    }
    if let Some(via) = host.via_bridge.as_deref() {
        let dial = resolve_via_bridge(&doc, via, &path)?;
        return Ok((pubkey_hex, dial));
    }
    bail!(
        "host {:?} in {} has neither `endpoints` nor `via_bridge`. Add one with \
         `drift-config peer rm {}` then re-add with --endpoint or --via-bridge.",
        host_name,
        path.display(),
        host_name,
    )
}

/// Resolve a specific `via_bridge` pubkey into a `Bridged` dial.
/// The bridge itself must be in the inventory with `endpoints`.
fn resolve_via_bridge(
    doc: &drift_config::schema::DriftToml,
    bridge_pub_hex: &str,
    path: &std::path::Path,
) -> Result<InventoryDial> {
    let bridge_pub_hex_lc = bridge_pub_hex.to_lowercase();
    let (_, bridge_host) = doc
        .hosts
        .iter()
        .find(|(_, h)| h.pubkey.to_lowercase() == bridge_pub_hex_lc)
        .ok_or_else(|| {
            anyhow!(
                "via_bridge points at pubkey {} but no such host \
                 is registered in {}. Add it with `drift-config \
                 peer add <bridge-name> --pubkey {} --endpoint <url>`.",
                bridge_pub_hex_lc,
                path.display(),
                bridge_pub_hex_lc,
            )
        })?;
    let bridge_endpoint = bridge_host.endpoints.first().ok_or_else(|| {
        anyhow!(
            "bridge host with pubkey {} has no `endpoints` in {}; \
             a bridge that doesn't listen can't accept federation \
             clients.",
            bridge_pub_hex_lc,
            path.display(),
        )
    })?;
    Ok(InventoryDial::Bridged {
        bridge_spec: format!("{}@{}", bridge_endpoint, bridge_pub_hex_lc),
        target_bridge_pub_hex: bridge_pub_hex_lc,
    })
}

/// Like `resolve_via_bridge` but signals "I don't know which
/// bridge holds the target" by setting target_bridge_pub_hex to
/// all-zeros. The default-bridge will look up the target in its
/// peer directory and re-route on the fly.
fn resolve_via_default_bridge(
    doc: &drift_config::schema::DriftToml,
    bridge_pub_hex: &str,
    path: &std::path::Path,
) -> Result<InventoryDial> {
    let bridge_pub_hex_lc = bridge_pub_hex.to_lowercase();
    let (_, bridge_host) = doc
        .hosts
        .iter()
        .find(|(_, h)| h.pubkey.to_lowercase() == bridge_pub_hex_lc)
        .ok_or_else(|| {
            anyhow!(
                "default_bridge points at pubkey {} but no such \
                 host is registered in {}. Add it with \
                 `drift-config peer add <bridge-name> --pubkey {} \
                 --endpoint <url>`.",
                bridge_pub_hex_lc,
                path.display(),
                bridge_pub_hex_lc,
            )
        })?;
    let bridge_endpoint = bridge_host.endpoints.first().ok_or_else(|| {
        anyhow!(
            "default bridge with pubkey {} has no `endpoints` in {}; \
             a bridge that doesn't listen can't accept federation \
             clients.",
            bridge_pub_hex_lc,
            path.display(),
        )
    })?;
    Ok(InventoryDial::Bridged {
        bridge_spec: format!("{}@{}", bridge_endpoint, bridge_pub_hex_lc),
        // All-zeros sentinel — receiving bridge will consult its
        // federation directory to find the actual target bridge.
        target_bridge_pub_hex: hex::encode([0u8; 32]),
    })
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

/// Decode a 64-hex-char string into a 32-byte array.
fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes (64 hex chars), got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// True if local stdin is connected to a terminal. We use this in
/// `--exec` mode to decide whether to pipe stdin through to the
/// remote shell — if a human is sitting at a tty there's nothing
/// useful to pipe, but if it's a file/pipe redirect the user wants
/// that as input to the remote command.
fn is_stdin_tty() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty is always safe; checks one int fd.
        unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
    }
    #[cfg(not(unix))]
    {
        // On non-Unix platforms we conservatively assume it IS a
        // tty so we don't try to read input that isn't there.
        true
    }
}

/// Naive substring search — `haystack.windows(n).position(...)`.
/// Used to spot the sentinel in the prelude buffer. The buffer
/// stays small (a few hundred bytes) so O(n*m) is fine.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
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

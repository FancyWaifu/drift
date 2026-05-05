//! `git-remote-drift` — git remote helper for `drift://` URLs.
//!
//! When the user runs `git push drift://<peerhex>@<host>:<port>/<path>`,
//! git looks up `git-remote-drift` in `PATH` and runs it with two
//! args: the remote name and the URL. The helper then speaks
//! [git's remote-helper protocol](https://git-scm.com/docs/gitremote-helpers)
//! on stdin/stdout.
//!
//! We declare the `connect` capability, which is the simplest of
//! the three modes: when git wants to talk to the remote service,
//! it asks us to `connect <service>` and from that moment we
//! become a transparent byte tunnel. Git negotiates refs and
//! ships pack data on stdio; we forward the bytes to/from a
//! DRIFT stream.
//!
//! Protocol on the helper's stdin:
//!
//!     capabilities\n
//!     connect git-upload-pack\n           (or git-receive-pack)
//!
//! And on its stdout:
//!
//!     connect\n                           (the only capability we offer)
//!     \n                                  (terminator)
//!     \n                                  (signals "I'm now in tunnel mode")
//!
//! After the second blank line, raw pack-protocol bytes flow.

use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use drift_git::{
    build_request, frame_data, frame_eod, parse_frame, parse_reply, DriftGitUrl, Frame,
    GitService,
};
use std::env;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    // Helpers must NOT log to stderr in normal operation — git
    // sometimes shows it directly to the user. Send tracing
    // through env-filter only when explicitly asked.
    if env::var("DRIFT_GIT_HELPER_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    }

    // Args: program-name, remote-name, url. Git always passes
    // both of these — we mostly care about the URL.
    let args: Vec<String> = env::args().collect();
    let url = args
        .get(2)
        .or_else(|| args.get(1))
        .ok_or_else(|| anyhow!("usage: git-remote-drift <remote-name> <url>"))?;
    let parsed = DriftGitUrl::parse(url)?;

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = stdout;

    // Speak the remote-helper protocol just long enough to land
    // in `connect` mode. We don't bother implementing `list` or
    // `fetch`/`push` directly because `connect` covers both.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Git closed our stdin without asking us to do
            // anything — clean exit.
            return Ok(());
        }
        let cmd = line.trim_end();
        if cmd.is_empty() {
            // Blank line between command groups; ignore.
            continue;
        }
        match cmd {
            "capabilities" => {
                // We support `connect` and nothing else.
                writer.write_all(b"connect\n\n").await?;
                writer.flush().await?;
            }
            other if other.starts_with("connect ") => {
                let service_name = other.trim_start_matches("connect ");
                let service = GitService::from_wire(service_name)?;
                // Per the protocol: an empty line right after a
                // `connect` line means "I accept; hand me the
                // tunnel."
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                return run_tunnel(parsed, service, reader, writer).await;
            }
            other => {
                return Err(anyhow!(
                    "git-remote-drift only supports `connect` mode; git asked for {:?}",
                    other
                ));
            }
        }
    }
}

async fn run_tunnel(
    url: DriftGitUrl,
    service: GitService,
    mut git_reader: BufReader<tokio::io::Stdin>,
    mut git_writer: tokio::io::Stdout,
) -> Result<()> {
    // Open a DRIFT transport with a fresh ephemeral identity.
    // Git's auth model is "the remote knows my pubkey via
    // out-of-band setup," so the user's identity must be
    // configured somewhere — for now we use a per-process
    // ephemeral key, which works for `--allow-any` testing.
    // Production deployments would load a stable key from
    // disk.
    let identity_secret = load_or_make_helper_identity()?;
    let identity = Identity::from_secret_bytes(identity_secret);

    // Two routing modes:
    //   1. Direct: connect to url.wire_url, server is the
    //      direct wire peer.
    //   2. Bridged: env vars DRIFT_GIT_BRIDGE_URL +
    //      DRIFT_GIT_BRIDGE_PUB tell us to connect to a bridge
    //      instead, then mesh-route to the server pubkey from
    //      the URL.
    let (transport, server_peer_id) = if let Ok(bridge_url) = env::var("DRIFT_GIT_BRIDGE_URL") {
        let bridge_pub_hex = env::var("DRIFT_GIT_BRIDGE_PUB")
            .context("DRIFT_GIT_BRIDGE_URL set but DRIFT_GIT_BRIDGE_PUB missing")?;
        let bridge_pub = parse_pubkey_hex_str(&bridge_pub_hex)?;
        let bridge_pid = drift_core::derive_peer_id(&bridge_pub);
        let (t, bridge_addr) = Transport::connect_url(
            &bridge_url,
            identity,
            TransportConfig::default(),
        )
        .await
        .with_context(|| format!("connecting to bridge {}", bridge_url))?;
        let t = Arc::new(t);
        // Register the bridge as our direct peer (wire-level
        // handshake). Mesh routing toward the server happens
        // via the bridge's mesh tables.
        t.add_peer(bridge_pub, bridge_addr, Direction::Initiator)
            .await
            .context("handshaking with bridge")?;
        // Warmup: send a probe so the bridge's peer-table
        // records us and announces us in beacons.
        let _ = t.send_data(&bridge_pid, b"warmup", 0, 0).await;
        // Wait for the bridge's beacon round so mesh routes
        // toward the server are populated in our routing
        // table. (1–2s on loopback; longer on real networks.)
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Register the server's pubkey for mesh routing — the
        // bridge_addr is a placeholder; mesh delivery uses the
        // routes built from beacons.
        let server_pid = t
            .add_peer(url.peer_pub, bridge_addr, Direction::Initiator)
            .await
            .context("registering server as mesh peer")?;
        (t, server_pid)
    } else {
        let (t, peer_addr) = Transport::connect_url(
            &url.wire_url,
            identity,
            TransportConfig::default(),
        )
        .await
        .with_context(|| format!("connecting to {}", url.wire_url))?;
        let t = Arc::new(t);
        let server_pid = t
            .add_peer(url.peer_pub, peer_addr, Direction::Initiator)
            .await
            .context("registering server as peer")?;
        (t, server_pid)
    };
    let transport = transport;

    let manager = StreamManager::bind(transport.clone()).await;
    let stream = manager
        .open(server_peer_id)
        .await
        .context("opening DRIFT stream to server")?;

    // Send the handshake envelope.
    stream.send(&build_request(service, &url.repo_path)).await?;

    // Wait for the server's reply. We may receive bytes after
    // the reply terminator that belong to the pack protocol;
    // those have to be forwarded onward.
    let mut reply_buf: Vec<u8> = Vec::new();
    let consumed = loop {
        let chunk = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("server closed stream before replying"))?;
        reply_buf.extend_from_slice(&chunk);
        if let Some(_) = reply_buf.windows(2).position(|w| w == b"\n\n") {
            break parse_reply(&reply_buf)?;
        }
    };
    let pack_tail = reply_buf[consumed..].to_vec();

    // If the server slipped framed bytes into the same chunk
    // as its OK reply, parse and forward them.
    if !pack_tail.is_empty() {
        match parse_frame(&pack_tail) {
            Frame::Data(payload) => {
                git_writer.write_all(payload).await?;
                git_writer.flush().await?;
            }
            Frame::EndOfData => {
                // Server already finished — close git's stdout
                // and stop. (Unusual but legal.)
                return Ok(());
            }
            Frame::Unknown(t) => {
                return Err(anyhow!(
                    "server sent unknown frame tag {:#x} alongside OK reply",
                    t
                ));
            }
        }
    }

    // Tunnel: git's stdin → DRIFT stream, DRIFT stream → git's
    // stdout. Each direction uses a `FRAME_DATA`/`FRAME_EOD`
    // wrapper so the two halves can finish independently
    // without tearing down the bidirectional DRIFT stream.
    let stream = Arc::new(stream);
    const CHUNK: usize = 1024;

    let stream_send = stream.clone();
    let to_stream = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match git_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream_send.send(&frame_data(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
        // EOD instead of close: server's response path stays
        // open until it sends its own EOD.
        let _ = stream_send.send(&frame_eod()).await;
    });

    let stream_recv = stream.clone();
    let from_stream = tokio::spawn(async move {
        loop {
            let chunk = match stream_recv.recv().await {
                Some(c) => c,
                None => break,
            };
            match parse_frame(&chunk) {
                Frame::Data(payload) => {
                    if git_writer.write_all(payload).await.is_err() {
                        break;
                    }
                    let _ = git_writer.flush().await;
                }
                Frame::EndOfData => {
                    // Server done — close git's stdout via task
                    // exit (the BufWriter on stdout flushes on
                    // drop).
                    break;
                }
                Frame::Unknown(_) => break,
            }
        }
    });

    let _ = tokio::join!(to_stream, from_stream);
    // Now safe to close — both directions have signaled EOD.
    let _ = stream.close().await;
    Ok(())
}

fn parse_pubkey_hex_str(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim())
        .with_context(|| format!("invalid hex pubkey: {:?}", s))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "pubkey must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

/// Helper-side identity. v1 reads from the env var
/// `DRIFT_GIT_HELPER_KEY` (32 raw bytes hex-encoded) if set,
/// otherwise generates a fresh ephemeral key. A future commit
/// should load from `~/.config/drift/git-identity` and
/// auto-provision on first use.
fn load_or_make_helper_identity() -> Result<[u8; 32]> {
    if let Ok(s) = env::var("DRIFT_GIT_HELPER_KEY") {
        let bytes = hex::decode(s.trim())
            .context("DRIFT_GIT_HELPER_KEY isn't valid hex")?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "DRIFT_GIT_HELPER_KEY must be 32 bytes (64 hex chars)"
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        return Ok(k);
    }
    let mut k = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut k);
    Ok(k)
}

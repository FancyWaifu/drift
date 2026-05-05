//! `drift-git-server` — git serving daemon over DRIFT.
//!
//! Listens on a DRIFT URL, accepts streams from authenticated
//! peers, and for each stream spawns the appropriate git
//! subprocess (`git-upload-pack` for fetches, `git-receive-pack`
//! for pushes). DRIFT's identity-as-key means ACL is just a list
//! of pubkeys — no ssh keys, no http auth, no usernames.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Transport, TransportConfig};
use drift_core::PeerId;
use drift_git::{
    build_err_reply, build_ok_reply, frame_data, frame_eod, parse_frame, parse_request, Frame,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{info, warn};

#[derive(Parser)]
#[clap(name = "drift-git-server", about = "Git daemon over DRIFT")]
struct Cli {
    /// DRIFT URL to listen on (e.g. `udp://0.0.0.0:9100`).
    #[clap(long, default_value = "udp://0.0.0.0:9100")]
    bind: String,

    /// Path to a 32-byte identity secret (raw or 64-char hex).
    /// If omitted, a fresh ephemeral identity is generated and
    /// its pubkey printed at startup.
    #[clap(long)]
    identity_file: Option<PathBuf>,

    /// Root directory holding bare repos. Client repo paths
    /// are resolved relative to this — anything that walks
    /// above root via `..` is rejected.
    #[clap(long, default_value = ".")]
    root: PathBuf,

    /// Allow this pubkey (hex) to read+write any repo. Repeat
    /// for multiple authorized clients.
    #[clap(long = "allow")]
    allow: Vec<String>,

    /// Disable ACL — accept any peer. Testing only.
    #[clap(long)]
    allow_any: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    "drift=warn,drift_git=info,drift_git_server=info".into()
                }),
        )
        .init();

    let cli = Cli::parse();
    let allowed: Vec<[u8; 32]> = cli
        .allow
        .iter()
        .map(|s| parse_pubkey_hex(s))
        .collect::<Result<Vec<_>>>()?;

    let identity = match &cli.identity_file {
        Some(p) => load_identity(p).await?,
        None => Identity::generate(),
    };
    let pub_hex = hex::encode(identity.public_bytes());
    info!("server pubkey: {}", pub_hex);
    println!("DRIFT_GIT_PUB={}", pub_hex);

    let mut config = TransportConfig::default();
    config.accept_any_peer = true; // we ACL on the stream side
    let (transport, bound_url) = Transport::bind_url(&cli.bind, identity, config)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    let transport = Arc::new(transport);
    info!("listening on {}", bound_url);
    println!("DRIFT_GIT_BIND={}", bound_url);

    let manager = StreamManager::bind(transport.clone()).await;

    let root = cli.root.canonicalize().with_context(|| {
        format!("canonicalizing root {:?}", cli.root)
    })?;
    let allow_any = cli.allow_any;
    let allowed = Arc::new(allowed);

    loop {
        let stream = match manager.accept().await {
            Some(s) => s,
            None => {
                warn!("accept() returned None — transport torn down, exiting");
                break;
            }
        };
        let peer_id = stream.peer();
        let transport = transport.clone();
        let allowed = allowed.clone();
        let root = root.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(
                stream, peer_id, transport, allowed, root, allow_any,
            )
            .await
            {
                warn!(?peer_id, error = %e, "stream handler exited with error");
            }
        });
    }
    Ok(())
}

async fn handle_stream(
    stream: drift::streams::Stream,
    peer_id: PeerId,
    transport: Arc<Transport>,
    allowed: Arc<Vec<[u8; 32]>>,
    root: PathBuf,
    allow_any: bool,
) -> Result<()> {
    let peer_pub = transport
        .peer_public(&peer_id)
        .await
        .ok_or_else(|| anyhow!("peer {:?} unknown to transport", peer_id))?;

    if !allow_any && !allowed.iter().any(|k| k == &peer_pub) {
        let _ = stream.send(&build_err_reply("not authorized")).await;
        return Err(anyhow!(
            "rejecting peer {} — not in --allow list",
            hex::encode(peer_pub)
        ));
    }

    // First chunk on the stream MUST contain the full handshake
    // envelope. <100 bytes — fits comfortably in any DRIFT chunk.
    let chunk = stream
        .recv()
        .await
        .ok_or_else(|| anyhow!("client closed stream before sending handshake"))?;
    let (service, repo_path, consumed) = parse_request(&chunk)?;
    let trailing = chunk[consumed..].to_vec();

    let resolved = match resolve_repo(&root, &repo_path) {
        Ok(p) => p,
        Err(e) => {
            let _ = stream.send(&build_err_reply(&format!("bad repo path: {}", e))).await;
            return Err(e);
        }
    };
    if !resolved.exists() {
        let _ = stream
            .send(&build_err_reply(&format!("no such repo: {}", repo_path)))
            .await;
        return Err(anyhow!("requested repo {:?} not found under root", repo_path));
    }

    info!(
        peer_pub = %hex::encode(peer_pub),
        ?service,
        repo = %resolved.display(),
        "spawning git subprocess"
    );

    let mut child = Command::new(service.binary_name())
        .arg(&resolved)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", service.binary_name()))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("child stdin wasn't piped"))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("child stdout wasn't piped"))?;
    let mut child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("child stderr wasn't piped"))?;

    // Reply OK before tunneling so the client knows the child
    // is up. After this byte everything on the stream is
    // framed pack-protocol traffic (DATA/EOD frames — see
    // `drift_git::frame_*`).
    stream.send(&build_ok_reply()).await?;

    // If the client's first chunk had bytes after the
    // handshake terminator, treat them as a possible first
    // frame. (In practice unlikely — git waits for our reply
    // before sending pack bytes — but spec-correct.)
    if !trailing.is_empty() {
        match parse_frame(&trailing) {
            Frame::Data(payload) => {
                child_stdin.write_all(payload).await?;
            }
            Frame::EndOfData => {
                let _ = child_stdin.shutdown().await;
            }
            Frame::Unknown(_) => {}
        }
    }

    // Share the stream across the two tunnel tasks.
    let stream = Arc::new(stream);
    const CHUNK: usize = 1024;

    // Stream → child.stdin (interpret incoming DATA/EOD).
    let stream_in = stream.clone();
    let to_stdin = tokio::spawn(async move {
        loop {
            let chunk = match stream_in.recv().await {
                Some(c) => c,
                None => break,
            };
            match parse_frame(&chunk) {
                Frame::Data(payload) => {
                    if child_stdin.write_all(payload).await.is_err() {
                        break;
                    }
                }
                Frame::EndOfData => {
                    // Client said "no more bytes." Close child's
                    // stdin so receive-pack/upload-pack sees EOF
                    // and finishes processing.
                    break;
                }
                Frame::Unknown(_) => break,
            }
        }
        let _ = child_stdin.shutdown().await;
    });

    // child.stdout → stream (wrap in DATA frames; finish with EOD).
    let stream_out = stream.clone();
    let from_stdout = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream_out.send(&frame_data(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = stream_out.send(&frame_eod()).await;
    });

    // Capture stderr for diagnostics — git emits status here
    // (e.g. "remote: Counting objects: ..."). Not forwarded
    // into the byte channel because the pack protocol doesn't
    // mix stderr.
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = child_stderr.read_to_end(&mut buf).await;
        if !buf.is_empty() {
            let s = String::from_utf8_lossy(&buf);
            info!(stderr = %s.trim_end(), "git child stderr");
        }
    });

    // Wait for both directions to flush.
    let _ = tokio::join!(to_stdin, from_stdout, stderr_task);

    let status = child.wait().await?;
    if !status.success() {
        warn!(?status, "git child exited non-zero");
    }

    // Close the stream so the client's recv loop sees EOF.
    let _ = stream.close().await;

    Ok(())
}

/// Resolve a client-supplied repo path against the server's
/// root. Refuses anything that resolves above root via `..`.
fn resolve_repo(root: &Path, requested: &str) -> Result<PathBuf> {
    let trimmed = requested.trim_start_matches('/');
    let combined = root.join(trimmed);
    let canonical = combined
        .canonicalize()
        .with_context(|| format!("canonicalize {:?}", combined))?;
    if !canonical.starts_with(root) {
        return Err(anyhow!(
            "repo path {:?} resolves outside root {:?}",
            requested,
            root
        ));
    }
    Ok(canonical)
}

fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)
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

async fn load_identity(path: &Path) -> Result<Identity> {
    let raw = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading identity file {:?}", path))?;
    let bytes = if raw.len() == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        b
    } else {
        let s = std::str::from_utf8(&raw)
            .with_context(|| {
                format!("identity file {:?} not UTF-8 hex or raw 32 bytes", path)
            })?
            .trim();
        let bytes = hex::decode(s)
            .with_context(|| format!("identity file {:?} hex decode", path))?;
        if bytes.len() != 32 {
            return Err(anyhow!("identity file must contain 32 bytes (raw or hex)"));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        b
    };
    Ok(Identity::from_secret_bytes(bytes))
}

//! `fed-pipe` — netcat-style file transfer over DRIFT federation.
//!
//! Demonstrates that *any* tool using the standard
//! `Transport::send_data` / `Transport::recv` API works through
//! federation when peers are registered via `add_federated_peer`.
//! That's the same API drift-mosh, drift-wormhole, drift-http,
//! drift-git all use — so if `fed-pipe` works, the path for the
//! other tools is just "wire up CLI flags to call
//! add_federated_peer at startup."
//!
//! Usage:
//!
//! ```sh
//! # Receiver:
//! fed-pipe recv \
//!   --identity /tmp/id.key \
//!   --bridge udp://<local-bridge>:51820@<bridge-pub> \
//!   --expect-from <sender-pubkey-hex> \
//!   --out received.bin
//!
//! # Sender (after receiver's "ready" appears):
//! fed-pipe send \
//!   --identity /tmp/id.key \
//!   --bridge udp://<local-bridge>:51820@<bridge-pub> \
//!   --target-bridge <remote-bridge-pubkey-hex> \
//!   --target-client <receiver-pubkey-hex> \
//!   --in file-to-send.bin
//! ```
//!
//! The sender chunks the file into ≤MAX_PAYLOAD-sized DATA
//! packets and ships them sequentially. The receiver writes
//! each chunk to disk in arrival order. Both ends compute a
//! SHA-256 of the bytes and the protocol's last packet carries
//! the sender's hash; the receiver verifies a match before
//! reporting success.

use clap::{Parser, Subcommand};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig, MAX_PAYLOAD};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Send(SendArgs),
    Recv(RecvArgs),
}

#[derive(Parser)]
struct SendArgs {
    #[arg(long)]
    identity: PathBuf,
    /// Local bridge: udp://host:port@<bridge-pubkey-hex>
    #[arg(long)]
    bridge: String,
    /// Pubkey of the bridge the receiver is connected to.
    #[arg(long)]
    target_bridge: String,
    /// Pubkey of the receiving client.
    #[arg(long)]
    target_client: String,
    /// Path to the file to send.
    #[arg(long)]
    r#in: PathBuf,
    /// Settle window before sending — lets bridge handshakes
    /// land before we start firing chunks.
    #[arg(long, default_value = "5")]
    settle_secs: u64,
}

#[derive(Parser)]
struct RecvArgs {
    #[arg(long)]
    identity: PathBuf,
    /// Local bridge.
    #[arg(long)]
    bridge: String,
    /// Pubkey of the expected sender. Anything else gets ignored.
    #[arg(long)]
    expect_from: String,
    /// Path to write the received bytes.
    #[arg(long)]
    out: PathBuf,
    /// Hard cap on how long to wait for bytes.
    #[arg(long, default_value = "120")]
    timeout_secs: u64,
}

// On-wire chunk framing inside the federated payload.
//
//   [0] tag       1 = DATA chunk, 2 = EOF (carries final SHA-256)
//   DATA: [tag=1][seq u32 BE][bytes…]
//   EOF:  [tag=2][total_bytes u64 BE][sha256:32]
//
// Plenty of slack under MAX_PAYLOAD; each DATA chunk carries
// up to MAX_PAYLOAD - 5 useful bytes.

const TAG_DATA: u8 = 1;
const TAG_EOF: u8 = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.mode {
        Mode::Send(a) => run_send(a).await,
        Mode::Recv(a) => run_recv(a).await,
    }
}

async fn run_send(args: SendArgs) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_identity(&args.identity)?;
    let (bridge_url, bridge_pub_hex) = args
        .bridge
        .split_once('@')
        .ok_or("--bridge expected <url>@<pubkey-hex>")?;
    let bridge_pub = parse_hex32(bridge_pub_hex)?;
    let target_bridge_pub = parse_hex32(&args.target_bridge)?;
    let target_client_pub = parse_hex32(&args.target_client)?;

    let (transport, bridge_addr) = Transport::connect_url(
        bridge_url,
        identity,
        TransportConfig {
            accept_any_peer: true,
            ..TransportConfig::default()
        },
    )
    .await?;
    let transport = Arc::new(transport);

    let bridge_handle = transport
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await?;
    let _ = transport.send_data(&bridge_handle, b".", 0, 0).await;

    let target_handle = transport
        .add_federated_peer(target_client_pub, bridge_handle, target_bridge_pub)
        .await?;

    println!("[evt] role=send file={:?} settle={}s", args.r#in, args.settle_secs);
    tokio::time::sleep(Duration::from_secs(args.settle_secs)).await;

    // Stream the file in MAX_PAYLOAD - 5 chunks. Compute SHA-256
    // alongside.
    // Outer DRIFT data payload ceiling is MAX_PAYLOAD; subtract
    // the federated envelope header (130 bytes — 4×32-byte
    // pubkeys + a 2-byte length) and our own chunk header (5
    // bytes — 1-byte tag + 4-byte seq) to get the bytes
    // available per chunk.
    let chunk_size = MAX_PAYLOAD.saturating_sub(130 + 5).max(1);

    let mut file = tokio::fs::File::open(&args.r#in).await?;
    let total_bytes_expected = file.metadata().await?.len();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; chunk_size];
    let mut seq: u32 = 0;
    let mut sent_bytes: u64 = 0;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        let mut wire = Vec::with_capacity(5 + n);
        wire.push(TAG_DATA);
        wire.extend_from_slice(&seq.to_be_bytes());
        wire.extend_from_slice(&buf[..n]);
        transport.send_data(&target_handle, &wire, 0, 0).await?;
        seq = seq.wrapping_add(1);
        sent_bytes += n as u64;
        if seq % 100 == 0 {
            println!(
                "[evt] sent {} chunks / {} bytes",
                seq, sent_bytes
            );
        }
        // Light pacing — DRIFT will queue but we don't want to
        // blow past the bridge's recv buffer.
        if seq % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    // Send EOF marker with total bytes + SHA-256.
    let digest = hasher.finalize();
    let mut eof = Vec::with_capacity(1 + 8 + 32);
    eof.push(TAG_EOF);
    eof.extend_from_slice(&sent_bytes.to_be_bytes());
    eof.extend_from_slice(&digest);
    transport.send_data(&target_handle, &eof, 0, 0).await?;
    // Give the last few packets time to fully flush through the
    // bridges before we tear down the transport.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let m = transport.metrics();
    println!(
        "[done] role=send chunks={} bytes={} expected={} sha256={} packets_sent={} auth_fail={}",
        seq,
        sent_bytes,
        total_bytes_expected,
        hex::encode(digest),
        m.packets_sent,
        m.auth_failures
    );
    Ok(())
}

async fn run_recv(args: RecvArgs) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_identity(&args.identity)?;
    let (bridge_url, bridge_pub_hex) = args
        .bridge
        .split_once('@')
        .ok_or("--bridge expected <url>@<pubkey-hex>")?;
    let bridge_pub = parse_hex32(bridge_pub_hex)?;
    let expect_from = parse_hex32(&args.expect_from)?;

    let (transport, bridge_addr) = Transport::connect_url(
        bridge_url,
        identity,
        TransportConfig {
            accept_any_peer: true,
            ..TransportConfig::default()
        },
    )
    .await?;
    let transport = Arc::new(transport);

    let bridge_handle = transport
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await?;
    let _ = transport.send_data(&bridge_handle, b".", 0, 0).await;

    println!("[evt] role=recv waiting for bytes from={} → {:?}",
        &args.expect_from[..16], args.out);

    // Write each chunk straight to disk. Defer hash check until
    // EOF marker arrives.
    let mut out = tokio::fs::File::create(&args.out).await?;
    use tokio::io::AsyncWriteExt;
    let mut hasher = Sha256::new();
    let mut got_bytes: u64 = 0;
    let mut got_chunks: u32 = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout_secs);
    let mut sender_total_bytes: Option<u64> = None;
    let mut sender_sha: Option<[u8; 32]> = None;

    loop {
        let timeout_left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout_left.is_zero() {
            println!("[evt] timeout");
            break;
        }
        let pkt = tokio::time::timeout(timeout_left, transport.recv()).await;
        let Ok(Some(pkt)) = pkt else { break };

        // Federation transparently re-keys peer_id to the
        // originating client's id. `federated_from` carries the
        // pubkey directly — use that for the sender check.
        let Some(from) = pkt.federated_from else { continue };
        if from != expect_from {
            continue;
        }
        if pkt.payload.is_empty() {
            continue;
        }
        match pkt.payload[0] {
            TAG_DATA => {
                // [tag=1][seq u32][bytes]
                if pkt.payload.len() < 5 {
                    continue;
                }
                let bytes = &pkt.payload[5..];
                hasher.update(bytes);
                out.write_all(bytes).await?;
                got_bytes += bytes.len() as u64;
                got_chunks += 1;
                if got_chunks % 100 == 0 {
                    println!(
                        "[evt] recv {} chunks / {} bytes",
                        got_chunks, got_bytes
                    );
                }
            }
            TAG_EOF => {
                // [tag=2][total u64][sha256:32]
                if pkt.payload.len() < 1 + 8 + 32 {
                    continue;
                }
                let mut total_bytes_buf = [0u8; 8];
                total_bytes_buf.copy_from_slice(&pkt.payload[1..9]);
                let total = u64::from_be_bytes(total_bytes_buf);
                let mut sha = [0u8; 32];
                sha.copy_from_slice(&pkt.payload[9..41]);
                sender_total_bytes = Some(total);
                sender_sha = Some(sha);
                println!("[evt] got EOF marker, draining...");
                break;
            }
            _ => {}
        }
    }
    out.flush().await?;
    drop(out);

    let my_sha = hasher.finalize();
    let m = transport.metrics();
    let total_ok = sender_total_bytes.map(|t| t == got_bytes).unwrap_or(false);
    let sha_ok = sender_sha
        .as_ref()
        .map(|s| s.as_slice() == my_sha.as_slice())
        .unwrap_or(false);

    println!(
        "[done] role=recv chunks={} bytes={} sender_total={} bytes_match={} sha_match={} my_sha={} sender_sha={} auth_fail={}",
        got_chunks,
        got_bytes,
        sender_total_bytes.unwrap_or(0),
        total_ok,
        sha_ok,
        hex::encode(my_sha),
        sender_sha.map(hex::encode).unwrap_or_else(|| "(none)".into()),
        m.auth_failures,
    );
    Ok(())
}

// ─── helpers ──────────────────────────────────────────────────────

fn load_identity(path: &std::path::Path) -> Result<Identity, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("reading {}: {}", path.display(), e))?;
    if bytes.len() == 36 && &bytes[..4] == b"DRFT" {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[4..]);
        return Ok(Identity::from_secret_bytes(secret));
    }
    if let Ok(s) = std::str::from_utf8(&bytes) {
        let trimmed = s.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let decoded = hex::decode(trimmed)?;
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&decoded);
            return Ok(Identity::from_secret_bytes(secret));
        }
    }
    Err(format!(
        "{} is neither DRFT-magic 36-byte binary nor 64 hex chars",
        path.display()
    )
    .into())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

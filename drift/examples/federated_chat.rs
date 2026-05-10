//! `federated-chat` — two clients separated by one or more
//! bridges, using `PacketType::Federated` envelopes instead of
//! the multi-hop mesh router.
//!
//! Each side:
//!   1. connects directly to its nearest bridge (via `--bridge`)
//!   2. registers the bridge as a normal peer + sends a 1-byte
//!      "warmup" so the local session establishes (HELLO is only
//!      kicked off when there's data to send)
//!   3. calls `Transport::send_federated(bridge_handle,
//!      target_bridge_pub, target_client_pub, payload)` which
//!      ships a Federated envelope to the local bridge; the bridge
//!      forwards by pubkey lookup to the destination bridge, which
//!      delivers to the destination client
//!   4. reads incoming via `Transport::recv()`; the `federated_from`
//!      field on `Received` carries the originating client's pubkey
//!
//! Usage:
//!
//! ```sh
//! federated-chat \
//!   --bridge udp://192.0.2.168:51820@<D2-pubkey-hex> \
//!   --target-bridge <D3-pubkey-hex> \
//!   --target-client <D4-pubkey-hex> \
//!   --count 5
//! ```
//!
//! Output is line-prefixed (`[evt]`, `[done]`) for grep-based
//! test harnesses.

use clap::Parser;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    /// Identity key file (64-hex-char DRIFT secret key, same on-
    /// disk format `drift keygen` writes). When omitted, a fresh
    /// random identity is generated — useful for ad-hoc tests
    /// where the peer pubkeys are discovered at startup, but
    /// NOT suitable when the test harness pre-knows the pubkeys
    /// (the harness's hex won't match the random runtime hex).
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Local bridge connection: <url>@<bridge-pubkey-hex>
    #[arg(long)]
    bridge: String,

    /// Destination bridge pubkey (hex). The bridge the target
    /// client is connected to.
    #[arg(long)]
    target_bridge: String,

    /// Target client pubkey (hex). The actual peer we want to
    /// exchange bytes with.
    #[arg(long)]
    target_client: String,

    /// Number of Federated DATA messages to send.
    #[arg(short, long, default_value = "5")]
    count: usize,

    /// Text body for each send; suffixed with #N + 32 random bytes.
    #[arg(long, default_value = "fed-msg")]
    send_text: String,

    /// Settle window after the local bridge handshake completes,
    /// before sending. Lets the bridge-to-bridge federation
    /// session finish establishing on the other side.
    #[arg(long, default_value = "3")]
    settle_secs: u64,

    /// Hard deadline for the receive loop.
    #[arg(long, default_value = "60")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let (bridge_url, bridge_pub_hex) = args
        .bridge
        .split_once('@')
        .ok_or("--bridge expected format <url>@<pubkey-hex>")?;
    let bridge_pub = parse_hex32(bridge_pub_hex)?;
    let target_bridge_pub = parse_hex32(&args.target_bridge)?;
    let target_client_pub = parse_hex32(&args.target_client)?;

    let identity = match &args.identity {
        Some(path) => load_identity_either_format(path)?,
        None => Identity::generate(),
    };
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);

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

    // Warmup byte to drive the bridge handshake. add_peer alone
    // never sends a HELLO; send_data does. Same trick the
    // `mesh-chat` example uses.
    let _ = transport
        .send_data(&bridge_handle, b".", 0, 0)
        .await;

    println!(
        "[evt] role=federated-chat my_pub={} bridge={} target_bridge={} target_client={} settle={}s",
        my_hex,
        &bridge_pub_hex[..16],
        &args.target_bridge[..16],
        &args.target_client[..16],
        args.settle_secs
    );

    // Receiver task.
    let recv_t = transport.clone();
    let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let mut got: usize = 0;
        while let Some(pkt) = recv_t.recv().await {
            // Only print packets that came in via federation.
            // Plain DRIFT DATA from the bridge (handshake echoes,
            // its periodic pings, etc.) we silently drain.
            let Some(from) = pkt.federated_from else {
                continue;
            };
            got += 1;
            let preview: String = pkt
                .payload
                .iter()
                .take(48)
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        char::from(*b)
                    } else {
                        '.'
                    }
                })
                .collect();
            println!(
                "[evt] recv #{} bytes={} from={} preview={:?}",
                got,
                pkt.payload.len(),
                &hex::encode(from)[..16],
                preview
            );
            let _ = got_tx.send(pkt.payload);
        }
    });

    // Give the local bridge handshake + the federation session
    // on the other side a moment to settle. We don't need beacons
    // to propagate (federation is direct lookup) but the bridge
    // ping-loop has to run at least once for the federation peer
    // session to be Established before we start sending.
    println!("[evt] waiting {}s for federation session to settle...", args.settle_secs);
    tokio::time::sleep(Duration::from_secs(args.settle_secs)).await;

    use rand::RngCore;
    for i in 0..args.count {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut msg = format!("{}#{} | ", args.send_text, i).into_bytes();
        msg.extend_from_slice(&hex::encode(nonce).into_bytes());

        match transport
            .send_federated(&bridge_handle, target_bridge_pub, target_client_pub, &msg)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                return Err(format!("send_federated #{} failed: {}", i, e).into());
            }
        }
        println!("[evt] sent #{} bytes={}", i + 1, msg.len());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Wait for inbound to converge or timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
    let mut got: usize = 0;
    while got < args.count {
        tokio::select! {
            r = got_rx.recv() => match r {
                Some(_) => got += 1,
                None => break,
            },
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    let m = transport.metrics();
    println!(
        "[done] role=federated-chat my_pub={} sent={} recv_msgs={} handshakes={} auth_fail={} packets_sent={} packets_recv={}",
        my_hex,
        args.count,
        got,
        m.handshakes_completed,
        m.auth_failures,
        m.packets_sent,
        m.packets_received,
    );
    Ok(())
}

/// Accept either of the two DRIFT identity-file formats on disk:
///
///   - 36-byte binary: `DRFT` magic + 32-byte secret (what
///     `drift keygen` writes by default)
///   - 64 hex chars + optional whitespace (what `drift-config
///     keygen` and `drift-vpn keygen` write)
fn load_identity_either_format(
    path: &std::path::Path,
) -> Result<Identity, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("reading {}: {}", path.display(), e))?;

    // Format 1: DRFT-magic 36-byte binary.
    if bytes.len() == 36 && &bytes[..4] == b"DRFT" {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[4..]);
        return Ok(Identity::from_secret_bytes(secret));
    }

    // Format 2: hex-encoded 32-byte secret.
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
        "{} is neither a DRFT-magic 36-byte file nor 64 hex chars (got {} bytes)",
        path.display(),
        bytes.len()
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

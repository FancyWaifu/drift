//! Client-machine side of the http+mesh demo.
//!
//! Stands up a drift node that:
//!   - LISTENS on $LISTEN_URL (typically http://0.0.0.0:PORT)
//!     for inbound peer connections — fronted by caddy in the
//!     demo compose
//!   - FEDERATES OUTBOUND to a remote bridge ($BRIDGE_URL +
//!     $BRIDGE_PUB), so the node is reachable through the mesh
//!     by peers that only know the remote bridge
//!   - DRAINS its own recv() loop, exiting 0 the first time it
//!     sees a packet whose payload contains $MAGIC (default
//!     "HTTP-MESH-DEMO"), or 1 after $TIMEOUT seconds
//!
//! Env:
//!   LISTEN_URL          — e.g. http://0.0.0.0:51820
//!   IDENTITY_FILE       — path to the drift keyfile for this node
//!   BRIDGE_URL          — e.g. udp://remote-bridge:51820
//!   BRIDGE_PUB          — 64-hex of the remote bridge's static pub
//!   MAGIC               — bytes we wait for (default "HTTP-MESH-DEMO")
//!   TIMEOUT_SECS        — give-up budget (default 30)

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let listen_url = std::env::var("LISTEN_URL").context("set LISTEN_URL")?;
    let identity_file = std::env::var("IDENTITY_FILE").context("set IDENTITY_FILE")?;
    let bridge_url = std::env::var("BRIDGE_URL").context("set BRIDGE_URL")?;
    let bridge_pub_hex =
        std::env::var("BRIDGE_PUB").context("set BRIDGE_PUB (64-hex)")?;
    let bridge_pub: [u8; 32] = hex::decode(&bridge_pub_hex)
        .context("BRIDGE_PUB is not hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("BRIDGE_PUB wrong length: {}", v.len()))?;
    let magic = std::env::var("MAGIC").unwrap_or_else(|_| "HTTP-MESH-DEMO".to_string());
    let timeout_secs: u64 = std::env::var("TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    // Load this node's identity from disk so its pubkey is
    // stable across runs (the demo runner needs to share the
    // pubkey out-of-band with the sender container).
    let secret_bytes = std::fs::read(&identity_file)
        .with_context(|| format!("read identity file {}", identity_file))?;
    // The drift keyfile is binary with a 4-byte "DRFT" magic
    // prefix; strip it. Mirrors the same handling sec/docker
    // already does for victim.key in the open-relay demo.
    let secret_payload: [u8; 32] = if secret_bytes.len() == 36 && &secret_bytes[..4] == b"DRFT" {
        secret_bytes[4..]
            .try_into()
            .expect("len 32 after strip")
    } else if secret_bytes.len() == 32 {
        secret_bytes[..]
            .try_into()
            .expect("len 32")
    } else {
        anyhow::bail!(
            "identity file is not 32 bytes (or 32+DRFT magic): got {}",
            secret_bytes.len()
        );
    };
    let me = Identity::from_secret_bytes(secret_payload);
    let my_pub_hex = hex::encode(me.public_bytes());
    eprintln!("[listener] my pubkey:    {}", my_pub_hex);
    eprintln!("[listener] LISTEN_URL:   {}", listen_url);
    eprintln!("[listener] BRIDGE_URL:   {}", bridge_url);
    eprintln!("[listener] BRIDGE_PUB:   {}", &bridge_pub_hex[..16]);
    eprintln!("[listener] waiting for payload contains {:?}", magic);

    let cfg = TransportConfig {
        // Accept any peer — this node is a bridge in the
        // architectural sense too. Real deployments would
        // pin allowed pubkeys.
        accept_any_peer: true,
        // Faster beacon to surface federation routes quickly
        // (mirrors `drift bridge`'s own bridge preset).
        beacon_interval_ms: 500,
        ..TransportConfig::default()
    };
    let (transport, _bound) = Transport::bind_url(&listen_url, me, cfg)
        .await
        .context("bind_url failed")?;
    eprintln!("[listener] listening on {}", listen_url);

    // Federate outbound to the remote bridge. connect_federate
    // does TCP/UDP/whatever-the-scheme-is connect + add_peer +
    // federation_table insert in one shot.
    let _federate_handle = transport
        .connect_federate(&bridge_url, bridge_pub)
        .await
        .context("connect_federate to remote bridge failed")?;
    eprintln!("[listener] federated to remote bridge");

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            let m = transport.metrics();
            anyhow::bail!(
                "LISTENER FAIL: didn't receive magic payload within {}s. \
                 metrics: packets_sent={} packets_received={} \
                 handshakes_completed={} forwarded={} \
                 hybrid_pq_handshakes_completed={}",
                timeout_secs, m.packets_sent, m.packets_received,
                m.handshakes_completed, m.forwarded,
                m.hybrid_pq_handshakes_completed
            );
        }
        match tokio::time::timeout(remaining, transport.recv()).await {
            Ok(Some(pkt)) => {
                let payload = String::from_utf8_lossy(&pkt.payload);
                eprintln!(
                    "[listener] recv from peer_id={} federated_from={:?} payload={:?}",
                    hex::encode(pkt.peer_id),
                    pkt.federated_from.map(|p| hex::encode(&p[..8])),
                    payload
                );
                if pkt.payload.windows(magic.len()).any(|w| w == magic.as_bytes()) {
                    println!("LISTENER PASS: magic payload received through the mesh");
                    return Ok(());
                }
            }
            Ok(None) => {
                anyhow::bail!("LISTENER FAIL: recv channel closed");
            }
            Err(_) => {
                continue; // timeout, loop to check deadline
            }
        }
    }
}

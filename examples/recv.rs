//! drift-recv: receives position updates.
//!
//! Phase 4: identity-based. Uses deterministic fixture keys so the demo
//! runs without manual key exchange.

use drift::identity::Identity;
use drift::{Direction, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=debug,drift_recv=info".into()),
        )
        .init();

    let server_identity = Identity::from_secret_bytes([0x22; 32]);
    let client_pub = Identity::from_secret_bytes([0x11; 32]).public_bytes();

    let transport = Transport::bind("0.0.0.0:9000".parse()?, server_identity).await?;
    println!("receiver bound to {}", transport.local_addr()?);
    println!("server peer_id: {}", hex(&transport.local_peer_id()));
    println!("server pubkey: {}", hex(&transport.local_public()));

    // Responder: we wait for the client's HELLO rather than initiate.
    transport
        .add_peer(client_pub, "0.0.0.0:0".parse()?, Direction::Responder)
        .await
        .unwrap();

    loop {
        let pkt = match transport.recv().await {
            Some(p) => p,
            None => break Ok(()),
        };
        if pkt.payload.len() >= 12 {
            let x = f32::from_be_bytes(pkt.payload[0..4].try_into().unwrap());
            let y = f32::from_be_bytes(pkt.payload[4..8].try_into().unwrap());
            let tick = u32::from_be_bytes(pkt.payload[8..12].try_into().unwrap());
            println!(
                "recv seq={} group={} tick={} pos=({:.2},{:.2})",
                pkt.seq, pkt.supersedes, tick, x, y
            );
        } else {
            println!("recv seq={} {} bytes", pkt.seq, pkt.payload.len());
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

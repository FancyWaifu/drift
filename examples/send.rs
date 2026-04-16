//! drift-send: sends coalesced "position updates" with deadlines.
//!
//! Usage:
//!   drift-send <target_addr> [--via <relay_addr>]
//!
//! If --via is provided, the target_addr is just informational (the actual
//! destination identity is derived from the built-in demo server key) and
//! packets are routed through the given relay first. Without --via,
//! drift-send talks directly to <target_addr>.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info,drift_send=info".into()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let target: std::net::SocketAddr = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:9000")
        .parse()?;

    // Optional --via <relay_addr>, --listen <addr>, --deadline <ms>
    let mut via: Option<std::net::SocketAddr> = None;
    let mut listen: std::net::SocketAddr = "0.0.0.0:0".parse()?;
    let mut deadline_ms: u16 = 200;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--via" {
            via = Some(args[i + 1].parse()?);
            i += 2;
        } else if args[i] == "--listen" {
            listen = args[i + 1].parse()?;
            i += 2;
        } else if args[i] == "--deadline" {
            deadline_ms = args[i + 1].parse()?;
            i += 2;
        } else {
            i += 1;
        }
    }

    let client_identity = Identity::from_secret_bytes([0x11; 32]);
    let server_pub = Identity::from_secret_bytes([0x22; 32]).public_bytes();
    let server_peer_id = derive_peer_id(&server_pub);

    let transport = Transport::bind(listen, client_identity).await?;
    println!("sender bound to {}", transport.local_addr()?);

    // If routing via a relay: register the server as a peer with a
    // placeholder address, then add a route to send through the relay.
    // Otherwise send directly.
    let peer_id = if let Some(relay) = via {
        println!("routing via relay {}", relay);
        let id = transport
            .add_peer(server_pub, target, Direction::Initiator)
            .await.unwrap();
        transport.add_route(server_peer_id, relay).await;
        id
    } else {
        transport
            .add_peer(server_pub, target, Direction::Initiator)
            .await.unwrap()
    };

    let mut x: f32 = 0.0;
    let mut y: f32 = 0.0;
    let mut seq_count: u32 = 0;
    loop {
        x += 1.5;
        y += 0.25;
        seq_count += 1;

        let mut payload = Vec::with_capacity(12);
        payload.extend_from_slice(&x.to_be_bytes());
        payload.extend_from_slice(&y.to_be_bytes());
        payload.extend_from_slice(&seq_count.to_be_bytes());

        transport.send_data(&peer_id, &payload, deadline_ms, 1).await?;

        println!("sent tick={} pos=({:.2},{:.2})", seq_count, x, y);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

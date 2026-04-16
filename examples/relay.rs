//! drift-relay: a standalone mesh relay.
//!
//! Takes a listen address and one or more static routes, binds a
//! Transport with no registered peers, and forwards any routable
//! packets it receives. Used for multi-container mesh tests.
//!
//! Usage:
//!   drift-relay <listen_addr> <route_id_hex>:<next_hop_addr> [...]
//!
//! Example (a relay listening on :9000 that forwards packets destined
//! for peer id 8d7bdef7c1f55505 to 10.30.0.4:9000):
//!
//!   drift-relay 0.0.0.0:9000 8d7bdef7c1f55505:10.30.0.4:9000

use drift::identity::Identity;
use drift::Transport;
use std::net::SocketAddr;

fn parse_route(s: &str) -> ([u8; 8], SocketAddr) {
    // Format: "hexid:host:port"
    let first_colon = s.find(':').expect("missing : in route");
    let id_hex = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];
    assert_eq!(id_hex.len(), 16, "peer id must be 16 hex chars (8 bytes)");
    let mut id = [0u8; 8];
    for i in 0..8 {
        id[i] = u8::from_str_radix(&id_hex[i * 2..i * 2 + 2], 16).expect("bad hex");
    }
    let addr: SocketAddr = addr_str.parse().expect("bad addr");
    (id, addr)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info,drift_relay=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <listen> <hexid:host:port> [more routes...]",
            args[0]
        );
        std::process::exit(2);
    }
    let listen: SocketAddr = args[1].parse()?;

    // Random identity — the relay doesn't authenticate anyone; it only
    // forwards packets that aren't addressed to its own peer id.
    let identity = Identity::generate();
    let transport = Transport::bind(listen, identity).await?;
    println!(
        "relay bound to {} (peer_id={})",
        transport.local_addr()?,
        hex(&transport.local_peer_id())
    );

    for route in &args[2..] {
        let (id, addr) = parse_route(route);
        transport.add_route(id, addr).await;
        println!("  route {} -> {}", hex(&id), addr);
    }

    // Run forever. The background receive task handles forwarding
    // automatically; we just need to stay alive.
    std::future::pending::<()>().await;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

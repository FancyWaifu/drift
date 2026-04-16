//! scale-client: a client with a unique identity derived from an
//! integer seed, used for multi-client scale tests.
//!
//! Usage:
//!   scale-client <server_addr> <seed_int> [--count N] [--interval_ms MS]

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let server_addr: std::net::SocketAddr = args[1].parse()?;
    let seed: u32 = args[2].parse()?;

    let mut count: u32 = 50;
    let mut interval_ms: u64 = 20;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                count = args[i + 1].parse()?;
                i += 2;
            }
            "--interval_ms" => {
                interval_ms = args[i + 1].parse()?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Unique identity from seed.
    let mut secret = [0u8; 32];
    secret[..4].copy_from_slice(&seed.to_be_bytes());
    secret[4] = 0xCC;
    let client_id = Identity::from_secret_bytes(secret);
    // Server identity is fixed (matches what drift-recv uses for its
    // TRUSTED peer lookups — scale-server uses a different scheme).
    // Here we use a specific server_pub supplied indirectly via the
    // scale-server's known secret.
    let server_pub = Identity::from_secret_bytes([0xEE; 32]).public_bytes();

    let transport = Transport::bind("0.0.0.0:0".parse()?, client_id).await?;
    let peer = transport
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await.unwrap();

    for i in 0..count {
        let mut buf = Vec::new();
        buf.extend_from_slice(&seed.to_be_bytes());
        buf.extend_from_slice(&i.to_be_bytes());
        transport.send_data(&peer, &buf, 0, 0).await?;
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    }
    // Drain time.
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("client seed={} done ({} packets)", seed, count);
    Ok(())
}

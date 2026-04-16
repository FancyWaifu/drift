//! big-send: like drift-send but with configurable payload size.
//! Used to probe MTU edges.
//!
//! Usage: big-send <addr> <payload_bytes>

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let addr: std::net::SocketAddr = args[1].parse()?;
    let size: usize = args[2].parse()?;

    let client = Identity::from_secret_bytes([0x11; 32]);
    let server_pub = Identity::from_secret_bytes([0x22; 32]).public_bytes();

    let transport = Transport::bind("0.0.0.0:0".parse()?, client).await?;
    let peer = transport
        .add_peer(server_pub, addr, Direction::Initiator)
        .await.unwrap();

    println!("big-send: addr={} size={}", addr, size);

    let payload = vec![0xABu8; size];
    for i in 0..30u32 {
        transport
            .send_data(&peer, &payload, 0, 0)
            .await
            .unwrap();
        println!("sent #{}, {} bytes", i + 1, size);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

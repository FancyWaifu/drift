//! Minimal DRIFT echo server used by the resumption compose
//! test. Binds to 0.0.0.0:9100, accepts handshakes from a
//! single known client identity, echoes every DATA payload it
//! receives to stdout. Exits cleanly on SIGTERM so docker
//! compose can tear it down.

use drift::identity::Identity;
use drift::{Direction, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let server_identity = Identity::from_secret_bytes([0x22; 32]);
    let client_pub = Identity::from_secret_bytes([0x11; 32]).public_bytes();

    let transport = Transport::bind("0.0.0.0:9100".parse()?, server_identity).await?;
    println!("resumption-server: bound {}", transport.local_addr()?);
    println!(
        "resumption-server: pubkey={}",
        hex(&transport.local_public())
    );

    transport
        .add_peer(client_pub, "0.0.0.0:0".parse()?, Direction::Responder)
        .await?;

    loop {
        let pkt = match transport.recv().await {
            Some(p) => p,
            None => break,
        };
        let m = transport.metrics();
        println!(
            "server: recv {} bytes | full_handshakes={} resumptions={} tickets_issued={}",
            pkt.payload.len(),
            m.handshakes_completed,
            m.resumptions_completed,
            m.resumption_tickets_issued
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

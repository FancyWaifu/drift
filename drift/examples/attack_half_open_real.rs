//! Open N real DRIFT handshakes against the bridge from N
//! ephemeral identities, then NEVER complete them (we send HELLO,
//! receive HELLO_ACK, then go silent). Watch the bridge's peer
//! table grow — does it cap, evict, or grow unbounded?
//!
//! This is the "real" half-open attack — unlike garbage UDP that
//! gets dropped at the AEAD layer, these HELLOs are properly
//! signed and the bridge SHOULD create peer state for each one.
//! The question is whether that state is bounded.
//!
//! Usage:
//!   cargo run --release --example attack_half_open_real -p drift -- \
//!     <bridge_url> <bridge_pub_hex> <N>

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} <bridge_url> <bridge_pub_hex> <N>", args[0]);
        std::process::exit(1);
    }
    let bridge_url = args[1].clone();
    let bridge_pub_hex = &args[2];
    let n: usize = args[3].parse().context("N")?;

    let mut bp = [0u8; 32];
    bp.copy_from_slice(&hex::decode(bridge_pub_hex)?);

    println!("Firing {} half-open handshakes against {}…", n, bridge_url);
    let mut transports = Vec::with_capacity(n);
    let mut failures = 0;
    for i in 0..n {
        let id = Identity::generate();
        let result = Transport::connect_url(&bridge_url, id, TransportConfig::default()).await;
        match result {
            Ok((t, addr)) => {
                let t = Arc::new(t);
                if let Ok(pid) = t.add_peer(bp, addr, Direction::Initiator).await {
                    // Trigger HELLO. Don't wait for HELLO_ACK.
                    let _ = t.send_data(&pid, b".", 0, 0).await;
                    transports.push(t);
                } else {
                    failures += 1;
                }
            }
            Err(_) => failures += 1,
        }
        if (i + 1) % 100 == 0 {
            println!("  {}/{} started", i + 1, n);
        }
    }
    println!("Started {} (failures: {})", transports.len(), failures);

    // Hold them all idle for 30s so the bridge sees them as
    // long-lived half-open sessions.
    println!("Holding idle for 30s…");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Drop them — release client side. Server-side state should
    // eventually evict.
    println!("Dropping client side; bridge should evict over time…");
    drop(transports);
    Ok(())
}

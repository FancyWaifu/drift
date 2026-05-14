//! Stream-layer abuse post-Established. Open a real session with
//! the bridge, then attempt to flood the stream table with
//! 10000 OPEN frames. MAX_STREAMS_PER_PEER should cap us.
//!
//! This is the WORST case for an attacker: a real session
//! (passed AEAD + cookie if any), then trying to exhaust
//! per-peer state. If the cap works, the bridge's memory and
//! `live_streams_for(peer)` should stay bounded.
//!
//! Usage:
//!   cargo run --release --example attack_stream_flood -p drift -- \
//!     <bridge_url> <bridge_pub_hex> <N>

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::streams::StreamManager;
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
    let url = &args[1];
    let mut bp = [0u8; 32];
    bp.copy_from_slice(&hex::decode(&args[2])?);
    let n: usize = args[3].parse()?;

    let attacker = Identity::generate();
    let (transport, addr) =
        Transport::connect_url(url, attacker, TransportConfig::default()).await?;
    let transport = Arc::new(transport);
    let bridge_pid = transport.add_peer(bp, addr, Direction::Initiator).await?;
    let _ = transport.send_data(&bridge_pid, b".", 0, 0).await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if transport.peer_is_established(&bridge_pid).await {
            break;
        }
    }
    if !transport.peer_is_established(&bridge_pid).await {
        anyhow::bail!("handshake didn't complete");
    }
    println!("✓ session established");

    let sm = StreamManager::bind(transport.clone()).await;
    let mut opened = 0;
    let mut failed = 0;
    for i in 0..n {
        match sm.open(bridge_pid).await {
            Ok(_) => opened += 1,
            Err(e) => {
                failed += 1;
                if failed <= 3 {
                    println!("open #{} failed: {}", i, e);
                }
            }
        }
        if (i + 1) % 500 == 0 {
            println!("  attempted {} (opened={}, failed={})", i + 1, opened, failed);
        }
    }
    println!("Done: opened={}, failed={}", opened, failed);
    Ok(())
}

//! Remote-peer side of the http+mesh demo.
//!
//! Connects to a remote drift bridge ($BRIDGE_URL + $BRIDGE_PUB),
//! then addresses a packet to $TARGET_PUB (the client-machine
//! node's pubkey). The bridge's mesh routing — populated by the
//! beacons that flow over the federation link to the
//! client-machine node — forwards the packet from the bridge to
//! the client machine. The client-machine node delivers the
//! packet locally.
//!
//! Env:
//!   BRIDGE_URL  — e.g. udp://remote-bridge:51820
//!   BRIDGE_PUB  — remote bridge's static pubkey (64-hex)
//!   TARGET_PUB  — client-machine node's pubkey (64-hex)
//!   MAGIC       — payload bytes (default "HTTP-MESH-DEMO")
//!   TRIES       — how many send attempts before giving up
//!                 (default 60, with ~500 ms backoff between)

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let bridge_url = std::env::var("BRIDGE_URL").context("set BRIDGE_URL")?;
    let bridge_pub_hex =
        std::env::var("BRIDGE_PUB").context("set BRIDGE_PUB (64-hex)")?;
    let target_pub_hex =
        std::env::var("TARGET_PUB").context("set TARGET_PUB (64-hex)")?;
    let magic = std::env::var("MAGIC").unwrap_or_else(|_| "HTTP-MESH-DEMO".to_string());
    let tries: u32 = std::env::var("TRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let bridge_pub: [u8; 32] = hex::decode(&bridge_pub_hex)
        .context("BRIDGE_PUB hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("BRIDGE_PUB len {}", v.len()))?;
    let target_pub: [u8; 32] = hex::decode(&target_pub_hex)
        .context("TARGET_PUB hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("TARGET_PUB len {}", v.len()))?;

    eprintln!("[sender] BRIDGE_URL={}", bridge_url);
    eprintln!("[sender] BRIDGE_PUB={}", &bridge_pub_hex[..16]);
    eprintln!("[sender] TARGET_PUB={}", &target_pub_hex[..16]);
    eprintln!("[sender] MAGIC={:?}", magic);

    let me = Identity::generate();
    let cfg = TransportConfig {
        handshake_max_attempts: 5,
        handshake_retry_base_ms: 500,
        ..TransportConfig::default()
    };

    let (transport, bridge_addr) = Transport::connect_url(&bridge_url, me, cfg)
        .await
        .context("connect_url to remote bridge")?;
    eprintln!("[sender] connected to bridge at {}", bridge_addr);

    // Register the bridge as a peer so we can drive the
    // handshake.
    let _bridge_handle = transport
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await
        .context("add_peer bridge")?;
    // Register the TARGET as a mesh peer — bridge will be the
    // hop. We use an unroutable placeholder addr; mesh routing
    // figures out the real next-hop.
    let target_handle = transport
        .add_peer(target_pub, "0.0.0.0:0".parse().unwrap(), Direction::Initiator)
        .await
        .context("add_peer target")?;

    // Retry loop — federation routes take a few beacon ticks
    // to converge. We send the magic payload; if it can't
    // route yet, drift will return an error / silently drop and
    // we try again.
    for attempt in 0..tries {
        let body = format!("{} attempt-{}", magic, attempt);
        match transport
            .send_data(&target_handle, body.as_bytes(), 5000, 0)
            .await
        {
            Ok(_) => {
                eprintln!("[sender] attempt {}: send_data ok", attempt);
                // Send a few extras to defeat any early-routing
                // races — by the time the listener's recv loop
                // wakes up, at least one of these should have
                // arrived along an established route.
                for i in 0..5u32 {
                    let extra = format!("{} salvo-{}", magic, i);
                    let _ = transport
                        .send_data(&target_handle, extra.as_bytes(), 5000, 0)
                        .await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                println!("SENDER PASS: dispatched {} packet(s) to target via bridge", 6);
                return Ok(());
            }
            Err(e) => {
                eprintln!("[sender] attempt {}: send err {:?}", attempt, e);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("SENDER FAIL: gave up after {} attempts", tries);
}

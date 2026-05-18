//! End-to-end smoke for `drift http://` behind a reverse proxy.
//!
//! Run as a one-shot container after the bridge + proxy are up.
//! Reads two env vars:
//!
//!   - DRIFT_URL          — e.g. `http://caddy:8080` (the proxy)
//!   - DRIFT_BRIDGE_PUB   — 64-hex bridge static pubkey
//!
//! Opens a DRIFT session via the URL, sends one DATA packet, and
//! waits until the peer-metrics report Established. Exits 0 on
//! success, non-zero on any failure (with a diagnostic line).
//!
//! The whole point is to prove that:
//!   - drift's hyper-based http:// listener works
//!   - caddy (or whatever proxy) correctly tunnels SSE + POST
//!   - --trust-proxy-headers + cap-skipping doesn't break the path
//!   - DRIFT's own AEAD handshake completes over the proxied wire

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("DRIFT_URL")
        .context("set DRIFT_URL — e.g. http://caddy:8080")?;
    let bridge_pub_hex = std::env::var("DRIFT_BRIDGE_PUB")
        .context("set DRIFT_BRIDGE_PUB — 64-hex of the bridge's static pubkey")?;
    let bridge_pub: [u8; 32] = hex::decode(&bridge_pub_hex)
        .context("DRIFT_BRIDGE_PUB is not valid hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("DRIFT_BRIDGE_PUB wrong length: {}", v.len()))?;

    eprintln!("[probe] DRIFT_URL = {}", url);
    eprintln!("[probe] DRIFT_BRIDGE_PUB = {}", &bridge_pub_hex[..16]);
    eprintln!("[probe] opening connect_url …");

    // Generate a fresh ephemeral identity. We don't need to be a
    // known peer of the bridge — `accept_any_peer` lets anyone in,
    // and the test is purely "does the wire round-trip through
    // the proxy?", not "does authorization work?"
    let me = Identity::generate();
    let cfg = TransportConfig {
        handshake_max_attempts: 5,
        handshake_retry_base_ms: 500,
        ..TransportConfig::default()
    };

    let (transport, peer_addr) = Transport::connect_url(&url, me, cfg)
        .await
        .context("Transport::connect_url failed — proxy unreachable or wire broken")?;
    eprintln!("[probe] SSE up; bridge peer_addr (synthesized) = {}", peer_addr);

    let bridge_handle = transport
        .add_peer(bridge_pub, peer_addr, Direction::Initiator)
        .await
        .context("add_peer failed")?;

    // Trigger the HELLO. send_data is lazy — it kicks off the
    // handshake on the first call. Payload content doesn't matter
    // for the test; we just need the bridge to AEAD-verify the
    // first DATA frame, which proves handshake completion.
    transport
        .send_data(&bridge_handle, b"http-probe-hello", 5000, 0)
        .await
        .context("send_data on bridge handle failed")?;
    eprintln!("[probe] HELLO sent; waiting for Established …");

    // Poll peer_metrics for is_established. Budget: 10 s total at
    // 100 ms granularity. With the default handshake_retry_base_ms
    // of 1000 we'd see retries every second; 10s = ~10 attempts.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pm) = transport.peer_metrics(&bridge_handle).await {
            if pm.is_established {
                eprintln!(
                    "[probe] PASS — session Established (srtt={:?}, next_tx_seq={})",
                    pm.srtt, pm.next_tx_seq
                );
                println!(
                    "PROBE PASS: drift http:// session established through reverse proxy"
                );
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            let m = transport.metrics();
            anyhow::bail!(
                "PROBE FAIL: handshake never reached Established within 10 s. \
                 metrics: packets_sent={} packets_received={} handshake_retries={} \
                 auth_failures={} handshakes_completed={}",
                m.packets_sent,
                m.packets_received,
                m.handshake_retries,
                m.auth_failures,
                m.handshakes_completed,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

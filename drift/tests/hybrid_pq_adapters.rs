//! Hybrid PQ handshake over every shipped wire scheme.
//!
//! Goal: confirm a ~1.3 KB HELLO survives each adapter's
//! framing / max-size constraints. If any adapter can't carry it,
//! that's a blocker for flipping `hybrid_pq` on by default.
//!
//! Schemes exercised:
//!   - udp://   — single datagram, fits comfortably under 1500 MTU
//!   - tcp://   — length-prefixed frames, no upper bound
//!   - ws://    — WebSocket binary frames, arbitrary size
//!   - tls://   — TLS records up to 16 KB
//!   - http://  — base64-SSE; ~70% inflation, ~2.2 KB → still tiny
//!   - dns://   — EDNS0 UDP up to 1232 B default; PQ HELLO is 1300+ →
//!                expected to fall back to TCP per-message
//!
//! Each subtest spawns a server on the given scheme, dials with
//! a hybrid client, asserts the session establishes + DATA flows.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn pq_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        ..Default::default()
    }
}

/// Stand up a PQ server on `listen_url`, dial it with a PQ
/// client whose `connect_url` matches, send one DATA message,
/// assert the message comes back through. Returns Ok(()) on
/// success.
async fn pq_handshake_over(listen_url: &str, dial_template: &str) -> anyhow::Result<()> {
    let server_id = Identity::generate();
    let server_pub = server_id.public_bytes();
    let (server, bound_url) = Transport::bind_url(listen_url, server_id, pq_cfg()).await?;
    let server = Arc::new(server);
    eprintln!("[{}] server bound at {}", listen_url, bound_url);

    let client_id = Identity::generate();
    let client_pub = client_id.public_bytes();

    // Substitute the actually-bound port (and host) into the dial
    // template. Tests use ":0" for ephemeral ports; the bound_url
    // tells us what the server actually got.
    let dial_url = dial_template.replace("__BOUND__", strip_scheme(&bound_url));

    let (client, server_addr) = Transport::connect_url(&dial_url, client_id, pq_cfg()).await?;
    let client = Arc::new(client);

    server
        .add_peer(client_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await?;
    let server_handle = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await?;

    client
        .send_data(&server_handle, b"hello-pq-over-wire", 0, 0)
        .await?;

    let pkt = timeout(Duration::from_secs(8), server.recv())
        .await
        .map_err(|_| anyhow::anyhow!("recv timeout"))?
        .ok_or_else(|| anyhow::anyhow!("recv returned None"))?;
    assert_eq!(pkt.payload, b"hello-pq-over-wire", "payload mismatch");

    let m = server.metrics();
    assert!(
        m.hybrid_pq_handshakes_completed >= 1,
        "server metrics didn't show a PQ handshake: {:?}",
        m
    );
    Ok(())
}

fn strip_scheme(url: &str) -> &str {
    url.split_once("://").map(|(_, rest)| rest).unwrap_or(url)
}

#[tokio::test]
async fn pq_over_udp() {
    pq_handshake_over("udp://127.0.0.1:0", "udp://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test]
async fn pq_over_tcp() {
    pq_handshake_over("tcp://127.0.0.1:0", "tcp://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test]
async fn pq_over_ws() {
    pq_handshake_over("ws://127.0.0.1:0", "ws://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test]
async fn pq_over_tls() {
    pq_handshake_over("tls://127.0.0.1:0", "tls://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test]
async fn pq_over_http() {
    pq_handshake_over("http://127.0.0.1:0", "http://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pq_over_h2() {
    pq_handshake_over("h2://127.0.0.1:0", "h2://__BOUND__")
        .await
        .unwrap();
}

#[tokio::test]
async fn pq_over_dns() {
    // dns:// is the most likely failure point — EDNS0 default
    // payload is 1232 B and the hybrid HELLO is ~1300 B. If
    // this fails we either bump EDNS0 or document dns:// as a
    // PQ-incompatible wire.
    match pq_handshake_over("dns://127.0.0.1:0", "dns://__BOUND__").await {
        Ok(_) => eprintln!("dns:// carries hybrid PQ HELLO ✓"),
        Err(e) => panic!("dns:// failed PQ handshake: {}", e),
    }
}

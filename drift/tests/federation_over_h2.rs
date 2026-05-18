//! Federation over the h2:// adapter.
//!
//! Two drift transports each bind h2://127.0.0.1:0. One opens a
//! federation link to the other (single HTTP/2 connection). We
//! drive a HELLO/data round-trip through that link to prove
//! drift packets actually flow over the bidirectional HTTP/2
//! stream pair.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

fn cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 200,
        ..TransportConfig::default()
    }
}

fn strip_scheme(url: &str) -> &str {
    url.split_once("://").map(|(_, rest)| rest).unwrap_or(url)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_can_handshake_over_h2_stream() {
    // Bob's node listens on h2://.
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let bob_pub = bob_id.public_bytes();
    let (bob, bob_url) = Transport::bind_url("h2://127.0.0.1:0", bob_id, cfg())
        .await
        .expect("bob bind h2");
    let bob = Arc::new(bob);
    let bob_addr = strip_scheme(&bob_url);
    eprintln!("[test] bob listening at {}", bob_url);

    // Alice connects to Bob over h2://.
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let dial_url = format!("h2://{}", bob_addr);
    let (alice, peer_addr) = Transport::connect_url(&dial_url, alice_id, cfg())
        .await
        .expect("alice connect h2");
    let alice = Arc::new(alice);
    eprintln!("[test] alice connected; peer_addr={}", peer_addr);

    let bob_handle = alice
        .add_peer(bob_pub, peer_addr, Direction::Initiator)
        .await
        .expect("add_peer bob");

    // Trigger the handshake.
    alice
        .send_data(&bob_handle, b"hello-over-h2", 5000, 0)
        .await
        .expect("send_data");

    // Bob should receive the message.
    let pkt = tokio::time::timeout(Duration::from_secs(5), bob.recv())
        .await
        .expect("recv timed out")
        .expect("recv returned None");
    assert_eq!(pkt.payload, b"hello-over-h2");
    eprintln!("[test] bob got: {:?}", String::from_utf8_lossy(&pkt.payload));
}

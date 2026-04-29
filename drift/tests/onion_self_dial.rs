//! End-to-end smoke test for the `onion://` adapter.
//!
//! Spins up an onion service in-process, retrieves its
//! `<base32>.onion` address, and dials it back through the
//! same `TorClient`. Proves three things at once:
//!
//! 1. arti bootstraps successfully (~30s).
//! 2. `OnionListenerIO::bind` publishes a descriptor that's
//!    actually retrievable from the live Tor network (~60–120s
//!    for HSDir publication).
//! 3. The full DRIFT handshake (HELLO / HELLO-ACK / DATA) survives
//!    the Tor circuit + length-prefix framing on top of arti's
//!    `DataStream`.
//!
//! Total wall-clock when running: 3–5 minutes. Requires internet
//! and the live Tor network. Gated behind `#[ignore]` so it never
//! runs on `cargo test`; invoke manually:
//!
//! ```text
//! cargo test --features onion --release \
//!     --test onion_self_dial -- --ignored --nocapture
//! ```

#![cfg(feature = "onion")]

use drift::identity::Identity;
use drift::io::Listener;
use drift::wire_onion::OnionListenerIO;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires internet + ~3-5 min for Tor bootstrap & HSDir publication"]
async fn drift_self_dial_through_tor() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info,arti_client=warn".into()),
        )
        .try_init();

    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    eprintln!("[onion-test] bootstrapping arti + launching Bob's onion service...");
    // The host portion is ignored; the port is just a hint.
    let mut bob_listener = OnionListenerIO::bind("0.0.0.0:9999".to_string())
        .await
        .expect("OnionListenerIO::bind");
    let onion_addr = bob_listener
        .onion_address()
        .expect("onion_address available")
        .to_string();
    eprintln!("[onion-test] Bob is at {}", onion_addr);

    // Wait a generous amount of time for descriptor publication
    // before Alice tries to look it up. Without this, Alice's
    // first dial typically fails with "no descriptor for service".
    eprintln!("[onion-test] sleeping 90s for HSDir publication...");
    tokio::time::sleep(Duration::from_secs(90)).await;

    // Bob's accept loop runs in the background, attaching each
    // accepted PacketIO to a Transport. Only one client is
    // expected for this test, but the loop pattern matches what
    // a real server does.
    let (bob_tx, mut bob_rx) =
        tokio::sync::mpsc::channel::<Arc<dyn drift::io::PacketIO>>(1);
    let _accept_task = tokio::spawn(async move {
        match bob_listener.accept().await {
            Ok(io) => {
                let _ = bob_tx.send(io).await;
            }
            Err(e) => eprintln!("[onion-test] Bob accept error: {}", e),
        }
    });

    eprintln!("[onion-test] Alice dialing {}", onion_addr);
    let dial_url = format!("onion://{}:9999", onion_addr);
    let (alice_t, _alice_peer_key) =
        Transport::connect_url(&dial_url, alice_id, TransportConfig::default())
            .await
            .expect("Alice connect_url");

    let bob_io = tokio::time::timeout(Duration::from_secs(120), bob_rx.recv())
        .await
        .expect("Bob accept timeout")
        .expect("Bob accept channel closed");
    eprintln!("[onion-test] Bob accepted Alice's stream");

    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .expect("Bob bind_with_io"),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .expect("Bob add_peer alice");

    let alice_t = Arc::new(alice_t);
    let bob_peer = alice_t
        .add_peer(bob_pub, "0.0.0.0:0".parse().unwrap(), Direction::Initiator)
        .await
        .expect("Alice add_peer bob");

    // Send a DATA packet. Triggers the full HELLO → HELLO-ACK →
    // DATA handshake, all riding the Tor circuit.
    alice_t
        .send_data(&bob_peer, b"hello over tor", 0, 0)
        .await
        .expect("Alice send_data");
    eprintln!("[onion-test] Alice sent DATA");

    let received = tokio::time::timeout(Duration::from_secs(30), bob_t.recv())
        .await
        .expect("Bob recv timeout")
        .expect("Bob recv error");
    assert_eq!(received.payload.as_slice(), b"hello over tor");
    eprintln!("[onion-test] Bob received DATA — round trip OK");
}

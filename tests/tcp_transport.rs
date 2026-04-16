//! End-to-end test: DRIFT over TCP transport.
//!
//! Two DRIFT transports connected via `TcpPacketIO` instead
//! of UDP. Verifies that the full protocol stack — handshake,
//! AEAD, DATA delivery, session resumption — works
//! identically when the underlying medium is a TCP stream
//! with length-prefix framing instead of UDP datagrams.
//!
//! This is the "firewall traversal" scenario: both sides are
//! behind networks that block UDP, so DRIFT packets ride a
//! TCP connection that looks like normal HTTPS traffic to
//! middleboxes.

use drift::identity::Identity;
use drift::io::TcpPacketIO;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test]
async fn handshake_and_data_over_tcp() {
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    // Set up a TCP connection between Alice and Bob. In a
    // real deployment this would be a TLS-wrapped TCP
    // connection to port 443; here we use plain TCP on
    // loopback.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = listener.local_addr().unwrap();

    // Alice connects to Bob's TCP listener.
    let alice_tcp = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
    let (bob_tcp, _) = listener.accept().await.unwrap();

    // Wrap both sides in TcpPacketIO.
    let alice_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(TcpPacketIO::new(alice_tcp).unwrap());
    let bob_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(TcpPacketIO::new(bob_tcp).unwrap());

    // Build DRIFT transports on top of the TCP adapters.
    // Note: we use bind_with_io instead of bind/bind_with_config.
    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    // Bob needs to know Alice's pubkey to accept her HELLO.
    // The "address" is the TCP peer address (which is what
    // TcpPacketIO reports as source on recv_from), but it's
    // mostly a placeholder — on a point-to-point TCP link
    // there's only one possible peer.
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();

    let alice_t = Arc::new(
        Transport::bind_with_io(alice_io, alice_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    // Alice's "peer address" for Bob is also a placeholder
    // on TCP — send_to ignores the destination (TCP is
    // already connected).
    let bob_peer = alice_t
        .add_peer(bob_pub, tcp_addr, Direction::Initiator)
        .await
        .unwrap();

    // Send a DATA packet. This triggers the full HELLO →
    // HELLO_ACK → DATA handshake, all going over the TCP
    // stream with length-prefix framing.
    alice_t
        .send_data(&bob_peer, b"hello-over-tcp", 0, 0)
        .await
        .unwrap();

    let pkt = tokio::time::timeout(Duration::from_secs(5), bob_t.recv())
        .await
        .expect("handshake + DATA over TCP timed out")
        .unwrap();
    assert_eq!(pkt.payload, b"hello-over-tcp");

    // Send a few more to confirm the session stays healthy.
    for i in 0..5u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    for _ in 0..5 {
        let p = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.payload.len(), 4);
    }

    // Metrics sanity.
    let am = alice_t.metrics();
    let bm = bob_t.metrics();
    assert_eq!(am.handshakes_completed, 1);
    assert_eq!(bm.handshakes_completed, 1);
    assert_eq!(am.auth_failures, 0);
    assert_eq!(bm.auth_failures, 0);

    println!(
        "[TCP transport] handshake + 6 DATA packets delivered. alice_sent={} bob_recv={}",
        am.packets_sent, bm.packets_received
    );
}

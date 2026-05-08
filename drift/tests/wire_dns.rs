//! End-to-end test: DRIFT over the `dns://` adapter.
//!
//! Two DRIFT transports talking through `DnsPacketIO` instead
//! of `UdpPacketIO`. Verifies that the full protocol stack —
//! handshake, AEAD, DATA delivery, multi-packet stream — works
//! identically when the underlying medium is DNS-shaped UDP
//! traffic with QNAME-encoded fragments and reassembly.
//!
//! This is the "everything else is blocked" scenario: UDP, TCP,
//! WS, TLS all filtered, but DNS-shaped traffic gets through
//! because blocking DNS would break the network for everyone.

use drift::identity::Identity;
use drift::wire_dns::DnsPacketIO;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn handshake_and_data_over_dns() {
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    // Bind both sides on loopback. The DNS adapter is symmetric
    // — same DnsPacketIO struct on both ends — so the test
    // setup mirrors the UDP transport test almost exactly.
    let bob_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let bob_addr = bob_sock.local_addr().unwrap();
    let alice_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let bob_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(DnsPacketIO::new(bob_sock).unwrap());
    let alice_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(DnsPacketIO::new(alice_sock).unwrap());

    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();

    let alice_t = Arc::new(
        Transport::bind_with_io(alice_io, alice_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Triggers the full HELLO → HELLO_ACK → DATA handshake,
    // every packet of which is fragmented across DNS queries
    // and reassembled by the receiver.
    alice_t
        .send_data(&bob_peer, b"hello-over-dns", 0, 0)
        .await
        .unwrap();

    let pkt = tokio::time::timeout(Duration::from_secs(5), bob_t.recv())
        .await
        .expect("handshake + DATA over DNS timed out")
        .unwrap();
    assert_eq!(pkt.payload, b"hello-over-dns");

    // Send a few more so we exercise the post-handshake data
    // path under the same fragmentation/reassembly machinery.
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

    let am = alice_t.metrics();
    let bm = bob_t.metrics();
    assert_eq!(am.handshakes_completed, 1);
    assert_eq!(bm.handshakes_completed, 1);
    assert_eq!(am.auth_failures, 0);
    assert_eq!(bm.auth_failures, 0);

    println!(
        "[DNS transport] handshake + 6 DATA packets delivered. \
         alice_sent={} bob_recv={}",
        am.packets_sent, bm.packets_received
    );
}

#[tokio::test]
async fn handshake_via_url_dispatch() {
    // Confirm the `dns://` scheme is registered and reachable
    // through `Transport::bind_url` / `connect_url`. This is
    // the path drift-http (and any other tool) uses, so it's
    // the integration that actually matters for end users.
    let alice_id = Identity::from_secret_bytes([0xA2; 32]);
    let bob_id = Identity::from_secret_bytes([0xB2; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let (bob_t, bob_url) = Transport::bind_url(
        "dns://127.0.0.1:0",
        bob_id,
        TransportConfig::default(),
    )
    .await
    .unwrap();
    let bob_t = Arc::new(bob_t);
    assert!(bob_url.starts_with("dns://"));
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();

    let (alice_t, bob_addr) = Transport::connect_url(
        &bob_url,
        alice_id,
        TransportConfig::default(),
    )
    .await
    .unwrap();
    let alice_t = Arc::new(alice_t);
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice_t
        .send_data(&bob_peer, b"url-dispatched", 0, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(5), bob_t.recv())
        .await
        .expect("url-dispatched DATA over DNS timed out")
        .unwrap();
    assert_eq!(pkt.payload, b"url-dispatched");
}

#[tokio::test]
async fn large_payload_fragmentation() {
    // Send a stream payload that DRIFT will chop into 1400-byte
    // packets — each of which the DNS adapter fragments across
    // 13 queries. Verifies the reassembly map handles many
    // concurrent in-flight fragments without confusion.
    let alice_id = Identity::from_secret_bytes([0xA3; 32]);
    let bob_id = Identity::from_secret_bytes([0xB3; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let bob_addr = bob_sock.local_addr().unwrap();
    let alice_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let bob_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(DnsPacketIO::new(bob_sock).unwrap());
    let alice_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(DnsPacketIO::new(alice_sock).unwrap());

    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();

    let alice_t = Arc::new(
        Transport::bind_with_io(alice_io, alice_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Several near-MAX_PAYLOAD packets back-to-back. Each one
    // becomes ~13 DNS queries; sending 4 of them means up to
    // 52 fragments in flight before the receiver finishes
    // reassembling the first.
    let max_payload = drift::MAX_PAYLOAD;
    for i in 0..4u32 {
        let mut payload = vec![0u8; max_payload];
        for (j, byte) in payload.iter_mut().enumerate() {
            *byte = ((i as usize + j) & 0xFF) as u8;
        }
        alice_t.send_data(&bob_peer, &payload, 0, 0).await.unwrap();
    }
    for i in 0..4u32 {
        let pkt = tokio::time::timeout(Duration::from_secs(10), bob_t.recv())
            .await
            .expect("large payload over DNS timed out")
            .unwrap();
        assert_eq!(pkt.payload.len(), max_payload);
        for (j, byte) in pkt.payload.iter().enumerate() {
            assert_eq!(
                *byte,
                ((i as usize + j) & 0xFF) as u8,
                "byte mismatch at i={} j={}",
                i,
                j
            );
        }
    }
}

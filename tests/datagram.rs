//! Datagram extension: unreliable, unordered messages multiplexed
//! onto the same authenticated DRIFT session as streams. Like
//! QUIC's DATAGRAM frame (RFC 9221).

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn datagrams_round_trip_alongside_streams() {
    let alice_id = Identity::from_secret_bytes([0x91; 32]);
    let bob_id = Identity::from_secret_bytes([0x92; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
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
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up handshake.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    // Send a few datagrams in rapid succession. Each is
    // self-contained — no setup, no acks, no ordering guarantee.
    for i in 0..5u8 {
        alice_mgr.send_datagram(bob_peer, &[0xDA, i]).await.unwrap();
    }

    // Drain on Bob's side. We expect 5 datagrams to land on
    // localhost (no loss), though order is not guaranteed by the
    // API. Collect by counting the first byte.
    let mut seen: Vec<u8> = Vec::new();
    for _ in 0..5 {
        let (peer, body) = tokio::time::timeout(Duration::from_secs(2), bob_mgr.recv_datagram())
            .await
            .expect("datagram recv timeout")
            .expect("datagram channel closed");
        assert_eq!(peer, alice_t.local_peer_id());
        assert_eq!(body.len(), 2);
        assert_eq!(body[0], 0xDA);
        seen.push(body[1]);
    }
    seen.sort();
    assert_eq!(seen, vec![0, 1, 2, 3, 4]);

    // Datagrams must NOT have created any stream state.
    assert_eq!(bob_mgr.live_streams_for(&alice_t.local_peer_id()).await, 0);
    assert_eq!(alice_mgr.live_streams_for(&bob_peer).await, 0);

    // Now open a real stream and confirm streams + datagrams
    // coexist on the same session.
    let stream_a = alice_mgr.open(bob_peer).await.unwrap();
    let stream_b = tokio::time::timeout(Duration::from_secs(2), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();
    stream_a.send(b"stream-after-datagram").await.unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(2), stream_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chunk, b"stream-after-datagram");

    // And a datagram after the stream is established.
    alice_mgr
        .send_datagram(bob_peer, b"final-datagram")
        .await
        .unwrap();
    let (_, body) = tokio::time::timeout(Duration::from_secs(2), bob_mgr.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, b"final-datagram");
}

#[tokio::test]
async fn empty_datagram_is_valid() {
    let alice_id = Identity::from_secret_bytes([0x93; 32]);
    let bob_id = Identity::from_secret_bytes([0x94; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
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
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    alice_mgr.send_datagram(bob_peer, b"").await.unwrap();
    let (_, body) = tokio::time::timeout(Duration::from_secs(2), bob_mgr.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, b"");
}

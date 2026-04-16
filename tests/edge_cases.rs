//! Edge case tests: boundaries, unknown values, reserved bits, oddities.

use drift::crypto::derive_peer_id;
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Direction, Transport, MAX_PAYLOAD};
use std::time::Duration;
use tokio::net::UdpSocket;

async fn pair() -> (std::sync::Arc<Transport>, std::sync::Arc<Transport>, drift::PeerId) {
    let bob = Identity::from_secret_bytes([0x80; 32]);
    let alice = Identity::from_secret_bytes([0x81; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = std::sync::Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = std::sync::Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    (alice_t, bob_t, bob_peer)
}

#[tokio::test]
async fn zero_payload_delivered() {
    let (alice, bob, peer) = pair().await;
    alice.send_data(&peer, &[], 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pkt.payload, Vec::<u8>::new());
}

#[tokio::test]
async fn max_payload_boundary() {
    let (alice, bob, peer) = pair().await;
    let max = vec![0xABu8; MAX_PAYLOAD];
    alice.send_data(&peer, &max, 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pkt.payload.len(), MAX_PAYLOAD);
    assert_eq!(pkt.payload, max);
}

#[tokio::test]
async fn over_max_payload_rejected() {
    let (alice, _bob, peer) = pair().await;
    let too_big = vec![0u8; MAX_PAYLOAD + 1];
    assert!(alice.send_data(&peer, &too_big, 0, 0).await.is_err());
}

#[tokio::test]
async fn unknown_packet_type_dropped() {
    // Craft a packet with type = 42 (not in PacketType enum).
    let bob = Identity::from_secret_bytes([0x82; 32]);
    let alice_pub = Identity::from_secret_bytes([0x83; 32]).public_bytes();
    let bob_t = Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
        .await
        .unwrap();
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let addr = bob_t.local_addr().unwrap();

    // Manually craft raw bytes with an invalid type byte.
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0] = 0x10; // version 1, flags 0
    bytes[1] = 42; // unknown type
    bytes[30..32].copy_from_slice(&10u16.to_be_bytes()); // payload_len

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&bytes, addr).await.unwrap();

    // Verify no panic and no delivery.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), bob_t.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn version_mismatch_dropped() {
    let bob = Identity::from_secret_bytes([0x84; 32]);
    let alice_pub = Identity::from_secret_bytes([0x85; 32]).public_bytes();
    let bob_t = Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
        .await
        .unwrap();
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let addr = bob_t.local_addr().unwrap();

    // Craft a packet with version 2 instead of 1.
    let mut header = Header::new(PacketType::Data, 1, [1; 8], [2; 8]);
    header.payload_len = 0;
    let mut bytes = [0u8; HEADER_LEN];
    header.encode(&mut bytes);
    // Override version byte to 2 (upper 4 bits).
    bytes[0] = (2 << 4) | (bytes[0] & 0x0F);

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&bytes, addr).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(200), bob_t.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reserved_byte_ignored_on_wire() {
    // Set byte 29 (reserved) to nonzero in a legitimate packet and verify
    // the receiver still accepts the rest of the header. This documents
    // that the reserved byte is truly reserved for future use.
    let (alice, bob, peer) = pair().await;

    // Warm up handshake with a normal packet first.
    alice.send_data(&peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv()).await;

    // We can't easily inject a packet with a tampered reserved byte
    // because it's AEAD-authenticated. Instead, assert the property via
    // the Header struct: reserved is hard-wired to 0 in encode(), and
    // decode() ignores the byte entirely.
    let mut buf = [0u8; HEADER_LEN];
    let h = Header::new(PacketType::Data, 1, [0; 8], [0; 8]);
    h.encode(&mut buf);
    assert_eq!(buf[29], 0);
    // Tamper the decoded version and verify decode still succeeds.
    buf[29] = 0xFF;
    let decoded = Header::decode(&buf).unwrap();
    assert_eq!(decoded.seq, 1);
}

#[tokio::test]
async fn tight_deadline_mostly_dropped() {
    // deadline_ms = 1 is shorter than most task schedule latencies.
    // A lot of packets should end up expired on the receive side.
    let (alice, bob, peer) = pair().await;

    // Warm up handshake.
    alice.send_data(&peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv()).await;

    // Blast 50 packets with deadline = 1ms and manual delay in between
    // to make sure each one ages at least 1ms before the receiver sees it.
    for i in 0..50u32 {
        alice.send_data(&peer, &i.to_be_bytes(), 1, 0).await.unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
    }

    let mut received = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), bob.recv()).await {
            Ok(Some(_)) => received += 1,
            _ => break,
        }
    }
    println!("tight_deadline: {}/50 delivered", received);
    // Some may slip through if scheduling is fast; verify at least SOME
    // were dropped, which proves the deadline filter is active.
    assert!(
        received < 50,
        "expected some packets to be expired, got all 50"
    );
}

/// Dual-initiation tiebreaker: if both sides try to be Initiator
/// simultaneously, the side with the LOWER static public key accepts
/// the incoming HELLO; the HIGHER-key side drops it and waits for ACK.
/// Both sides converge on a single session.
#[tokio::test]
async fn handshake_race_both_initiators() {
    let a_id = Identity::from_secret_bytes([0x90; 32]);
    let b_id = Identity::from_secret_bytes([0x91; 32]);
    let a_pub = a_id.public_bytes();
    let b_pub = b_id.public_bytes();

    let a = std::sync::Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), a_id)
            .await
            .unwrap(),
    );
    let b = std::sync::Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), b_id)
            .await
            .unwrap(),
    );
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    let b_peer_on_a = a.add_peer(b_pub, b_addr, Direction::Initiator).await.unwrap();
    let a_peer_on_b = b.add_peer(a_pub, a_addr, Direction::Initiator).await.unwrap();

    // Both try to initiate.
    let ta = a.clone();
    let tb = b.clone();
    let h1 = tokio::spawn(async move {
        ta.send_data(&b_peer_on_a, b"from-a", 0, 0).await
    });
    let h2 = tokio::spawn(async move {
        tb.send_data(&a_peer_on_b, b"from-b", 0, 0).await
    });
    let _ = h1.await.unwrap();
    let _ = h2.await.unwrap();

    // At least one side should eventually deliver something, even if
    // the other is stuck. Give it a few seconds.
    let got_a = tokio::time::timeout(Duration::from_secs(3), a.recv())
        .await
        .ok()
        .flatten();
    let got_b = tokio::time::timeout(Duration::from_secs(3), b.recv())
        .await
        .ok()
        .flatten();

    assert!(
        got_a.is_some() || got_b.is_some(),
        "neither side delivered anything after dual-initiator handshake"
    );
}

#[tokio::test]
async fn handshake_duplicate_different_nonces_regenerates() {
    // If the server receives a HELLO with a new client_nonce after it's
    // already derived a session with the old client_nonce, it should
    // treat the new HELLO as a restart and regenerate.
    let alice_secret = [0x93u8; 32];
    let bob = Identity::from_secret_bytes([0x92; 32]);
    let bob_pub = bob.public_bytes();
    let alice_pub = Identity::from_secret_bytes(alice_secret).public_bytes();

    let bob_t = std::sync::Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    // First handshake.
    let alice_t = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes(alice_secret),
    )
    .await
    .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();
    alice_t.send_data(&bob_peer, b"first", 0, 0).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"first");
    drop(alice_t);

    // Alice restarts with the same static key but fresh transport.
    let alice2 = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes(alice_secret),
    )
    .await
    .unwrap();
    let bob_peer2 = alice2.add_peer(bob_pub, bob_addr, Direction::Initiator).await.unwrap();
    alice2.send_data(&bob_peer2, b"second", 0, 0).await.unwrap();
    let second = tokio::time::timeout(Duration::from_secs(3), bob_t.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.payload, b"second");
    // Both client_peer_id values are equal because the static key is the same.
    assert_eq!(first.peer_id, derive_peer_id(&alice_pub));
    assert_eq!(second.peer_id, derive_peer_id(&alice_pub));
}

#[tokio::test]
async fn empty_beacon_before_handshake_dropped() {
    // Receive a BEACON-typed packet from a peer we've never completed
    // a handshake with. It has no session key so decryption fails silently.
    let bob = Identity::from_secret_bytes([0x94; 32]);
    let alice_pub = Identity::from_secret_bytes([0x95; 32]).public_bytes();
    let bob_t = Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
        .await
        .unwrap();
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let addr = bob_t.local_addr().unwrap();

    // Forge a BEACON header with random bytes as ciphertext.
    let mut h = Header::new(
        PacketType::Beacon,
        1,
        derive_peer_id(&alice_pub),
        derive_peer_id(&Identity::from_secret_bytes([0x94; 32]).public_bytes()),
    );
    h.payload_len = 32;
    let mut hbuf = [0u8; HEADER_LEN];
    h.encode(&mut hbuf);
    let mut wire = hbuf.to_vec();
    wire.extend_from_slice(&[0u8; 48]); // random ciphertext+tag

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&wire, addr).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(200), bob_t.recv())
            .await
            .is_err()
    );
}

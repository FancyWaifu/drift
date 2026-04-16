//! Adversarial packet injection tests.
//!
//! Each test opens a raw UDP socket, crafts a malicious packet, sends it
//! to a running DRIFT receiver, and verifies the receiver:
//!  1. Doesn't panic or hang
//!  2. Doesn't deliver the bad packet to the application
//!  3. Continues to correctly receive subsequent legitimate packets

use drift::crypto::derive_peer_id;
use drift::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

async fn setup_victim() -> (Transport, SocketAddr, Identity) {
    let bob = Identity::from_secret_bytes([0x55; 32]);
    let alice_pub = Identity::from_secret_bytes([0x66; 32]).public_bytes();
    let transport = Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
        .await
        .unwrap();
    transport
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let addr = transport.local_addr().unwrap();
    (transport, addr, Identity::from_secret_bytes([0x66; 32]))
}

async fn raw_send(victim_addr: SocketAddr, bytes: &[u8]) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(bytes, victim_addr).await.unwrap();
}

async fn victim_has_pending(transport: &Transport, ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(ms), transport.recv())
        .await
        .ok()
        .flatten()
        .is_some()
}

#[tokio::test]
async fn truncated_header_no_panic() {
    let (victim, addr, _) = setup_victim().await;
    // Send a few bytes of garbage — less than a full header.
    for _ in 0..50 {
        raw_send(addr, &[0xDE, 0xAD, 0xBE, 0xEF]).await;
    }
    // Victim should be alive and not have delivered anything.
    assert!(!victim_has_pending(&victim, 100).await);
}

#[tokio::test]
async fn random_garbage_no_panic() {
    let (victim, addr, _) = setup_victim().await;
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    for _ in 0..200 {
        let n = (rng.next_u32() as usize % 1400) + 1;
        let mut buf = vec![0u8; n];
        rng.fill_bytes(&mut buf);
        raw_send(addr, &buf).await;
    }
    assert!(!victim_has_pending(&victim, 100).await);
}

#[tokio::test]
async fn hello_with_unknown_key_dropped() {
    let (victim, addr, _) = setup_victim().await;
    // Forge a HELLO with a random (non-trusted) static key.
    let bad_id = Identity::from_secret_bytes([0x99; 32]);
    let local_id = derive_peer_id(&bad_id.public_bytes());

    let mut header = Header::new(
        PacketType::Hello,
        0,
        local_id,
        derive_peer_id(&Identity::from_secret_bytes([0x55; 32]).public_bytes()),
    );
    header.payload_len = 48;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + 48);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&bad_id.public_bytes());
    wire.extend_from_slice(&[0u8; 16]);

    raw_send(addr, &wire).await;
    assert!(!victim_has_pending(&victim, 100).await);
}

#[tokio::test]
async fn oversized_payload_len_rejected() {
    let (victim, addr, _) = setup_victim().await;
    // Header claims payload_len=65535 but we send only 40 bytes.
    let mut header = Header::new(PacketType::Data, 1, [1; 8], [2; 8]);
    header.payload_len = 65535;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    raw_send(addr, &hbuf).await;
    assert!(!victim_has_pending(&victim, 100).await);
}

#[tokio::test]
async fn tampered_data_tag_rejected() {
    // Establish a real session, capture a valid DATA packet, flip a bit,
    // resend it directly — verify it's dropped.
    let bob = Identity::from_secret_bytes([0x55; 32]);
    let bob_pub = bob.public_bytes();
    let alice = Identity::from_secret_bytes([0x66; 32]);
    let alice_pub = alice.public_bytes();

    let bob_t = Transport::bind("127.0.0.1:0".parse().unwrap(), bob).await.unwrap();
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice).await.unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    alice_t.send_data(&bob_peer, b"hello1", 0, 0).await.unwrap();
    let first = tokio::time::timeout(Duration::from_millis(500), bob_t.recv())
        .await
        .expect("recv timed out")
        .expect("channel closed");
    assert_eq!(first.payload, b"hello1");

    // Intercept by replaying: capture a legitimate packet via a sniff
    // socket isn't possible from this side, so instead craft a bogus
    // DATA with a random tag and verify it's dropped.
    let mut header = Header::new(
        PacketType::Data,
        999,
        derive_peer_id(&alice_pub),
        derive_peer_id(&bob_pub),
    );
    header.payload_len = 10;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let _ = canonical_aad(&hbuf);

    let mut wire = hbuf.to_vec();
    wire.extend_from_slice(&vec![0xFFu8; 10 + 16]); // fake ciphertext+tag
    raw_send(bob_addr, &wire).await;

    // Subsequent legitimate packet should still go through.
    alice_t.send_data(&bob_peer, b"hello2", 0, 0).await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(500), bob_t.recv())
        .await
        .expect("recv timed out")
        .expect("channel closed");
    assert_eq!(second.payload, b"hello2");
}

#[tokio::test]
async fn flood_survives() {
    // Spray the victim with 1000 garbage packets, verify it still processes
    // a legitimate packet afterwards.
    let (victim, addr, _) = setup_victim().await;

    for i in 0..1000u32 {
        let junk = i.to_be_bytes().repeat(50);
        raw_send(addr, &junk).await;
    }

    // Now talk to it legitimately.
    let alice = Identity::from_secret_bytes([0x66; 32]);
    let bob_pub = Identity::from_secret_bytes([0x55; 32]).public_bytes();
    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, addr, Direction::Initiator)
        .await.unwrap();

    alice_t.send_data(&bob_peer, b"alive?", 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), victim.recv())
        .await
        .expect("victim unresponsive after flood")
        .expect("channel closed");
    assert_eq!(pkt.payload, b"alive?");
}

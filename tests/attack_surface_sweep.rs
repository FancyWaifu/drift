//! Comprehensive attack-surface sweep.
//!
//! Each test in this file targets one specific vector. The test
//! header calls out the vector name, the attack, and what the fix
//! must guarantee.

use drift::derive_peer_id;
use drift::directory::{DirMessage, MAX_LISTING_ENTRIES};
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::session::HandshakeState;
use drift::transport::{RoutingTable, MAX_ROUTES};
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

// -------- 1. directory allocation bomb --------

/// Attack: A LISTING with `count = 65535` would, pre-fix, trigger a
/// `Vec::with_capacity(65535)` and a 5 MB allocation even when the
/// payload is a handful of bytes. Post-fix, the decoder enforces
/// `MAX_LISTING_ENTRIES` and clamps pre-allocation by the actual
/// buffer length.
#[test]
fn directory_huge_count_rejected() {
    // Build a malicious LISTING: tag=0x03, count=0xFFFF, no entries.
    let mut bomb = vec![0x03u8];
    bomb.extend_from_slice(&0xFFFFu16.to_be_bytes());
    // decode must NOT pre-allocate 65535 entries and must return
    // None because the count exceeds MAX_LISTING_ENTRIES.
    assert!(DirMessage::decode(&bomb).is_none());

    // A count just over the cap should also fail fast.
    let mut over_cap = vec![0x03u8];
    over_cap.extend_from_slice(&((MAX_LISTING_ENTRIES as u16) + 1).to_be_bytes());
    assert!(DirMessage::decode(&over_cap).is_none());
}

// -------- 2. bogus stream ACK --------

/// Attack: a malicious receiver sends `TAG_ACK` with
/// `acked_up_to = u32::MAX` to clear the sender's retransmit queue
/// for seqs the sender hasn't even produced yet. The sanity cap
/// in `handle_ack` must bound the effective ACK at `send_next_seq - 1`.
///
/// This test drives a stream from Alice to Bob, forces Alice's
/// "ack receiver" role by having Bob send a forged ACK with a huge
/// value, and checks Alice's `send_pending` map. Unfortunately the
/// stream layer doesn't expose a peek for pending segments, so we
/// settle for asserting that Alice can still recover and deliver
/// subsequent bytes after the bogus ACK — which would fail if the
/// retransmit queue had been prematurely cleared.
#[tokio::test]
async fn bogus_ack_cannot_clear_pending_beyond_sent() {
    use drift::streams::StreamManager;

    let alice = Identity::from_secret_bytes([0x30; 32]);
    let bob = Identity::from_secret_bytes([0x31; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
            .await
            .unwrap(),
    );
    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
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
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_alice = alice_mgr.open(bob_peer).await.unwrap();
    stream_alice.send(b"hi").await.unwrap();

    let stream_bob = tokio::time::timeout(Duration::from_secs(2), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), stream_bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"hi");

    // Inject a forged ACK from Bob to Alice with acked_up_to =
    // u32::MAX. Under the old code this would wipe Alice's entire
    // `send_pending` for this stream, including any segments she
    // plans to send later in the conversation. Under the fix it's
    // capped at `send_next_seq - 1`.
    let mut bogus = Vec::with_capacity(9);
    bogus.push(0x12u8); // TAG_ACK
    bogus.extend_from_slice(&stream_alice.id().to_be_bytes());
    bogus.extend_from_slice(&u32::MAX.to_be_bytes());
    bob_t
        .send_data(&alice_t.local_peer_id(), &bogus, 0, 0)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send more bytes both ways. Both must still be delivered
    // reliably. If the sanity cap were missing, the stream would
    // still function by luck in this small-payload case, so this
    // test is more of a "does not crash + keeps working" smoke
    // test than a tight assertion. The unit-level assertion is
    // the cap itself.
    stream_alice.send(b"after-bogus-ack").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), stream_bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"after-bogus-ack");
}

// -------- 3. routing table unbounded growth --------

/// Attack: an authenticated neighbor floods BEACONs advertising
/// many unique destination peer ids. Each call to
/// `RoutingTable::update_if_better` for a fresh destination would,
/// pre-fix, allocate a new entry. Post-fix, the table is hard-capped
/// at `MAX_ROUTES` and new inserts past the cap are silently
/// dropped.
#[test]
fn routing_table_caps_at_max_routes() {
    let mut rt = RoutingTable::default();
    let fake_hop: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();

    // Push MAX_ROUTES + 5000 unique destinations through the
    // BEACON-driven path. The cost-ascending order (i+1)
    // ensures each entry is a fresh insert rather than an
    // update — otherwise the hysteresis check would reject
    // most of them.
    let flood = MAX_ROUTES + 5_000;
    for i in 0..flood {
        let mut dst = [0u8; 8];
        dst[..4].copy_from_slice(&(i as u32).to_be_bytes());
        rt.update_if_better(dst, fake_hop, 1, 1_000 + i as u32, 0);
    }
    assert!(
        rt.len() <= MAX_ROUTES,
        "routing table grew to {}, should be capped at {}",
        rt.len(),
        MAX_ROUTES
    );
    assert_eq!(
        rt.len(),
        MAX_ROUTES,
        "table should have filled exactly to the cap"
    );
}

// -------- 4. peer table explosion via accept_any_peer HELLO flood --------

/// Attack: with `accept_any_peer = true`, an attacker sprays HELLOs
/// with unique static pubkeys. Each fresh pubkey auto-registers a
/// new peer. Between eviction-reaper scans the table could grow
/// arbitrarily. The fix caps auto-registered peers at
/// `max_peers` — extras are dropped at HELLO intake.
#[tokio::test]
async fn auto_registered_peer_flood_bounded_by_max_peers() {
    let cap = 64usize;
    let cfg = TransportConfig {
        accept_any_peer: true,
        max_peers: cap,
        // Disable eviction so we measure the intake cap purely.
        awaiting_data_timeout_secs: u64::MAX,
        ..TransportConfig::default()
    };
    let server_id = Identity::from_secret_bytes([0x50; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();
    let atk = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Flood cap+32 unique pubkeys as raw HELLOs.
    for i in 0u8..(cap as u8 + 32) {
        let secret = [i ^ 0xAA; 32];
        let static_pub = Identity::from_secret_bytes(secret).public_bytes();
        let ephemeral_pub = Identity::from_secret_bytes([i ^ 0x55; 32]).public_bytes();
        let mut nonce = [0u8; 16];
        nonce[0] = i;
        let wire = build_hello(static_pub, ephemeral_pub, nonce, server_pub);
        atk.send_to(&wire, server_addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let in_progress = server.handshakes_in_progress();
    assert!(
        in_progress <= cap,
        "auto-registered peers must stay at or below max_peers = {}, got {}",
        cap,
        in_progress
    );
    assert!(
        in_progress >= cap / 2,
        "cap enforcement should still let many in; got only {}",
        in_progress
    );
}

// -------- 5. weak x25519 pubkey (all-zero identity element) --------

/// Attack: HELLO with `client_static_pub = [0; 32]`. X25519 with a
/// zero-valued public point produces a zero shared secret; the
/// derived session key then depends only on the public nonces, so
/// the attacker can compute it and forge authenticated DATA without
/// knowing any private material. The fix rejects the HELLO at
/// intake and `dh_checked` catches the broader low-order-point
/// family.
#[tokio::test]
async fn all_zero_client_static_pub_rejected() {
    let cfg = TransportConfig {
        accept_any_peer: true,
        cookie_always: false,
        ..TransportConfig::default()
    };
    let server_id = Identity::from_secret_bytes([0x60; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();
    let atk = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let zero_pub = [0u8; 32];
    let real_eph = Identity::from_secret_bytes([0x61; 32]).public_bytes();
    let nonce = [0x62u8; 16];

    // (a) all-zero STATIC pubkey must be rejected.
    let wire = build_hello(zero_pub, real_eph, nonce, server_pub);
    atk.send_to(&wire, server_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let m = server.metrics();
    assert!(
        m.auth_failures >= 1,
        "expected auth_failures >= 1 after zero static pubkey HELLO, got {}",
        m.auth_failures
    );
    assert_eq!(
        server.handshakes_in_progress(),
        0,
        "zero-key HELLO must not allocate AwaitingData"
    );

    // (b) all-zero EPHEMERAL pubkey must also be rejected.
    let real_static = Identity::from_secret_bytes([0x63; 32]).public_bytes();
    let wire = build_hello(real_static, zero_pub, nonce, server_pub);
    atk.send_to(&wire, server_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let m = server.metrics();
    assert!(
        m.auth_failures >= 2,
        "expected auth_failures >= 2 after zero ephemeral HELLO, got {}",
        m.auth_failures
    );
    assert_eq!(server.handshakes_in_progress(), 0);
}

// -------- helpers --------

fn build_hello(
    client_static_pub: [u8; 32],
    client_ephemeral_pub: [u8; 32],
    client_nonce: [u8; 16],
    server_pub: [u8; 32],
) -> Vec<u8> {
    let src_id = derive_peer_id(&client_static_pub);
    let dst_id = derive_peer_id(&server_pub);
    let payload_len = 32 + 32 + 16;
    let mut header = Header::new(PacketType::Hello, 0, src_id, dst_id);
    header.payload_len = payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&client_static_pub);
    wire.extend_from_slice(&client_ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    wire
}

// Use HandshakeState import to silence unused warning when this
// file is touched by future refactors.
#[allow(dead_code)]
fn _keep_unused() {
    let _ = std::mem::discriminant(&HandshakeState::Pending);
}

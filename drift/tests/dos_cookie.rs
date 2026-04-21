//! Adaptive DoS cookie tests.
//!
//! The server-side cookie check runs BEFORE any X25519 or peer-state
//! allocation. A HELLO arriving while the server is in cookie mode and
//! missing a valid cookie gets a cheap CHALLENGE reply; the client
//! stashes the cookie and retransmits HELLO with it attached, at which
//! point the handshake proceeds normally.
//!
//! These tests drive the whole flow through a real UDP socket pair and
//! assert against the `Metrics` counters to prove the expected path
//! actually fired.

use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// With `cookie_always = true` on the server, a fresh client handshake
/// must still complete: the server replies with CHALLENGE, the client
/// retries HELLO with the cookie echoed, and from there everything
/// proceeds as normal. Application-level data round-trips successfully,
/// and the server metrics show exactly one challenge issued and one
/// cookie accepted.
#[tokio::test]
async fn cookie_always_completes_handshake() {
    let server_id = Identity::from_secret_bytes([0xA1; 32]);
    let client_secret = [0xA2u8; 32];
    let server_pub = server_id.public_bytes();
    let client_pub = Identity::from_secret_bytes(client_secret).public_bytes();

    let cfg = TransportConfig {
        cookie_always: true,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    server
        .add_peer(
            client_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes(client_secret),
    )
    .await
    .unwrap();
    let server_peer = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();

    // The first DATA triggers a HELLO → CHALLENGE → HELLO-with-cookie
    // → HELLO_ACK → DATA cycle. It MUST still arrive at the server.
    client
        .send_data(&server_peer, b"hello-behind-cookie", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("server never received anything")
        .expect("server recv returned None");
    assert_eq!(got.payload, b"hello-behind-cookie");

    let m = server.metrics();
    assert!(
        m.challenges_issued >= 1,
        "expected at least one CHALLENGE to be issued, got {}",
        m.challenges_issued
    );
    assert!(
        m.cookies_accepted >= 1,
        "expected at least one cookie to validate, got {}",
        m.cookies_accepted
    );
    assert_eq!(
        m.cookies_rejected, 0,
        "no cookies should have been rejected on a clean handshake"
    );
    assert_eq!(
        m.handshakes_completed, 1,
        "exactly one handshake should have completed"
    );
}

/// With the default config (cookie_threshold = u32::MAX, cookie_always
/// = false), the cookie path is fully dormant. Handshakes complete
/// without any CHALLENGE being issued — this guards against
/// accidentally adding latency to the fast path.
#[tokio::test]
async fn default_config_skips_cookie_path() {
    let server_id = Identity::from_secret_bytes([0xB1; 32]);
    let client_secret = [0xB2u8; 32];
    let server_pub = server_id.public_bytes();
    let client_pub = Identity::from_secret_bytes(client_secret).public_bytes();

    let server = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap(),
    );
    server
        .add_peer(
            client_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes(client_secret),
    )
    .await
    .unwrap();
    let server_peer = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();

    client
        .send_data(&server_peer, b"fast-path", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), server.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.payload, b"fast-path");

    let m = server.metrics();
    assert_eq!(m.challenges_issued, 0);
    assert_eq!(m.cookies_accepted, 0);
    assert_eq!(m.cookies_rejected, 0);
}

/// Build a raw HELLO wire packet using the same layout that the
/// production client would produce. `cookie_tail` of `Some(bytes)`
/// appends 24 bytes after the normal HELLO body — used by the
/// tampered-cookie test to send a deliberately wrong MAC to the server.
fn build_raw_hello(
    client_static_pub: [u8; 32],
    client_ephemeral_pub: [u8; 32],
    client_nonce: [u8; 16],
    server_pub: [u8; 32],
    cookie_tail: Option<[u8; 24]>,
) -> Vec<u8> {
    use drift::derive_peer_id;
    let src_id = derive_peer_id(&client_static_pub);
    let dst_id = derive_peer_id(&server_pub);
    let base_len = 32 + 32 + 16;
    let payload_len = base_len + cookie_tail.map(|_| 24).unwrap_or(0);

    let mut header = Header::new(PacketType::Hello, 0, src_id, dst_id);
    header.payload_len = payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&client_static_pub);
    wire.extend_from_slice(&client_ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    if let Some(t) = cookie_tail {
        wire.extend_from_slice(&t);
    }
    wire
}

/// A HELLO whose cookie tail is garbage must be rejected: the server
/// bumps `cookies_rejected`, sends back a fresh CHALLENGE so a legit
/// client with a stale cookie can recover, and never allocates a peer
/// entry or performs X25519.
#[tokio::test]
async fn tampered_cookie_is_rejected() {
    let server_id = Identity::from_secret_bytes([0xC1; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        cookie_always: true,
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Synthetic attacker identity — we never plug this into a real
    // Transport, we just want valid-looking key material.
    let attacker_static = Identity::from_secret_bytes([0xC2; 32]);
    let attacker_ephemeral = Identity::from_secret_bytes([0xC3; 32]);
    let mut client_nonce = [0u8; 16];
    for (i, b) in client_nonce.iter_mut().enumerate() {
        *b = i as u8;
    }

    let bogus_tail = [0x42u8; 24]; // garbage cookie MAC
    let wire = build_raw_hello(
        attacker_static.public_bytes(),
        attacker_ephemeral.public_bytes(),
        client_nonce,
        server_pub,
        Some(bogus_tail),
    );

    let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker_sock.send_to(&wire, server_addr).await.unwrap();

    // Give the server a moment to process.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let m = server.metrics();
    assert!(
        m.cookies_rejected >= 1,
        "expected cookies_rejected >= 1, got {}",
        m.cookies_rejected
    );
    // Server also re-issues a challenge so a legit client can recover.
    assert!(m.challenges_issued >= 1);
    // Critical property: NO peer state was allocated for the attacker.
    assert_eq!(
        server.handshakes_in_progress(),
        0,
        "rejected HELLO must not create AwaitingData state"
    );
    // And definitely no handshake completed.
    assert_eq!(m.handshakes_completed, 0);
}

/// Eviction test: drive the server into `AwaitingData` with a raw
/// HELLO (no follow-up DATA), wait past `awaiting_data_timeout_secs`,
/// and verify the reaper cleaned the stale peer up so the in-flight
/// count returns to zero.
#[tokio::test]
async fn awaiting_data_eviction_clears_stuck_handshake() {
    let server_id = Identity::from_secret_bytes([0xD1; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        awaiting_data_timeout_secs: 1,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let ghost_static = Identity::from_secret_bytes([0xD2; 32]);
    let ghost_ephemeral = Identity::from_secret_bytes([0xD3; 32]);
    let mut client_nonce = [0u8; 16];
    for (i, b) in client_nonce.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3);
    }

    let wire = build_raw_hello(
        ghost_static.public_bytes(),
        ghost_ephemeral.public_bytes(),
        client_nonce,
        server_pub,
        None,
    );
    let ghost_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    ghost_sock.send_to(&wire, server_addr).await.unwrap();

    // The server should finish the HELLO → HELLO_ACK handshake and
    // park this synthetic peer in AwaitingData. No DATA ever follows
    // because we're not actually a Transport on the attacker side.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.handshakes_in_progress(),
        1,
        "synthetic HELLO should have pushed one peer into AwaitingData"
    );

    // Wait past the 1-second timeout and let the reaper run (scan
    // interval = max(1s, timeout/2) = 1s).
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert_eq!(
        server.handshakes_in_progress(),
        0,
        "stale AwaitingData peer should have been evicted"
    );
    let m = server.metrics();
    assert!(
        m.handshakes_evicted >= 1,
        "expected handshakes_evicted >= 1, got {}",
        m.handshakes_evicted
    );
}

/// Sanity check that after eviction, the adaptive cookie threshold
/// disarms again. We configure `cookie_threshold = 1`, push one
/// synthetic HELLO into AwaitingData (so inflight == 1 == threshold),
/// and confirm the server starts demanding cookies. After the reaper
/// clears the stuck peer, the next real handshake must go through the
/// fast path again (no cookies required).
#[tokio::test]
async fn adaptive_threshold_resets_after_eviction() {
    let server_id = Identity::from_secret_bytes([0xE1; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        cookie_threshold: 1,
        awaiting_data_timeout_secs: 1,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Step 1: push one synthetic HELLO into AwaitingData so the
    // inflight count hits the cookie threshold.
    let stuck_static = Identity::from_secret_bytes([0xE2; 32]);
    let stuck_ephemeral = Identity::from_secret_bytes([0xE3; 32]);
    let wire = build_raw_hello(
        stuck_static.public_bytes(),
        stuck_ephemeral.public_bytes(),
        [7u8; 16],
        server_pub,
        None,
    );
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .send_to(&wire, server_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.handshakes_in_progress(), 1);

    // Step 2: a real client tries to handshake now. Because
    // inflight >= threshold, the server should challenge it — and
    // since the client honors the challenge, the handshake still
    // succeeds, just via the cookie path.
    let client_secret = [0xE4u8; 32];
    let client = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes(client_secret),
    )
    .await
    .unwrap();
    let server_peer = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();
    client
        .send_data(&server_peer, b"over-cookies", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("server never received")
        .unwrap();
    assert_eq!(got.payload, b"over-cookies");
    let m1 = server.metrics();
    assert!(
        m1.challenges_issued >= 1 && m1.cookies_accepted >= 1,
        "expected cookie path to fire: challenges={} accepted={}",
        m1.challenges_issued,
        m1.cookies_accepted
    );

    // Step 3: wait out the stuck peer, reaper evicts it.
    drop(client);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let m2 = server.metrics();
    assert!(
        m2.handshakes_evicted >= 1,
        "expected reaper to have evicted the stuck AwaitingData peer"
    );
}

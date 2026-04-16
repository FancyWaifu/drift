//! Attack test: cookie nonce-replay.
//!
//! The DoS cookie's MAC must bind the `client_nonce` from the HELLO
//! body, not just the source address + pubkeys + timestamp. Otherwise
//! an attacker who obtains a single valid cookie can replay it with a
//! fresh `client_nonce` on every subsequent HELLO, forcing the server
//! to run `regenerate_session` (X25519 + session-key derivation) for
//! each one — exactly the amplification the cookie was supposed to
//! prevent.
//!
//! This test demonstrates that replaying a captured cookie with a
//! different nonce is rejected: the server increments `cookies_rejected`
//! and never allocates a fresh `AwaitingData` entry.

use drift::derive_peer_id;
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const HELLO_BASE_LEN: usize = 32 + 32 + 16;
const COOKIE_BLOB_LEN: usize = 24;

fn build_hello_wire(
    client_static_pub: [u8; 32],
    client_ephemeral_pub: [u8; 32],
    client_nonce: [u8; 16],
    server_pub: [u8; 32],
    cookie_tail: Option<[u8; COOKIE_BLOB_LEN]>,
) -> Vec<u8> {
    let src_id = derive_peer_id(&client_static_pub);
    let dst_id = derive_peer_id(&server_pub);
    let payload_len = HELLO_BASE_LEN + cookie_tail.map(|_| COOKIE_BLOB_LEN).unwrap_or(0);

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

#[tokio::test]
async fn cookie_replay_with_different_nonce_is_rejected() {
    let server_id = Identity::from_secret_bytes([0xF1; 32]);
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

    // Attacker identity — we never plug this into a real Transport.
    let atk_static = Identity::from_secret_bytes([0xF2; 32]).public_bytes();
    let atk_ephemeral = Identity::from_secret_bytes([0xF3; 32]).public_bytes();

    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Step 1: send a plain HELLO with nonce N1; receive the CHALLENGE
    // reply and pull the 24-byte cookie blob out of its body.
    let nonce1 = [0x11u8; 16];
    let hello1 =
        build_hello_wire(atk_static, atk_ephemeral, nonce1, server_pub, None);
    attacker.send_to(&hello1, server_addr).await.unwrap();

    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(2),
        attacker.recv_from(&mut buf),
    )
    .await
    .expect("server never sent a CHALLENGE")
    .unwrap();
    assert!(n >= HEADER_LEN + COOKIE_BLOB_LEN, "challenge too short");

    let hdr = Header::decode(&buf[..HEADER_LEN]).unwrap();
    assert_eq!(hdr.packet_type, PacketType::Challenge);
    let mut cookie = [0u8; COOKIE_BLOB_LEN];
    cookie.copy_from_slice(&buf[HEADER_LEN..HEADER_LEN + COOKIE_BLOB_LEN]);

    let metrics_before = server.metrics();

    // Step 2: replay the captured cookie with a DIFFERENT client_nonce.
    // This is the core of the attack — on a broken server the cookie
    // MAC doesn't bind the nonce, so the blob still validates and the
    // server burns an X25519 on this forged packet. A properly bound
    // cookie must reject it.
    let nonce2 = [0x22u8; 16];
    let hello2 = build_hello_wire(
        atk_static,
        atk_ephemeral,
        nonce2,
        server_pub,
        Some(cookie),
    );
    attacker.send_to(&hello2, server_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let metrics_after = server.metrics();
    let rejects_delta = metrics_after.cookies_rejected - metrics_before.cookies_rejected;
    let accepts_delta = metrics_after.cookies_accepted - metrics_before.cookies_accepted;

    assert_eq!(
        accepts_delta, 0,
        "replayed cookie with fresh nonce was accepted: {} new acceptances",
        accepts_delta
    );
    assert!(
        rejects_delta >= 1,
        "replayed cookie with fresh nonce must be rejected (delta={})",
        rejects_delta
    );
}

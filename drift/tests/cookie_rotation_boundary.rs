//! Cookie rotation boundary: a cookie issued under the previous
//! secret must still validate after ONE rotation (the grace
//! window), but must NOT validate after TWO rotations (previous has
//! been replaced by then). This pins down the single-rotation grace
//! behavior that in-flight handshakes depend on.

use drift::derive_peer_id;
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const HELLO_BASE: usize = 32 + 32 + 16;
const COOKIE_BLOB: usize = 24;

fn build_raw_hello(
    client_static: [u8; 32],
    client_ephemeral: [u8; 32],
    nonce: [u8; 16],
    server_pub: [u8; 32],
    cookie: Option<[u8; COOKIE_BLOB]>,
) -> Vec<u8> {
    let src = derive_peer_id(&client_static);
    let dst = derive_peer_id(&server_pub);
    let plen = HELLO_BASE + cookie.map(|_| COOKIE_BLOB).unwrap_or(0);
    let mut h = Header::new(PacketType::Hello, 0, src, dst);
    h.payload_len = plen as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    h.encode(&mut hbuf);
    let mut wire = Vec::with_capacity(HEADER_LEN + plen);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&client_static);
    wire.extend_from_slice(&client_ephemeral);
    wire.extend_from_slice(&nonce);
    if let Some(c) = cookie {
        wire.extend_from_slice(&c);
    }
    wire
}

#[tokio::test]
async fn cookie_survives_one_rotation_but_not_two() {
    let server_id = Identity::from_secret_bytes([0x10; 32]);
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

    let static_pub = Identity::from_secret_bytes([0x11; 32]).public_bytes();
    let eph_pub = Identity::from_secret_bytes([0x12; 32]).public_bytes();
    let nonce = [0x99u8; 16];

    let atk = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // --- step 1: issue HELLO #1, capture cookie from CHALLENGE ---
    let hello1 = build_raw_hello(static_pub, eph_pub, nonce, server_pub, None);
    atk.send_to(&hello1, server_addr).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), atk.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n >= HEADER_LEN + COOKIE_BLOB);
    let hdr = Header::decode(&buf[..HEADER_LEN]).unwrap();
    assert_eq!(hdr.packet_type, PacketType::Challenge);
    let mut cookie = [0u8; COOKIE_BLOB];
    cookie.copy_from_slice(&buf[HEADER_LEN..HEADER_LEN + COOKIE_BLOB]);

    let metrics_start = server.metrics();

    // --- step 2: ONE rotation (previous = old current, current = new).
    server.test_rotate_cookies().await;

    // The same HELLO + cookie must still validate thanks to the
    // grace window that keeps `previous` alive for one rotation.
    let hello2 = build_raw_hello(static_pub, eph_pub, nonce, server_pub, Some(cookie));
    atk.send_to(&hello2, server_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let m1 = server.metrics();
    assert!(
        m1.cookies_accepted > metrics_start.cookies_accepted,
        "cookie should have validated after 1 rotation (grace window). \
         cookies_accepted before={} after={}",
        metrics_start.cookies_accepted,
        m1.cookies_accepted
    );
    assert_eq!(
        m1.cookies_rejected, metrics_start.cookies_rejected,
        "should not have been rejected"
    );

    // --- step 3: TWO MORE rotations (now the original secret is
    // no longer `previous` either — it's gone).
    server.test_rotate_cookies().await;
    server.test_rotate_cookies().await;

    // A fresh handshake attempt reusing the OLD cookie must now
    // fail validation. We use a different nonce to avoid hitting
    // the cached-ack replay branch.
    let different_nonce = [0xAAu8; 16];
    let hello3 = build_raw_hello(
        static_pub,
        eph_pub,
        different_nonce,
        server_pub,
        Some(cookie),
    );
    atk.send_to(&hello3, server_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let m2 = server.metrics();
    assert!(
        m2.cookies_rejected > m1.cookies_rejected,
        "old cookie must fail validation after 2+ rotations. \
         cookies_rejected before={} after={}",
        m1.cookies_rejected,
        m2.cookies_rejected
    );
}

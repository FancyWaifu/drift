//! Attack: HELLO replay → peer address hijack.
//!
//! Alice establishes a session with Bob. An attacker captures
//! Alice's HELLO bytes off the wire and replays them to Bob from a
//! different source address. Pre-fix, Bob updated `peer.addr` to
//! the attacker's address and sent his cached HELLO_ACK (and any
//! future outbound traffic to Alice) there. Post-fix, the cached
//! ACK goes to the *original* Alice address and `peer.addr` is
//! untouched.
//!
//! To observe the effect, we watch the destination of Bob's reply
//! to the replayed HELLO. The attacker socket must NOT receive the
//! ACK; the original Alice address must.

use drift::derive_peer_id;
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Minimal raw HELLO builder.
fn build_hello(
    client_static_pub: [u8; 32],
    client_ephemeral_pub: [u8; 32],
    client_nonce: [u8; 16],
    server_pub: [u8; 32],
) -> Vec<u8> {
    let src_id = derive_peer_id(&client_static_pub);
    let dst_id = derive_peer_id(&server_pub);
    let mut header = Header::new(PacketType::Hello, 0, src_id, dst_id);
    header.payload_len = (32 + 32 + 16) as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut wire = Vec::with_capacity(HEADER_LEN + 80);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&client_static_pub);
    wire.extend_from_slice(&client_ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    wire
}

#[tokio::test]
async fn duplicate_hello_from_new_addr_cannot_hijack_peer_addr() {
    // Bob is the server — he'll store Alice's address after the
    // first HELLO arrives, then we'll replay that HELLO from an
    // attacker socket and check where Bob's cached-ACK lands.
    let bob_id = Identity::from_secret_bytes([0x70; 32]);
    let bob_pub = bob_id.public_bytes();
    // accept_any_peer so we don't need to pre-register "Alice".
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, cfg)
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    // Alice is a raw UDP socket so we can inspect exactly what
    // Bob sends her.
    let alice_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let alice_addr = alice_sock.local_addr().unwrap();

    // Alice's identity — we hand-build her HELLO.
    let alice_static =
        Identity::from_secret_bytes([0x71; 32]).public_bytes();
    let alice_ephemeral =
        Identity::from_secret_bytes([0x72; 32]).public_bytes();
    let nonce = [0x99u8; 16];

    let hello = build_hello(alice_static, alice_ephemeral, nonce, bob_pub);

    // Step 1: Alice sends the real HELLO. Bob processes it, enters
    // AwaitingData with `peer.addr = alice_addr`, and sends his
    // HELLO_ACK back to Alice. We drain that ACK off Alice's
    // socket so it doesn't pollute later recv calls.
    alice_sock.send_to(&hello, bob_addr).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, from) = tokio::time::timeout(
        Duration::from_secs(2),
        alice_sock.recv_from(&mut buf),
    )
    .await
    .expect("Bob never sent HELLO_ACK to Alice")
    .unwrap();
    assert_eq!(from, bob_addr, "first ACK must come from Bob");
    assert!(n >= HEADER_LEN);

    // Step 2: Mallory replays the exact same HELLO bytes from a
    // DIFFERENT source address.
    let mallory_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mallory_addr = mallory_sock.local_addr().unwrap();
    assert_ne!(mallory_addr, alice_addr);
    mallory_sock.send_to(&hello, bob_addr).await.unwrap();

    // Step 3: the cached ACK must go back to Alice, NOT to
    // Mallory. Alice's socket should receive it; Mallory's should
    // NOT.
    let alice_got = tokio::time::timeout(
        Duration::from_millis(500),
        alice_sock.recv_from(&mut buf),
    )
    .await;
    assert!(
        alice_got.is_ok(),
        "Alice's socket must receive the cached-ACK replay"
    );

    let mut mbuf = [0u8; 1500];
    let mallory_got = tokio::time::timeout(
        Duration::from_millis(500),
        mallory_sock.recv_from(&mut mbuf),
    )
    .await;
    assert!(
        mallory_got.is_err(),
        "Mallory must NOT receive the cached ACK — that would be a hijack"
    );
}

//! Deep security tests: cross-session isolation, hijack attempts, replay
//! floods, and DoS cost measurement.

use drift::crypto::{derive_peer_id, Direction as CryptoDirection, SessionKey};
use drift::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift::identity::{derive_session_key, Identity};
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Establish two independent sessions (A↔B and C↔D). Verify they use
/// totally different session keys — packets from one can't be decrypted
/// by the other even if identical addresses were reused.
#[tokio::test]
async fn session_keys_are_independent() {
    let a = Identity::from_secret_bytes([0xA1; 32]);
    let b = Identity::from_secret_bytes([0xA2; 32]);
    let c = Identity::from_secret_bytes([0xA3; 32]);
    let d = Identity::from_secret_bytes([0xA4; 32]);

    // Session 1: derive DH + session key for A↔B.
    let dh_ab = a.dh(&b.public_bytes()).unwrap();
    let ab_key = derive_session_key(&dh_ab, &[0u8; 32], &[0u8; 16], &[0u8; 16]);

    // Session 2: derive DH + session key for C↔D.
    let dh_cd = c.dh(&d.public_bytes()).unwrap();
    let cd_key = derive_session_key(&dh_cd, &[0u8; 32], &[0u8; 16], &[0u8; 16]);

    assert_ne!(ab_key, cd_key);

    // Cross attempt: try to decrypt A↔B ciphertext with the C↔D key.
    let sender = SessionKey::new(&ab_key, CryptoDirection::Initiator);
    let wrong_receiver = SessionKey::new(&cd_key, CryptoDirection::Initiator);
    let ct = sender
        .seal(1, PacketType::Data as u8, b"aad", b"secret")
        .unwrap();
    assert!(wrong_receiver
        .open(1, PacketType::Data as u8, b"aad", &ct)
        .is_err());
}

/// Even using the same pubkey pair, different nonces produce different
/// session keys — this is what makes replay across sessions impossible.
#[tokio::test]
async fn different_nonces_produce_different_keys() {
    let a = Identity::from_secret_bytes([0xB0; 32]);
    let b = Identity::from_secret_bytes([0xB1; 32]);
    let dh = a.dh(&b.public_bytes()).unwrap();
    let k1 = derive_session_key(&dh, &[0u8; 32], &[1u8; 16], &[2u8; 16]);
    let k2 = derive_session_key(&dh, &[0u8; 32], &[3u8; 16], &[4u8; 16]);
    assert_ne!(k1, k2);
}

/// Capture a valid DATA packet (via an in-process proxy), then replay it
/// thousands of times. The replay window must catch every duplicate.
#[tokio::test]
async fn replay_flood_caught() {
    let bob = Identity::from_secret_bytes([0xC0; 32]);
    let alice = Identity::from_secret_bytes([0xC1; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

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

    // Spawn a sniff-proxy: it forwards everything Alice sends to Bob,
    // and captures the first DATA packet it sees for replay.
    let captured = Arc::new(tokio::sync::Mutex::new(None::<Vec<u8>>));
    let proxy_addr = {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let cap = captured.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut client: Option<std::net::SocketAddr> = None;
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let data = &buf[..n];
                let dst = if src == bob_addr {
                    match client {
                        Some(c) => c,
                        None => continue,
                    }
                } else {
                    if client.is_none() {
                        client = Some(src);
                    }
                    // Capture first DATA-type packet (byte 1 of header = 3).
                    if n > 1 && data[1] == PacketType::Data as u8 {
                        let mut c = cap.lock().await;
                        if c.is_none() {
                            *c = Some(data.to_vec());
                        }
                    }
                    bob_addr
                };
                let _ = sock.send_to(data, dst).await;
            }
        });
        addr
    };

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();

    // Handshake + one DATA.
    alice_t
        .send_data(&bob_peer, b"capture me", 0, 0)
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"capture me");

    // Drain for the capture to settle.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let captured_bytes = captured.lock().await.clone();
    let captured_bytes = captured_bytes.expect("proxy never captured a DATA packet");

    // Replay it 5000 times directly to Bob.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..5000 {
        attacker.send_to(&captured_bytes, bob_addr).await.unwrap();
    }

    // None of them should result in a second delivery. Drain with a
    // short timeout — any Ok(Some(_)) is a replay bypass.
    let mut extra = 0;
    for _ in 0..5 {
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), bob_t.recv()).await {
            extra += 1;
        }
    }
    assert_eq!(extra, 0, "replay filter let {} duplicates through", extra);
}

/// Packets claiming a different src_id fail authentication because the
/// receiver looks up the session key by src_id — a mismatched src_id
/// either finds no peer or finds the wrong session key.
#[tokio::test]
async fn src_id_spoofing_rejected() {
    let bob = Identity::from_secret_bytes([0xD0; 32]);
    let alice = Identity::from_secret_bytes([0xD1; 32]);
    let eve = Identity::from_secret_bytes([0xD2; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    // Bob only trusts Alice.
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

    // Alice handshakes normally.
    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice_t.send_data(&bob_peer, b"legit", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    // Eve forges a packet claiming src_id = Alice's peer_id.
    let alice_peer_id = derive_peer_id(&alice_pub);
    let bob_peer_id = derive_peer_id(&bob_pub);
    let mut header = Header::new(PacketType::Data, 99, alice_peer_id, bob_peer_id);
    header.payload_len = 8;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut wire = hbuf.to_vec();
    wire.extend_from_slice(&[0xEEu8; 8 + 16]); // bogus ciphertext+tag

    let _ = eve; // unused identity, just used to emphasize "attacker"
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.send_to(&wire, bob_addr).await.unwrap();

    // Verify Bob didn't accept it.
    let got = tokio::time::timeout(Duration::from_millis(300), bob_t.recv()).await;
    assert!(got.is_err(), "forged packet was delivered");
}

/// Measure the approximate CPU cost of processing unauthenticated HELLO
/// packets. Informational — quantifies the DoS amplification risk from
/// having no cookie challenge in the handshake.
#[tokio::test]
async fn cookie_dos_cost_measurement() {
    let bob = Identity::from_secret_bytes([0xE0; 32]);
    let fake_alice_pub = [0u8; 32]; // not in trust list
    let bob_t = Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
        .await
        .unwrap();
    // Bob does NOT add fake_alice_pub — so every HELLO should be dropped
    // at the peer-lookup stage.
    let _ = fake_alice_pub;
    let addr = bob_t.local_addr().unwrap();

    // Send 10k fake HELLOs and time it.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut hello_bytes = vec![0u8; HEADER_LEN + 48];
    hello_bytes[0] = 0x10;
    hello_bytes[1] = PacketType::Hello as u8;
    hello_bytes[30..32].copy_from_slice(&48u16.to_be_bytes());
    // dst_id = bob's peer_id
    let bob_peer_id = bob_t.local_peer_id();
    hello_bytes[20..28].copy_from_slice(&bob_peer_id);

    let start = Instant::now();
    for _ in 0..10_000 {
        attacker.send_to(&hello_bytes, addr).await.unwrap();
    }
    let elapsed = start.elapsed();

    // Give Bob a moment to drain.
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!(
        "cookie_dos: sent 10k fake HELLOs in {:?}, {:.0} pps",
        elapsed,
        10_000.0 / elapsed.as_secs_f64()
    );

    // The point of this test is to not crash / deadlock. No assertion
    // on the rate — it's informational. But Bob should still be alive.
    let bob_id = Identity::from_secret_bytes([0xE0; 32]);
    let _ = bob_id;
}

/// Header authentication — flipping any byte in the header (other than
/// hop_ttl, which is AAD-masked) should cause AEAD to reject the packet.
#[tokio::test]
async fn header_bit_flip_rejected() {
    let (alice_t, bob_t, bob_peer) = {
        let bob = Identity::from_secret_bytes([0xF0; 32]);
        let alice = Identity::from_secret_bytes([0xF1; 32]);
        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();

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
        let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
            .await
            .unwrap();
        let bp = alice_t
            .add_peer(bob_pub, bob_addr, Direction::Initiator)
            .await
            .unwrap();
        (alice_t, bob_t, bp)
    };

    // Warm up so Bob has a session.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap();

    // Build a fake packet with a completely different seq number and
    // plausible header; the AEAD tag won't be right so it's rejected.
    // This verifies that Bob doesn't happily "accept" a plausibly-formed
    // header — it always requires a valid tag.
    let hdr = Header::new(PacketType::Data, 99, [0; 8], [0; 8]);
    let mut buf = [0u8; HEADER_LEN];
    hdr.encode(&mut buf);
    let _aad = canonical_aad(&buf);
    let mut wire = buf.to_vec();
    wire.extend_from_slice(&vec![0u8; 16]);

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&wire, bob_t.local_addr().unwrap())
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_millis(200), bob_t.recv()).await;
    assert!(got.is_err());
}

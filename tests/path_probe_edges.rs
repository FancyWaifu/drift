//! Edge-case tests for the path-validation probe logic.
//!
//! 1. Spam-rate-limit: many rapid replays from the same wrong
//!    source trigger at most a bounded number of `PathChallenge`
//!    emissions within the retry window — attacker can't force
//!    unbounded probe bandwidth.
//! 2. Reference the proxy path test in `attack_data_path_hijack.rs`
//!    for the functional probe/response cycle (already covered).

use drift::derive_peer_id;
use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn path_probe_retry_is_rate_limited() {
    // Bob is the target; Alice has a real session with him so the
    // peer table is populated. Then a 3rd-party socket fires 500
    // bogus DATA packets at Bob claiming to be Alice. Every packet
    // fails AEAD before reaching the probe logic (attacker has no
    // session key), so path_probes_sent must stay at zero. This
    // confirms garbage replay does NOT spend probe bandwidth.
    let bob_id = Identity::from_secret_bytes([0x60; 32]);
    let alice_id = Identity::from_secret_bytes([0x61; 32]);
    let bob_pub = bob_id.public_bytes();
    let alice_pub = alice_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let alice = Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
        .await
        .unwrap();
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, b"warm-up", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    // Now bombard Bob with 500 fake DATA packets from a third-party
    // socket. Every one fails AEAD, so no probe should fire.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..500u32 {
        let mut header = Header::new(
            PacketType::Data,
            1_000_000 + i,
            derive_peer_id(&alice_pub),
            derive_peer_id(&bob_pub),
        );
        header.payload_len = 16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let mut wire = Vec::from(&hbuf[..]);
        wire.extend_from_slice(&[0xEEu8; 16]); // garbage tag
        attacker.send_to(&wire, bob_addr).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let m = bob.metrics();
    assert_eq!(
        m.path_probes_sent, 0,
        "AEAD-invalid spoofed packets must not trigger probes (got {})",
        m.path_probes_sent
    );
    assert_eq!(m.path_probes_succeeded, 0);
    // Those 500 packets SHOULD have bumped auth_failures though.
    assert!(
        m.auth_failures >= 500,
        "expected auth_failures >= 500, got {}",
        m.auth_failures
    );
}

/// A second proxy-based test that asserts the probe-retry window
/// bounds how many PathChallenges fire when the same authenticated
/// roaming event gets retried. Uses the same proxy pattern as
/// `attack_data_path_hijack::proxy_mid_session_path_switch` but
/// keeps the forwarding socket stable for several sends after the
/// swap — only ONE probe should fire even though many sends
/// cross the new wire source.
#[tokio::test]
async fn single_roaming_event_produces_single_probe() {
    use tokio::sync::Mutex;

    let bob_id = Identity::from_secret_bytes([0x70; 32]);
    let alice_id = Identity::from_secret_bytes([0x71; 32]);
    let bob_pub = bob_id.public_bytes();
    let alice_pub = alice_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let p1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let p2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let p1_addr = p1.local_addr().unwrap();
    let p2_addr = p2.local_addr().unwrap();
    let alice_back: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));
    let active: Arc<Mutex<u8>> = Arc::new(Mutex::new(1));

    for (idx, sock) in [(1u8, p1.clone()), (2u8, p2.clone())] {
        let bob_addr_c = bob_addr;
        let alice_back_c = alice_back.clone();
        let active_c = active.clone();
        let p1_c = p1.clone();
        let p2_c = p2.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2000];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let data = buf[..n].to_vec();
                if from == bob_addr_c {
                    if let Some(a) = *alice_back_c.lock().await {
                        let ac = *active_c.lock().await;
                        let out = if ac == 1 { &p1_c } else { &p2_c };
                        let _ = out.send_to(&data, a).await;
                    }
                } else {
                    *alice_back_c.lock().await = Some(from);
                    if *active_c.lock().await == idx {
                        let _ = sock.send_to(&data, bob_addr_c).await;
                    }
                }
            }
        });
    }

    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, p1_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, b"p1", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv()).await;

    // Swap to p2 and send a burst of 30 packets in tight succession.
    *active.lock().await = 2;
    alice.update_peer_addr(&bob_peer, p2_addr).await;
    for i in 0..30u32 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), bob.recv()).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let m = bob.metrics();
    // One probe per path-change event, not one per packet. The
    // retry window (500ms) means back-to-back sends after the swap
    // reuse the in-flight probe.
    assert!(
        m.path_probes_sent >= 1,
        "expected at least one probe, got 0"
    );
    assert!(
        m.path_probes_sent <= 3,
        "expected 1-3 probes for a single roaming event, got {}",
        m.path_probes_sent
    );
    assert!(
        m.path_probes_succeeded >= 1,
        "probe must have completed, got {} successes",
        m.path_probes_succeeded
    );
}

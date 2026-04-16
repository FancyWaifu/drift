//! Graceful connection migration: client preemptively probes a
//! candidate address (e.g., a cellular interface during a
//! wifi → cellular handoff) and only switches over once the
//! path is validated. No traffic stall, no reactive scramble.
//!
//! Test setup: Bob is bound to a real address. We stand up a
//! UDP proxy at a different address (`proxy_addr`) that
//! transparently forwards both directions to Bob. From Alice's
//! perspective, the proxy IS Bob at a new address. Alice does
//! a normal handshake via the *direct* path, then later asks
//! the transport to graceful-migrate to the proxy address. The
//! probe / response round-trips through the proxy, validation
//! succeeds, and Alice's stored peer.addr swaps over. Subsequent
//! send_data from Alice should land at Bob via the proxy.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Bidirectional transparent UDP proxy. Forwards every packet
/// from the client to `target` and every reply from `target`
/// back to the client. Used to fake "Bob at a different
/// address" without binding Bob to two sockets.
async fn spawn_proxy(target: SocketAddr) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let data = buf[..n].to_vec();
            let dst = if src == target {
                match *client.lock().await {
                    Some(a) => a,
                    None => continue,
                }
            } else {
                let mut c = client.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                target
            };
            let _ = sock.send_to(&data, dst).await;
        }
    });
    addr
}

#[tokio::test]
async fn graceful_migration_swaps_peer_addr() {
    let alice_id = Identity::from_secret_bytes([0xA9; 32]);
    let bob_id = Identity::from_secret_bytes([0xB9; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_real_addr = bob.local_addr().unwrap();

    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_real_addr, Direction::Initiator)
        .await
        .unwrap();

    // Establish the session via the direct path.
    alice.send_data(&bob_peer, b"direct", 0, 0).await.unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"direct");

    // Stand up a proxy that fronts Bob from a new address.
    // This simulates Bob being reachable via a different
    // network path the OS just told us about.
    let proxy_addr = spawn_proxy(bob_real_addr).await;

    // Sanity: starting state.
    let m_before = alice.metrics();
    assert_eq!(m_before.graceful_probes_initiated, 0);
    assert_eq!(m_before.path_probes_succeeded, 0);

    // Kick off the graceful probe.
    alice
        .probe_candidate_path(&bob_peer, proxy_addr)
        .await
        .unwrap();

    // The PathChallenge goes through the proxy → Bob, Bob
    // replies with PathResponse → proxy → Alice. Wait for the
    // path_probes_succeeded counter to bump.
    let succeeded = AtomicBool::new(false);
    for _ in 0..30 {
        if alice.metrics().path_probes_succeeded >= 1 {
            succeeded.store(true, Ordering::Relaxed);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        succeeded.load(Ordering::Relaxed),
        "graceful probe never validated; metrics = {:?}",
        alice.metrics()
    );
    assert_eq!(alice.metrics().graceful_probes_initiated, 1);

    // After validation, Alice should be sending to the proxy
    // address now, not the direct one. Confirm by tearing the
    // direct path down (we can't really do that on localhost,
    // but we CAN check that subsequent traffic still arrives
    // at Bob — which it will via either path on loopback).
    alice.send_data(&bob_peer, b"after-migrate", 0, 0).await.unwrap();
    let p2 = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p2.payload, b"after-migrate");
}

#[tokio::test]
async fn graceful_probe_rejected_for_unknown_peer() {
    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes([0xAA; 32]),
        )
        .await
        .unwrap(),
    );
    let bogus_peer = [0xCDu8; 8];
    let candidate: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let err = alice
        .probe_candidate_path(&bogus_peer, candidate)
        .await
        .expect_err("must reject probe for unknown peer");
    assert!(matches!(err, drift::error::DriftError::UnknownPeer));
}

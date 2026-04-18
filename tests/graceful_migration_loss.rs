//! Graceful migration robustness under a flaky candidate path.
//!
//! The happy-path test in `graceful_migration.rs` uses a
//! clean proxy. This one drops the first few packets in each
//! direction to simulate a lossy candidate path, and verifies
//! that the migration either:
//!   (a) eventually succeeds once packets start flowing, or
//!   (b) times out cleanly without corrupting state.
//!
//! The current implementation issues a single challenge per
//! `probe_candidate_path` call with no internal retry loop, so
//! the expected behavior today is (b) — a clean timeout when
//! the candidate is lossy enough that neither the challenge nor
//! the response get through. The app is expected to retry.
//!
//! This test exercises two scenarios:
//!   - lossy_candidate_times_out_cleanly: 100% loss → the
//!     probe state gets abandoned once stale, no stuck state.
//!   - lossy_candidate_succeeds_on_retry: 50% loss with a
//!     couple of app-level retries → the migration eventually
//!     lands.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrd};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Proxy that drops packets according to a per-direction
/// counter: "drop first N packets from client → target, then
/// forward everything." Both directions share the counter so
/// the probe round-trip has to cross a shared loss window.
async fn spawn_head_drop_proxy(target: SocketAddr, drops: usize) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let dropped = Arc::new(AtomicUsize::new(0));

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
            if dropped.fetch_add(1, AtomicOrd::Relaxed) < drops {
                continue;
            }
            let _ = sock.send_to(&data, dst).await;
        }
    });
    addr
}

async fn setup_pair() -> (
    Arc<Transport>,
    Arc<Transport>,
    drift::crypto::PeerId,
    SocketAddr,
) {
    let alice_id = Identity::from_secret_bytes([0xC1; 32]);
    let bob_id = Identity::from_secret_bytes([0xC2; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

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

    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    (alice, bob, bob_peer, bob_addr)
}

#[tokio::test]
async fn lossy_candidate_succeeds_on_retry() {
    let (alice, _bob, bob_peer, bob_real_addr) = setup_pair().await;

    // Proxy drops just the first packet then forwards cleanly.
    // The first `probe_candidate_path` call eats the drop on
    // its PathChallenge; the retry lands.
    let proxy_addr = spawn_head_drop_proxy(bob_real_addr, 1).await;

    // First attempt: challenge dropped. The probe is recorded
    // in peer.probing but no response comes.
    alice
        .probe_candidate_path(&bob_peer, proxy_addr)
        .await
        .unwrap();
    assert_eq!(alice.metrics().graceful_probes_initiated, 1);

    // Wait past the PATH_PROBE_RETRY interval (500ms) so a
    // fresh probe to the same candidate is allowed.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Second attempt: this one should get through (proxy has
    // now exhausted its drop budget).
    alice
        .probe_candidate_path(&bob_peer, proxy_addr)
        .await
        .unwrap();
    assert_eq!(alice.metrics().graceful_probes_initiated, 2);

    // Wait for validation.
    let mut validated = false;
    for _ in 0..30 {
        if alice.metrics().path_probes_succeeded >= 1 {
            validated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        validated,
        "probe should have validated after retry, metrics = {:?}",
        alice.metrics()
    );
}

#[tokio::test]
async fn lossy_candidate_probe_does_not_corrupt_state() {
    // Worst-case: the candidate path is totally unresponsive.
    // The probe goes out, no response ever comes back. Session
    // state (peer.addr, cwnd, streams) must remain intact —
    // we should still be able to send on the original path.
    let (alice, bob, bob_peer, bob_real_addr) = setup_pair().await;

    // Proxy drops EVERYTHING — effectively a black hole.
    let black_hole = spawn_head_drop_proxy(bob_real_addr, usize::MAX).await;

    alice
        .probe_candidate_path(&bob_peer, black_hole)
        .await
        .unwrap();

    // Session should still work via the direct path.
    alice
        .send_data(&bob_peer, b"still-alive", 0, 0)
        .await
        .unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("direct-path send should still work while probe is stuck")
        .unwrap();
    assert_eq!(p.payload, b"still-alive");

    // No migration happened.
    assert_eq!(alice.metrics().path_probes_succeeded, 0);
}

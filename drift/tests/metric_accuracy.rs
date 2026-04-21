//! Exact-count assertions for the metric counters. Sanity check
//! that the plumbing is right end-to-end: every action that should
//! bump a counter does so, and nothing bumps unexpectedly.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn exact_counts_for_clean_session() {
    let bob_id = Identity::from_secret_bytes([0x30; 32]);
    let alice_id = Identity::from_secret_bytes([0x31; 32]);
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

    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Drive exactly 10 data packets through a warm session. Each
    // send is a single DATA packet (no fragmentation, no coalesce
    // drop, no replay).
    alice.send_data(&bob_peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    for i in 0u32..10 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
            .await
            .unwrap()
            .unwrap();
    }

    // Let any stray background ticks finish before reading metrics.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alice_m = alice.metrics();
    let bob_m = bob.metrics();

    // --- Alice sent: 1 HELLO + 11 DATA = 12. Can be more if
    //     beacons fired; the default beacon_interval is 2s and
    //     this test runs in <1s, so 0 beacons.
    assert_eq!(
        alice_m.packets_sent, 12,
        "Alice should have sent exactly 1 HELLO + 11 DATA, got {}",
        alice_m.packets_sent
    );
    // --- Bob sent: 1 HELLO_ACK + 1 ResumptionTicket (issued on
    //     first DATA) = 2.
    assert_eq!(
        bob_m.packets_sent, 2,
        "Bob should have sent 1 HELLO_ACK + 1 ResumptionTicket, got {}",
        bob_m.packets_sent
    );
    // Ticket counter sanity.
    assert_eq!(bob_m.resumption_tickets_issued, 1);

    // --- handshakes_completed: exactly 1 on each side.
    // Alice increments on HELLO_ACK receive, Bob increments on
    // the first DATA receive.
    assert_eq!(alice_m.handshakes_completed, 1);
    assert_eq!(bob_m.handshakes_completed, 1);

    // --- Nothing should have been dropped.
    assert_eq!(alice_m.replays_caught, 0);
    assert_eq!(bob_m.replays_caught, 0);
    assert_eq!(alice_m.auth_failures, 0);
    assert_eq!(bob_m.auth_failures, 0);
    assert_eq!(alice_m.deadline_dropped, 0);
    assert_eq!(bob_m.deadline_dropped, 0);
    assert_eq!(alice_m.coalesce_dropped, 0);
    assert_eq!(bob_m.coalesce_dropped, 0);
    assert_eq!(alice_m.handshake_retries, 0);
    assert_eq!(bob_m.handshake_retries, 0);
    assert_eq!(bob_m.path_probes_sent, 0);
    assert_eq!(bob_m.path_probes_succeeded, 0);
    assert_eq!(bob_m.cookies_accepted, 0);
    assert_eq!(bob_m.cookies_rejected, 0);
    assert_eq!(bob_m.challenges_issued, 0);
    assert_eq!(bob_m.handshakes_evicted, 0);
    assert_eq!(bob_m.peer_id_collisions, 0);

    // --- Newer counters (added with amp limit, batching,
    //     RTT probes, auto-rekey, resumption rejections,
    //     graceful migration). On a clean 1-second session
    //     none of these should fire.
    assert_eq!(alice_m.auto_rekeys, 0);
    assert_eq!(bob_m.auto_rekeys, 0);
    assert_eq!(alice_m.resumption_attempts, 0);
    assert_eq!(bob_m.resumption_rejects, 0);
    assert_eq!(alice_m.resumptions_completed, 0);
    assert_eq!(bob_m.resumptions_completed, 0);
    assert_eq!(alice_m.amplification_blocked, 0);
    assert_eq!(bob_m.amplification_blocked, 0);
    assert_eq!(alice_m.batched_sends, 0);
    assert_eq!(bob_m.batched_sends, 0);
    assert_eq!(alice_m.ecn_ce_received, 0);
    assert_eq!(bob_m.ecn_ce_received, 0);
    assert_eq!(alice_m.graceful_probes_initiated, 0);
    assert_eq!(bob_m.graceful_probes_initiated, 0);
    // RTT probe interval is 5s default, test runs <1s, so
    // no active pings fire. Passive RTT samples from the
    // handshake path DON'T bump the ping counters.
    assert_eq!(alice_m.pings_sent, 0);
    assert_eq!(bob_m.pings_sent, 0);
    assert_eq!(alice_m.pongs_sent, 0);
    assert_eq!(bob_m.pongs_sent, 0);
    assert_eq!(alice_m.pongs_received, 0);
    assert_eq!(bob_m.pongs_received, 0);
    // Alice is the one that RECEIVED a ticket; Bob issued
    // one but received none.
    assert_eq!(alice_m.resumption_tickets_issued, 0);
    assert_eq!(bob_m.resumption_tickets_received, 0);
    assert_eq!(alice_m.resumption_tickets_received, 1);
}

#[tokio::test]
async fn cookie_counts_match_under_forced_cookie_mode() {
    let cfg = TransportConfig {
        cookie_always: true,
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let bob_id = Identity::from_secret_bytes([0x40; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, cfg)
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    let alice_id = Identity::from_secret_bytes([0x41; 32]);
    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice
        .send_data(&bob_peer, b"behind-cookie", 0, 0)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .unwrap()
        .unwrap();

    let m = bob.metrics();
    // In cookie_always mode, exactly one CHALLENGE is issued for
    // the first HELLO and exactly one cookie is accepted on the
    // retry. No rejections on a clean flow.
    assert_eq!(
        m.challenges_issued, 1,
        "expected exactly one CHALLENGE, got {}",
        m.challenges_issued
    );
    assert_eq!(
        m.cookies_accepted, 1,
        "expected exactly one cookie accepted, got {}",
        m.cookies_accepted
    );
    assert_eq!(
        m.cookies_rejected, 0,
        "expected zero rejections, got {}",
        m.cookies_rejected
    );
    assert_eq!(m.handshakes_completed, 1);
}

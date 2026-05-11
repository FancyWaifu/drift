//! Federation-directory routing-table semantics.
//!
//! These tests lock in two protocol invariants that protect
//! federation directories against bad-faith neighbors:
//!
//! 1. **First-write-wins on cross-announcer conflicts.** If
//!    bridge B announces client X, a later announcement from a
//!    different bridge C claiming the same X must not displace
//!    B's entry. A malicious federated bridge can otherwise race
//!    to hijack routing for any pubkey it cares to.
//!
//! 2. **Idempotent-set semantics on announcements.** Each
//!    FederationDirectory packet from a bridge is the COMPLETE
//!    current set of that bridge's clients. A client dropping
//!    off bridge B's peer table evicts from receivers within one
//!    announce interval (~7 s) instead of waiting out the 20 s
//!    stale-entry TTL.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;
use tokio::time::sleep;

/// Build a FederationDirectory wire payload from a slice of
/// client pubkeys. Matches the format documented on
/// `PacketType::FederationDirectory`:
///
/// ```text
///   [0]    version (u8) = 1
///   [1]    reserved (u8) = 0
///   [2..4] count (u16 BE)
///   [4..]  count * 32-byte pubkeys
/// ```
fn build_directory_payload(pubs: &[[u8; 32]]) -> Vec<u8> {
    let count = pubs.len() as u16;
    let mut out = Vec::with_capacity(4 + pubs.len() * 32);
    out.push(1); // version
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for p in pubs {
        out.extend_from_slice(p);
    }
    out
}

/// Three-Transport setup:
///   - `receiver` is the bridge whose directory we'll be testing.
///   - `bridge_b` and `bridge_c` are two federation peers of
///     receiver — both in receiver's federation_table so their
///     directory announcements are accepted.
///
/// Returns (receiver, bridge_b, bridge_c, b_handle, c_handle)
/// where `b_handle` / `c_handle` are the PeerIds bridge_b /
/// bridge_c use to address `receiver` (so they can call
/// `__debug_send_directory_announcement(&handle, …)`).
async fn three_bridges() -> (
    Transport,
    Transport,
    Transport,
    drift_core::PeerId,
    drift_core::PeerId,
) {
    let receiver_id = Identity::from_secret_bytes([0x11; 32]);
    let bridge_b_id = Identity::from_secret_bytes([0x22; 32]);
    let bridge_c_id = Identity::from_secret_bytes([0x33; 32]);
    let receiver_pub = receiver_id.public_bytes();
    let bridge_b_pub = bridge_b_id.public_bytes();
    let bridge_c_pub = bridge_c_id.public_bytes();

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    };
    let receiver =
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), receiver_id, cfg.clone())
            .await
            .unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    let bridge_b =
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bridge_b_id, cfg.clone())
            .await
            .unwrap();
    let bridge_c =
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bridge_c_id, cfg)
            .await
            .unwrap();

    let b_to_receiver = bridge_b
        .add_peer(receiver_pub, receiver_addr, Direction::Initiator)
        .await
        .unwrap();
    let c_to_receiver = bridge_c
        .add_peer(receiver_pub, receiver_addr, Direction::Initiator)
        .await
        .unwrap();
    // Warmup to drive HELLO on both sides.
    let _ = bridge_b.send_data(&b_to_receiver, b".", 0, 0).await;
    let _ = bridge_c.send_data(&c_to_receiver, b".", 0, 0).await;
    sleep(Duration::from_millis(300)).await;
    // Drain any inbound that landed during warmup so it doesn't
    // confuse a later recv().
    let _ = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;

    // Add B and C to receiver's federation_table so its directory
    // handler accepts their announcements. (In real deployments
    // this is done by `drift bridge --federate <url>@<pub>` on
    // startup, which calls register_federation_peer internally.)
    let b_peer_id_on_receiver = derive_peer_id(&bridge_b_pub);
    let c_peer_id_on_receiver = derive_peer_id(&bridge_c_pub);
    receiver.register_federation_peer(bridge_b_pub, b_peer_id_on_receiver);
    receiver.register_federation_peer(bridge_c_pub, c_peer_id_on_receiver);

    (receiver, bridge_b, bridge_c, b_to_receiver, c_to_receiver)
}

// ─── Test 1: first-write-wins ─────────────────────────────────────

#[tokio::test]
async fn cross_announcer_conflict_keeps_first_writer() {
    let (receiver, bridge_b, bridge_c, b_to_recv, c_to_recv) = three_bridges().await;

    // A client pubkey neither bridge actually hosts — the point
    // of the test is the routing-table arithmetic, not real
    // sessions with the claimed client.
    let contested = Identity::generate().public_bytes();

    // Bridge B announces it has the contested client.
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[contested]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        receiver.peer_directory_contains(&contested),
        "B's announcement should have populated the directory"
    );
    let count_after_b = receiver.peer_directory_count();

    // Bridge C tries to claim the same client. First-write-wins
    // means this is silently ignored — B's entry persists.
    bridge_c
        .__debug_send_directory_announcement(
            &c_to_recv,
            &build_directory_payload(&[contested]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        receiver.peer_directory_contains(&contested),
        "DEFENSE REGRESSION: bridge C displaced bridge B's directory \
         entry just by announcing later. Cross-announcer conflicts \
         must be resolved first-write-wins."
    );
    assert_eq!(
        receiver.peer_directory_count(),
        count_after_b,
        "DEFENSE REGRESSION: directory count changed after C's \
         conflicting announce — indicates the entry was rewritten."
    );
    println!(
        "DEFENSE: first-write-wins held; directory count = {}",
        receiver.peer_directory_count()
    );
}

// ─── Test 2: idempotent-set semantics + implicit retraction ─────

#[tokio::test]
async fn announce_set_replaces_announcer_entries() {
    let (receiver, bridge_b, _bridge_c, b_to_recv, _c_to_recv) = three_bridges().await;

    let alice = Identity::generate().public_bytes();
    let bob = Identity::generate().public_bytes();

    // Bridge B announces [alice, bob].
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[alice, bob]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(receiver.peer_directory_contains(&alice));
    assert!(receiver.peer_directory_contains(&bob));

    // Bridge B re-announces with bob removed (he disconnected).
    // Idempotent-set semantics: receiver prunes the entry it
    // recorded under B for bob, because bob isn't in B's new
    // complete set.
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[alice]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        receiver.peer_directory_contains(&alice),
        "alice should still be present — B re-announced her"
    );
    assert!(
        !receiver.peer_directory_contains(&bob),
        "DEFENSE REGRESSION: bob remained in the directory after B \
         announced a complete set that omitted him. This breaks \
         fast-retraction on client disconnect — disconnected \
         clients keep attracting traffic until the 20 s TTL."
    );

    // Empty announce from B prunes alice too. This is how a
    // bridge with zero clients (e.g. just-restarted) signals
    // "drop everything you previously recorded under me".
    bridge_b
        .__debug_send_directory_announcement(&b_to_recv, &build_directory_payload(&[]))
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        !receiver.peer_directory_contains(&alice),
        "DEFENSE REGRESSION: B's empty announce didn't prune its \
         prior entries — bridges can't signal client departures \
         without waiting out the TTL."
    );

    println!(
        "DEFENSE: idempotent-set semantics held across announce + \
         shrink + empty. Final directory count = {}",
        receiver.peer_directory_count()
    );
}

// ─── Test 3: legitimate migration after first-writer goes silent ─

#[tokio::test]
async fn migration_after_silence_is_allowed() {
    let (receiver, bridge_b, bridge_c, b_to_recv, c_to_recv) = three_bridges().await;

    let migrating = Identity::generate().public_bytes();

    // B announces the client.
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[migrating]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(receiver.peer_directory_contains(&migrating));

    // B announces it no longer has the client (it disconnected).
    bridge_b
        .__debug_send_directory_announcement(&b_to_recv, &build_directory_payload(&[]))
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        !receiver.peer_directory_contains(&migrating),
        "B's idempotent retraction should have cleared the entry"
    );

    // Now C announces the client — the legitimate migration. With
    // the prior entry properly retracted by B, C's claim should
    // be accepted (no first-writer holding the slot).
    bridge_c
        .__debug_send_directory_announcement(
            &c_to_recv,
            &build_directory_payload(&[migrating]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(
        receiver.peer_directory_contains(&migrating),
        "DEFENSE REGRESSION: legitimate client migration after the \
         original bridge cleanly retracted should be accepted — \
         first-write-wins only fires while the prior write is \
         still live."
    );
    println!(
        "MIGRATION OK: client moved B → C cleanly after B's empty announce"
    );
}

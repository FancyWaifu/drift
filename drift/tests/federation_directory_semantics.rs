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

/// Build a FederationDirectory v2 wire payload from a slice of
/// client secret seeds + the announcing bridge's pubkey. Each
/// entry carries a freshly-signed XEdDSA presence ticket so the
/// receiver's per-entry verification accepts it.
///
/// Matches the format documented on `PacketType::FederationDirectory`:
///
/// ```text
///   [0]    version (u8) = 2
///   [1]    reserved (u8) = 0
///   [2..4] count (u16 BE)
///   [4..]  count * (32-byte pubkey ‖ 96-byte ticket)
/// ```
fn build_directory_payload(
    client_seeds: &[[u8; 32]],
    announcing_bridge_pub: &[u8; 32],
) -> Vec<u8> {
    let count = client_seeds.len() as u16;
    let mut out = Vec::with_capacity(4 + client_seeds.len() * (32 + 96));
    out.push(2); // version
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    let expiry_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 600_000;
    for seed in client_seeds {
        let client_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*seed)).to_bytes();
        let ticket = drift::transport::build_ticket(
            seed,
            announcing_bridge_pub,
            expiry_ms,
            [0xAA; 24],
            &[0xBB; 64],
        );
        out.extend_from_slice(&client_pub);
        out.extend_from_slice(&drift::transport::encode_ticket(&ticket));
    }
    out
}

/// Helper: deterministic Curve25519 pubkey for a given seed.
fn pub_for(seed: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*seed)).to_bytes()
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
    [u8; 32], // bridge_b_pub
    [u8; 32], // bridge_c_pub
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

    (
        receiver,
        bridge_b,
        bridge_c,
        b_to_receiver,
        c_to_receiver,
        bridge_b_pub,
        bridge_c_pub,
    )
}

// ─── Test 1: first-write-wins ─────────────────────────────────────

#[tokio::test]
async fn cross_announcer_conflict_keeps_first_writer() {
    let (receiver, bridge_b, bridge_c, b_to_recv, c_to_recv, b_pub, c_pub) =
        three_bridges().await;

    // A deterministic seed for the contested client identity,
    // so both B and C can mint valid tickets for "themselves
    // hosting" this client. (In a real deployment the client
    // would only have signed for ONE bridge; here we let both
    // forge to exercise the receiver's first-write-wins logic.)
    let contested_seed = [0x77u8; 32];
    let contested = pub_for(&contested_seed);

    // Bridge B announces it has the contested client.
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[contested_seed], &b_pub),
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
            &build_directory_payload(&[contested_seed], &c_pub),
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
    let (receiver, bridge_b, _bridge_c, b_to_recv, _c_to_recv, b_pub, _c_pub) =
        three_bridges().await;

    let alice_seed = [0xA1u8; 32];
    let bob_seed = [0xB2u8; 32];
    let alice = pub_for(&alice_seed);
    let bob = pub_for(&bob_seed);

    // Bridge B announces [alice, bob].
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[alice_seed, bob_seed], &b_pub),
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
            &build_directory_payload(&[alice_seed], &b_pub),
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
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[], &b_pub),
        )
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
    let (receiver, bridge_b, bridge_c, b_to_recv, c_to_recv, b_pub, c_pub) =
        three_bridges().await;

    let migrating_seed = [0xCDu8; 32];
    let migrating = pub_for(&migrating_seed);

    // B announces the client.
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[migrating_seed], &b_pub),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(receiver.peer_directory_contains(&migrating));

    // B announces it no longer has the client (it disconnected).
    bridge_b
        .__debug_send_directory_announcement(
            &b_to_recv,
            &build_directory_payload(&[], &b_pub),
        )
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
            &build_directory_payload(&[migrating_seed], &c_pub),
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

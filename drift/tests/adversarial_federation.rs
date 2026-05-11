//! Adversarial tests against the federation envelope layer.
//!
//! Federation envelopes carry four pubkey claims in plaintext
//! (target_bridge_pub, target_client_pub, source_bridge_pub,
//! source_client_pub). The outer DRIFT packet authenticates *who*
//! sent the envelope to the bridge (the immediate hop), but the
//! envelope's `source_client_pub` and `source_bridge_pub` fields
//! are application-supplied bytes. Each test below crafts a
//! forged envelope and reports what the receiver does with it.
//!
//! Each test asserts that the receiver REJECTS the forgery. If
//! a future change weakens the source-authentication check in
//! `handle_federated`, these tests fail loudly so the regression
//! gets caught at PR review.
//!
//! All tests use a minimal collapsed topology:
//!
//!     attacker ──┐
//!                ├──▶ bridge ──▶ victim
//!     (forged envelope where source = some other identity)
//!
//! The bridge is both the source AND target bridge (per envelope
//! fields). This isolates the test from any mesh / multi-hop
//! complications and focuses purely on what the bridge and
//! victim do with the claims in the envelope header.

use drift::header::PacketType;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;
use tokio::time::timeout;

/// Hand-roll a federation envelope. This is intentionally NOT
/// going through `transport::federated::build()` — the wire
/// format is publicly documented (in transport/federated.rs)
/// and an attacker would code it from scratch. Keeping the
/// test free of internal API helps it match the real adversary
/// model: any pubkey-32 + payload-len-2 layout is reachable.
fn envelope(
    target_bridge: [u8; 32],
    target_client: [u8; 32],
    source_bridge: [u8; 32],
    source_client: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(130 + payload.len());
    v.extend_from_slice(&target_bridge);
    v.extend_from_slice(&target_client);
    v.extend_from_slice(&source_bridge);
    v.extend_from_slice(&source_client);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Spin up a 3-Transport topology: bridge (accept_any_peer),
/// attacker (one connected client), victim (another connected
/// client). Returns (bridge, attacker, victim) and the handles
/// each attacker/victim has for the bridge. Both attacker and
/// victim handshake before we return, so they have established
/// sessions and can send.
async fn three_party() -> (
    Transport,
    Transport,
    Transport,
    drift_core::PeerId, // attacker's handle for bridge
    drift_core::PeerId, // victim's handle for bridge
) {
    // Use deterministic seeds so re-runs reproduce. Identity
    // doesn't implement Clone; we re-derive the bridge pub from
    // its public_bytes() once we have the Transport.
    let bridge_id = Identity::from_secret_bytes([0x01; 32]);
    let attacker_id = Identity::from_secret_bytes([0x02; 32]);
    let victim_id = Identity::from_secret_bytes([0x03; 32]);
    let bridge_pub = bridge_id.public_bytes();

    let bridge_cfg = TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    };
    let bridge = Transport::bind_with_config(
        "127.0.0.1:0".parse().unwrap(),
        bridge_id,
        bridge_cfg,
    )
    .await
    .unwrap();
    let bridge_addr = bridge.local_addr().unwrap();

    let attacker =
        Transport::bind("127.0.0.1:0".parse().unwrap(), attacker_id)
            .await
            .unwrap();
    let attacker_to_bridge = attacker
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await
        .unwrap();
    // Warm up the session — handshake needs at least one DATA
    // send to drive HELLO.
    let _ = attacker.send_data(&attacker_to_bridge, b".", 0, 0).await;

    let victim =
        Transport::bind("127.0.0.1:0".parse().unwrap(), victim_id)
            .await
            .unwrap();
    let victim_to_bridge = victim
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = victim.send_data(&victim_to_bridge, b".", 0, 0).await;

    // Drain the warmup DATAs the bridge received so they don't
    // confuse later recv() assertions.
    for _ in 0..2 {
        let _ = timeout(Duration::from_millis(200), bridge.recv()).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    (bridge, attacker, victim, attacker_to_bridge, victim_to_bridge)
}

// ─── Test 1 ──────────────────────────────────────────────────────
// FORGED `source_client_pub`
//
// The attacker has a real DRIFT identity and a real session with
// the bridge. They construct an envelope whose `source_client_pub`
// is some OTHER identity (a real person they want to impersonate).
// They ship it to the victim through the bridge.
//
// Question: when the victim receives, whose identity does
// `Received.federated_from` and `Received.peer_id` attribute the
// message to?
//
// If the answer is the forged identity, then ANY client of any
// bridge can spoof ANY other client. drift-mosh, drift-chat,
// drift-wormhole all use `peer_id` as the sender identity, so this
// is an end-to-end identity-spoof vulnerability.

#[tokio::test]
async fn forged_source_client_pub_is_rejected_at_source_bridge() {
    let (bridge, attacker, victim, attacker_to_bridge, _victim_to_bridge) =
        three_party().await;
    let bridge_pub = bridge.local_public();
    let victim_pub = victim.local_public();

    // Identity we're trying to impersonate — attacker doesn't
    // control the private key.
    let impersonated_pub = Identity::generate().public_bytes();

    let env = envelope(
        bridge_pub,
        victim_pub,
        bridge_pub,
        impersonated_pub, // ← FORGED
        b"forged-payload",
    );

    // The send itself succeeds — the attacker has a valid session
    // with the bridge; the bridge can't tell at the wire layer
    // that the envelope contains a forgery. The protection fires
    // inside `handle_federated`.
    attacker
        .__debug_send_federated_envelope(&attacker_to_bridge, &env)
        .await
        .expect("attacker has an established session with the bridge");

    let received = timeout(Duration::from_millis(500), victim.recv())
        .await
        .ok()
        .flatten();

    assert!(
        received.is_none(),
        "DEFENSE REGRESSION: forged envelope was delivered to the victim. \
         The source bridge MUST reject envelopes whose source_client_pub \
         doesn't match the session-authenticated sender."
    );

    // The metric should record the drop so operators can monitor
    // for spoofing attempts.
    let m = bridge.metrics();
    assert!(
        m.federation_spoof_drops >= 1,
        "DEFENSE REGRESSION: federation_spoof_drops metric didn't tick. \
         got {} drops; expected >= 1",
        m.federation_spoof_drops
    );
    println!(
        "DEFENSE: forged envelope dropped; federation_spoof_drops = {}",
        m.federation_spoof_drops
    );
}

// ─── Test 2 ──────────────────────────────────────────────────────
// FEDERATION-TABLE POISONING via the auto-register helper
//
// In handle_federated case (2) (we're the destination bridge),
// we auto-register `env.source_bridge_pub → outer_packet.src_id`
// into our federation table, so the reply path works without
// requiring symmetric `--federate` config.
//
// Attacker exploits this by sending an envelope whose
// `source_bridge_pub` is some legit bridge's pubkey they want
// to MITM. If the auto-register fires, future federated traffic
// our bridge forwards toward that bridge will route to the
// attacker instead.
//
// Defenses to look for:
//   - or_insert (does NOT overwrite an existing entry).
//   - Any check that `source_bridge_pub` belongs to an actual
//     bridge — e.g. we previously --federate'd to it, or it has
//     an established session with us.

#[tokio::test]
async fn federation_table_cannot_be_poisoned_by_unrelated_client() {
    let (bridge, _attacker, victim, attacker_to_bridge, _victim_to_bridge) =
        three_party().await;
    let bridge_pub = bridge.local_public();
    let victim_pub = victim.local_public();

    // Pubkey of a bridge the attacker wants to hijack traffic to.
    // (Made up here; could just as easily be a real bridge's pub.)
    let target_bridge_to_hijack = Identity::generate().public_bytes();
    assert!(
        !bridge.federation_table_contains(&target_bridge_to_hijack),
        "table should be empty for the target before the attack"
    );

    let env = envelope(
        bridge_pub,
        victim_pub,
        target_bridge_to_hijack, // ← claim THIS is our source bridge
        Identity::generate().public_bytes(), // source_client doesn't matter
        b"poison-payload",
    );

    let _ = _attacker
        .__debug_send_federated_envelope(&attacker_to_bridge, &env)
        .await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        !bridge.federation_table_contains(&target_bridge_to_hijack),
        "DEFENSE REGRESSION: the bridge inserted attacker's claimed \
         source_bridge_pub into its federation table. Any client could \
         now hijack future federated traffic addressed to that pubkey."
    );

    // Belt-and-suspenders: the spoof-drops metric should fire
    // on this envelope because the attacker's source_bridge_pub
    // claim doesn't match either (a) our pubkey or (b) the
    // attacker's own pubkey.
    let m = bridge.metrics();
    assert!(
        m.federation_spoof_drops >= 1,
        "DEFENSE REGRESSION: federation_spoof_drops should tick on a \
         poisoning attempt; got {}",
        m.federation_spoof_drops
    );
    println!(
        "DEFENSE: poisoning attempt blocked; federation_spoof_drops = {}",
        m.federation_spoof_drops
    );
    // Silence the unused warnings: we intentionally keep these
    // bindings to document the topology.
    let _ = victim;
}

// Keep the import live even if a future refactor stops using it
// directly in test bodies.
#[allow(dead_code)]
fn _keep_import() {
    let _ = PacketType::Federated;
}

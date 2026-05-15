//! Federation peer discovery — Phase A integration tests.
//!
//! Covers the reactive lookup path defined in
//! `FEDERATION_DISCOVERY.md`:
//!
//! 1. **1-hop discovery + flush**: Bridge B receives a `Federated`
//!    envelope for a client it doesn't know about, with the
//!    `UNKNOWN_BRIDGE_PUB` sentinel. It originates `FindPeer` to
//!    Bridge A (its federation peer). A hosts the client and
//!    replies `PeerHere`. B caches the route and re-issues the
//!    queued envelope through A. A second send for the same
//!    target takes the cached path — no second `FindPeer`.
//!
//! 2. **PeerGone evicts cache**: After the route is cached on B,
//!    the client disconnects from A. A emits `PeerGone` to every
//!    federation peer (including B). B's directory entry for the
//!    client is evicted immediately, rather than waiting for the
//!    next idempotent-set FederationDirectory announce (~7 s).

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::transport::FindPeerMode;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;
use tokio::time::sleep;

/// Tighter timeout than tokio's default makes flaky-on-CI tests
/// fail loudly with a clear "took too long" rather than hanging.
const ROUND_TRIP_WAIT: Duration = Duration::from_millis(600);

async fn build_transport(secret: [u8; 32]) -> Transport {
    let id = Identity::from_secret_bytes(secret);
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    };
    Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), id, cfg)
        .await
        .unwrap()
}

async fn build_transport_with_privacy(secret: [u8; 32], find_peer_disabled: bool) -> Transport {
    let id = Identity::from_secret_bytes(secret);
    let cfg = TransportConfig {
        accept_any_peer: true,
        find_peer_disabled,
        ..Default::default()
    };
    Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), id, cfg)
        .await
        .unwrap()
}

async fn build_transport_with_mode(secret: [u8; 32], mode: FindPeerMode) -> Transport {
    let id = Identity::from_secret_bytes(secret);
    let cfg = TransportConfig {
        accept_any_peer: true,
        find_peer_mode: mode,
        ..Default::default()
    };
    Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), id, cfg)
        .await
        .unwrap()
}

/// Establish a bidirectional federation between `bridge_a` and
/// `bridge_b`. Returns the PeerIds each bridge uses to address
/// the other.
async fn federate(
    bridge_a: &Transport,
    a_pub: &[u8; 32],
    bridge_b: &Transport,
    b_pub: &[u8; 32],
) -> (drift::crypto::PeerId, drift::crypto::PeerId) {
    let a_addr = bridge_a.local_addr().unwrap();
    let b_addr = bridge_b.local_addr().unwrap();

    let b_to_a = bridge_b
        .add_peer(*a_pub, a_addr, Direction::Initiator)
        .await
        .unwrap();
    let a_to_b = bridge_a
        .add_peer(*b_pub, b_addr, Direction::Initiator)
        .await
        .unwrap();
    // Warmup HELLO both directions.
    let _ = bridge_a.send_data(&a_to_b, b".", 0, 0).await;
    let _ = bridge_b.send_data(&b_to_a, b".", 0, 0).await;
    sleep(Duration::from_millis(200)).await;
    // Drain warmup blips.
    let _ = tokio::time::timeout(Duration::from_millis(100), bridge_a.recv()).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), bridge_b.recv()).await;

    // Wire both directions into the federation_table — the
    // discovery protocol's source-auth gate refuses FindPeer /
    // PeerHere / PeerGone from senders not on this table.
    bridge_a.register_federation_peer(*b_pub, derive_peer_id(b_pub));
    bridge_b.register_federation_peer(*a_pub, derive_peer_id(a_pub));
    (a_to_b, b_to_a)
}

/// Bring up a client identity that's connected to `bridge` and has
/// emitted a presence ticket. After this returns, the bridge holds
/// a presence_ticket entry for the client AND has an Established
/// session with them — both gates that `handle_find_peer` checks.
async fn client_on_bridge(
    bridge: &Transport,
    bridge_pub: &[u8; 32],
    client_secret: [u8; 32],
) -> (Transport, drift::crypto::PeerId) {
    let client = build_transport(client_secret).await;
    let bridge_addr = bridge.local_addr().unwrap();
    let client_to_bridge = client
        .add_peer(*bridge_pub, bridge_addr, Direction::Initiator)
        .await
        .unwrap();
    // Drive handshake.
    let _ = client.send_data(&client_to_bridge, b".", 0, 0).await;
    sleep(Duration::from_millis(200)).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), bridge.recv()).await;
    // Now register presence — bridge stores the ticket keyed by
    // the client's authenticated pubkey.
    client
        .register_presence_to(&client_to_bridge, 600_000)
        .await
        .unwrap();
    sleep(Duration::from_millis(150)).await;
    (client, client_to_bridge)
}

/// Build a `Federated` envelope that triggers the
/// `UNKNOWN_BRIDGE_PUB` directory-lookup path on the receiving
/// bridge. `source_*` claim a hypothetical client_C connected via
/// bridge_b; the receiving bridge accepts these claims because the
/// sender (bridge_b) is in its federation_table.
fn build_unknown_target_envelope(
    target_client_pub: &[u8; 32],
    source_bridge_pub: &[u8; 32],
    source_client_pub: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    drift::transport::build_federated(
        &drift::transport::UNKNOWN_BRIDGE_PUB,
        target_client_pub,
        source_bridge_pub,
        source_client_pub,
        payload,
    )
}

// ─── Test 1: 1-hop discovery + cache flush ────────────────────────

#[tokio::test]
async fn find_peer_resolves_cross_bridge_and_caches() {
    // bridge_a hosts client_x; bridge_b federates with bridge_a.
    let bridge_a = build_transport([0x11; 32]).await;
    let a_pub = Identity::from_secret_bytes([0x11; 32]).public_bytes();
    let bridge_b = build_transport([0x22; 32]).await;
    let b_pub = Identity::from_secret_bytes([0x22; 32]).public_bytes();

    let (_a_to_b, b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;

    // client_x on bridge_a — bridge_a now holds a presence ticket
    // for client_x and has an Established session with them.
    let client_x_secret = [0x33; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (_client_x, _x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    // Pre-conditions: bridge_b knows nothing about client_x yet.
    assert!(
        !bridge_b.peer_directory_contains(&client_x_pub),
        "directory should be empty before lookup"
    );
    assert_eq!(
        bridge_b.pending_finds_count(),
        0,
        "no pending finds yet"
    );

    // Trigger: ship a Federated envelope at bridge_b with
    // target_bridge_pub = UNKNOWN_BRIDGE_PUB, target_client_pub
    // = client_x. The source fields claim a hypothetical client
    // on bridge_b. bridge_b is in bridge_a's federation_table
    // (since federate() wired it both directions), so when
    // bridge_a issues __debug_send_federated_envelope to
    // bridge_b, the receiver-side source-auth check trusts the
    // claim.
    //
    // We use bridge_a → bridge_b as the carrier (any federated
    // peer of bridge_b would do; bridge_a is what we have).
    let source_client_pub = [0xCC; 32];
    let env = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &source_client_pub,
        b"hello from outside",
    );
    bridge_a
        .__debug_send_federated_envelope(&_a_to_b, &env)
        .await
        .unwrap();

    // Bridge_b's handle_federated should fire the UNKNOWN_BRIDGE
    // path → originate FindPeer to bridge_a (its only federation
    // peer). Bridge_a's handle_find_peer should see it has
    // client_x as a local client, reply PeerHere. Bridge_b
    // caches and flushes the waiter.
    sleep(ROUND_TRIP_WAIT).await;

    assert!(
        bridge_b.peer_directory_contains(&client_x_pub),
        "PHASE A: FindPeer round-trip should have populated bridge_b's directory"
    );
    assert_eq!(
        bridge_b.pending_finds_count(),
        0,
        "PHASE A: pending_finds should drain once PeerHere arrives"
    );

    // Second envelope for the same target: must NOT originate a
    // new FindPeer (cache hit).
    let env2 = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &source_client_pub,
        b"second packet",
    );
    bridge_a
        .__debug_send_federated_envelope(&_a_to_b, &env2)
        .await
        .unwrap();
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        bridge_b.pending_finds_count(),
        0,
        "PHASE A: cached lookup must not re-issue FindPeer"
    );

    let _ = b_to_a;
}

// ─── Test 1b: 2-hop multi-bridge discovery (Phase B) ──────────────

#[tokio::test]
async fn find_peer_multi_hop_chain() {
    // Topology: A — B — C  (chain, NOT triangle).
    // Client X lives on A. C federates only with B; C must reach
    // X through B's transitive forward.
    let bridge_a = build_transport([0xA1; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xA1; 32]).public_bytes();
    let bridge_b = build_transport([0xB2; 32]).await;
    let b_pub = Identity::from_secret_bytes([0xB2; 32]).public_bytes();
    let bridge_c = build_transport([0xC3; 32]).await;
    let c_pub = Identity::from_secret_bytes([0xC3; 32]).public_bytes();

    let (_a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;
    let (_b_to_c, c_to_b) = federate(&bridge_b, &b_pub, &bridge_c, &c_pub).await;
    // Deliberately do NOT federate A and C — discovery must
    // traverse B.

    let client_x_secret = [0xDD; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (_client_x, _x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    assert!(
        !bridge_c.peer_directory_contains(&client_x_pub),
        "C should not yet know client_x"
    );

    // Trigger: ship a Federated envelope at bridge_c with
    // UNKNOWN_BRIDGE_PUB for client_x. C's directory misses,
    // C originates FindPeer to B (its only federation peer).
    // B doesn't host client_x but its ttl > 1, so B forwards
    // to A. A replies PeerHere → B re-emits with extended path
    // → C caches.
    let env = build_unknown_target_envelope(
        &client_x_pub,
        &c_pub,
        &[0x77; 32],
        b"hop-test",
    );
    bridge_b
        .__debug_send_federated_envelope(&_b_to_c, &env)
        .await
        .unwrap();

    // Multi-hop takes a hair longer than 1-hop — give it 2x.
    sleep(Duration::from_millis(1200)).await;

    assert!(
        bridge_c.peer_directory_contains(&client_x_pub),
        "PHASE B: C should have cached client_x via the B-A chain"
    );
    assert_eq!(
        bridge_c.pending_finds_count(),
        0,
        "PHASE B: pending_finds should drain once the multi-hop reply arrives"
    );
    // B should also have cached (it's a transit bridge — caching
    // the forwarded route benefits its own future traffic).
    assert!(
        bridge_b.peer_directory_contains(&client_x_pub),
        "PHASE B: transit bridge B should have cached too"
    );

    let _ = c_to_b;
}

// ─── Test 1d: Phase E — find_peer_disabled opt-out ────────────────

#[tokio::test]
async fn find_peer_disabled_blocks_discovery() {
    // Same setup as Phase A, but bridge_b runs with
    // find_peer_disabled = true. An UNKNOWN_BRIDGE_PUB envelope
    // arriving at B should be dropped silently — no FindPeer
    // emitted, no directory population. Privacy opt-out works.
    let bridge_a = build_transport([0xE1; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xE1; 32]).public_bytes();
    let bridge_b = build_transport_with_privacy([0xE2; 32], true).await;
    let b_pub = Identity::from_secret_bytes([0xE2; 32]).public_bytes();
    let (a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;

    let client_x_secret = [0xE3; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (_client_x, _x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    let env = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &[0x77; 32],
        b"should-be-dropped",
    );
    bridge_a
        .__debug_send_federated_envelope(&a_to_b, &env)
        .await
        .unwrap();
    sleep(ROUND_TRIP_WAIT).await;

    assert_eq!(
        bridge_b.pending_finds_count(),
        0,
        "PHASE E: find_peer_disabled must suppress FindPeer origination"
    );
    assert!(
        !bridge_b.peer_directory_contains(&client_x_pub),
        "PHASE E: nothing should have been cached — discovery is off"
    );
}

// ─── Test 1e: Phase E v2 — OriginateHashed mode ───────────────────

#[tokio::test]
async fn originate_hashed_resolves_and_caches() {
    // bridge_b runs in OriginateHashed mode: when it encounters
    // an UNKNOWN_BRIDGE_PUB envelope, it emits the *hashed*
    // FindPeer variant. The destination bridge A scans its
    // presence_tickets, hashes each client_pub with the query
    // salt, finds a match, and replies. End result: same as
    // plain Phase A, but transit / forwarder bridges see only
    // the hash on the wire.
    let bridge_a = build_transport([0xE5; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xE5; 32]).public_bytes();
    let bridge_b =
        build_transport_with_mode([0xE6; 32], FindPeerMode::OriginateHashed).await;
    let b_pub = Identity::from_secret_bytes([0xE6; 32]).public_bytes();
    let (a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;

    let client_x_secret = [0xE7; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (_client_x, _x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    let env = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &[0x77; 32],
        b"hashed-trigger",
    );
    bridge_a
        .__debug_send_federated_envelope(&a_to_b, &env)
        .await
        .unwrap();
    sleep(ROUND_TRIP_WAIT).await;

    assert!(
        bridge_b.peer_directory_contains(&client_x_pub),
        "PHASE E v2: OriginateHashed should still resolve the target via hash-match on bridge A"
    );
    assert_eq!(
        bridge_b.pending_finds_count(),
        0,
        "PHASE E v2: pending_finds should drain after PeerHere arrives"
    );
}

// ─── Test 1f: Phase E v2 — NoForward suppresses transit ───────────

#[tokio::test]
async fn no_forward_mode_answers_local_but_does_not_transit() {
    // A → B (NoForward) → C: client_x on C. B is NoForward, so
    // when B receives a FindPeer for client_x (which B doesn't
    // host), B refuses to forward to C. Discovery fails — C
    // never receives the query, and A's directory stays empty
    // for client_x.
    let bridge_a = build_transport([0xF1; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xF1; 32]).public_bytes();
    let bridge_b =
        build_transport_with_mode([0xF2; 32], FindPeerMode::NoForward).await;
    let b_pub = Identity::from_secret_bytes([0xF2; 32]).public_bytes();
    let bridge_c = build_transport([0xF3; 32]).await;
    let c_pub = Identity::from_secret_bytes([0xF3; 32]).public_bytes();

    let (_a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;
    let (_b_to_c, _c_to_b) = federate(&bridge_b, &b_pub, &bridge_c, &c_pub).await;

    let client_x_secret = [0xF4; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    // Place client_x on C, not B.
    let (_client_x, _x_to_c) =
        client_on_bridge(&bridge_c, &c_pub, client_x_secret).await;

    // Trigger A → B with UNKNOWN_BRIDGE_PUB for client_x.
    let env = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &[0x88; 32],
        b"noforward-trigger",
    );
    bridge_b
        .__debug_send_federated_envelope(&_b_to_a, &env)
        .await
        .unwrap();
    sleep(ROUND_TRIP_WAIT).await;

    // A originates a FindPeer to its federation peers (B). B is
    // NoForward → drops the query (client_x isn't local to B).
    // Therefore A's directory should NOT have client_x cached.
    assert!(
        !bridge_a.peer_directory_contains(&client_x_pub),
        "PHASE E v2: NoForward bridge must not propagate queries → A should not learn client_x"
    );
}

// ─── Test 1g: local-hit on UNKNOWN_BRIDGE_PUB (regression for 7ee8412) ──

#[tokio::test]
async fn unknown_bridge_pub_resolves_to_local_client() {
    // Single bridge with a local client; another client dials
    // the local one with target_bridge_pub = UNKNOWN_BRIDGE_PUB.
    // Before commit 7ee8412 this would miss peer_directory (empty
    // in a one-bridge federation), fire a FindPeer that nobody
    // could answer, and time out. With the fix, the bridge
    // checks its local peers FIRST and delivers without
    // gossiping the target.
    //
    // Wire shape: an "outsider client" (built as a peer of the
    // bridge for warmup but treated as a non-federation client)
    // ships a Federated envelope at the bridge with UNKNOWN
    // target_bridge_pub. We assert the local-hit path drains:
    //   - peer_directory stays empty (no entries needed)
    //   - pending_finds stays at 0 (no FindPeer ever fires)
    let bridge = build_transport([0x91; 32]).await;
    let bridge_pub = Identity::from_secret_bytes([0x91; 32]).public_bytes();

    // Local client of the bridge — registers its presence ticket
    // so the bridge has session+ticket gates satisfied (same
    // gates handle_find_peer would check).
    let local_client_secret = [0x92; 32];
    let local_client_pub =
        Identity::from_secret_bytes(local_client_secret).public_bytes();
    let (_local_client, _local_to_bridge) =
        client_on_bridge(&bridge, &bridge_pub, local_client_secret).await;

    // "Outsider" — also handshakes with the bridge but stands in
    // for an arbitrary federation-routable client. Critically,
    // we don't put outsider in federation_table, so the bridge
    // treats their source_* claims with the usual client-grade
    // anti-spoof check. Outsider must claim *itself* as source.
    let outsider = build_transport([0x93; 32]).await;
    let outsider_pub = Identity::from_secret_bytes([0x93; 32]).public_bytes();
    let bridge_addr = bridge.local_addr().unwrap();
    let outsider_to_bridge = outsider
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = outsider.send_data(&outsider_to_bridge, b".", 0, 0).await;
    sleep(Duration::from_millis(200)).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), bridge.recv()).await;

    // Ship a Federated envelope at the bridge: UNKNOWN target
    // bridge, target client = local_client_pub. source_* must be
    // outsider's own pubkey (since it's not a federation peer).
    let env = build_unknown_target_envelope(
        &local_client_pub,
        &bridge_pub,
        &outsider_pub,
        b"hello local",
    );
    outsider
        .__debug_send_federated_envelope(&outsider_to_bridge, &env)
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    // No FindPeer should have fired — the local-hit path
    // bypasses the discovery layer entirely.
    assert_eq!(
        bridge.pending_finds_count(),
        0,
        "REGRESSION (7ee8412): UNKNOWN_BRIDGE_PUB for a local client must NOT fire FindPeer"
    );
    // peer_directory stays empty too — local clients aren't
    // tracked there (only remote announces are).
    assert!(
        !bridge.peer_directory_contains(&local_client_pub),
        "local-hit path must not pollute peer_directory with local clients"
    );
}

// ─── Test 1c: Phase C — proactive multi-hop announce ──────────────

#[tokio::test]
async fn proactive_announce_propagates_2_hops() {
    // Same A-B-C chain as the Phase B test but exercise the
    // *proactive* path: no FindPeer fired. A announces, B caches
    // (hops=0). B announces, includes the transitive entry, C
    // caches (hops=1).
    let bridge_a = build_transport([0xA4; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xA4; 32]).public_bytes();
    let bridge_b = build_transport([0xB5; 32]).await;
    let b_pub = Identity::from_secret_bytes([0xB5; 32]).public_bytes();
    let bridge_c = build_transport([0xC6; 32]).await;
    let c_pub = Identity::from_secret_bytes([0xC6; 32]).public_bytes();

    let (_a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;
    let (_b_to_c, _c_to_b) = federate(&bridge_b, &b_pub, &bridge_c, &c_pub).await;

    let client_x_secret = [0xDE; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (_client_x, _x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    // First announce hop: A → B.
    let a_entries = bridge_a.established_client_entries().await;
    bridge_a.announce_directory(&a_entries).await;
    sleep(Duration::from_millis(300)).await;
    assert!(
        bridge_b.peer_directory_contains(&client_x_pub),
        "B should have learned X directly from A's announce (hops=0)"
    );

    // Second announce hop: B → C. B's direct clients list is
    // empty, but its announce_directory pulls transitive entries
    // from peer_directory_hops with hops < MAX_ANNOUNCE_HOPS - 1
    // and re-emits them with hops+1.
    let b_entries = bridge_b.established_client_entries().await;
    bridge_b.announce_directory(&b_entries).await;
    sleep(Duration::from_millis(300)).await;

    assert!(
        bridge_c.peer_directory_contains(&client_x_pub),
        "PHASE C: C should have learned X transitively from B's announce (hops=1) — no FindPeer triggered"
    );
    assert_eq!(
        bridge_c.pending_finds_count(),
        0,
        "PHASE C: proactive propagation must not require a reactive FindPeer"
    );
}

// ─── Test 2: PeerGone evicts cache ────────────────────────────────

#[tokio::test]
async fn peer_gone_evicts_cached_route() {
    let bridge_a = build_transport([0xAA; 32]).await;
    let a_pub = Identity::from_secret_bytes([0xAA; 32]).public_bytes();
    let bridge_b = build_transport([0xBB; 32]).await;
    let b_pub = Identity::from_secret_bytes([0xBB; 32]).public_bytes();
    let (a_to_b, _b_to_a) = federate(&bridge_a, &a_pub, &bridge_b, &b_pub).await;

    let client_x_secret = [0xCC; 32];
    let client_x_pub = Identity::from_secret_bytes(client_x_secret).public_bytes();
    let (client_x, x_to_a) =
        client_on_bridge(&bridge_a, &a_pub, client_x_secret).await;

    // Trigger initial discovery so bridge_b caches the route.
    let env = build_unknown_target_envelope(
        &client_x_pub,
        &b_pub,
        &[0x77; 32],
        b"trigger",
    );
    bridge_a
        .__debug_send_federated_envelope(&a_to_b, &env)
        .await
        .unwrap();
    sleep(ROUND_TRIP_WAIT).await;
    assert!(
        bridge_b.peer_directory_contains(&client_x_pub),
        "precondition: bridge_b should have client_x cached"
    );

    // client_x closes its session with bridge_a. bridge_a's
    // handle_close fires PeerGone emission to every federation
    // peer.
    client_x.close_peer(&x_to_a).await.unwrap();
    sleep(ROUND_TRIP_WAIT).await;

    assert!(
        !bridge_b.peer_directory_contains(&client_x_pub),
        "PHASE A: PeerGone must evict the cached directory entry"
    );
}

//! Adversarial tests for XEdDSA presence tickets in
//! FederationDirectory v2.
//!
//! These tests close the "malicious federated bridge can announce
//! pubkeys it doesn't host" gap (Issue 1 from the federation
//! security work). The receiver's `handle_federation_directory`
//! now verifies each entry's presence ticket against the
//! announcing bridge's pubkey — a bridge that doesn't have a real
//! session with the claimed client can't produce a valid ticket,
//! so the entry gets dropped.
//!
//! Each test sets up:
//!   * `receiver` — the bridge under test.
//!   * `attacker_bridge` — a federation peer of `receiver` that
//!     tries to announce a victim it doesn't actually host.
//!   * a victim Identity that the attacker is impersonating.
//!
//! We hand-roll the FederationDirectory v2 wire bytes so we can
//! construct adversarial entries the legitimate codec wouldn't
//! produce.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;
use tokio::time::sleep;

/// Build a v2 FederationDirectory payload from `(client_pub,
/// optional_ticket)` pairs. If `ticket` is None, embeds a 96-byte
/// all-zero blob in its place — used to test the receiver's
/// rejection path for invalid signatures.
fn build_v2_payload(entries: &[([u8; 32], Option<drift::transport::PresenceTicket>)]) -> Vec<u8> {
    let count = entries.len() as u16;
    let mut out = Vec::with_capacity(4 + entries.len() * 128);
    out.push(2); // version
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for (pubkey, ticket) in entries {
        out.extend_from_slice(pubkey);
        match ticket {
            Some(t) => out.extend_from_slice(&drift::transport::encode_ticket(t)),
            None => out.extend_from_slice(&[0u8; 96]),
        }
    }
    out
}

/// (receiver, attacker_bridge, attacker_to_receiver_handle, attacker_pub)
async fn setup() -> (Transport, Transport, drift_core::PeerId, [u8; 32]) {
    let receiver_id = Identity::from_secret_bytes([0x11; 32]);
    let attacker_id = Identity::from_secret_bytes([0xFF; 32]);
    let receiver_pub = receiver_id.public_bytes();
    let attacker_pub = attacker_id.public_bytes();

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    };
    let receiver =
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), receiver_id, cfg.clone())
            .await
            .unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let attacker_bridge =
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), attacker_id, cfg)
            .await
            .unwrap();

    let a_to_recv = attacker_bridge
        .add_peer(receiver_pub, receiver_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = attacker_bridge.send_data(&a_to_recv, b".", 0, 0).await;
    sleep(Duration::from_millis(300)).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;

    // Add the attacker to receiver's federation_table so its
    // announcements get past the source-auth gate. The whole
    // point of these tests is that being in the federation_table
    // is NOT sufficient to announce arbitrary pubkeys — the
    // ticket layer is what enforces "you must actually host this
    // client to announce them."
    let attacker_peer_id_on_recv = derive_peer_id(&attacker_pub);
    receiver.register_federation_peer(attacker_pub, attacker_peer_id_on_recv);

    (receiver, attacker_bridge, a_to_recv, attacker_pub)
}

/// A federated bridge that announces a victim pubkey with NO
/// ticket attached must have its announcement entry rejected.
#[tokio::test]
async fn announce_without_ticket_is_rejected() {
    let (receiver, attacker_bridge, a_to_recv, _attacker_pub) = setup().await;

    let victim = Identity::generate().public_bytes();
    let baseline = receiver.metrics().federation_invalid_tickets_dropped;

    attacker_bridge
        .__debug_send_directory_announcement(&a_to_recv, &build_v2_payload(&[(victim, None)]))
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    assert!(
        !receiver.peer_directory_contains(&victim),
        "DEFENSE REGRESSION: attacker announced victim without a \
         valid ticket and receiver accepted it. XEdDSA verification \
         must drop ticketless entries."
    );
    let dropped = receiver.metrics().federation_invalid_tickets_dropped - baseline;
    assert!(
        dropped >= 1,
        "expected federation_invalid_tickets_dropped to tick on \
         ticketless announce, got {} drops",
        dropped
    );
}

/// A federated bridge that forges a ticket — claiming a client
/// signed for them when no such session exists — produces an
/// invalid XEdDSA signature. The entry must be rejected.
#[tokio::test]
async fn announce_with_forged_ticket_is_rejected() {
    let (receiver, attacker_bridge, a_to_recv, attacker_pub) = setup().await;

    let victim_seed = [0x55u8; 32];
    let victim_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(victim_seed))
        .to_bytes();

    // Attacker tries to mint a ticket by signing with their OWN
    // identity but claiming it's from the victim. The receiver
    // will verify the ticket against `victim_pub` (the claimed
    // client) and find the signature was made under
    // `attacker_pub` — verification fails.
    let attacker_seed = [0xFFu8; 32];
    let forged_ticket = drift::transport::build_ticket(
        &attacker_seed, // signs with attacker's key
        &attacker_pub,
        9_999_999_999_999,
        [0x77; 24],
        &[0x88; 64],
    );

    let baseline = receiver.metrics().federation_invalid_tickets_dropped;
    attacker_bridge
        .__debug_send_directory_announcement(
            &a_to_recv,
            &build_v2_payload(&[(victim_pub, Some(forged_ticket))]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    assert!(
        !receiver.peer_directory_contains(&victim_pub),
        "DEFENSE REGRESSION: attacker forged a ticket and receiver \
         accepted it. The XEdDSA signature must verify under the \
         claimed client's pubkey, not the announcer's."
    );
    assert!(
        receiver.metrics().federation_invalid_tickets_dropped - baseline >= 1,
        "expected federation_invalid_tickets_dropped to tick"
    );
}

/// A real ticket signed for bridge X must not verify when
/// announced by bridge Y. The bridge identity is implicit in the
/// receiver's reconstruction of the signed message, so ticket
/// replay across bridges is structurally impossible.
#[tokio::test]
async fn ticket_signed_for_other_bridge_is_rejected() {
    let (receiver, attacker_bridge, a_to_recv, _attacker_pub) = setup().await;

    let victim_seed = [0x66u8; 32];
    let victim_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(victim_seed))
        .to_bytes();

    // Victim legitimately signed a ticket for some OTHER bridge
    // (call it "honest_bridge"). The attacker somehow acquired
    // it (sniffed off the wire) and re-announces it as if the
    // victim were a client of the attacker's bridge.
    let honest_bridge_pub = [0xAA; 32];
    let real_ticket = drift::transport::build_ticket(
        &victim_seed,
        &honest_bridge_pub,
        9_999_999_999_999,
        [0x11; 24],
        &[0x22; 64],
    );

    let baseline = receiver.metrics().federation_invalid_tickets_dropped;
    attacker_bridge
        .__debug_send_directory_announcement(
            &a_to_recv,
            &build_v2_payload(&[(victim_pub, Some(real_ticket))]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    assert!(
        !receiver.peer_directory_contains(&victim_pub),
        "DEFENSE REGRESSION: receiver accepted a ticket signed for \
         a different bridge. Tickets must be bridge-specific via \
         the receiver's reconstruction of the signed message."
    );
    assert!(
        receiver.metrics().federation_invalid_tickets_dropped - baseline >= 1
    );
}

/// An expired ticket — even one the victim legitimately signed
/// for THIS bridge — must be rejected. Prevents replay of stale
/// tickets after a client has logged off.
#[tokio::test]
async fn expired_ticket_is_rejected() {
    let (receiver, attacker_bridge, a_to_recv, attacker_pub) = setup().await;

    let victim_seed = [0x99u8; 32];
    let victim_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(victim_seed))
        .to_bytes();

    // Victim signed a ticket for the attacker's bridge ages ago.
    let stale_ticket = drift::transport::build_ticket(
        &victim_seed,
        &attacker_pub,
        1, // unix-ms epoch + 1 — long expired
        [0x33; 24],
        &[0x44; 64],
    );

    let baseline = receiver.metrics().federation_invalid_tickets_dropped;
    attacker_bridge
        .__debug_send_directory_announcement(
            &a_to_recv,
            &build_v2_payload(&[(victim_pub, Some(stale_ticket))]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    assert!(
        !receiver.peer_directory_contains(&victim_pub),
        "DEFENSE REGRESSION: expired ticket accepted — clients that \
         logged off remain announceable forever, breaking the \
         freshness property tickets are supposed to provide."
    );
    assert!(
        receiver.metrics().federation_invalid_tickets_dropped - baseline >= 1
    );
}

/// Sanity counterpart: a legitimate ticket signed by the right
/// client for THIS bridge MUST be accepted. Without this test, the
/// other four could pass on any code that rejects everything.
#[tokio::test]
async fn legitimate_ticket_is_accepted() {
    let (receiver, attacker_bridge, a_to_recv, attacker_pub) = setup().await;

    let client_seed = [0xCCu8; 32];
    let client_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_seed))
        .to_bytes();
    let expiry_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 600_000;
    let legit_ticket = drift::transport::build_ticket(
        &client_seed,
        &attacker_pub, // signed for THIS bridge → valid
        expiry_ms,
        [0xEE; 24],
        &[0xFF; 64],
    );

    attacker_bridge
        .__debug_send_directory_announcement(
            &a_to_recv,
            &build_v2_payload(&[(client_pub, Some(legit_ticket))]),
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(300)).await;

    assert!(
        receiver.peer_directory_contains(&client_pub),
        "DEFENSE REGRESSION: legitimate ticket-bearing announcement \
         was rejected. The receiver is too strict — federation \
         routing won't work."
    );
}

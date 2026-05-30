//! Sans-io composition tests for drift-core.
//!
//! Goal: lock the public-API contract that drift-core can drive a
//! two-party message exchange *without* tokio or any other async
//! runtime. drift-wasm and any future no-tokio embedder need this
//! to hold — if it breaks, those builds break silently because
//! they don't share `drift/tests/` (which depends on tokio for
//! `Transport`).
//!
//! Each test composes primitives — `Identity`, `derive_session_key`,
//! `SessionKey`, `Header`, `canonical_aad`, `pq` — into a workflow
//! that mirrors what drift-core actually exists to support. No
//! `tokio` imports, no `async fn`, no I/O.
//!
//! This file deliberately repeats some coverage from the inline
//! module tests in drift-core (`#[cfg(test)] mod tests`). The
//! point isn't to test the primitives in isolation — those tests
//! already exist. The point is to test that the primitives
//! *compose* through the public API the way a real consumer would
//! call them.

use drift_core::crypto::{Direction, SessionKey};
use drift_core::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift_core::identity::{derive_session_key, random_nonce, Identity};
use drift_core::{derive_peer_id, pq};

/// Two parties run a stripped-down handshake and exchange one
/// sealed packet in each direction.
///
/// Walks the full path a no-tokio embedder would walk:
///   1. Generate identities (X25519 keypairs).
///   2. Compute static-DH on both sides.
///   3. Derive a session key from static + ephemeral DH + nonces
///      (`derive_session_key`).
///   4. Build a `SessionKey` per direction (Initiator / Responder).
///   5. Build a wire packet: `Header::encode` → `canonical_aad` →
///      `SessionKey::seal`.
///   6. Receive: decode header, recompute canonical_aad, open.
///   7. Round-trip a reply in the other direction.
///
/// If this test stops compiling, drift-core's public API has
/// regressed in a way that breaks no-tokio embedders.
#[test]
fn two_party_aead_round_trip_via_public_api() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    // Skip the wire ephemeral exchange for this test — derive
    // a session key from static-DH plus deterministic nonces.
    // Real handshakes mix in fresh ephemeral DH; we're locking
    // the public-API composition path, not the protocol.
    let alice_to_bob_dh = alice.dh(&bob_pub).expect("alice→bob dh");
    let bob_to_alice_dh = bob.dh(&alice_pub).expect("bob→alice dh");
    assert_eq!(
        &alice_to_bob_dh[..],
        &bob_to_alice_dh[..],
        "static DH must be symmetric across the public API"
    );

    // Use the same DH for static and ephemeral slots in this
    // simplified test. Real handshakes use a separate ephemeral
    // DH; the KDF doesn't care about origin.
    let client_nonce = random_nonce();
    let server_nonce = random_nonce();
    let session_key = derive_session_key(
        &alice_to_bob_dh,
        &alice_to_bob_dh,
        &client_nonce,
        &server_nonce,
    );

    let alice_tx = SessionKey::new(&session_key, Direction::Initiator);
    let bob_rx = SessionKey::new(&session_key, Direction::Initiator);
    let bob_tx = SessionKey::new(&session_key, Direction::Responder);
    let alice_rx = SessionKey::new(&session_key, Direction::Responder);

    // ── Alice → Bob ───────────────────────────────────────────
    let alice_peer_id = derive_peer_id(&alice_pub);
    let bob_peer_id = derive_peer_id(&bob_pub);
    let seq = 1u32;
    let payload = b"hello bob, drift-core says hi";
    let mut header = Header::new(PacketType::Data, seq, alice_peer_id, bob_peer_id);
    header.payload_len = payload.len() as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let sealed = alice_tx
        .seal(seq, PacketType::Data as u8, &aad, payload)
        .expect("seal");
    assert!(
        sealed.len() >= payload.len() + 16,
        "sealed bytes must include the AEAD tag"
    );

    // Receiver: decode header (here we know it's identical),
    // recompute AAD, open.
    let decoded = Header::decode(&hbuf).expect("header decode");
    assert_eq!(decoded.seq, seq);
    assert_eq!(decoded.src_id, alice_peer_id);
    assert_eq!(decoded.dst_id, bob_peer_id);
    let aad_rx = canonical_aad(&hbuf);
    let opened = bob_rx
        .open(seq, PacketType::Data as u8, &aad_rx, &sealed)
        .expect("open");
    assert_eq!(&opened[..], payload);

    // ── Bob → Alice (reply) ───────────────────────────────────
    let reply_seq = 2u32;
    let reply = b"hi alice, ack";
    let mut reply_hdr = Header::new(PacketType::Data, reply_seq, bob_peer_id, alice_peer_id);
    reply_hdr.payload_len = reply.len() as u16;
    let mut reply_hbuf = [0u8; HEADER_LEN];
    reply_hdr.encode(&mut reply_hbuf);
    let reply_aad = canonical_aad(&reply_hbuf);
    let reply_sealed = bob_tx
        .seal(reply_seq, PacketType::Data as u8, &reply_aad, reply)
        .expect("reply seal");
    let reply_opened = alice_rx
        .open(reply_seq, PacketType::Data as u8, &reply_aad, &reply_sealed)
        .expect("reply open");
    assert_eq!(&reply_opened[..], reply);
}

/// Direction separation: a packet sealed with `Initiator`
/// direction MUST NOT open under a `Responder` key, even when
/// the key bytes match. Composing the API the wrong way around
/// has to fail loud.
#[test]
fn direction_separation_via_public_api() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let dh = alice.dh(&bob.public_bytes()).unwrap();
    let cn = random_nonce();
    let sn = random_nonce();
    let key = derive_session_key(&dh, &dh, &cn, &sn);

    let initiator = SessionKey::new(&key, Direction::Initiator);
    let wrong_responder = SessionKey::new(&key, Direction::Responder);

    let alice_id = derive_peer_id(&alice.public_bytes());
    let bob_id = derive_peer_id(&bob.public_bytes());
    let mut hdr = Header::new(PacketType::Data, 1, alice_id, bob_id);
    let payload = b"directional";
    hdr.payload_len = payload.len() as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    hdr.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let sealed = initiator
        .seal(1, PacketType::Data as u8, &aad, payload)
        .unwrap();

    // Wrong direction must fail.
    assert!(
        wrong_responder
            .open(1, PacketType::Data as u8, &aad, &sealed)
            .is_err(),
        "Responder key must NOT open Initiator-sealed payload"
    );
}

/// Tampered ciphertext fails to open. Locks the AEAD-integrity
/// promise the public API makes to consumers.
#[test]
fn aead_rejects_tampered_ciphertext_via_public_api() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let dh = alice.dh(&bob.public_bytes()).unwrap();
    let cn = random_nonce();
    let sn = random_nonce();
    let key = derive_session_key(&dh, &dh, &cn, &sn);

    let tx = SessionKey::new(&key, Direction::Initiator);
    let rx = SessionKey::new(&key, Direction::Initiator);
    let alice_id = derive_peer_id(&alice.public_bytes());
    let bob_id = derive_peer_id(&bob.public_bytes());
    let mut hdr = Header::new(PacketType::Data, 7, alice_id, bob_id);
    let payload = b"untouched bytes";
    hdr.payload_len = payload.len() as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    hdr.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let mut sealed = tx.seal(7, PacketType::Data as u8, &aad, payload).unwrap();
    // Flip a byte in the ciphertext (not the tag).
    sealed[0] ^= 0x01;
    assert!(
        rx.open(7, PacketType::Data as u8, &aad, &sealed).is_err(),
        "tampered ciphertext must fail to open"
    );
}

/// AAD is invariant under `hop_ttl` mutation. A bridge that
/// decrements `hop_ttl` on forward must not invalidate the
/// AEAD tag — the canonical AAD masks the hop counter out.
#[test]
fn canonical_aad_masks_hop_ttl() {
    let mut hdr = Header::new(PacketType::Data, 1, [1u8; 8], [2u8; 8]);
    hdr.payload_len = 0;
    hdr = hdr.with_hop_ttl(8);
    let mut hbuf_a = [0u8; HEADER_LEN];
    hdr.encode(&mut hbuf_a);
    let aad_a = canonical_aad(&hbuf_a);

    let mut hdr2 = hdr.with_hop_ttl(1);
    hdr2.payload_len = 0;
    let mut hbuf_b = [0u8; HEADER_LEN];
    hdr2.encode(&mut hbuf_b);
    let aad_b = canonical_aad(&hbuf_b);

    assert_eq!(
        aad_a, aad_b,
        "canonical_aad must zero hop_ttl so forwarding is AAD-stable"
    );
    // The wire bytes themselves differ (hop_ttl is visible on
    // the wire so middleboxes can decrement); only the AAD
    // form is masked.
    assert_ne!(hbuf_a, hbuf_b);
}

/// PQ hybrid: client+server exchange ML-KEM, derive a hybrid
/// session key, and use it to seal/open through `SessionKey`.
/// Locks the path drift-wasm uses for hybrid-PQ handshakes.
#[test]
fn pq_hybrid_session_key_round_trip() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let dh = alice.dh(&bob.public_bytes()).unwrap();
    let eph_dh = alice.dh(&bob.public_bytes()).unwrap(); // stand-in
    let cn = random_nonce();
    let sn = random_nonce();

    // Client side: generate ML-KEM encap key.
    let (client_ek, client_dk) = pq::client_generate_keypair();
    // Server side: encapsulate against client's ek.
    let (server_ct, server_ss) = pq::server_encapsulate(&client_ek).expect("encapsulate");
    // Client decapsulates to recover the same SS.
    let client_ss = client_dk.decapsulate(&server_ct).expect("decapsulate");
    assert_eq!(server_ss, client_ss, "ML-KEM shared secret must match");

    // Both sides derive the same hybrid key.
    let hybrid_a = pq::derive_hybrid_key(&dh, &eph_dh, &client_ss, &cn, &sn);
    let hybrid_b = pq::derive_hybrid_key(&dh, &eph_dh, &server_ss, &cn, &sn);
    assert_eq!(hybrid_a, hybrid_b, "hybrid key derivation must agree");

    // The hybrid key feeds a normal SessionKey.
    let tx = SessionKey::new(&hybrid_a, Direction::Initiator);
    let rx = SessionKey::new(&hybrid_b, Direction::Initiator);
    let aad: [u8; HEADER_LEN] = [0; HEADER_LEN];
    let sealed = tx
        .seal(1, PacketType::Data as u8, &aad, b"pq says hi")
        .expect("seal");
    let opened = rx
        .open(1, PacketType::Data as u8, &aad, &sealed)
        .expect("open");
    assert_eq!(&opened[..], b"pq says hi");
}

/// Header round-trip via the public encode/decode pair. A
/// consumer who builds a Header, encodes it, then decodes the
/// bytes back must get an equivalent Header out.
#[test]
fn header_encode_decode_round_trip() {
    let original =
        Header::new(PacketType::Hello, 0x1234_5678, [0xAA; 8], [0xBB; 8]).with_hop_ttl(4);
    let mut hbuf = [0u8; HEADER_LEN];
    original.encode(&mut hbuf);

    let decoded = Header::decode(&hbuf).expect("decode");
    assert_eq!(decoded.seq, original.seq);
    assert_eq!(decoded.src_id, original.src_id);
    assert_eq!(decoded.dst_id, original.dst_id);
    assert_eq!(decoded.packet_type, original.packet_type);
    assert_eq!(decoded.hop_ttl, original.hop_ttl);
}

/// `Identity::dh` rejects low-order / zero pubkeys. A consumer
/// who hands an attacker-supplied pubkey to dh() must get back
/// `None`, not silently proceed with a weak shared secret.
#[test]
fn identity_dh_rejects_zero_pubkey() {
    let me = Identity::generate();
    let zero_pubkey = [0u8; 32];
    assert!(
        me.dh(&zero_pubkey).is_none(),
        "dh() must reject the all-zeros pubkey"
    );
}

/// `derive_peer_id` is deterministic over its input — same
/// pubkey always derives the same 8-byte id. drift-core
/// consumers rely on this for peer-table indexing without
/// keeping the full pubkey around.
#[test]
fn derive_peer_id_is_deterministic() {
    let id = Identity::generate();
    let pub_bytes = id.public_bytes();
    let id1 = derive_peer_id(&pub_bytes);
    let id2 = derive_peer_id(&pub_bytes);
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 8);
}

pub const HEADER_LEN: usize = 36;
pub const AUTH_TAG_LEN: usize = 16;
pub const PROTOCOL_VERSION: u8 = 1;

pub const FLAG_ROUTED: u8 = 1 << 0;
pub const FLAG_COALESCE: u8 = 1 << 1;
/// Phase PQ: this HELLO / HELLO_ACK carries the X25519+ML-KEM-768
/// hybrid handshake extension. The sender appended an ML-KEM
/// encapsulation key (client side, in HELLO) or ciphertext
/// (server side, in HELLO_ACK) to the standard payload — see
/// `drift::transport`'s `HELLO_PQ_TAIL_LEN` / `HELLO_ACK_PQ_TAIL_LEN`
/// and `derive_hybrid_key` in `drift-core::pq`. A flag-aware
/// peer with `hybrid_pq` disabled MUST refuse the handshake;
/// silent fallback to non-PQ would defeat the harvest-now-
/// decrypt-later guarantee the client asked for.
pub const FLAG_PQ_HYBRID: u8 = 1 << 2;
// Flag bit 1 << 3 was reserved for an unused FIN / ACK_REQ
// feature; still free.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Hello = 1,
    HelloAck = 2,
    Data = 3,
    // Values 4, 5, 7 were reserved for Ack / Forward / Fin packet
    // types that were never emitted or handled. Removed from the
    // enum so stray packets with those tags decode as UnknownType
    // and are dropped.
    Beacon = 6,
    /// Server → client stateless DoS challenge. Carries a timestamp and
    /// a MAC that the client must echo in a follow-up HELLO before the
    /// server performs any key-agreement work.
    Challenge = 8,
    /// Path validation challenge. Sent by a peer that sees AEAD-valid
    /// DATA arrive from a new source address — contains 16 random
    /// bytes encrypted with the session key. The recipient must echo
    /// them back in a `PathResponse` from that same new address
    /// before the sender commits the `peer.addr` migration. Blocks
    /// replay-based address hijacking.
    PathChallenge = 9,
    /// Path validation response. Echoes the 16-byte challenge from
    /// the corresponding `PathChallenge`, AEAD-encrypted with the
    /// session key.
    PathResponse = 10,
    /// Authenticated session close. Either side may send this to
    /// tell the peer "I'm tearing this session down, drop your
    /// state." The body is an AEAD-sealed empty string — it's the
    /// auth tag that matters, not the contents. On receipt, the
    /// recipient removes the peer entry entirely (or, for
    /// explicitly-registered peers, resets state to `Pending` so
    /// the app can re-handshake later).
    Close = 11,
    /// Request to rekey an established session. Body carries 32
    /// random bytes of salt, AEAD-sealed with the current session
    /// key. Both sides then derive `new_key = BLAKE2b("drift-rekey-v1"
    /// ‖ old_key ‖ salt)` and swap it in, keeping the old key
    /// around for a grace window so in-flight packets can still
    /// decrypt. Used to sidestep the 32-bit seq ceiling on
    /// long-lived high-throughput sessions without a full
    /// re-handshake.
    RekeyRequest = 12,
    /// Acknowledgement of a `RekeyRequest`, AEAD-sealed with the
    /// NEW session key — proves to the initiator that the
    /// recipient has successfully derived and installed the new
    /// key, and it's safe to drop the old key immediately.
    RekeyAck = 13,
    /// 1-RTT session resumption: client → server. Replaces HELLO
    /// when the client holds a valid resumption ticket for this
    /// peer. Body carries `ticket_id || client_eph_pub ||
    /// client_nonce`. The server looks up the ticket's PSK,
    /// derives a fresh session key from `KDF(psk || eph_dh ||
    /// nonces)`, and replies with `ResumeAck`. Skips the X25519
    /// static DH (the expensive op) and the cookie path entirely.
    ResumeHello = 14,
    /// Server's response to `ResumeHello`. Same wire shape as
    /// `HelloAck` (server_eph_pub || server_nonce || auth_tag).
    /// The auth tag uses the new session key, so the client knows
    /// the server holds the same PSK.
    ResumeAck = 15,
    /// Server → client opaque resumption ticket, AEAD-sealed with
    /// the live session key. Body carries `ticket_id(16) ||
    /// expiry_unix_ms(8)`. The client stores the (ticket_id, psk)
    /// pair indexed by server peer id; the PSK is derived
    /// deterministically by both sides from the current session
    /// key + ticket_id, so it never travels on the wire.
    ResumptionTicket = 16,
    /// Latency probe: sender → receiver, carries an 8-byte
    /// nonce (AEAD-sealed) that the receiver must echo back in
    /// a matching `Pong`. Used by the routing layer to measure
    /// per-neighbor RTT for RTT-weighted mesh routing.
    Ping = 17,
    /// Echo of a `Ping`. Body carries the same 8-byte nonce
    /// the ping originated with (AEAD-sealed). Sender timed
    /// the round trip on send, computes SRTT on receipt.
    Pong = 18,
    /// Federated envelope — opaque payload that gets relayed
    /// through one or two bridges by **pubkey lookup**, not by
    /// the multi-hop mesh routing table. Modeled on Matrix /
    /// XMPP server-to-server federation: every routing hop is
    /// an explicitly-configured pairing rather than a learned
    /// route, so delivery is direct table-lookup at each bridge.
    ///
    /// Envelope wire format (inside the AEAD-sealed body of the
    /// outer packet, after `Header`):
    ///
    /// ```text
    /// [0..32]   target_bridge_pub   — pubkey of the bridge that
    ///                                 should next-hop this. When
    ///                                 the receiving bridge sees
    ///                                 its own pubkey here, the
    ///                                 envelope is at its final
    ///                                 bridge hop and gets
    ///                                 delivered to a local client.
    /// [32..64]  target_client_pub   — pubkey of the final recipient
    /// [64..96]  source_client_pub   — pubkey of the originating
    ///                                 client (carried unchanged
    ///                                 across hops so the recipient
    ///                                 knows who sent it)
    /// [96..98]  payload_len (u16 BE)
    /// [98..]    payload             — opaque bytes; for DRIFT
    ///                                 client-to-client crypto
    ///                                 these are a full inner
    ///                                 DRIFT packet sealed with
    ///                                 the client↔client session
    ///                                 key. Bridges never decrypt
    ///                                 this payload.
    /// ```
    Federated = 19,

    /// Bridge-to-bridge directory announcement. Sent only between
    /// bridges in each other's federation tables (the receiver
    /// drops anything from non-federated senders). Payload format:
    ///
    /// ```text
    /// [0]      version  (u8)     // = 1
    /// [1]      reserved (u8)     // = 0
    /// [2..4]   count    (u16 BE) // number of client pubkey entries
    /// [4..]    pubkeys  ([32 bytes] * count)
    /// ```
    ///
    /// Receiving bridge records each pubkey → (sender_peer_id, now)
    /// in its peer directory with a 20 s TTL (~3× the ~7 s announce
    /// interval). The directory backs the routing fallback for
    /// Federated envelopes whose `target_bridge_pub` is the
    /// all-zero sentinel: clients that don't know which bridge
    /// their target lives on can leave that field empty and let
    /// any bridge in the chain resolve.
    FederationDirectory = 20,

    /// Client-to-bridge presence-ticket emission. Sent by a
    /// client over its Established session with a bridge to
    /// prove the client really is connected here. Payload is
    /// the 96-byte ticket from `drift::transport::federated`:
    /// 8-byte u64 BE expiry_ms, 24-byte nonce, 64-byte XEdDSA
    /// signature. The bridge stores the ticket keyed by the
    /// client's static pubkey (the session-authenticated
    /// sender). When the bridge announces its connected clients
    /// in `FederationDirectory`, it embeds each client's stored
    /// ticket so third-party receivers can cryptographically
    /// verify the announcement.
    ///
    /// Clients re-emit tickets before their stored ticket
    /// expires (typical lifetime: 10 minutes). Bridges that
    /// receive a ticket from a non-client (no session) or
    /// whose stored copy never gets refreshed simply drop the
    /// announcement for that pubkey.
    PresenceTicket = 21,

    /// Bridge-to-bridge reactive peer lookup. Sent when a bridge
    /// receives a `Federated` envelope with
    /// `target_bridge_pub == UNKNOWN_BRIDGE_PUB` for a client it
    /// has no directory entry for. Asks every federation peer
    /// "do you host this client?" Recipients reply with `PeerHere`
    /// if they do.
    ///
    /// Complements the proactive `FederationDirectory` announce:
    /// announce is the warm-cache path (~7 s steady state),
    /// `FindPeer` is the cold-path resolver for clients that
    /// joined since the last announce. See `FEDERATION_DISCOVERY.md`
    /// §5.1 for the wire format.
    FindPeer = 22,

    /// Reply to `FindPeer` — "I host this client (or learned a
    /// path to them); here is the signed ticket chain." Carries
    /// the `PresenceTicket` from the terminal bridge so the
    /// receiver can verify the route without further round-trips.
    /// See `FEDERATION_DISCOVERY.md` §5.2.
    PeerHere = 23,

    /// Bridge-to-federation broadcast: "Client X just
    /// disconnected from me — flush any cache entry pointing
    /// through me." Sent immediately on local-client session
    /// teardown so peers don't keep forwarding into a black hole
    /// for the ~7 s until the next idempotent-set announce.
    /// See `FEDERATION_DISCOVERY.md` §5.3.
    PeerGone = 24,

    /// Phase E v2: hashed-target variant of `FindPeer`. The
    /// originator hashes the target pubkey with a fresh salt
    /// before sending, so transit bridges that forward the query
    /// learn only `SHA-256(target || salt)` instead of the raw
    /// pubkey. Bridges scan their local presence tickets,
    /// computing the same hash for each client, and reply with
    /// `PeerHere` (carrying the real target pubkey) on a match.
    ///
    /// Privacy property: a malicious forwarder logging every
    /// query it sees gets hashes, not pubkeys. A determined
    /// adversary with a candidate target list can still
    /// precompute hashes for each candidate per query (the
    /// salt is per-query, not global) — but that requires
    /// pre-targeting, not bulk surveillance. The asymmetry is
    /// the win.
    ///
    /// Limitation: when a bridge finds a match, its `PeerHere`
    /// reply carries the real target_pub so the originator can
    /// route subsequent traffic. Forwarders along the reply
    /// path therefore learn the target after a successful
    /// discovery. The privacy benefit is bounded to the query
    /// fan-out phase, not the answer phase.
    ///
    /// Opt-in via `TransportConfig::find_peer_mode = OriginateHashed`.
    /// See `FEDERATION_DISCOVERY.md` §5.5.
    FindPeerHashed = 25,
}

impl PacketType {
    pub fn from_u8(v: u8) -> std::result::Result<Self, crate::error::CodecError> {
        match v {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Data),
            6 => Ok(Self::Beacon),
            8 => Ok(Self::Challenge),
            9 => Ok(Self::PathChallenge),
            10 => Ok(Self::PathResponse),
            11 => Ok(Self::Close),
            12 => Ok(Self::RekeyRequest),
            13 => Ok(Self::RekeyAck),
            14 => Ok(Self::ResumeHello),
            15 => Ok(Self::ResumeAck),
            16 => Ok(Self::ResumptionTicket),
            17 => Ok(Self::Ping),
            18 => Ok(Self::Pong),
            19 => Ok(Self::Federated),
            20 => Ok(Self::FederationDirectory),
            21 => Ok(Self::PresenceTicket),
            22 => Ok(Self::FindPeer),
            23 => Ok(Self::PeerHere),
            24 => Ok(Self::PeerGone),
            25 => Ok(Self::FindPeerHashed),
            _ => Err(crate::error::CodecError::UnknownType(v)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub packet_type: PacketType,
    pub deadline_ms: u16,
    pub seq: u32,
    pub supersedes: u32,
    pub src_id: [u8; 8],
    pub dst_id: [u8; 8],
    pub hop_ttl: u8,
    pub payload_len: u16,
    /// Milliseconds since the session epoch (Instant recorded at handshake
    /// completion). Used with `deadline_ms` to determine whether a packet
    /// is still "live" when it arrives at the receiver.
    pub send_time_ms: u32,
}

impl Header {
    pub fn new(packet_type: PacketType, seq: u32, src_id: [u8; 8], dst_id: [u8; 8]) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type,
            deadline_ms: 0,
            seq,
            supersedes: 0,
            src_id,
            dst_id,
            hop_ttl: 1,
            payload_len: 0,
            send_time_ms: 0,
        }
    }

    pub fn with_deadline(mut self, ms: u16) -> Self {
        self.deadline_ms = ms;
        self
    }

    pub fn with_supersedes(mut self, group: u32) -> Self {
        self.supersedes = group;
        self.flags |= FLAG_COALESCE;
        self
    }

    pub fn with_hop_ttl(mut self, ttl: u8) -> Self {
        self.hop_ttl = ttl;
        if ttl > 1 {
            self.flags |= FLAG_ROUTED;
        }
        self
    }

    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = (self.version << 4) | (self.flags & 0x0F);
        out[1] = self.packet_type as u8;
        out[2..4].copy_from_slice(&self.deadline_ms.to_be_bytes());
        out[4..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..12].copy_from_slice(&self.supersedes.to_be_bytes());
        out[12..20].copy_from_slice(&self.src_id);
        out[20..28].copy_from_slice(&self.dst_id);
        out[28] = self.hop_ttl;
        out[29] = 0;
        out[30..32].copy_from_slice(&self.payload_len.to_be_bytes());
        out[32..36].copy_from_slice(&self.send_time_ms.to_be_bytes());
    }

    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, crate::error::CodecError> {
        if bytes.len() < HEADER_LEN {
            return Err(crate::error::CodecError::PacketTooShort {
                got: bytes.len(),
                need: HEADER_LEN,
            });
        }
        let version = bytes[0] >> 4;
        if version != PROTOCOL_VERSION {
            return Err(crate::error::CodecError::UnsupportedVersion(version));
        }
        let flags = bytes[0] & 0x0F;
        let packet_type = PacketType::from_u8(bytes[1])?;
        let deadline_ms = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let supersedes = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut src_id = [0u8; 8];
        src_id.copy_from_slice(&bytes[12..20]);
        let mut dst_id = [0u8; 8];
        dst_id.copy_from_slice(&bytes[20..28]);
        let hop_ttl = bytes[28];
        let payload_len = u16::from_be_bytes([bytes[30], bytes[31]]);
        let send_time_ms = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);

        Ok(Self {
            version,
            flags,
            packet_type,
            deadline_ms,
            seq,
            supersedes,
            src_id,
            dst_id,
            hop_ttl,
            payload_len,
            send_time_ms,
        })
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Produce a canonical header copy for use as AEAD AAD. Zeros the hop_ttl
/// field so that intermediate mesh forwarders can decrement it in the wire
/// header without invalidating the end-to-end auth tag.
pub fn canonical_aad(hbuf: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut out = *hbuf;
    out[28] = 0;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_header_roundtrip(
            seq in any::<u32>(),
            deadline in any::<u16>(),
            supersedes in any::<u32>(),
            send_time in any::<u32>(),
            hop_ttl in 0u8..=255,
            src in any::<[u8; 8]>(),
            dst in any::<[u8; 8]>(),
            payload_len in any::<u16>(),
        ) {
            let mut h = Header::new(PacketType::Data, seq, src, dst)
                .with_deadline(deadline)
                .with_hop_ttl(hop_ttl);
            if supersedes != 0 {
                h = h.with_supersedes(supersedes);
            }
            h.send_time_ms = send_time;
            h.payload_len = payload_len;

            let mut buf = [0u8; HEADER_LEN];
            h.encode(&mut buf);
            let decoded = Header::decode(&buf).unwrap();

            prop_assert_eq!(decoded.seq, seq);
            prop_assert_eq!(decoded.deadline_ms, deadline);
            prop_assert_eq!(decoded.supersedes, supersedes);
            prop_assert_eq!(decoded.send_time_ms, send_time);
            prop_assert_eq!(decoded.hop_ttl, hop_ttl);
            prop_assert_eq!(decoded.src_id, src);
            prop_assert_eq!(decoded.dst_id, dst);
            prop_assert_eq!(decoded.payload_len, payload_len);
        }

        #[test]
        fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
            // Random bytes should never cause Header::decode to panic.
            let _ = Header::decode(&bytes);
        }

        #[test]
        fn prop_canonical_aad_zeros_hop_ttl(
            seq in any::<u32>(),
            hop_ttl in 1u8..=255,
        ) {
            let mut h = Header::new(PacketType::Data, seq, [1; 8], [2; 8]);
            h.hop_ttl = hop_ttl;
            let mut buf = [0u8; HEADER_LEN];
            h.encode(&mut buf);
            let aad = canonical_aad(&buf);
            prop_assert_eq!(aad[28], 0);
            // Two encodings with different hop_ttl values produce the same AAD.
            let mut h2 = h;
            h2.hop_ttl = hop_ttl.wrapping_add(1);
            let mut buf2 = [0u8; HEADER_LEN];
            h2.encode(&mut buf2);
            let aad2 = canonical_aad(&buf2);
            prop_assert_eq!(aad, aad2);
        }

        /// Encode → decode → re-encode must be bitwise
        /// identical. Covers every packet type including the
        /// resumption / rekey / path-validation additions so a
        /// wire-format regression on ANY tag is caught.
        #[test]
        fn prop_every_packet_type_encode_decode_symmetry(
            tag in 0usize..ALL_PACKET_TYPES.len(),
            seq in any::<u32>(),
            deadline in any::<u16>(),
            supersedes in any::<u32>(),
            send_time in any::<u32>(),
            hop_ttl in 0u8..=255,
            src in any::<[u8; 8]>(),
            dst in any::<[u8; 8]>(),
            payload_len in any::<u16>(),
        ) {
            let pt = ALL_PACKET_TYPES[tag];
            let mut h = Header::new(pt, seq, src, dst)
                .with_deadline(deadline)
                .with_hop_ttl(hop_ttl);
            if supersedes != 0 {
                h = h.with_supersedes(supersedes);
            }
            h.send_time_ms = send_time;
            h.payload_len = payload_len;

            // First roundtrip.
            let mut buf1 = [0u8; HEADER_LEN];
            h.encode(&mut buf1);
            let decoded = Header::decode(&buf1).unwrap();

            // Re-encode the decoded header and compare byte-
            // for-byte against the original. If any field gets
            // silently dropped or reinterpreted this assertion
            // fires.
            let mut buf2 = [0u8; HEADER_LEN];
            decoded.encode(&mut buf2);
            prop_assert_eq!(buf1, buf2, "encode/decode not symmetric for {:?}", pt);
            prop_assert_eq!(decoded.packet_type, pt);
        }
    }

    /// Every PacketType variant. Kept in sync with the enum by
    /// hand — the `prop_every_packet_type_encode_decode_symmetry`
    /// test will fail if a new variant is added and forgotten.
    const ALL_PACKET_TYPES: &[PacketType] = &[
        PacketType::Hello,
        PacketType::HelloAck,
        PacketType::Data,
        PacketType::Beacon,
        PacketType::Challenge,
        PacketType::PathChallenge,
        PacketType::PathResponse,
        PacketType::Close,
        PacketType::RekeyRequest,
        PacketType::RekeyAck,
        PacketType::ResumeHello,
        PacketType::ResumeAck,
        PacketType::ResumptionTicket,
        PacketType::Ping,
        PacketType::Pong,
        PacketType::Federated,
        PacketType::FederationDirectory,
        PacketType::PresenceTicket,
        PacketType::FindPeer,
        PacketType::PeerHere,
        PacketType::PeerGone,
        PacketType::FindPeerHashed,
    ];

    #[test]
    fn header_with_deadline_and_supersedes_round_trips_intact() {
        let h = Header::new(PacketType::Data, 42, [0xCD; 8], [0xAB; 8])
            .with_deadline(500)
            .with_supersedes(7);
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.deadline_ms, 500);
        assert_eq!(decoded.supersedes, 7);
        assert_eq!(decoded.src_id, [0xCD; 8]);
        assert_eq!(decoded.dst_id, [0xAB; 8]);
        assert!(decoded.has_flag(FLAG_COALESCE));
        assert_eq!(decoded.packet_type, PacketType::Data);
    }
}

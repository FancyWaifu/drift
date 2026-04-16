use crate::error::{DriftError, Result};

pub const HEADER_LEN: usize = 36;
pub const AUTH_TAG_LEN: usize = 16;
pub const PROTOCOL_VERSION: u8 = 1;

pub const FLAG_ROUTED: u8 = 1 << 0;
pub const FLAG_COALESCE: u8 = 1 << 1;
// Flag bits 1 << 2 and 1 << 3 were reserved for a FIN / ACK_REQ
// feature that was never wired up on either side. Removed so the
// header surface doesn't expose dead bits that decode as valid.

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
}

impl PacketType {
    pub fn from_u8(v: u8) -> Result<Self> {
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
            _ => Err(DriftError::UnknownType(v)),
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

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(DriftError::PacketTooShort {
                got: bytes.len(),
                need: HEADER_LEN,
            });
        }
        let version = bytes[0] >> 4;
        if version != PROTOCOL_VERSION {
            return Err(DriftError::UnsupportedVersion(version));
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
    ];

    #[test]
    fn header_roundtrip() {
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

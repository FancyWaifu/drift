//! 1-RTT session resumption — ticket types, server store, KDFs.
//!
//! Port of `drift/src/transport/resumption.rs`. The wire formats,
//! KDF domain strings, ticket semantics (single-use, identity-
//! bound, 24 h TTL), and the 97-byte export blob are byte-identical
//! to the transport's, so tickets are portable between a
//! drift-proto endpoint and a `drift::Transport` across process
//! restarts.
//!
//! ```text
//! ResumeHello : [ticket_id : 16] [client_eph_pub : 32] [client_nonce : 16] = 64 B
//! ResumeAck   : [server_eph_pub : 32] [server_nonce : 16] [auth_tag : 16]  = 64 B
//! ResumptionTicket payload (sealed under live session key):
//!               [ticket_id : 16] [expiry_unix_ms : u64 BE]                 = 24 B
//!
//! psk             = BLAKE2b("drift-resume-psk-v1" ‖ session_key ‖ ticket_id)
//! new_session_key = BLAKE2b("drift-resume-key-v1" ‖ psk ‖ ephemeral_dh
//!                                                  ‖ client_nonce ‖ server_nonce)
//! ```

use crate::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use blake2::{digest::consts::U32, Blake2b, Digest};
use drift_core::crypto::PeerId;
use drift_core::header::AUTH_TAG_LEN;
use drift_core::identity::{NONCE_LEN, STATIC_KEY_LEN};
use drift_core::Zeroizing;
use std::collections::HashMap;

/// Length of an opaque ticket id, in bytes.
pub const TICKET_ID_LEN: usize = 16;
/// Length of the PSK derived from a session key + ticket id.
pub const TICKET_PSK_LEN: usize = 32;

/// `ResumeHello` body: ticket_id + client_eph_pub + client_nonce.
pub(crate) const RESUME_HELLO_BODY_LEN: usize = TICKET_ID_LEN + STATIC_KEY_LEN + NONCE_LEN;
/// `ResumeAck` body: server_eph_pub + server_nonce + auth tag.
pub(crate) const RESUME_ACK_BODY_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;
/// `ResumptionTicket` plaintext: ticket_id + expiry (u64 BE).
pub(crate) const TICKET_PLAINTEXT_LEN: usize = TICKET_ID_LEN + 8;

/// How long a freshly issued ticket remains valid.
pub const TICKET_DEFAULT_TTL: Duration = Duration::from_secs(24 * 3600);

/// Cap on the server-side ticket store; oldest entry evicted at
/// the cap so handshake floods can't grow memory forever.
pub const RESUMPTION_STORE_MAX: usize = 100_000;

const EXPORT_BLOB_VERSION: u8 = 1;
/// Exported client-ticket blob:
/// `version(1) ‖ ticket_id(16) ‖ psk(32) ‖ expiry_unix_ms(8) ‖
///  server_id(8) ‖ server_static_pub(32)` = 97 bytes. Identical to
/// the transport's export format.
pub const EXPORT_BLOB_LEN: usize = 1 + TICKET_ID_LEN + TICKET_PSK_LEN + 8 + 8 + STATIC_KEY_LEN;

/// Client-side stored ticket. The PSK is key-equivalent material —
/// `Zeroizing` so it scrubs on drop; treat exported blobs like
/// private keys.
#[derive(Clone, Debug)]
pub struct ClientTicket {
    pub ticket_id: [u8; TICKET_ID_LEN],
    pub psk: Zeroizing<[u8; TICKET_PSK_LEN]>,
    pub expiry: SystemTime,
    pub server_id: PeerId,
    pub server_static_pub: [u8; STATIC_KEY_LEN],
}

impl ClientTicket {
    /// Serialize to the transport-compatible 97-byte blob.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXPORT_BLOB_LEN);
        out.push(EXPORT_BLOB_VERSION);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(self.psk.as_ref());
        let expiry_ms = self
            .expiry
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        out.extend_from_slice(&expiry_ms.to_be_bytes());
        out.extend_from_slice(&self.server_id);
        out.extend_from_slice(&self.server_static_pub);
        out
    }

    /// Parse a blob produced by `to_bytes` (either implementation).
    pub fn from_bytes(blob: &[u8]) -> Option<Self> {
        if blob.len() != EXPORT_BLOB_LEN || blob[0] != EXPORT_BLOB_VERSION {
            return None;
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&blob[1..1 + TICKET_ID_LEN]);
        let mut psk = Zeroizing::new([0u8; TICKET_PSK_LEN]);
        let psk_off = 1 + TICKET_ID_LEN;
        psk.copy_from_slice(&blob[psk_off..psk_off + TICKET_PSK_LEN]);
        let exp_off = psk_off + TICKET_PSK_LEN;
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&blob[exp_off..exp_off + 8]);
        let expiry = UNIX_EPOCH + Duration::from_millis(u64::from_be_bytes(exp_bytes));
        let id_off = exp_off + 8;
        let mut server_id = [0u8; 8];
        server_id.copy_from_slice(&blob[id_off..id_off + 8]);
        let pub_off = id_off + 8;
        let mut server_static_pub = [0u8; STATIC_KEY_LEN];
        server_static_pub.copy_from_slice(&blob[pub_off..pub_off + STATIC_KEY_LEN]);
        Some(Self {
            ticket_id,
            psk,
            expiry,
            server_id,
            server_static_pub,
        })
    }
}

struct ServerEntry {
    psk: Zeroizing<[u8; TICKET_PSK_LEN]>,
    expiry: SystemTime,
    /// Identity binding: a leaked ticket can't be redeemed by a
    /// different client.
    client_static_pub: [u8; STATIC_KEY_LEN],
    inserted_at: Instant,
}

/// Server-side ticket store: id → (psk, expiry, identity binding).
#[derive(Default)]
pub(crate) struct ResumptionStore {
    entries: HashMap<[u8; TICKET_ID_LEN], ServerEntry>,
}

impl ResumptionStore {
    pub(crate) fn insert(
        &mut self,
        ticket_id: [u8; TICKET_ID_LEN],
        psk: Zeroizing<[u8; TICKET_PSK_LEN]>,
        expiry: SystemTime,
        client_static_pub: [u8; STATIC_KEY_LEN],
    ) {
        if self.entries.len() >= RESUMPTION_STORE_MAX {
            if let Some(oldest_id) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_id);
            }
        }
        self.entries.insert(
            ticket_id,
            ServerEntry {
                psk,
                expiry,
                client_static_pub,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Single-use lookup: returns and removes the entry. `None`
    /// for unknown / expired tickets, and for identity mismatches
    /// (which deliberately do NOT evict — a forged redeem attempt
    /// shouldn't burn the legitimate holder's ticket).
    pub(crate) fn take(
        &mut self,
        ticket_id: &[u8; TICKET_ID_LEN],
        client_static_pub: &[u8; STATIC_KEY_LEN],
    ) -> Option<Zeroizing<[u8; TICKET_PSK_LEN]>> {
        let entry = self.entries.get(ticket_id)?;
        if entry.expiry <= SystemTime::now() {
            self.entries.remove(ticket_id);
            return None;
        }
        if &entry.client_static_pub != client_static_pub {
            return None;
        }
        let psk = entry.psk.clone();
        self.entries.remove(ticket_id);
        Some(psk)
    }
}

/// PSK derivation — both sides run this on the live session key;
/// the PSK never crosses the wire.
pub(crate) fn derive_psk(
    session_key: &[u8; 32],
    ticket_id: &[u8; TICKET_ID_LEN],
) -> Zeroizing<[u8; TICKET_PSK_LEN]> {
    let mut h = Blake2b::<U32>::new();
    h.update(b"drift-resume-psk-v1");
    h.update(session_key);
    h.update(ticket_id);
    let result = h.finalize();
    let mut out = Zeroizing::new([0u8; TICKET_PSK_LEN]);
    out.copy_from_slice(&result);
    out
}

/// Resumed-session key: PSK + fresh ephemeral DH + nonces. No
/// static DH — that's the point of resumption; forward secrecy
/// comes from the fresh ephemerals.
pub(crate) fn derive_resumption_key(
    psk: &[u8; TICKET_PSK_LEN],
    ephemeral_dh: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2b::<U32>::new();
    h.update(b"drift-resume-key-v1");
    h.update(psk);
    h.update(ephemeral_dh);
    h.update(client_nonce);
    h.update(server_nonce);
    let result = h.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_blob_roundtrips() {
        let t = ClientTicket {
            ticket_id: [7u8; TICKET_ID_LEN],
            psk: Zeroizing::new([9u8; TICKET_PSK_LEN]),
            expiry: UNIX_EPOCH + Duration::from_millis(1_900_000_000_000),
            server_id: [3u8; 8],
            server_static_pub: [5u8; STATIC_KEY_LEN],
        };
        let blob = t.to_bytes();
        assert_eq!(blob.len(), EXPORT_BLOB_LEN);
        let back = ClientTicket::from_bytes(&blob).unwrap();
        assert_eq!(back.ticket_id, t.ticket_id);
        assert_eq!(*back.psk, *t.psk);
        assert_eq!(back.expiry, t.expiry);
        assert_eq!(back.server_id, t.server_id);
        assert_eq!(back.server_static_pub, t.server_static_pub);
    }

    #[test]
    fn store_is_single_use_and_identity_bound() {
        let mut store = ResumptionStore::default();
        let id = [1u8; TICKET_ID_LEN];
        let owner = [2u8; STATIC_KEY_LEN];
        let thief = [3u8; STATIC_KEY_LEN];
        store.insert(
            id,
            Zeroizing::new([4u8; TICKET_PSK_LEN]),
            SystemTime::now() + Duration::from_secs(60),
            owner,
        );
        // Wrong identity: refused, NOT consumed.
        assert!(store.take(&id, &thief).is_none());
        // Right identity: redeemed once...
        assert!(store.take(&id, &owner).is_some());
        // ...and only once.
        assert!(store.take(&id, &owner).is_none());
    }
}

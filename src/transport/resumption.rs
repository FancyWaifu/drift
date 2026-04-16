//! 1-RTT session resumption via pre-shared key.
//!
//! After a normal handshake completes, the server hands the
//! client a small opaque ticket. On a future reconnect to the
//! same peer, the client presents the ticket in a `ResumeHello`;
//! the server looks up the associated PSK, derives a fresh
//! session key from `KDF(psk ‖ ephemeral_dh ‖ nonces)`, and
//! replies with `ResumeAck`. The X25519 *static* DH (the
//! expensive op) is skipped entirely. Forward secrecy is
//! preserved because both sides still do a fresh ephemeral DH
//! each time.
//!
//! Wire format:
//!
//! ```text
//! ResumeHello : [ticket_id : 16] [client_eph_pub : 32] [client_nonce : 16] = 64 B
//! ResumeAck   : [server_eph_pub : 32] [server_nonce : 16] [auth_tag : 16]  = 64 B
//! ResumptionTicket payload (sealed under live session key):
//!               [ticket_id : 16] [expiry_unix_ms : u64 BE]                 = 24 B
//! ```
//!
//! The PSK is **never on the wire**. Both sides derive it
//! deterministically from the live session key:
//!
//! ```text
//! psk = BLAKE2b("drift-resume-psk-v1" ‖ session_key ‖ ticket_id)
//! new_session_key = BLAKE2b("drift-resume-key-v1" ‖ psk ‖ ephemeral_dh
//!                                                  ‖ client_nonce ‖ server_nonce)
//! ```
//!
//! Default ticket TTL is 24 hours. Past expiry the client falls
//! back to a full HELLO and the server rejects stale tickets.

use super::Inner;
use crate::crypto::{Direction, PeerId, SessionKey};
use crate::error::{DriftError, Result};
use crate::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use crate::identity::{Identity, NONCE_LEN, STATIC_KEY_LEN};
use crate::session::{HandshakeState, PendingResumption, PrevSession};
use blake2::{digest::consts::U32, Blake2b, Digest};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Length of an opaque ticket id, in bytes.
pub const TICKET_ID_LEN: usize = 16;
/// Length of the PSK derived from a session key + ticket id.
pub const TICKET_PSK_LEN: usize = 32;

/// `ResumeHello` body length: ticket_id (16) + client_eph_pub (32)
/// + client_nonce (16).
pub(crate) const RESUME_HELLO_BODY_LEN: usize = TICKET_ID_LEN + STATIC_KEY_LEN + NONCE_LEN;

/// `ResumeAck` body length: server_eph_pub (32) + server_nonce
/// (16) + AEAD auth tag (16).
pub(crate) const RESUME_ACK_BODY_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;

/// `ResumptionTicket` plaintext length: ticket_id (16) + expiry
/// (u64 BE, 8). The wire body is this plus the AEAD auth tag.
pub(crate) const TICKET_PLAINTEXT_LEN: usize = TICKET_ID_LEN + 8;

/// How long a freshly issued ticket remains valid by default.
pub const TICKET_DEFAULT_TTL: Duration = Duration::from_secs(24 * 3600);

/// Maximum number of (ticket_id → entry) records the server-side
/// store will hold. Past this we evict the oldest entry on insert.
/// Bounds memory against an attacker who completes many
/// handshakes and accumulates tickets forever.
pub const RESUMPTION_STORE_MAX: usize = 100_000;

/// Server-side stored ticket record.
struct ServerEntry {
    psk: [u8; TICKET_PSK_LEN],
    expiry: SystemTime,
    /// Bound to the original client's static pubkey so a leaked
    /// ticket can't be redeemed by a different identity.
    client_static_pub: [u8; STATIC_KEY_LEN],
    /// Insertion order, used for LRU-style eviction at the cap.
    inserted_at: Instant,
}

/// Server-side resumption store: ticket id → (psk, expiry,
/// client identity binding). Lives on `Inner`. Entries are
/// looked up by incoming `ResumeHello` packets and evicted
/// either on expiry or on cap-exceed (oldest first).
pub(crate) struct ResumptionStore {
    entries: HashMap<[u8; TICKET_ID_LEN], ServerEntry>,
}

impl Default for ResumptionStore {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl ResumptionStore {
    /// Install a freshly minted ticket. Drops the oldest entry
    /// first if we're at the cap.
    pub(crate) fn insert(
        &mut self,
        ticket_id: [u8; TICKET_ID_LEN],
        psk: [u8; TICKET_PSK_LEN],
        expiry: SystemTime,
        client_static_pub: [u8; STATIC_KEY_LEN],
    ) {
        if self.entries.len() >= RESUMPTION_STORE_MAX {
            // O(N) sweep — fine since this only triggers once
            // we're at the cap. For higher scale, swap in an
            // LinkedHashMap or similar.
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

    /// Look up a ticket and remove it (single-use semantics).
    /// Returns `None` if the ticket id is unknown, expired, or
    /// bound to a different client identity.
    fn take(
        &mut self,
        ticket_id: &[u8; TICKET_ID_LEN],
        client_static_pub: &[u8; STATIC_KEY_LEN],
    ) -> Option<([u8; TICKET_PSK_LEN], SystemTime)> {
        let entry = self.entries.get(ticket_id)?;
        if entry.expiry <= SystemTime::now() {
            self.entries.remove(ticket_id);
            return None;
        }
        if &entry.client_static_pub != client_static_pub {
            // Ticket is bound to a different identity — refuse
            // and DON'T evict (this could be an attack we want
            // to ignore, not a state mutation).
            return None;
        }
        let psk = entry.psk;
        let expiry = entry.expiry;
        // Single-use: a ticket only resumes once. The client
        // gets a fresh ticket on the resumed session.
        self.entries.remove(ticket_id);
        Some((psk, expiry))
    }
}

/// Client-side persistent ticket: what the app exports/imports
/// across restarts. The PSK is sensitive material — treat the
/// blob like a private key when persisting.
#[derive(Clone)]
pub struct ClientTicket {
    pub ticket_id: [u8; TICKET_ID_LEN],
    pub psk: [u8; TICKET_PSK_LEN],
    pub expiry: SystemTime,
    pub server_id: PeerId,
    pub server_static_pub: [u8; STATIC_KEY_LEN],
}

const EXPORT_BLOB_VERSION: u8 = 1;
/// Length of an exported client ticket blob.
/// `version(1) || ticket_id(16) || psk(32) || expiry_unix_ms(8) ||
///  server_id(8) || server_static_pub(32)` = 97 bytes.
pub const EXPORT_BLOB_LEN: usize = 1 + TICKET_ID_LEN + TICKET_PSK_LEN + 8 + 8 + STATIC_KEY_LEN;

impl ClientTicket {
    /// Serialize to an opaque blob suitable for persisting on
    /// disk / in a keychain. The blob carries the PSK in the
    /// clear, so apps must store it with the same care as a
    /// private key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXPORT_BLOB_LEN);
        out.push(EXPORT_BLOB_VERSION);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(&self.psk);
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

    /// Parse an opaque blob produced by `to_bytes`. Returns
    /// `None` for malformed input or unrecognized versions.
    pub fn from_bytes(blob: &[u8]) -> Option<Self> {
        if blob.len() != EXPORT_BLOB_LEN || blob[0] != EXPORT_BLOB_VERSION {
            return None;
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&blob[1..1 + TICKET_ID_LEN]);
        let mut psk = [0u8; TICKET_PSK_LEN];
        let psk_off = 1 + TICKET_ID_LEN;
        psk.copy_from_slice(&blob[psk_off..psk_off + TICKET_PSK_LEN]);
        let exp_off = psk_off + TICKET_PSK_LEN;
        let expiry_ms = u64::from_be_bytes([
            blob[exp_off],
            blob[exp_off + 1],
            blob[exp_off + 2],
            blob[exp_off + 3],
            blob[exp_off + 4],
            blob[exp_off + 5],
            blob[exp_off + 6],
            blob[exp_off + 7],
        ]);
        let expiry = UNIX_EPOCH + Duration::from_millis(expiry_ms);
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

/// Derive a per-ticket PSK from the live session key + ticket
/// id. Both peers run this independently; the PSK never travels
/// on the wire.
pub(crate) fn derive_psk(
    session_key: &[u8; 32],
    ticket_id: &[u8; TICKET_ID_LEN],
) -> [u8; TICKET_PSK_LEN] {
    let mut h = Blake2b::<U32>::new();
    h.update(b"drift-resume-psk-v1");
    h.update(session_key);
    h.update(ticket_id);
    let result = h.finalize();
    let mut out = [0u8; TICKET_PSK_LEN];
    out.copy_from_slice(&result);
    out
}

/// Derive a fresh session key for a resumed connection from the
/// PSK + ephemeral DH + nonces. No static DH — that's the
/// whole point of resumption.
pub(crate) fn derive_resumption_key(
    psk: &[u8; TICKET_PSK_LEN],
    ephemeral_dh: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(b"drift-resume-key-v1");
    h.update(psk);
    h.update(ephemeral_dh);
    h.update(client_nonce);
    h.update(server_nonce);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

impl Inner {
    /// Server side: emit a fresh `ResumptionTicket` to a peer
    /// whose handshake just completed. Generates a random ticket
    /// id, derives the per-ticket PSK from the current session
    /// key, stores the entry server-side, and ships the
    /// (ticket_id, expiry) blob sealed under the live session
    /// key. The PSK never crosses the wire.
    pub(crate) async fn issue_resumption_ticket(&self, peer_id: PeerId) -> Result<()> {
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        rand::thread_rng().fill_bytes(&mut ticket_id);
        let expiry = SystemTime::now() + TICKET_DEFAULT_TTL;
        let expiry_ms = expiry
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (wire, addr) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let session_key_bytes = match &peer.handshake {
                HandshakeState::Established { key_bytes, .. } => *key_bytes,
                _ => return Err(DriftError::UnknownPeer),
            };
            let client_static_pub = peer.peer_static_pub;

            // Compute per-ticket PSK locally and stash it
            // server-side. The client will independently derive
            // the same PSK on receipt.
            let psk = derive_psk(&session_key_bytes, &ticket_id);
            self.resumption_store
                .lock()
                .await
                .insert(ticket_id, psk, expiry, client_static_pub);

            // Build the sealed payload.
            let seq = peer
                .next_seq_checked()
                .ok_or(DriftError::SessionExhausted)?;
            let mut header = Header::new(
                PacketType::ResumptionTicket,
                seq,
                self.local_peer_id,
                peer_id,
            );
            header.payload_len = (TICKET_PLAINTEXT_LEN + AUTH_TAG_LEN) as u16;
            header.send_time_ms = peer.send_time_ms();
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let aad = canonical_aad(&hbuf);

            let mut plaintext = [0u8; TICKET_PLAINTEXT_LEN];
            plaintext[..TICKET_ID_LEN].copy_from_slice(&ticket_id);
            plaintext[TICKET_ID_LEN..].copy_from_slice(&expiry_ms.to_be_bytes());

            let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
            let mut wire =
                Vec::with_capacity(HEADER_LEN + TICKET_PLAINTEXT_LEN + AUTH_TAG_LEN);
            wire.extend_from_slice(&hbuf);
            tx.seal_into(
                seq,
                PacketType::ResumptionTicket as u8,
                &aad,
                &plaintext,
                &mut wire,
            )?;
            (wire, peer.addr)
        };

        self.ifaces.send_for(self.iface_for(&peer_id).await, &wire, addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        self.metrics
            .resumption_tickets_issued
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Client side: process an incoming `ResumptionTicket`.
    /// Decrypts the body with the live session key, derives the
    /// PSK locally (mirroring what the server did), and stores
    /// a `ClientTicket` keyed by the issuing peer's id.
    ///
    /// A stale ticket whose rx-key has already rotated out is
    /// silently dropped (no auth_failure bump) — it's not an
    /// attack, just normal rekey-window racing.
    pub(crate) async fn handle_resumption_ticket(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let server_id = header.src_id;
        let (plaintext_opt, server_session_key, server_static_pub) = {
            let mut peers = self.peers.lock_for(&server_id).await;
            let Some(peer) = peers.get_mut(&server_id) else {
                return Ok(());
            };
            let session_key_bytes = match &peer.handshake {
                HandshakeState::Established { key_bytes, .. } => *key_bytes,
                _ => return Ok(()),
            };
            let static_pub = peer.peer_static_pub;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);

            // Try current rx. If it fails AND prev is alive,
            // try prev. Either failure path is silent — a
            // stale ticket is not an attack.
            let pt = {
                let (_, rx) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
                rx.open(header.seq, PacketType::ResumptionTicket as u8, &aad, body)
            };
            let pt = match pt {
                Ok(p) => Some(p),
                Err(_) => {
                    if let HandshakeState::Established { prev: Some(p), .. } = &peer.handshake {
                        p.rx
                            .open(header.seq, PacketType::ResumptionTicket as u8, &aad, body)
                            .ok()
                    } else {
                        None
                    }
                }
            };
            (pt, session_key_bytes, static_pub)
        };
        let plaintext = match plaintext_opt {
            Some(p) => p,
            None => return Ok(()),
        };

        if plaintext.len() != TICKET_PLAINTEXT_LEN {
            return Err(DriftError::PacketTooShort {
                got: plaintext.len(),
                need: TICKET_PLAINTEXT_LEN,
            });
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&plaintext[..TICKET_ID_LEN]);
        let expiry_ms = u64::from_be_bytes([
            plaintext[TICKET_ID_LEN],
            plaintext[TICKET_ID_LEN + 1],
            plaintext[TICKET_ID_LEN + 2],
            plaintext[TICKET_ID_LEN + 3],
            plaintext[TICKET_ID_LEN + 4],
            plaintext[TICKET_ID_LEN + 5],
            plaintext[TICKET_ID_LEN + 6],
            plaintext[TICKET_ID_LEN + 7],
        ]);
        let expiry = UNIX_EPOCH + Duration::from_millis(expiry_ms);
        let psk = derive_psk(&server_session_key, &ticket_id);

        let ticket = ClientTicket {
            ticket_id,
            psk,
            expiry,
            server_id,
            server_static_pub,
        };
        self.client_tickets
            .lock()
            .await
            .insert(server_id, ticket);
        self.metrics
            .resumption_tickets_received
            .fetch_add(1, Ordering::Relaxed);
        debug!(server = ?server_id, "stored resumption ticket");
        Ok(())
    }

    /// Client side: build and send a `ResumeHello` for `peer`
    /// using a ticket previously stored via `handle_resumption_ticket`
    /// (or imported via `Transport::import_resumption_ticket`).
    /// Installs `pending_resumption` on the peer so the matching
    /// `ResumeAck` knows which PSK to use.
    ///
    /// Caller has already verified that a usable ticket exists
    /// for this peer.
    pub(crate) async fn send_resume_hello(&self, peer_id: PeerId) -> Result<()> {
        let ticket = match self.client_tickets.lock().await.get(&peer_id).cloned() {
            Some(t) if t.expiry > SystemTime::now() => t,
            Some(_) => {
                // Expired — drop and bail; caller will fall
                // back to a normal HELLO.
                self.client_tickets.lock().await.remove(&peer_id);
                return Err(DriftError::UnknownPeer);
            }
            None => return Err(DriftError::UnknownPeer),
        };

        let ephemeral = Identity::generate();
        let client_eph_pub = ephemeral.public_bytes();
        let mut client_nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut client_nonce);

        let (wire, addr) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;

            // Stash the ephemeral + PSK + ticket_id so the
            // matching ResumeAck handler can finish key
            // derivation. We hijack `AwaitingAck` for the
            // ephemeral plumbing (last_sent / attempts / cookie
            // are unused on the resumption path) and add a
            // parallel `pending_resumption` marker so the
            // `ResumeAck` handler can tell this apart from a
            // normal HELLO_ACK.
            peer.pending_resumption = Some(PendingResumption {
                ticket_id: ticket.ticket_id,
                psk: ticket.psk,
            });
            peer.handshake = HandshakeState::AwaitingAck {
                client_nonce,
                ephemeral,
                last_sent: Instant::now(),
                attempts: 1,
                cookie: None,
            };

            let seq = peer
                .next_seq_checked()
                .ok_or(DriftError::SessionExhausted)?;
            let mut header = Header::new(
                PacketType::ResumeHello,
                seq,
                self.local_peer_id,
                peer_id,
            );
            header.payload_len = RESUME_HELLO_BODY_LEN as u16;
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);

            let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_HELLO_BODY_LEN);
            wire.extend_from_slice(&hbuf);
            wire.extend_from_slice(&ticket.ticket_id);
            wire.extend_from_slice(&client_eph_pub);
            wire.extend_from_slice(&client_nonce);
            (wire, peer.addr)
        };

        self.ifaces.send_for(self.iface_for(&peer_id).await, &wire, addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        self.metrics
            .resumption_attempts
            .fetch_add(1, Ordering::Relaxed);
        debug!(peer = ?peer_id, "sent ResumeHello");
        Ok(())
    }

    /// Server side: handle an incoming `ResumeHello`. Looks up
    /// the ticket, derives a fresh session key, installs it, and
    /// replies with a `ResumeAck` whose AEAD tag proves we hold
    /// the same PSK.
    pub(crate) async fn handle_resume_hello(
        &self,
        header: &Header,
        body: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        if body.len() < RESUME_HELLO_BODY_LEN {
            return Err(DriftError::PacketTooShort {
                got: body.len(),
                need: RESUME_HELLO_BODY_LEN,
            });
        }
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }

        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&body[..TICKET_ID_LEN]);
        let mut client_eph_pub = [0u8; STATIC_KEY_LEN];
        client_eph_pub.copy_from_slice(
            &body[TICKET_ID_LEN..TICKET_ID_LEN + STATIC_KEY_LEN],
        );
        let mut client_nonce = [0u8; NONCE_LEN];
        client_nonce.copy_from_slice(
            &body[TICKET_ID_LEN + STATIC_KEY_LEN..RESUME_HELLO_BODY_LEN],
        );

        // Reject low-order ephemerals up front.
        if client_eph_pub == [0u8; STATIC_KEY_LEN] {
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(DriftError::AuthFailed);
        }

        let client_peer_id = header.src_id;

        // The peer must already be known to us — resumption
        // re-uses an identity we previously authenticated. If
        // we've forgotten the peer, fall through to AuthFailed
        // so the client retries with a full HELLO.
        let client_static_pub = {
            let peers = self.peers.lock_for(&client_peer_id).await;
            let peer = peers.get(&client_peer_id).ok_or(DriftError::UnknownPeer)?;
            peer.peer_static_pub
        };

        // Look up + take the ticket from the server store.
        let (psk, _expiry) = {
            let mut store = self.resumption_store.lock().await;
            match store.take(&ticket_id, &client_static_pub) {
                Some(v) => v,
                None => {
                    self.metrics
                        .resumption_rejects
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(DriftError::AuthFailed);
                }
            }
        };

        // Fresh ephemeral DH for forward secrecy on the resumed
        // session. Must use `dh_checked`-equivalent (Identity::dh
        // already returns None for low-order points).
        let server_ephemeral = Identity::generate();
        let server_eph_pub = server_ephemeral.public_bytes();
        let server_nonce = crate::identity::random_nonce();

        let ephemeral_dh = server_ephemeral
            .dh(&client_eph_pub)
            .ok_or(DriftError::AuthFailed)?;
        drop(server_ephemeral);

        let new_session_key =
            derive_resumption_key(&psk, &ephemeral_dh, &client_nonce, &server_nonce);

        // Build the ResumeAck. Same shape as HELLO_ACK: header
        // || server_eph_pub || server_nonce || auth_tag. The
        // auth tag is computed over an empty payload using the
        // NEW session key, so a successful decrypt on the
        // client side proves we derived the same key from the
        // same PSK.
        let (ack_wire, ack_addr, prev_session, was_awaiting_data) = {
            let mut peers = self.peers.lock_for(&client_peer_id).await;
            let peer = peers.get_mut(&client_peer_id).ok_or(DriftError::UnknownPeer)?;
            let was_awaiting_data =
                matches!(peer.handshake, HandshakeState::AwaitingData { .. });

            // Capture the OLD session keys (if any) so we can
            // hold them in the rekey-style `prev` slot for the
            // grace window — DATA already in flight under the
            // pre-resumption key still needs to decrypt for a
            // moment.
            let prev_session = match &peer.handshake {
                HandshakeState::Established { tx, rx, .. } => Some(PrevSession {
                    tx: tx.clone(),
                    rx: rx.clone(),
                    installed_at: Instant::now(),
                }),
                _ => None,
            };

            // Build header.
            let seq = 1u32;
            let mut header = Header::new(
                PacketType::ResumeAck,
                seq,
                self.local_peer_id,
                client_peer_id,
            );
            header.payload_len = RESUME_ACK_BODY_LEN as u16;
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);

            // AAD includes the canonical header + the in-the-clear
            // server_eph_pub + server_nonce, mirroring HELLO_ACK.
            let canon = canonical_aad(&hbuf);
            let mut aad =
                Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
            aad.extend_from_slice(&canon);
            aad.extend_from_slice(&server_eph_pub);
            aad.extend_from_slice(&server_nonce);

            // Server seals with Responder direction (mirrors HELLO_ACK).
            let server_tx = SessionKey::new(&new_session_key, Direction::Responder);
            let auth_tag =
                server_tx.seal(seq, PacketType::ResumeAck as u8, &aad, b"")?;
            // `seal` returns just the auth tag for empty plaintext
            // (16 bytes). Concat into the wire.
            let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_ACK_BODY_LEN);
            wire.extend_from_slice(&hbuf);
            wire.extend_from_slice(&server_eph_pub);
            wire.extend_from_slice(&server_nonce);
            wire.extend_from_slice(&auth_tag);

            // Install the new keys. Use Established directly —
            // the client will start sending DATA as soon as it
            // gets the ResumeAck, and we want to be ready.
            let server_rx = SessionKey::new(&new_session_key, Direction::Initiator);
            peer.reset_seq();
            // ResumeAck used seq=1, so next outgoing is 2.
            peer.next_tx_seq = 2;
            peer.coalesce_state.clear();
            peer.coalesce_order.clear();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx: server_tx,
                rx: server_rx,
                key_bytes: new_session_key,
                prev: prev_session.clone(),
            };
            peer.addr = src;

            (wire, src, prev_session, was_awaiting_data)
        };
        let _ = prev_session; // (used inside the block via clone)

        if was_awaiting_data {
            self.metrics
                .handshakes_inflight
                .fetch_sub(1, Ordering::Relaxed);
        }

        self.ifaces.send_for(self.iface_for(&client_peer_id).await, &ack_wire, ack_addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ack_wire.len() as u64, Ordering::Relaxed);
        self.metrics
            .resumptions_completed
            .fetch_add(1, Ordering::Relaxed);
        debug!(peer = ?client_peer_id, "completed 1-RTT resumption");

        // Issue a fresh ticket on the resumed session so the
        // client can resume again next time.
        let _ = self.issue_resumption_ticket(client_peer_id).await;
        Ok(())
    }

    /// Client side: handle an incoming `ResumeAck`. The peer
    /// should be in `AwaitingAck` with `pending_resumption` set
    /// (installed by `send_resume_hello`). We derive the same
    /// fresh key from `psk + eph_dh + nonces` and verify the
    /// auth tag — a successful decrypt proves the server held
    /// the same PSK and is therefore the same identity we
    /// previously authenticated.
    pub(crate) async fn handle_resume_ack(
        &self,
        header: &Header,
        body: &[u8],
    ) -> Result<()> {
        if body.len() < RESUME_ACK_BODY_LEN {
            return Err(DriftError::PacketTooShort {
                got: body.len(),
                need: RESUME_ACK_BODY_LEN,
            });
        }
        let mut server_eph_pub = [0u8; STATIC_KEY_LEN];
        server_eph_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag_start = STATIC_KEY_LEN + NONCE_LEN;
        let tag = &body[tag_start..tag_start + AUTH_TAG_LEN];

        let server_id = header.src_id;
        let pending_built: Vec<(Vec<u8>, SocketAddr)>;
        {
            let mut peers = self.peers.lock_for(&server_id).await;
            let peer = peers.get_mut(&server_id).ok_or(DriftError::UnknownPeer)?;

            let resumption = match peer.pending_resumption.take() {
                Some(r) => r,
                None => {
                    debug!("ResumeAck without pending_resumption, dropping");
                    return Ok(());
                }
            };

            let old_state =
                std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
            let (client_nonce, ephemeral) = match old_state {
                HandshakeState::AwaitingAck {
                    client_nonce,
                    ephemeral,
                    ..
                } => (client_nonce, ephemeral),
                other => {
                    peer.handshake = other;
                    debug!("ResumeAck in wrong state, ignoring");
                    return Ok(());
                }
            };

            let ephemeral_dh = ephemeral
                .dh(&server_eph_pub)
                .ok_or(DriftError::AuthFailed)?;
            drop(ephemeral);
            let new_session_key = derive_resumption_key(
                &resumption.psk,
                &ephemeral_dh,
                &client_nonce,
                &server_nonce,
            );

            let tx = SessionKey::new(&new_session_key, Direction::Initiator);
            let rx = SessionKey::new(&new_session_key, Direction::Responder);

            // Verify the auth tag.
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let canon = canonical_aad(&hbuf);
            let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
            aad.extend_from_slice(&canon);
            aad.extend_from_slice(&server_eph_pub);
            aad.extend_from_slice(&server_nonce);
            // The server sealed with Responder direction → we
            // verify with Responder rx-side check by using
            // `rx.open`. Our `rx` is Responder-direction here
            // because we're the Initiator side.
            rx.open(header.seq, PacketType::ResumeAck as u8, &aad, tag)?;

            peer.reset_seq();
            peer.coalesce_state.clear();
            peer.coalesce_order.clear();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx,
                rx,
                key_bytes: new_session_key,
                prev: None,
            };
            self.metrics
                .resumptions_completed
                .fetch_add(1, Ordering::Relaxed);

            // Drain any DATA that was queued before the
            // ResumeHello got its reply. Mirrors what
            // `handle_hello_ack` does for the full handshake
            // path.
            let pending = std::mem::take(&mut peer.pending);
            let mut built = Vec::with_capacity(pending.len());
            for ps in pending {
                if let Ok(super::SendAction::Data(bytes, target)) = super::build_data_packet(
                    self.local_peer_id,
                    peer,
                    &ps.payload,
                    ps.deadline_ms,
                    ps.coalesce_group,
                    None,
                ) {
                    built.push((bytes, target));
                }
            }
            pending_built = built;
        }

        for (bytes, target) in pending_built {
            self.ifaces.send_for(0, &bytes, target).await?;
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }

        debug!(server = ?server_id, "1-RTT resumption complete");
        Ok(())
    }
}

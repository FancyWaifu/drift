//! The sans-IO protocol engine.
//!
//! Every function in this file is a port of the corresponding logic
//! in `drift/src/transport/mod.rs` / `cookies.rs`, with the socket
//! sends replaced by a transmit queue and the tokio timers replaced
//! by an injected `now: Instant`. The wire bytes and the check
//! ordering are deliberately identical — see the "byte-compat
//! invariants" section of `docs/SANSIO_DESIGN.md` before changing
//! anything here.

use crate::resumption::{
    derive_psk, derive_resumption_key, ClientTicket, ResumptionStore, RESUME_ACK_BODY_LEN,
    RESUME_HELLO_BODY_LEN, TICKET_DEFAULT_TTL, TICKET_ID_LEN, TICKET_PLAINTEXT_LEN,
};
use drift_core::crypto::{cookie_mac, Direction, PeerId, SessionKey, COOKIE_MAC_LEN};
use drift_core::error::{CodecError, CryptoError, DriftError, PeerError, SessionError};
use drift_core::header::{
    canonical_aad, Header, PacketType, AUTH_TAG_LEN, FLAG_PQ_HYBRID, HEADER_LEN,
};
use drift_core::identity::{
    derive_session_key, random_nonce, rekey_derive, NONCE_LEN, STATIC_KEY_LEN,
};
use drift_core::session::{
    HandshakeState, Peer, PendingResumption, PendingSend, PrevSession, SEQ_SEND_CEILING,
};
use drift_core::short_header::{
    derive_initiator_rx_cid, derive_responder_rx_cid, encode_short, is_short_header, open_short,
};
use drift_core::{derive_peer_id, Identity, Zeroizing};
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Wire-size constants, identical to drift/src/transport/mod.rs and
// cookies.rs.
const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN; // 80
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN; // 64
const HELLO_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_EK_LEN; // 1184
const HELLO_ACK_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_CT_LEN; // 1088
const COOKIE_TS_LEN: usize = 8;
const COOKIE_BLOB_LEN: usize = COOKIE_TS_LEN + COOKIE_MAC_LEN; // 24
const HELLO_WITH_COOKIE_LEN: usize = HELLO_PAYLOAD_LEN + COOKIE_BLOB_LEN; // 104

/// Grace window during which the pre-rekey session keys stay live
/// on the receive path, so old-key DATA already in flight at the
/// key switch still decrypts. Identical to the transport's.
const REKEY_GRACE: Duration = Duration::from_secs(2);

/// Auto-rekey watermark: once a session's tx seq crosses 3/4 of
/// `SEQ_SEND_CEILING`, the next send triggers a transparent rekey
/// so the caller never sees `SessionExhausted`. Identical to the
/// transport's.
const AUTO_REKEY_THRESHOLD: u32 = (SEQ_SEND_CEILING / 4) * 3;

/// Engine configuration. Field names, semantics, and defaults match
/// the corresponding `drift::TransportConfig` fields so behavior is
/// comparable across the two implementations.
#[derive(Debug, Clone)]
pub struct Config {
    /// Offer / require the X25519+ML-KEM-768 hybrid handshake.
    pub hybrid_pq: bool,
    /// Auto-register unknown peers on inbound HELLO (server mode).
    pub accept_any_peer: bool,
    /// Cap on auto-registered peers.
    pub max_peers: usize,
    /// Base for the exponential handshake retransmit backoff (ms).
    pub handshake_retry_base_ms: u64,
    /// Give up retransmitting HELLO after this many attempts.
    pub handshake_max_attempts: u8,
    /// Always demand a DoS cookie before doing key agreement.
    pub cookie_always: bool,
    /// Demand cookies once this many handshakes are in flight.
    pub cookie_threshold: u32,
    /// Cookie validity window (seconds, wall clock).
    pub cookie_max_age_secs: u64,
    /// Cookie-secret rotation interval (seconds).
    pub cookie_rotate_secs: u64,
    /// Cap on DATA payloads queued per peer while a handshake is in
    /// flight.
    pub pending_queue_cap: usize,
    /// Reap peers stuck half-open (`AwaitingData` / `AwaitingAck`)
    /// for longer than this. `u64::MAX` disables eviction.
    pub awaiting_data_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hybrid_pq: true,
            accept_any_peer: false,
            max_peers: 8192,
            handshake_retry_base_ms: 1000,
            handshake_max_attempts: 10,
            cookie_always: false,
            cookie_threshold: 1000,
            cookie_max_age_secs: 60,
            cookie_rotate_secs: 30,
            pending_queue_cap: 256,
            awaiting_data_timeout_secs: 30,
        }
    }
}

/// A datagram the driver must put on the wire.
#[derive(Debug, Clone)]
pub struct Transmit {
    pub dst: SocketAddr,
    pub contents: Vec<u8>,
}

/// Protocol events for the application, drained via
/// [`Endpoint::poll_event`].
#[derive(Debug)]
pub enum Event {
    /// A session with this peer reached `Established`. Fires on the
    /// client when HELLO_ACK verifies; on the server when the first
    /// authenticated DATA arrives (the transport's definition of
    /// "handshake fully complete").
    Connected { peer: PeerId },
    /// An authenticated, replay-checked DATA payload.
    Data {
        peer: PeerId,
        seq: u32,
        payload: Vec<u8>,
    },
    /// The handshake retransmit budget is exhausted. The peer stays
    /// parked in `AwaitingAck` (mirroring the transport); a later
    /// `send` after resetting via `connect` starts fresh.
    HandshakeTimedOut { peer: PeerId },
    /// The peer sent an authenticated `Close`: its session state is
    /// gone (auto-registered peers are removed entirely; explicit
    /// peers reset to `Pending` and can re-handshake later).
    Closed { peer: PeerId },
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error(transparent)]
    Drift(#[from] DriftError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("payload too large: {len} bytes (max {max})")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("pending queue full for peer")]
    PendingQueueFull,
}

type Result<T> = std::result::Result<T, ProtoError>;

/// Rotating DoS-cookie secrets — port of
/// `drift::transport::cookies::CookieSecrets`, with rotation driven
/// by `handle_timeout` instead of a tokio interval.
struct CookieSecrets {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    rotated_at: Instant,
}

impl CookieSecrets {
    fn new(now: Instant) -> Self {
        let mut current = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut current);
        Self {
            current,
            previous: None,
            rotated_at: now,
        }
    }

    fn rotate(&mut self, now: Instant) {
        let mut fresh = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut fresh);
        self.previous = Some(self.current);
        self.current = fresh;
        self.rotated_at = now;
    }
}

/// Canonical address bytes inside the cookie MAC input.
/// v4: [0x04][addr][port BE], v6: [0x06][addr][port BE].
fn addr_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = Vec::with_capacity(1 + 4 + 2);
            out.push(0x04);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = Vec::with_capacity(1 + 16 + 2);
            out.push(0x06);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
            out
        }
    }
}

/// Constant-time MAC comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// The engine's one wall-clock read, used only for cookie
/// timestamps (60 s tolerance) — same as the transport.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cookie_input(
    src: &SocketAddr,
    client_static_pub: &[u8; STATIC_KEY_LEN],
    client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
    client_nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> Vec<u8> {
    let a = addr_bytes(src);
    let mut out = Vec::with_capacity(a.len() + 64 + NONCE_LEN + COOKIE_TS_LEN);
    out.extend_from_slice(&a);
    out.extend_from_slice(client_static_pub);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// Exponential backoff: `base * 2^attempts` ms, shift-capped.
/// Identical to the transport's `handshake_backoff_ms`.
fn handshake_backoff_ms(base: u64, attempts: u8) -> u64 {
    let shift = attempts.min(12) as u32;
    base << shift
}

/// Build a HELLO wire packet. Port of the transport's
/// `build_hello_wire` with `mesh = false` (the engine has no mesh
/// routes yet — phase 4).
fn build_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    identity: &Identity,
    ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    cookie: Option<&[u8; COOKIE_BLOB_LEN]>,
    pq_ek: Option<&[u8]>,
) -> Vec<u8> {
    let mut header = Header::new(PacketType::Hello, 0, local_peer_id, dst_id);
    if pq_ek.is_some() {
        header.flags |= FLAG_PQ_HYBRID;
    }
    let base_len = if cookie.is_some() {
        HELLO_WITH_COOKIE_LEN
    } else {
        HELLO_PAYLOAD_LEN
    };
    let payload_len = base_len + pq_ek.map(|ek| ek.len()).unwrap_or(0);
    header.payload_len = payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&identity.public_bytes());
    wire.extend_from_slice(&ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    if let Some(c) = cookie {
        wire.extend_from_slice(c);
    }
    if let Some(ek) = pq_ek {
        wire.extend_from_slice(ek);
    }
    wire
}

/// Rebuild a `ResumeHello` wire packet for the retransmit path.
/// Port of the transport's `build_resume_hello_wire` (mesh=false);
/// note the transport quirk that retransmits carry seq 0 while the
/// initial send allocates a real seq — neither is AEAD-relevant
/// (ResumeHello is unsealed) and the server ignores it.
fn build_resume_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    client_eph_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    ticket_id: [u8; TICKET_ID_LEN],
) -> Vec<u8> {
    let mut header = Header::new(PacketType::ResumeHello, 0, local_peer_id, dst_id);
    header.payload_len = RESUME_HELLO_BODY_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_HELLO_BODY_LEN);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&ticket_id);
    wire.extend_from_slice(&client_eph_pub);
    wire.extend_from_slice(&client_nonce);
    wire
}

/// Server-side session derivation + HELLO_ACK construction. Port of
/// the transport's `regenerate_session` (minus the interface
/// bookkeeping and the inflight atomic, which the engine derives by
/// scanning).
#[allow(clippy::too_many_arguments)]
fn regenerate_session(
    identity: &Identity,
    peer: &mut Peer,
    client_static_pub: [u8; STATIC_KEY_LEN],
    client_ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    local_peer_id: PeerId,
    client_peer_id: PeerId,
    src: SocketAddr,
    pq_client_ek: Option<&[u8]>,
) -> Result<(Vec<u8>, SocketAddr)> {
    let server_nonce = random_nonce();
    let server_ephemeral = Identity::generate();
    let server_ephemeral_pub = server_ephemeral.public_bytes();

    // Contributory-checked DH — low-order client points fail cleanly.
    let static_dh = identity
        .dh(&client_static_pub)
        .ok_or(CryptoError::KeyExchangeFailed)?;
    let ephemeral_dh = server_ephemeral
        .dh(&client_ephemeral_pub)
        .ok_or(CryptoError::KeyExchangeFailed)?;

    let (session_key_bytes, server_mlkem_ct) = if let Some(ek) = pq_client_ek {
        let (ct, mlkem_ss) =
            drift_core::pq::server_encapsulate(ek).ok_or(CryptoError::KeyExchangeFailed)?;
        let key = drift_core::pq::derive_hybrid_key(
            &static_dh,
            &ephemeral_dh,
            &mlkem_ss,
            &client_nonce,
            &server_nonce,
        );
        (Zeroizing::new(key), Some(ct))
    } else {
        (
            derive_session_key(&static_dh, &ephemeral_dh, &client_nonce, &server_nonce),
            None,
        )
    };
    drop(server_ephemeral);

    let tx = SessionKey::new(&session_key_bytes, Direction::Responder);
    let rx = SessionKey::new(&session_key_bytes, Direction::Initiator);

    peer.reset_seq();
    peer.coalesce_state.clear();
    peer.coalesce_order.clear();
    peer.mark_session_start();
    peer.addr = src;

    // `with_hop_ttl(DEFAULT_MESH_TTL)` to match the transport's ACK
    // bytes exactly — it sets hop_ttl=8 AND the FLAG_ROUTED bit,
    // both of which are inside the client's AAD computation (flags
    // byte directly; hop_ttl zeroed by canonical_aad).
    let mut ack_header = Header::new(PacketType::HelloAck, 1, local_peer_id, client_peer_id)
        .with_hop_ttl(drift_core::session::DEFAULT_MESH_TTL);
    if server_mlkem_ct.is_some() {
        ack_header.flags |= FLAG_PQ_HYBRID;
    }
    let ack_payload_len =
        HELLO_ACK_PAYLOAD_LEN + server_mlkem_ct.as_ref().map(|ct| ct.len()).unwrap_or(0);
    ack_header.payload_len = ack_payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    ack_header.encode(&mut hbuf);

    let canon = canonical_aad(&hbuf);
    let mut aad = Vec::with_capacity(
        HEADER_LEN
            + STATIC_KEY_LEN
            + NONCE_LEN
            + server_mlkem_ct.as_ref().map(|ct| ct.len()).unwrap_or(0),
    );
    aad.extend_from_slice(&canon);
    aad.extend_from_slice(&server_ephemeral_pub);
    aad.extend_from_slice(&server_nonce);
    if let Some(ct) = &server_mlkem_ct {
        aad.extend_from_slice(ct);
    }
    let tag = tx.seal(1, PacketType::HelloAck as u8, &aad, b"")?;

    let mut wire = Vec::with_capacity(HEADER_LEN + ack_payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&server_ephemeral_pub);
    wire.extend_from_slice(&server_nonce);
    wire.extend_from_slice(&tag);
    if let Some(ct) = &server_mlkem_ct {
        wire.extend_from_slice(ct);
    }

    peer.handshake = HandshakeState::AwaitingData {
        tx,
        rx,
        key_bytes: session_key_bytes,
        cached_ack: wire.clone(),
        cached_client_nonce: client_nonce,
        was_hybrid_pq: server_mlkem_ct.is_some(),
    };

    Ok((wire, src))
}

/// Authenticated session-close packet: an AEAD-sealed empty body —
/// the tag is the message. Port of the transport's
/// `build_close_packet`.
fn build_close_packet(local_peer_id: PeerId, peer: &mut Peer) -> Result<Vec<u8>> {
    let seq = peer.next_seq_checked()?;
    let mut header = peer.make_header(PacketType::Close, seq, local_peer_id);
    header.payload_len = AUTH_TAG_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Close as u8, &aad, b"", &mut wire)?;
    Ok(wire)
}

/// Long-header DATA construction. Port of the transport's
/// `build_data_packet` (no CID/short-header fast path, no mesh —
/// phase 2/4).
fn build_data_packet(
    local_peer_id: PeerId,
    peer: &mut Peer,
    payload: &[u8],
    deadline_ms: u16,
    coalesce_group: u32,
) -> Result<Transmit> {
    let seq = peer.next_seq_checked()?;

    let send_time_ms = peer.send_time_ms();
    let mut header =
        Header::new(PacketType::Data, seq, local_peer_id, peer.id).with_deadline(deadline_ms);
    if coalesce_group != 0 {
        header = header.with_supersedes(coalesce_group);
    }
    header.payload_len = payload.len() as u16;
    header.send_time_ms = send_time_ms;

    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

    let mut wire = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)?;

    Ok(Transmit {
        dst: peer.addr,
        contents: wire,
    })
}

/// The sans-IO DRIFT endpoint: feed it datagrams and time, drain
/// transmits and events.
pub struct Endpoint {
    identity: Identity,
    local_peer_id: PeerId,
    config: Config,
    peers: HashMap<PeerId, Peer>,
    cookies: CookieSecrets,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
    /// Short-header receive map: CID in an inbound short-header
    /// packet → the peer whose session key it belongs to.
    cid_map: HashMap<u16, PeerId>,
    /// Short-header send map: peer → the CID to stamp on outgoing
    /// short-header packets so the peer's recv path can look us up.
    peer_out_cid: HashMap<PeerId, u16>,
    /// Client-side resumption tickets, keyed by the issuing peer.
    client_tickets: HashMap<PeerId, ClientTicket>,
    /// Server-side ticket store (single-use, identity-bound).
    resumption_store: ResumptionStore,
}

impl Endpoint {
    pub fn new(identity: Identity, config: Config) -> Self {
        let local_peer_id = derive_peer_id(&identity.public_bytes());
        Self {
            identity,
            local_peer_id,
            config,
            peers: HashMap::new(),
            cookies: CookieSecrets::new(Instant::now()),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            cid_map: HashMap::new(),
            peer_out_cid: HashMap::new(),
            client_tickets: HashMap::new(),
            resumption_store: ResumptionStore::default(),
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn public_bytes(&self) -> [u8; STATIC_KEY_LEN] {
        self.identity.public_bytes()
    }

    /// Export the stored resumption ticket for a peer as an opaque
    /// blob (97 bytes, transport-compatible format). The blob
    /// carries the PSK in the clear — persist it with the same care
    /// as a private key. `None` if no unexpired ticket is on file.
    pub fn export_resumption_ticket(&self, peer_id: &PeerId) -> Option<Vec<u8>> {
        self.client_tickets
            .get(peer_id)
            .filter(|t| t.expiry > SystemTime::now())
            .map(|t| t.to_bytes())
    }

    /// Import a ticket blob produced by `export_resumption_ticket`
    /// (or by `drift::Transport`'s exporter — same format). The
    /// blob is validated before storage: well-formed, unexpired,
    /// and — when the issuing peer is already registered — its
    /// embedded server pubkey must match the stored one. Returns
    /// the issuing peer's id; `connect` to that peer will then use
    /// the 1-RTT resumption path.
    pub fn import_resumption_ticket(&mut self, blob: &[u8]) -> Result<PeerId> {
        let ticket = ClientTicket::from_bytes(blob).ok_or(PeerError::ResumptionTicketNotFound)?;
        if ticket.expiry <= SystemTime::now() {
            return Err(PeerError::TicketExpired.into());
        }
        if let Some(p) = self.peers.get(&ticket.server_id) {
            if p.peer_static_pub != ticket.server_static_pub {
                return Err(PeerError::ResumptionTicketNotFound.into());
            }
        }
        let id = ticket.server_id;
        self.client_tickets.insert(id, ticket);
        Ok(id)
    }

    /// Test hook (same convention as `Transport::test_bump_peer_seq`):
    /// force a peer's tx seq counter so tests can cross the
    /// auto-rekey watermark without sending 1.6 billion packets.
    /// Returns false if the peer is unknown.
    #[doc(hidden)]
    pub fn test_bump_peer_seq(&mut self, peer_id: &PeerId, value: u32) -> bool {
        match self.peers.get_mut(peer_id) {
            Some(peer) => {
                peer.next_tx_seq = value;
                true
            }
            None => false,
        }
    }

    /// Register a peer without initiating a handshake (server-side
    /// allowlisting). Mirrors `Transport::add_peer`.
    pub fn add_peer(
        &mut self,
        static_pub: [u8; STATIC_KEY_LEN],
        addr: SocketAddr,
        direction: Direction,
    ) -> PeerId {
        let id = derive_peer_id(&static_pub);
        self.peers
            .entry(id)
            .or_insert_with(|| Peer::new(id, addr, static_pub, direction));
        id
    }

    /// Register a peer and queue the opening flight — a 1-RTT
    /// `ResumeHello` when a valid ticket is on file for the peer
    /// (stored from a previous session or imported), a full HELLO
    /// otherwise.
    pub fn connect(
        &mut self,
        now: Instant,
        static_pub: [u8; STATIC_KEY_LEN],
        addr: SocketAddr,
    ) -> PeerId {
        let id = self.add_peer(static_pub, addr, Direction::Initiator);
        self.start_session(now, &id);
        id
    }

    /// Send an application payload. If the session is live the DATA
    /// packet is queued immediately; if a handshake is needed or in
    /// flight, the payload parks in the peer's pending queue and
    /// flushes on establishment. Mirrors `Transport::send_data`.
    pub fn send(
        &mut self,
        now: Instant,
        peer_id: &PeerId,
        payload: &[u8],
        deadline_ms: u16,
        coalesce_group: u32,
    ) -> Result<()> {
        if payload.len() > crate::MAX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge {
                len: payload.len(),
                max: crate::MAX_PAYLOAD,
            });
        }
        // Transparent auto-rekey: when the session's seq counter is
        // 3/4 of the way to the nonce-reuse ceiling, rekey before
        // building this packet so the caller never sees
        // `SessionExhausted`. Same watermark as the transport.
        let needs_rekey = self
            .peers
            .get(peer_id)
            .map(|p| {
                matches!(p.handshake, HandshakeState::Established { .. })
                    && p.next_tx_seq >= AUTO_REKEY_THRESHOLD
            })
            .unwrap_or(false);
        if needs_rekey {
            self.rekey(now, peer_id)?;
        }
        let pending_cap = self.config.pending_queue_cap;
        let local_peer_id = self.local_peer_id;
        let out_cid = self.peer_out_cid.get(peer_id).copied();
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotRegistered)?;

        if peer.handshake.is_ready_for_data() {
            // Short-header fast path, mirroring the transport's
            // eligibility rules: a CID is installed and no
            // deadline/coalesce features are in play. (Mesh is the
            // third condition; the engine has no mesh yet.)
            //
            // `next_tx_seq > 1` guards a trap the transport only
            // dodges by accident: the responder installs its CID map
            // at the AwaitingData → Established transition, which is
            // driven by receiving our first DATA — so that first
            // DATA must be long-header or the responder can't look
            // it up. The transport always flushes a long-header
            // pending packet at handshake completion; the engine
            // makes the rule explicit so a connect()-then-send flow
            // is safe too.
            if let Some(cid) = out_cid {
                if deadline_ms == 0 && coalesce_group == 0 && peer.next_tx_seq > 1 {
                    let seq = peer.next_seq_checked()?;
                    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
                    let wire = encode_short(cid, seq, tx, payload)?;
                    self.transmits.push_back(Transmit {
                        dst: peer.addr,
                        contents: wire,
                    });
                    return Ok(());
                }
            }
            let t = build_data_packet(local_peer_id, peer, payload, deadline_ms, coalesce_group)?;
            self.transmits.push_back(t);
            return Ok(());
        }

        // Session not ready: park the payload.
        if peer.pending.len() >= pending_cap {
            return Err(ProtoError::PendingQueueFull);
        }
        peer.pending.push(PendingSend {
            payload: payload.to_vec(),
            deadline_ms,
            coalesce_group,
        });

        // First send to a Pending initiator kicks off the handshake
        // (resumed when a ticket is on file, full HELLO otherwise).
        if matches!(peer.handshake, HandshakeState::Pending)
            && peer.direction == Direction::Initiator
        {
            self.start_session(now, peer_id);
        }
        Ok(())
    }

    /// Rekey an established session: derive a fresh session key
    /// from the old key + 32 random salt bytes, ship the salt in a
    /// `RekeyRequest` sealed under the OLD key, and keep the old
    /// keys in a grace slot so in-flight packets still decrypt.
    /// Port of the transport's `rekey`.
    pub fn rekey(&mut self, now: Instant, peer_id: &PeerId) -> Result<()> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let local_peer_id = self.local_peer_id;

        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
            HandshakeState::Established {
                tx, rx, key_bytes, ..
            } => (tx.clone(), rx.clone(), key_bytes.clone()),
            _ => return Err(PeerError::SessionNotEstablished.into()),
        };

        // 1. RekeyRequest sealed with the OLD tx key, body = salt.
        let seq = peer.next_seq_checked()?;
        let mut header = peer.make_header(PacketType::RekeyRequest, seq, local_peer_id);
        header.payload_len = (32 + AUTH_TAG_LEN) as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        let mut wire = Vec::with_capacity(HEADER_LEN + 32 + AUTH_TAG_LEN);
        wire.extend_from_slice(&hbuf);
        old_tx.seal_into(seq, PacketType::RekeyRequest as u8, &aad, &salt, &mut wire)?;

        // 2. Derive + install the new key; old keys go to the grace
        //    slot. The rekey initiator takes the Initiator nonce
        //    direction for the new key namespace regardless of who
        //    initiated the original handshake — same as the
        //    transport.
        let new_key_bytes = rekey_derive(&old_key_bytes, &salt);
        let new_tx = SessionKey::new(&new_key_bytes, Direction::Initiator);
        let new_rx = SessionKey::new(&new_key_bytes, Direction::Responder);
        peer.reset_seq();
        peer.mark_session_start();
        let mut cid_key = [0u8; 32];
        cid_key.copy_from_slice(&*new_key_bytes);
        peer.handshake = HandshakeState::Established {
            tx: new_tx,
            rx: new_rx,
            key_bytes: new_key_bytes,
            prev: Some(PrevSession {
                tx: old_tx,
                rx: old_rx,
                installed_at: now,
            }),
        };
        let dst = peer.addr;

        self.transmits.push_back(Transmit {
            dst,
            contents: wire,
        });
        // Refresh CID maps for the new key. The old CID entries
        // stay in the map (the transport's insert-only behavior) —
        // they're what routes in-flight old-key short-header
        // packets to this peer for the grace-window fallback.
        self.install_cids(*peer_id, &cid_key, true);
        Ok(())
    }

    /// Close an established (or half-open) session: emit an
    /// AEAD-sealed `Close` and drop local session state immediately
    /// — no retry if the packet is lost. Port of the transport's
    /// `close_peer`.
    pub fn close(&mut self, peer_id: &PeerId) -> Result<()> {
        let local_peer_id = self.local_peer_id;
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotRegistered)?;
        if !peer.handshake.is_ready_for_data() {
            return Err(PeerError::SessionNotReady.into());
        }
        let wire = build_close_packet(local_peer_id, peer)?;
        let dst = peer.addr;

        if peer.auto_registered {
            self.peers.remove(peer_id);
        } else {
            peer.handshake = HandshakeState::Pending;
            peer.pending.clear();
            peer.session_epoch = None;
            peer.probing = None;
        }
        // Engine divergence (safe direction): drop this peer's CID
        // entries so a dead session can't leave stale short-header
        // routes behind. The transport leaves them to be
        // overwritten by the next session.
        self.drop_cids(peer_id);
        // Engine divergence (safe direction): drop the resumption
        // ticket too. An auto-registered server forgets us on
        // Close, so resuming against it can never succeed — the
        // transport keeps the ticket and a redial parks in
        // ResumeHello retries until give-up.
        self.client_tickets.remove(peer_id);

        self.transmits.push_back(Transmit {
            dst,
            contents: wire,
        });
        Ok(())
    }

    /// Drain the next outbound datagram.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Drain the next application event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Feed one inbound datagram. Returns `Err` for packets the
    /// engine rejected (malformed, unauthenticated, replayed, wrong
    /// destination); drivers typically log and continue — a remote
    /// peer must not be able to wedge the endpoint.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        src: SocketAddr,
        datagram: &[u8],
    ) -> Result<()> {
        // Short-header fast path (version nibble 0x2): the
        // transport switches to these for plain DATA the moment a
        // session establishes, so any byte-compatible peer must
        // accept them.
        if is_short_header(datagram) {
            return self.on_short_data(now, datagram);
        }
        let header = Header::decode(datagram)?;
        let body = &datagram[HEADER_LEN..];
        match header.packet_type {
            PacketType::Hello => self.on_hello(now, &header, body, src),
            PacketType::HelloAck => self.on_hello_ack(now, &header, body),
            PacketType::Challenge => self.on_challenge(now, &header, body),
            PacketType::Data => self.on_data(now, &header, body),
            PacketType::RekeyRequest => self.on_rekey_request(now, &header, body),
            PacketType::RekeyAck => self.on_rekey_ack(&header, body),
            PacketType::Close => self.on_close(&header, body),
            PacketType::ResumeHello => self.on_resume_hello(now, &header, body, src),
            PacketType::ResumeAck => self.on_resume_ack(now, &header, body),
            PacketType::ResumptionTicket => self.on_resumption_ticket(&header, body),
            // Mesh / resumption / federation packet types arrive in
            // later phases; drop them for now.
            _ => Ok(()),
        }
    }

    /// Drive time-based behavior: HELLO retransmits with exponential
    /// backoff, give-up notifications, and cookie-secret rotation.
    /// Call at least every ~100 ms when handshakes may be in flight,
    /// or per `next_timeout`.
    pub fn handle_timeout(&mut self, now: Instant) {
        // Cookie rotation (server side).
        if now.saturating_duration_since(self.cookies.rotated_at)
            >= Duration::from_secs(self.config.cookie_rotate_secs.max(1))
        {
            self.cookies.rotate(now);
        }

        // Handshake retransmits — port of run_handshake_retry_loop.
        let max_attempts = self.config.handshake_max_attempts;
        let base_default = self.config.handshake_retry_base_ms;
        let local_peer_id = self.local_peer_id;
        let identity = &self.identity;
        let mut out: Vec<Transmit> = Vec::new();
        let mut timed_out: Vec<PeerId> = Vec::new();
        let mut resume_failed: Vec<PeerId> = Vec::new();
        for peer in self.peers.values_mut() {
            // RFC 6298-style RTT-aware base when a previous session
            // measured this neighbor; static default otherwise.
            let effective_base_ms = match peer.neighbor_srtt {
                Some(srtt) => {
                    let srtt_ms = srtt.as_millis() as u64;
                    (4 * srtt_ms).max(200)
                }
                None => base_default,
            };
            let peer_id = peer.id;
            let peer_addr = peer.addr;
            // Snapshot before borrowing handshake mutably: an
            // AwaitingAck entered via ResumeHello must retransmit
            // as ResumeHello — a single dropped packet must not
            // silently downgrade the client to a cold handshake.
            let resumption_ctx = peer.pending_resumption.clone();
            if let HandshakeState::AwaitingAck {
                client_nonce,
                ephemeral,
                last_sent,
                attempts,
                cookie,
                pq,
            } = &mut peer.handshake
            {
                let wait = handshake_backoff_ms(effective_base_ms, *attempts);
                if now.saturating_duration_since(*last_sent) < Duration::from_millis(wait) {
                    continue;
                }
                if *attempts >= max_attempts {
                    // Transport parks the peer silently; the engine
                    // additionally notifies once (attempts is bumped
                    // past the max as the "already notified" marker).
                    if *attempts == max_attempts {
                        *attempts = attempts.saturating_add(1);
                        timed_out.push(peer_id);
                        // Engine divergence (safe direction): a
                        // failed RESUMPTION attempt falls back —
                        // reset to Pending and burn the ticket so
                        // the next send issues a full HELLO. The
                        // transport documents this fallback but
                        // parks instead, leaving the client
                        // re-presenting a ticket the server may
                        // have already consumed or lost.
                        if resumption_ctx.is_some() {
                            resume_failed.push(peer_id);
                        }
                    }
                    continue;
                }
                *attempts += 1;
                *last_sent = now;

                let wire = if let Some(res) = &resumption_ctx {
                    build_resume_hello_wire(
                        local_peer_id,
                        peer_id,
                        ephemeral.public_bytes(),
                        *client_nonce,
                        res.ticket_id,
                    )
                } else {
                    let pq_ek = pq.as_ref().map(|(ek, _)| ek.as_slice());
                    build_hello_wire(
                        local_peer_id,
                        peer_id,
                        identity,
                        ephemeral.public_bytes(),
                        *client_nonce,
                        cookie.as_ref(),
                        pq_ek,
                    )
                };
                out.push(Transmit {
                    dst: peer_addr,
                    contents: wire,
                });
            }
        }
        self.transmits.extend(out);
        self.events.extend(
            timed_out
                .into_iter()
                .map(|peer| Event::HandshakeTimedOut { peer }),
        );
        for id in resume_failed {
            if let Some(peer) = self.peers.get_mut(&id) {
                peer.pending_resumption = None;
                peer.handshake = HandshakeState::Pending;
            }
            self.client_tickets.remove(&id);
        }

        // Half-open eviction — port of run_handshake_eviction_loop.
        // Reap peers stuck in either half-open state past the
        // cutoff: AwaitingData (server replied, client never sent
        // DATA — aged via session_epoch) and AwaitingAck (we sent
        // HELLO, no reply — aged via last_sent, which retransmits
        // refresh). Auto-registered peers are removed; explicit
        // peers reset to Pending so the app can redial.
        if self.config.awaiting_data_timeout_secs != u64::MAX {
            let cutoff = Duration::from_secs(self.config.awaiting_data_timeout_secs);
            let mut to_remove: Vec<PeerId> = Vec::new();
            for peer in self.peers.values_mut() {
                let stale_age = match &peer.handshake {
                    HandshakeState::AwaitingData { .. } => peer
                        .session_epoch
                        .map(|e| now.saturating_duration_since(e))
                        .unwrap_or_default(),
                    HandshakeState::AwaitingAck { last_sent, .. } => {
                        now.saturating_duration_since(*last_sent)
                    }
                    _ => continue,
                };
                if stale_age <= cutoff {
                    continue;
                }
                if peer.auto_registered {
                    to_remove.push(peer.id);
                } else {
                    peer.handshake = HandshakeState::Pending;
                    peer.pending.clear();
                    peer.session_epoch = None;
                }
            }
            for id in to_remove {
                self.peers.remove(&id);
                self.drop_cids(&id);
            }
        }
    }

    /// Earliest instant at which `handle_timeout` has work to do.
    pub fn next_timeout(&self) -> Option<Instant> {
        let rotate_at =
            self.cookies.rotated_at + Duration::from_secs(self.config.cookie_rotate_secs.max(1));
        let mut next = Some(rotate_at);
        for peer in self.peers.values() {
            let effective_base_ms = match peer.neighbor_srtt {
                Some(srtt) => (4 * srtt.as_millis() as u64).max(200),
                None => self.config.handshake_retry_base_ms,
            };
            if let HandshakeState::AwaitingAck {
                last_sent,
                attempts,
                ..
            } = &peer.handshake
            {
                if *attempts > self.config.handshake_max_attempts {
                    continue;
                }
                let wait = handshake_backoff_ms(effective_base_ms, *attempts);
                let due = *last_sent + Duration::from_millis(wait);
                if next.map(|n| due < n).unwrap_or(true) {
                    next = Some(due);
                }
            }
        }
        next
    }

    // ---- internals -------------------------------------------------

    /// Install the deterministic short-header CIDs for an
    /// established session. Port of `Transport::install_cids`.
    fn install_cids(&mut self, peer_id: PeerId, session_key: &[u8; 32], local_is_initiator: bool) {
        let my_rx_cid = if local_is_initiator {
            derive_initiator_rx_cid(session_key)
        } else {
            derive_responder_rx_cid(session_key)
        };
        let peer_rx_cid = if local_is_initiator {
            derive_responder_rx_cid(session_key)
        } else {
            derive_initiator_rx_cid(session_key)
        };
        self.cid_map.insert(my_rx_cid, peer_id);
        self.peer_out_cid.insert(peer_id, peer_rx_cid);
    }

    /// Server-side completion: first authenticated DATA moves the
    /// peer from `AwaitingData` to `Established`, clears the
    /// amplification counters, installs short-header CIDs, emits
    /// `Connected`, and flushes any parked payloads. No-op if the
    /// peer is already `Established`.
    fn complete_server_handshake(&mut self, peer_id: PeerId) -> Result<()> {
        let local_peer_id = self.local_peer_id;
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return Ok(());
        };
        if !matches!(peer.handshake, HandshakeState::AwaitingData { .. }) {
            return Ok(());
        }
        let old = std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
        let mut cid_key = [0u8; 32];
        if let HandshakeState::AwaitingData {
            tx, rx, key_bytes, ..
        } = old
        {
            cid_key.copy_from_slice(&*key_bytes);
            peer.handshake = HandshakeState::Established {
                tx,
                rx,
                key_bytes,
                prev: None,
            };
        }
        peer.clear_unauth_counters();
        let pending = std::mem::take(&mut peer.pending);
        let mut flushed = Vec::with_capacity(pending.len());
        for ps in pending {
            flushed.push(build_data_packet(
                local_peer_id,
                peer,
                &ps.payload,
                ps.deadline_ms,
                ps.coalesce_group,
            )?);
        }
        self.install_cids(peer_id, &cid_key, false);
        self.events.push_back(Event::Connected { peer: peer_id });
        self.transmits.extend(flushed);
        // Hand the client a resumption ticket for 1-RTT reconnects
        // — best-effort, same as the transport's post-transition
        // issue in handle_data.
        let _ = self.issue_ticket(peer_id);
        Ok(())
    }

    /// Short-header DATA receive. Port of the transport's
    /// `process_short_header` (minus path migration — phase 4).
    fn on_short_data(&mut self, now: Instant, datagram: &[u8]) -> Result<()> {
        let (cid, _seq, _body) = drift_core::short_header::decode_short(datagram)?;
        let peer_id = *self.cid_map.get(&cid).ok_or(PeerError::NotRegistered)?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
        let first_try = open_short(datagram, rx);
        let (_cid, seq, payload) = match first_try {
            Ok(out) => out,
            Err(err) => {
                // Rekey grace fallback, same as the long-header
                // path. The pre-rekey CID entries are still in the
                // map — that's how an old-key packet found this
                // peer in the first place.
                let mut recovered = None;
                if let HandshakeState::Established { prev, .. } = &mut peer.handshake {
                    if let Some(p) = prev {
                        if now.saturating_duration_since(p.installed_at) <= REKEY_GRACE {
                            if let Ok(out) = open_short(datagram, &p.rx) {
                                recovered = Some(out);
                            }
                        } else {
                            *prev = None;
                        }
                    }
                }
                match recovered {
                    Some(out) => out,
                    None => return Err(err.into()),
                }
            }
        };
        peer.check_and_update_replay(seq)?;
        peer.last_seen = now;
        self.complete_server_handshake(peer_id)?;
        self.events.push_back(Event::Data {
            peer: peer_id,
            seq,
            payload,
        });
        Ok(())
    }

    fn start_hello(&mut self, now: Instant, peer_id: &PeerId) {
        let local_peer_id = self.local_peer_id;
        let hybrid_pq = self.config.hybrid_pq;
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return;
        };
        let client_nonce = random_nonce();
        let ephemeral = Identity::generate();
        let ephemeral_pub = ephemeral.public_bytes();
        let pq = if hybrid_pq {
            Some(drift_core::pq::client_generate_keypair())
        } else {
            None
        };
        let wire = build_hello_wire(
            local_peer_id,
            peer.id,
            &self.identity,
            ephemeral_pub,
            client_nonce,
            None,
            pq.as_ref().map(|(ek, _)| ek.as_slice()),
        );
        peer.handshake = HandshakeState::AwaitingAck {
            client_nonce,
            ephemeral,
            last_sent: now,
            attempts: 1,
            cookie: None,
            pq,
        };
        self.transmits.push_back(Transmit {
            dst: peer.addr,
            contents: wire,
        });
    }

    /// True when inbound HELLOs must carry a cookie. Port of
    /// `cookie_required_sync`; the inflight gauge is a scan here
    /// (peer counts are bounded; the engine has no atomics).
    fn cookie_required(&self) -> bool {
        if self.config.cookie_always {
            return true;
        }
        if self.config.cookie_threshold == u32::MAX {
            return false;
        }
        let inflight = self
            .peers
            .values()
            .filter(|p| matches!(p.handshake, HandshakeState::AwaitingData { .. }))
            .count();
        inflight >= self.config.cookie_threshold as usize
    }

    fn queue_challenge(
        &mut self,
        client_peer_id: PeerId,
        src: SocketAddr,
        client_static_pub: &[u8; STATIC_KEY_LEN],
        client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
        client_nonce: &[u8; NONCE_LEN],
    ) {
        let timestamp = now_unix_secs();
        let input = cookie_input(
            &src,
            client_static_pub,
            client_ephemeral_pub,
            client_nonce,
            timestamp,
        );
        let mac = cookie_mac(&self.cookies.current, &input);

        let mut header = Header::new(PacketType::Challenge, 0, self.local_peer_id, client_peer_id);
        header.payload_len = COOKIE_BLOB_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + COOKIE_BLOB_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&timestamp.to_be_bytes());
        wire.extend_from_slice(&mac);

        self.transmits.push_back(Transmit {
            dst: src,
            contents: wire,
        });
    }

    fn validate_cookie(
        &self,
        src: &SocketAddr,
        client_static_pub: &[u8; STATIC_KEY_LEN],
        client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
        client_nonce: &[u8; NONCE_LEN],
        tail: &[u8],
    ) -> bool {
        if tail.len() != COOKIE_BLOB_LEN {
            return false;
        }
        let mut ts_buf = [0u8; COOKIE_TS_LEN];
        ts_buf.copy_from_slice(&tail[..COOKIE_TS_LEN]);
        let timestamp = u64::from_be_bytes(ts_buf);
        let now = now_unix_secs();
        if now.saturating_sub(timestamp) > self.config.cookie_max_age_secs {
            return false;
        }
        let presented = &tail[COOKIE_TS_LEN..];
        let input = cookie_input(
            src,
            client_static_pub,
            client_ephemeral_pub,
            client_nonce,
            timestamp,
        );
        let expected_current = cookie_mac(&self.cookies.current, &input);
        if ct_eq(presented, &expected_current) {
            return true;
        }
        if let Some(prev) = self.cookies.previous {
            let expected_prev = cookie_mac(&prev, &input);
            if ct_eq(presented, &expected_prev) {
                return true;
            }
        }
        false
    }

    /// Server-side HELLO processing. Port of `handle_hello`,
    /// preserving the check ordering exactly.
    fn on_hello(
        &mut self,
        now: Instant,
        header: &Header,
        body: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        if body.len() < HELLO_PAYLOAD_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: HELLO_PAYLOAD_LEN,
            }
            .into());
        }
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let mut client_static_pub = [0u8; STATIC_KEY_LEN];
        client_static_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut client_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        client_ephemeral_pub.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN * 2]);
        let mut client_nonce = [0u8; NONCE_LEN];
        client_nonce.copy_from_slice(&body[STATIC_KEY_LEN * 2..STATIC_KEY_LEN * 2 + NONCE_LEN]);

        // Reject obviously-weak pubkeys before any X25519 work.
        if client_static_pub == [0u8; STATIC_KEY_LEN]
            || client_ephemeral_pub == [0u8; STATIC_KEY_LEN]
        {
            return Err(CryptoError::KeyExchangeFailed.into());
        }

        // PQ posture: no silent downgrade in either direction.
        let pq_requested = (header.flags & FLAG_PQ_HYBRID) != 0;
        if pq_requested && !self.config.hybrid_pq {
            return Err(CryptoError::KeyExchangeFailed.into());
        }
        let pq_client_ek: Option<Vec<u8>> = if pq_requested {
            if body.len() < HELLO_PAYLOAD_LEN + HELLO_PQ_TAIL_LEN {
                return Err(CodecError::PacketTooShort {
                    got: body.len(),
                    need: HELLO_PAYLOAD_LEN + HELLO_PQ_TAIL_LEN,
                }
                .into());
            }
            let ek_start = body.len() - HELLO_PQ_TAIL_LEN;
            Some(body[ek_start..].to_vec())
        } else {
            None
        };

        // Adaptive DoS cookie gate — before any allocation or DH.
        // The PQ ek sits at the tail; strip it before deciding
        // whether a cookie is present.
        let cookie_required = self.cookie_required();
        let body_minus_pq =
            body.len()
                .saturating_sub(if pq_requested { HELLO_PQ_TAIL_LEN } else { 0 });
        let has_cookie_tail = body_minus_pq >= HELLO_WITH_COOKIE_LEN;
        if cookie_required {
            if !has_cookie_tail {
                self.queue_challenge(
                    header.src_id,
                    src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                );
                return Ok(());
            }
            let cookie_tail = &body[HELLO_PAYLOAD_LEN..HELLO_WITH_COOKIE_LEN];
            if !self.validate_cookie(
                &src,
                &client_static_pub,
                &client_ephemeral_pub,
                &client_nonce,
                cookie_tail,
            ) {
                // Fresh challenge so a client with an expired cookie
                // can recover without restarting.
                self.queue_challenge(
                    header.src_id,
                    src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                );
                return Ok(());
            }
        }

        let client_peer_id = derive_peer_id(&client_static_pub);

        // Auto-registration.
        if !self.peers.contains_key(&client_peer_id) {
            if self.config.accept_any_peer {
                if self.peers.values().filter(|p| p.auto_registered).count()
                    >= self.config.max_peers
                {
                    return Err(PeerError::NotRegistered.into());
                }
                let mut new_peer =
                    Peer::new(client_peer_id, src, client_static_pub, Direction::Responder);
                new_peer.auto_registered = true;
                self.peers.insert(client_peer_id, new_peer);
            } else {
                return Err(PeerError::NotRegistered.into());
            }
        }

        let local_pub = self.identity.public_bytes();
        let local_peer_id = self.local_peer_id;
        let peer = self
            .peers
            .get_mut(&client_peer_id)
            .ok_or(PeerError::NotRegistered)?;

        if peer.peer_static_pub != client_static_pub {
            return Err(CryptoError::SignatureInvalid.into());
        }

        // Dual-initiation tiebreak: lower static pubkey yields and
        // becomes the responder.
        if matches!(peer.handshake, HandshakeState::AwaitingAck { .. }) {
            if local_pub > client_static_pub {
                return Ok(()); // we win — keep waiting for our ACK
            }
            peer.handshake = HandshakeState::Pending;
        }

        // Duplicate HELLO (same nonce) → replay the cached ACK to the
        // trusted address, never the datagram source.
        let cached: Option<(Vec<u8>, SocketAddr)> = match &peer.handshake {
            HandshakeState::AwaitingData {
                cached_ack,
                cached_client_nonce,
                ..
            } if *cached_client_nonce == client_nonce => Some((cached_ack.clone(), peer.addr)),
            _ => None,
        };
        let (ack_bytes, ack_addr) = match cached {
            Some(out) => out,
            None => regenerate_session(
                &self.identity,
                peer,
                client_static_pub,
                client_ephemeral_pub,
                client_nonce,
                local_peer_id,
                client_peer_id,
                src,
                pq_client_ek.as_deref(),
            )?,
        };
        peer.last_seen = now;

        // 3× amplification budget (RFC 9000 §8.1 style).
        peer.note_unauth_bytes_rx(body.len() + HEADER_LEN);
        if !peer.try_spend_unauth_budget(ack_bytes.len()) {
            return Ok(());
        }

        self.transmits.push_back(Transmit {
            dst: ack_addr,
            contents: ack_bytes,
        });
        Ok(())
    }

    /// Client-side HELLO_ACK processing. Port of `handle_hello_ack`.
    fn on_hello_ack(&mut self, now: Instant, header: &Header, body: &[u8]) -> Result<()> {
        if body.len() < HELLO_ACK_PAYLOAD_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: HELLO_ACK_PAYLOAD_LEN,
            }
            .into());
        }
        let server_pq = (header.flags & FLAG_PQ_HYBRID) != 0;
        let pq_ct: Option<&[u8]> = if server_pq {
            let need = HELLO_ACK_PAYLOAD_LEN + HELLO_ACK_PQ_TAIL_LEN;
            if body.len() < need {
                return Err(CodecError::PacketTooShort {
                    got: body.len(),
                    need,
                }
                .into());
            }
            Some(&body[HELLO_ACK_PAYLOAD_LEN..HELLO_ACK_PAYLOAD_LEN + HELLO_ACK_PQ_TAIL_LEN])
        } else {
            None
        };
        let mut server_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        server_ephemeral_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag_start = STATIC_KEY_LEN + NONCE_LEN;
        let tag = &body[tag_start..tag_start + AUTH_TAG_LEN];

        let peer_id = header.src_id;
        let local_peer_id = self.local_peer_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;

        let old_state = std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
        let (client_nonce, ephemeral, hello_sent_at, pq_dk_opt) = match old_state {
            HandshakeState::AwaitingAck {
                client_nonce,
                ephemeral,
                last_sent,
                pq,
                ..
            } => (client_nonce, ephemeral, last_sent, pq.map(|(_ek, dk)| dk)),
            other => {
                peer.handshake = other;
                return Ok(()); // HELLO_ACK in wrong state — ignore
            }
        };

        // PQ posture must match what we asked for; refuse both the
        // silent downgrade and the unsolicited upgrade.
        if pq_dk_opt.is_some() != server_pq {
            return Err(CryptoError::KeyExchangeFailed.into());
        }

        // Passive RTT sample for the retry-base and (later) routing.
        peer.update_neighbor_rtt(now.saturating_duration_since(hello_sent_at));

        let static_dh = self
            .identity
            .dh(&peer.peer_static_pub)
            .ok_or(CryptoError::KeyExchangeFailed)?;
        let ephemeral_dh = ephemeral
            .dh(&server_ephemeral_pub)
            .ok_or(CryptoError::KeyExchangeFailed)?;
        drop(ephemeral);

        let session_key_bytes = if let (Some(dk), Some(ct)) = (pq_dk_opt, pq_ct) {
            let mlkem_ss = dk.decapsulate(ct).ok_or(CryptoError::KeyExchangeFailed)?;
            let key = drift_core::pq::derive_hybrid_key(
                &static_dh,
                &ephemeral_dh,
                &mlkem_ss,
                &client_nonce,
                &server_nonce,
            );
            Zeroizing::new(key)
        } else {
            derive_session_key(&static_dh, &ephemeral_dh, &client_nonce, &server_nonce)
        };

        let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
        let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

        // AAD mirrors the server's: canonical header + eph + nonce
        // + (when hybrid) the ML-KEM ciphertext.
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let canon = canonical_aad(&hbuf);
        let mut aad = Vec::with_capacity(
            HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN + pq_ct.map(|c| c.len()).unwrap_or(0),
        );
        aad.extend_from_slice(&canon);
        aad.extend_from_slice(&server_ephemeral_pub);
        aad.extend_from_slice(&server_nonce);
        if let Some(ct) = pq_ct {
            aad.extend_from_slice(ct);
        }
        rx.open(1, PacketType::HelloAck as u8, &aad, tag)?;

        peer.reset_seq();
        peer.coalesce_state.clear();
        peer.coalesce_order.clear();
        peer.mark_session_start();
        let mut cid_key = [0u8; 32];
        cid_key.copy_from_slice(&*session_key_bytes);
        peer.handshake = HandshakeState::Established {
            tx,
            rx,
            key_bytes: session_key_bytes,
            prev: None,
        };
        peer.last_seen = now;
        self.events.push_back(Event::Connected { peer: peer_id });

        // Flush DATA parked during the handshake.
        let pending = std::mem::take(&mut peer.pending);
        for ps in pending {
            let t = build_data_packet(
                local_peer_id,
                peer,
                &ps.payload,
                ps.deadline_ms,
                ps.coalesce_group,
            )?;
            self.transmits.push_back(t);
        }
        self.install_cids(peer_id, &cid_key, true);
        Ok(())
    }

    /// Client-side CHALLENGE processing. Port of `handle_challenge`:
    /// stash the cookie, immediately re-emit the same HELLO with the
    /// cookie appended (same nonce, same ephemeral, same ek).
    fn on_challenge(&mut self, now: Instant, header: &Header, body: &[u8]) -> Result<()> {
        if body.len() < COOKIE_BLOB_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: COOKIE_BLOB_LEN,
            }
            .into());
        }
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let server_peer_id = header.src_id;
        let mut blob = [0u8; COOKIE_BLOB_LEN];
        blob.copy_from_slice(&body[..COOKIE_BLOB_LEN]);

        let local_peer_id = self.local_peer_id;
        let Some(peer) = self.peers.get_mut(&server_peer_id) else {
            return Ok(()); // CHALLENGE for unknown peer — ignore
        };
        let peer_addr = peer.addr;
        let peer_id = peer.id;
        if let HandshakeState::AwaitingAck {
            client_nonce,
            ephemeral,
            last_sent,
            cookie,
            pq,
            ..
        } = &mut peer.handshake
        {
            *cookie = Some(blob);
            *last_sent = now;
            let pq_ek = pq.as_ref().map(|(ek, _)| ek.as_slice());
            let wire = build_hello_wire(
                local_peer_id,
                peer_id,
                &self.identity,
                ephemeral.public_bytes(),
                *client_nonce,
                Some(&blob),
                pq_ek,
            );
            self.transmits.push_back(Transmit {
                dst: peer_addr,
                contents: wire,
            });
        }
        Ok(())
    }

    /// Receiver side of the rekey handshake. Port of
    /// `handle_rekey_request`: decrypt the salt with the CURRENT rx
    /// (the old key from the sender's perspective), derive + install
    /// the same new key with the old pair in the grace slot, and ack
    /// under the NEW tx key.
    fn on_rekey_request(&mut self, now: Instant, header: &Header, body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let local_peer_id = self.local_peer_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
            HandshakeState::Established {
                tx, rx, key_bytes, ..
            } => (tx.clone(), rx.clone(), key_bytes.clone()),
            _ => return Err(PeerError::SessionNotEstablished.into()),
        };

        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        let salt_bytes = old_rx.open(header.seq, PacketType::RekeyRequest as u8, &aad, body)?;
        if salt_bytes.len() != 32 {
            return Err(CodecError::PacketTooShort {
                got: salt_bytes.len(),
                need: 32,
            }
            .into());
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        // The request receiver takes the Responder nonce direction
        // for the new key namespace — mirror of `rekey()`.
        let new_key_bytes = rekey_derive(&old_key_bytes, &salt);
        let new_tx = SessionKey::new(&new_key_bytes, Direction::Responder);
        let new_rx = SessionKey::new(&new_key_bytes, Direction::Initiator);

        peer.reset_seq();
        peer.mark_session_start();
        let mut cid_key = [0u8; 32];
        cid_key.copy_from_slice(&*new_key_bytes);
        peer.handshake = HandshakeState::Established {
            tx: new_tx,
            rx: new_rx,
            key_bytes: new_key_bytes,
            prev: Some(PrevSession {
                tx: old_tx,
                rx: old_rx,
                installed_at: now,
            }),
        };

        // RekeyAck sealed with the NEW tx — proves to the initiator
        // that we hold the new key.
        let ack_seq = peer.next_seq_checked()?;
        let mut ack_header = peer.make_header(PacketType::RekeyAck, ack_seq, local_peer_id);
        ack_header.payload_len = AUTH_TAG_LEN as u16;
        let mut ack_hbuf = [0u8; HEADER_LEN];
        ack_header.encode(&mut ack_hbuf);
        let ack_aad = canonical_aad(&ack_hbuf);
        let (tx_ref, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
        let mut ack_wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
        ack_wire.extend_from_slice(&ack_hbuf);
        tx_ref.seal_into(
            ack_seq,
            PacketType::RekeyAck as u8,
            &ack_aad,
            b"",
            &mut ack_wire,
        )?;
        let dst = peer.addr;

        self.transmits.push_back(Transmit {
            dst,
            contents: ack_wire,
        });
        self.install_cids(peer_id, &cid_key, false);
        Ok(())
    }

    /// `RekeyAck` arrival: sealed with the NEW key, so a successful
    /// open proves the peer installed it. `prev` is deliberately NOT
    /// dropped here — old-key DATA may still be in flight; the
    /// grace-window timer expires it instead. Port of
    /// `handle_rekey_ack`.
    fn on_rekey_ack(&mut self, header: &Header, body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        if let HandshakeState::Established { rx, .. } = &mut peer.handshake {
            let _ = rx.open(header.seq, PacketType::RekeyAck as u8, &aad, body)?;
        }
        Ok(())
    }

    /// Authenticated `Close` arrival. Port of `handle_close` (minus
    /// the federation PeerGone emission — phase 4): verify the tag,
    /// then drop session state — removal for auto-registered peers,
    /// reset-to-Pending for explicit ones.
    fn on_close(&mut self, header: &Header, body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        // AEAD-authenticated: a Close can't be forged without the
        // session key, so acting on it immediately is safe.
        let _ = rx.open(header.seq, PacketType::Close as u8, &aad, body)?;

        if peer.auto_registered {
            self.peers.remove(&peer_id);
        } else {
            peer.handshake = HandshakeState::Pending;
            peer.pending.clear();
            peer.session_epoch = None;
            peer.probing = None;
        }
        self.drop_cids(&peer_id);
        // See close(): a peer that closed on us has likely dropped
        // our entry; a stored ticket would only park future redials.
        self.client_tickets.remove(&peer_id);
        self.events.push_back(Event::Closed { peer: peer_id });
        Ok(())
    }

    /// Remove every CID-map entry pointing at this peer (both
    /// directions). Used on close and eviction.
    fn drop_cids(&mut self, peer_id: &PeerId) {
        self.cid_map.retain(|_cid, pid| pid != peer_id);
        self.peer_out_cid.remove(peer_id);
    }

    /// Open a session toward a Pending initiator peer: 1-RTT
    /// `ResumeHello` when a valid ticket is on file (mirroring the
    /// transport's `try_resume` branch in `send_data`), full HELLO
    /// otherwise.
    fn start_session(&mut self, now: Instant, peer_id: &PeerId) {
        let can_resume = self
            .client_tickets
            .get(peer_id)
            .map(|t| t.expiry > SystemTime::now())
            .unwrap_or(false)
            && self
                .peers
                .get(peer_id)
                .map(|p| {
                    matches!(p.handshake, HandshakeState::Pending)
                        && p.direction == Direction::Initiator
                })
                .unwrap_or(false);
        if can_resume && self.send_resume_hello(now, peer_id).is_ok() {
            return;
        }
        self.start_hello(now, peer_id);
    }

    /// Build and queue a `ResumeHello` using the stored ticket.
    /// Port of the transport's `send_resume_hello`: stashes the
    /// ephemeral in `AwaitingAck` (cookie/PQ unused on this path)
    /// plus a `pending_resumption` marker so the matching
    /// `ResumeAck` knows which PSK finishes the derivation.
    fn send_resume_hello(&mut self, now: Instant, peer_id: &PeerId) -> Result<()> {
        let ticket = match self.client_tickets.get(peer_id) {
            Some(t) if t.expiry > SystemTime::now() => t.clone(),
            Some(_) => {
                self.client_tickets.remove(peer_id);
                return Err(PeerError::ResumptionTicketNotFound.into());
            }
            None => return Err(PeerError::ResumptionTicketNotFound.into()),
        };
        let local_peer_id = self.local_peer_id;

        let ephemeral = Identity::generate();
        let client_eph_pub = ephemeral.public_bytes();
        let mut client_nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut client_nonce);

        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PeerError::NotRegistered)?;
        peer.pending_resumption = Some(PendingResumption {
            ticket_id: ticket.ticket_id,
            psk: ticket.psk,
        });
        peer.handshake = HandshakeState::AwaitingAck {
            client_nonce,
            ephemeral,
            last_sent: now,
            attempts: 1,
            cookie: None,
            // Resumption doesn't run a fresh KEM — the resumed
            // session inherits the original session's key strength
            // via the PSK. Same as the transport.
            pq: None,
        };

        let seq = peer.next_seq_checked()?;
        let mut header = peer.make_header(PacketType::ResumeHello, seq, local_peer_id);
        header.payload_len = RESUME_HELLO_BODY_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_HELLO_BODY_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&ticket.ticket_id);
        wire.extend_from_slice(&client_eph_pub);
        wire.extend_from_slice(&client_nonce);
        let dst = peer.addr;
        self.transmits.push_back(Transmit {
            dst,
            contents: wire,
        });
        Ok(())
    }

    /// Server side: mint + queue a `ResumptionTicket` on a live
    /// session. Port of `issue_resumption_ticket`. The PSK derives
    /// from the current session key and never crosses the wire.
    fn issue_ticket(&mut self, peer_id: PeerId) -> Result<()> {
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        rand::thread_rng().fill_bytes(&mut ticket_id);
        let expiry = SystemTime::now() + TICKET_DEFAULT_TTL;
        let expiry_ms = expiry
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let local_peer_id = self.local_peer_id;

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let session_key_bytes = match &peer.handshake {
            HandshakeState::Established { key_bytes, .. } => key_bytes.clone(),
            _ => return Err(PeerError::SessionNotEstablished.into()),
        };
        let client_static_pub = peer.peer_static_pub;

        let seq = peer.next_seq_checked()?;
        let mut header = peer.make_header(PacketType::ResumptionTicket, seq, local_peer_id);
        header.payload_len = (TICKET_PLAINTEXT_LEN + AUTH_TAG_LEN) as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);

        let mut plaintext = [0u8; TICKET_PLAINTEXT_LEN];
        plaintext[..TICKET_ID_LEN].copy_from_slice(&ticket_id);
        plaintext[TICKET_ID_LEN..].copy_from_slice(&expiry_ms.to_be_bytes());

        let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
        let mut wire = Vec::with_capacity(HEADER_LEN + TICKET_PLAINTEXT_LEN + AUTH_TAG_LEN);
        wire.extend_from_slice(&hbuf);
        tx.seal_into(
            seq,
            PacketType::ResumptionTicket as u8,
            &aad,
            &plaintext,
            &mut wire,
        )?;
        let dst = peer.addr;

        let psk = derive_psk(&session_key_bytes, &ticket_id);
        self.resumption_store
            .insert(ticket_id, psk, expiry, client_static_pub);
        self.transmits.push_back(Transmit {
            dst,
            contents: wire,
        });
        Ok(())
    }

    /// Client side: store an incoming `ResumptionTicket`. Port of
    /// `handle_resumption_ticket` — decrypt failures are silent
    /// (a ticket racing a rekey window is not an attack), and the
    /// PSK is derived from the CURRENT session key even when the
    /// ticket decrypted under `prev` (transport behavior, kept).
    fn on_resumption_ticket(&mut self, header: &Header, body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let server_id = header.src_id;
        let Some(peer) = self.peers.get_mut(&server_id) else {
            return Ok(());
        };
        let session_key_bytes = match &peer.handshake {
            HandshakeState::Established { key_bytes, .. } => key_bytes.clone(),
            _ => return Ok(()),
        };
        let server_static_pub = peer.peer_static_pub;

        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        let pt = {
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            rx.open(header.seq, PacketType::ResumptionTicket as u8, &aad, body)
        };
        let pt = match pt {
            Ok(p) => Some(p),
            Err(_) => {
                if let HandshakeState::Established { prev: Some(p), .. } = &peer.handshake {
                    p.rx.open(header.seq, PacketType::ResumptionTicket as u8, &aad, body)
                        .ok()
                } else {
                    None
                }
            }
        };
        let Some(plaintext) = pt else {
            return Ok(());
        };
        if plaintext.len() != TICKET_PLAINTEXT_LEN {
            return Err(CodecError::PacketTooShort {
                got: plaintext.len(),
                need: TICKET_PLAINTEXT_LEN,
            }
            .into());
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&plaintext[..TICKET_ID_LEN]);
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&plaintext[TICKET_ID_LEN..]);
        let expiry = UNIX_EPOCH + Duration::from_millis(u64::from_be_bytes(exp_bytes));
        let psk = derive_psk(&session_key_bytes, &ticket_id);

        self.client_tickets.insert(
            server_id,
            ClientTicket {
                ticket_id,
                psk,
                expiry,
                server_id,
                server_static_pub,
            },
        );
        Ok(())
    }

    /// Server side: redeem a `ResumeHello`. Port of
    /// `handle_resume_hello`: single-use identity-bound ticket
    /// lookup, fresh ephemeral DH, `ResumeAck` (seq 1) sealed under
    /// the new key, peer installed directly as Established with the
    /// old keys (if any) in the grace slot, address migration to
    /// the datagram source (safe — the PSK authenticates), and a
    /// fresh ticket issued on the resumed session.
    fn on_resume_hello(
        &mut self,
        now: Instant,
        header: &Header,
        body: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        if body.len() < RESUME_HELLO_BODY_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: RESUME_HELLO_BODY_LEN,
            }
            .into());
        }
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let mut ticket_id = [0u8; TICKET_ID_LEN];
        ticket_id.copy_from_slice(&body[..TICKET_ID_LEN]);
        let mut client_eph_pub = [0u8; STATIC_KEY_LEN];
        client_eph_pub.copy_from_slice(&body[TICKET_ID_LEN..TICKET_ID_LEN + STATIC_KEY_LEN]);
        let mut client_nonce = [0u8; NONCE_LEN];
        client_nonce.copy_from_slice(&body[TICKET_ID_LEN + STATIC_KEY_LEN..RESUME_HELLO_BODY_LEN]);

        if client_eph_pub == [0u8; STATIC_KEY_LEN] {
            return Err(CryptoError::KeyExchangeFailed.into());
        }
        let client_peer_id = header.src_id;
        let local_peer_id = self.local_peer_id;

        // Resumption reuses a previously authenticated identity —
        // the peer must still be known (a server that forgot the
        // peer drops the attempt; the client falls back to a full
        // HELLO via its retry path).
        let client_static_pub = self
            .peers
            .get(&client_peer_id)
            .ok_or(PeerError::NotRegistered)?
            .peer_static_pub;

        let psk = self
            .resumption_store
            .take(&ticket_id, &client_static_pub)
            .ok_or(PeerError::ResumptionTicketNotFound)?;

        let server_ephemeral = Identity::generate();
        let server_eph_pub = server_ephemeral.public_bytes();
        let server_nonce = random_nonce();
        let ephemeral_dh = server_ephemeral
            .dh(&client_eph_pub)
            .ok_or(CryptoError::KeyExchangeFailed)?;
        drop(server_ephemeral);

        let new_session_key =
            derive_resumption_key(&psk, &ephemeral_dh, &client_nonce, &server_nonce);

        let peer = self
            .peers
            .get_mut(&client_peer_id)
            .ok_or(PeerError::NotRegistered)?;

        // Old keys (if any) ride the grace slot so in-flight
        // pre-resumption DATA still decrypts briefly.
        let prev_session = match &peer.handshake {
            HandshakeState::Established { tx, rx, .. } => Some(PrevSession {
                tx: tx.clone(),
                rx: rx.clone(),
                installed_at: now,
            }),
            _ => None,
        };

        let seq = 1u32;
        let mut ack_header = peer.make_header(PacketType::ResumeAck, seq, local_peer_id);
        ack_header.payload_len = RESUME_ACK_BODY_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        ack_header.encode(&mut hbuf);
        let canon = canonical_aad(&hbuf);
        let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
        aad.extend_from_slice(&canon);
        aad.extend_from_slice(&server_eph_pub);
        aad.extend_from_slice(&server_nonce);

        let server_tx = SessionKey::new(&new_session_key, Direction::Responder);
        let auth_tag = server_tx.seal(seq, PacketType::ResumeAck as u8, &aad, b"")?;
        let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_ACK_BODY_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&server_eph_pub);
        wire.extend_from_slice(&server_nonce);
        wire.extend_from_slice(&auth_tag);

        let server_rx = SessionKey::new(&new_session_key, Direction::Initiator);
        peer.reset_seq();
        // The ResumeAck used seq 1, so the next outgoing is 2.
        peer.next_tx_seq = 2;
        peer.coalesce_state.clear();
        peer.coalesce_order.clear();
        peer.mark_session_start();
        peer.handshake = HandshakeState::Established {
            tx: server_tx,
            rx: server_rx,
            key_bytes: new_session_key,
            prev: prev_session,
        };
        peer.addr = src;
        peer.last_seen = now;

        self.transmits.push_back(Transmit {
            dst: src,
            contents: wire,
        });
        self.events.push_back(Event::Connected {
            peer: client_peer_id,
        });
        // Fresh ticket for next time — best-effort, same as the
        // transport.
        let _ = self.issue_ticket(client_peer_id);
        Ok(())
    }

    /// Client side: finish a 1-RTT resumption. Port of
    /// `handle_resume_ack`: requires `pending_resumption` + an
    /// in-flight `AwaitingAck`, derives the same key from
    /// PSK + ephemeral DH + nonces, verifies the ack's tag, and
    /// flushes parked DATA.
    fn on_resume_ack(&mut self, now: Instant, header: &Header, body: &[u8]) -> Result<()> {
        if body.len() < RESUME_ACK_BODY_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: RESUME_ACK_BODY_LEN,
            }
            .into());
        }
        let mut server_eph_pub = [0u8; STATIC_KEY_LEN];
        server_eph_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag_start = STATIC_KEY_LEN + NONCE_LEN;
        let tag = &body[tag_start..tag_start + AUTH_TAG_LEN];

        let server_id = header.src_id;
        let local_peer_id = self.local_peer_id;
        let peer = self
            .peers
            .get_mut(&server_id)
            .ok_or(PeerError::NotRegistered)?;

        let Some(resumption) = peer.pending_resumption.take() else {
            return Ok(()); // ResumeAck without a pending resumption
        };
        let old_state = std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
        let (client_nonce, ephemeral) = match old_state {
            HandshakeState::AwaitingAck {
                client_nonce,
                ephemeral,
                ..
            } => (client_nonce, ephemeral),
            other => {
                peer.handshake = other;
                return Ok(()); // wrong state — ignore
            }
        };

        let ephemeral_dh = ephemeral
            .dh(&server_eph_pub)
            .ok_or(CryptoError::KeyExchangeFailed)?;
        drop(ephemeral);
        let new_session_key =
            derive_resumption_key(&resumption.psk, &ephemeral_dh, &client_nonce, &server_nonce);

        let tx = SessionKey::new(&new_session_key, Direction::Initiator);
        let rx = SessionKey::new(&new_session_key, Direction::Responder);

        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let canon = canonical_aad(&hbuf);
        let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
        aad.extend_from_slice(&canon);
        aad.extend_from_slice(&server_eph_pub);
        aad.extend_from_slice(&server_nonce);
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
        peer.last_seen = now;
        self.events.push_back(Event::Connected { peer: server_id });

        // Flush DATA parked while the resumption was in flight.
        let pending = std::mem::take(&mut peer.pending);
        for ps in pending {
            let t = build_data_packet(
                local_peer_id,
                peer,
                &ps.payload,
                ps.deadline_ms,
                ps.coalesce_group,
            )?;
            self.transmits.push_back(t);
        }
        Ok(())
    }

    /// DATA processing. Port of `handle_data`'s long-header path:
    /// AEAD open → replay → deadline → coalesce → (AwaitingData →
    /// Established transition) → deliver.
    fn on_data(&mut self, now: Instant, header: &Header, body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            // Mesh forwarding is phase 4; the engine drops
            // other-destination packets.
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;

        let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);
        // Try the current rx key; on failure fall back to the
        // pre-rekey keys if the grace window is still open (old-key
        // DATA already in flight at the key switch).
        let first_try = rx.open(header.seq, PacketType::Data as u8, &aad, body);
        let payload = match first_try {
            Ok(pt) => pt,
            Err(err) => {
                let mut recovered = None;
                if let HandshakeState::Established { prev, .. } = &mut peer.handshake {
                    if let Some(p) = prev {
                        if now.saturating_duration_since(p.installed_at) <= REKEY_GRACE {
                            if let Ok(pt) =
                                p.rx.open(header.seq, PacketType::Data as u8, &aad, body)
                            {
                                recovered = Some(pt);
                            }
                        } else {
                            *prev = None;
                        }
                    }
                }
                match recovered {
                    Some(pt) => pt,
                    None => return Err(err.into()),
                }
            }
        };

        peer.check_and_update_replay(header.seq)?;

        if !peer.deadline_ok(header, now) {
            return Ok(()); // stale — drop silently, like the transport
        }
        if !peer.coalesce_accept(header) {
            return Ok(()); // superseded — drop silently
        }

        peer.last_seen = now;
        // First authenticated DATA completes the server-side
        // handshake: AwaitingData → Established.
        self.complete_server_handshake(peer_id)?;
        self.events.push_back(Event::Data {
            peer: peer_id,
            seq: header.seq,
            payload,
        });
        Ok(())
    }
}

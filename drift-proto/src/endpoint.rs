//! The sans-IO protocol engine.
//!
//! Every function in this file is a port of the corresponding logic
//! in `drift/src/transport/mod.rs` / `cookies.rs`, with the socket
//! sends replaced by a transmit queue and the tokio timers replaced
//! by an injected `now: Instant`. The wire bytes and the check
//! ordering are deliberately identical — see the "byte-compat
//! invariants" section of `docs/SANSIO_DESIGN.md` before changing
//! anything here.

use drift_core::crypto::{cookie_mac, Direction, PeerId, SessionKey, COOKIE_MAC_LEN};
use drift_core::error::{CodecError, CryptoError, DriftError, PeerError, SessionError};
use drift_core::header::{
    canonical_aad, Header, PacketType, AUTH_TAG_LEN, FLAG_PQ_HYBRID, HEADER_LEN,
};
use drift_core::identity::{derive_session_key, random_nonce, NONCE_LEN, STATIC_KEY_LEN};
use drift_core::session::{HandshakeState, Peer, PendingSend};
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
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn public_bytes(&self) -> [u8; STATIC_KEY_LEN] {
        self.identity.public_bytes()
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

    /// Register a peer and queue the opening HELLO.
    pub fn connect(
        &mut self,
        now: Instant,
        static_pub: [u8; STATIC_KEY_LEN],
        addr: SocketAddr,
    ) -> PeerId {
        let id = self.add_peer(static_pub, addr, Direction::Initiator);
        self.start_hello(now, &id);
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

        // First send to a Pending initiator kicks off the handshake.
        if matches!(peer.handshake, HandshakeState::Pending)
            && peer.direction == Direction::Initiator
        {
            self.start_hello(now, peer_id);
        }
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
            // Mesh / rekey / resumption / federation packet types
            // arrive in later phases; drop them for now.
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
                    }
                    continue;
                }
                *attempts += 1;
                *last_sent = now;

                let pq_ek = pq.as_ref().map(|(ek, _)| ek.as_slice());
                let wire = build_hello_wire(
                    local_peer_id,
                    peer_id,
                    identity,
                    ephemeral.public_bytes(),
                    *client_nonce,
                    cookie.as_ref(),
                    pq_ek,
                );
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
        Ok(())
    }

    /// Short-header DATA receive. Port of the transport's
    /// `process_short_header` (minus the rekey grace window — phase
    /// 2 — and path migration — phase 4).
    fn on_short_data(&mut self, now: Instant, datagram: &[u8]) -> Result<()> {
        let (cid, _seq, _body) = drift_core::short_header::decode_short(datagram)?;
        let peer_id = *self.cid_map.get(&cid).ok_or(PeerError::NotRegistered)?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(PeerError::NotRegistered)?;
        let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
        let (_cid, seq, payload) = open_short(datagram, rx)?;
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
        let payload = rx.open(header.seq, PacketType::Data as u8, &aad, body)?;

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

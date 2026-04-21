//! Wire-agnostic DRIFT session state.
//!
//! Owns the protocol state machine (peer sessions, handshake
//! flow, DATA encrypt/decrypt). Has no knowledge of *how* bytes
//! reach the peer — that's the job of a thin wire adapter (WS,
//! WebRTC, WebTransport) which plugs its send function in via
//! `Session::new`.
//!
//! Wire code calls `session.handle_incoming_bytes(buf)` when
//! bytes arrive. Session calls the supplied `send_fn` closure
//! when it wants to send bytes. Neither side knows what the
//! other is made of.

use crate::peer_session::{PeerSession, PendingHandshake};
use drift_core::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use drift_core::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use drift_core::identity::{derive_session_key, Identity, NONCE_LEN, STATIC_KEY_LEN};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN;
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;
const MESH_HOP_TTL: u8 = 8;

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("getrandom");
    nonce
}

/// Closure type used to hand bytes to the underlying wire.
pub(crate) type Sender = dyn Fn(&[u8]) -> Result<(), JsValue>;

/// All protocol state. Wire-agnostic.
pub(crate) struct SessionState {
    local_secret: [u8; 32],
    local_peer_id: PeerId,
    server_peer_id: PeerId,
    peers: HashMap<PeerId, PeerSession>,
    on_message: Option<js_sys::Function>,
}

/// Wire-agnostic DRIFT session. Clone-able via `Rc`.
#[derive(Clone)]
pub(crate) struct Session {
    state: Rc<RefCell<SessionState>>,
    send_fn: Rc<Sender>,
}

impl Session {
    /// Construct a Session with a freshly-built wire. The caller
    /// is responsible for arranging that `send_fn` actually ships
    /// bytes over the wire, and for calling
    /// `handle_incoming_bytes` on every inbound frame.
    pub(crate) fn new(
        local_secret: [u8; 32],
        server_pub: [u8; STATIC_KEY_LEN],
        send_fn: Rc<Sender>,
    ) -> Self {
        let local_id = Identity::from_secret_bytes(local_secret);
        let local_public = local_id.public_bytes();
        let local_peer_id = derive_peer_id(&local_public);
        let server_peer_id = derive_peer_id(&server_pub);

        let mut peers = HashMap::new();
        peers.insert(server_peer_id, PeerSession::new(server_pub));

        Self {
            state: Rc::new(RefCell::new(SessionState {
                local_secret,
                local_peer_id,
                server_peer_id,
                peers,
                on_message: None,
            })),
            send_fn,
        }
    }

    pub(crate) fn server_peer_id(&self) -> PeerId {
        self.state.borrow().server_peer_id
    }

    pub(crate) fn set_on_message(&self, cb: js_sys::Function) {
        self.state.borrow_mut().on_message = Some(cb);
    }

    /// Kick off a DRIFT handshake with the given peer. Returns a
    /// JS Promise that resolves when the matching HELLO_ACK
    /// arrives.
    pub(crate) fn begin_handshake(&self, peer_id: PeerId) -> Result<js_sys::Promise, JsValue> {
        let state = self.state.clone();
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let mut s = state.borrow_mut();
            if let Some(peer) = s.peers.get_mut(&peer_id) {
                peer.handshake_resolve = Some(resolve);
                peer.handshake_reject = Some(reject);
            }
        });
        self.send_hello(peer_id)?;
        Ok(promise)
    }

    /// Register a mesh peer (known only by pubkey), then begin a
    /// handshake with them. The handshake bytes ride the
    /// existing wire — the server routes them to wherever the
    /// target peer lives.
    pub(crate) async fn add_peer(
        &self,
        peer_pub: [u8; STATIC_KEY_LEN],
    ) -> Result<(), JsValue> {
        let peer_id = derive_peer_id(&peer_pub);
        {
            let mut s = self.state.borrow_mut();
            s.peers
                .entry(peer_id)
                .or_insert_with(|| PeerSession::new(peer_pub));
        }
        let p = self.begin_handshake(peer_id)?;
        wasm_bindgen_futures::JsFuture::from(p).await?;
        Ok(())
    }

    /// Send an AEAD-encrypted DATA packet to `peer_id`.
    pub(crate) async fn send_data_to(
        &self,
        peer_id: PeerId,
        payload: &[u8],
    ) -> Result<(), JsValue> {
        let wire = {
            let mut s = self.state.borrow_mut();
            let local_peer_id = s.local_peer_id;
            let server_peer_id = s.server_peer_id;
            let peer = s
                .peers
                .get_mut(&peer_id)
                .ok_or_else(|| JsValue::from_str("unknown peer"))?;
            if !peer.is_established() {
                return Err(JsValue::from_str("peer session not established"));
            }

            let seq = peer.next_seq;
            peer.next_seq += 1;

            let hop_ttl = if peer_id == server_peer_id {
                1
            } else {
                MESH_HOP_TTL
            };
            let mut header = Header::new(PacketType::Data, seq, local_peer_id, peer_id);
            header.hop_ttl = hop_ttl;
            if hop_ttl > 1 {
                header.flags |= drift_core::header::FLAG_ROUTED;
            }
            header.payload_len = payload.len() as u16;
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let aad = canonical_aad(&hbuf);

            let mut wire = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
            wire.extend_from_slice(&hbuf);
            peer.tx
                .as_ref()
                .unwrap()
                .seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)
                .map_err(|e| JsValue::from_str(&format!("seal: {}", e)))?;
            wire
        };

        (self.send_fn)(&wire)
    }

    /// Dispatch one incoming binary frame. Called by wire code
    /// from its receive callback. No-op on malformed or
    /// unexpected packet types — this minimal client doesn't
    /// participate in beacons, pings, etc.
    pub(crate) fn handle_incoming_bytes(&self, data: &[u8]) {
        if data.len() < HEADER_LEN {
            return;
        }
        let header = match Header::decode(&data[..HEADER_LEN]) {
            Ok(h) => h,
            Err(_) => return,
        };
        match header.packet_type {
            PacketType::HelloAck => {
                if let Err(e) = self.handle_hello_ack(&header, data) {
                    web_sys::console::warn_1(&format!("DRIFT hello_ack: {:?}", e).into());
                }
            }
            PacketType::Data => {
                self.handle_data(&header, data);
            }
            _ => {}
        }
    }

    fn send_hello(&self, peer_id: PeerId) -> Result<(), JsValue> {
        let local_secret;
        let local_peer_id;
        let server_peer_id;
        {
            let s = self.state.borrow();
            local_secret = s.local_secret;
            local_peer_id = s.local_peer_id;
            server_peer_id = s.server_peer_id;
        }

        let local_id = Identity::from_secret_bytes(local_secret);
        let local_public = local_id.public_bytes();
        let client_nonce = random_nonce();
        let ephemeral = Identity::generate();
        let ephemeral_pub = ephemeral.public_bytes();

        let hop_ttl = if peer_id == server_peer_id {
            1
        } else {
            MESH_HOP_TTL
        };
        let mut header = Header::new(PacketType::Hello, 0, local_peer_id, peer_id);
        header.hop_ttl = hop_ttl;
        if hop_ttl > 1 {
            header.flags |= drift_core::header::FLAG_ROUTED;
        }
        header.payload_len = HELLO_PAYLOAD_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + HELLO_PAYLOAD_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&local_public);
        wire.extend_from_slice(&ephemeral_pub);
        wire.extend_from_slice(&client_nonce);

        {
            let mut s = self.state.borrow_mut();
            if let Some(peer) = s.peers.get_mut(&peer_id) {
                peer.pending_hs = Some(PendingHandshake {
                    client_nonce,
                    ephemeral,
                });
            } else {
                return Err(JsValue::from_str("unknown peer for HELLO"));
            }
        }

        (self.send_fn)(&wire)
    }

    fn handle_hello_ack(&self, header: &Header, data: &[u8]) -> Result<(), JsValue> {
        if data.len() < HEADER_LEN + HELLO_ACK_PAYLOAD_LEN {
            return Err(JsValue::from_str("HELLO_ACK too short"));
        }
        let body = &data[HEADER_LEN..];
        let mut server_eph_pub = [0u8; STATIC_KEY_LEN];
        server_eph_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag = &body[STATIC_KEY_LEN + NONCE_LEN..STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN];
        let peer_id = header.src_id;

        let (resolve, _reject) = {
            let mut s = self.state.borrow_mut();
            let local_secret = s.local_secret;
            let peer = s
                .peers
                .get_mut(&peer_id)
                .ok_or_else(|| JsValue::from_str("HELLO_ACK for unknown peer"))?;
            let hs = peer
                .pending_hs
                .take()
                .ok_or_else(|| JsValue::from_str("HELLO_ACK with no pending handshake"))?;

            let local_id = Identity::from_secret_bytes(local_secret);
            let static_dh = local_id
                .dh(&peer.peer_pub)
                .ok_or_else(|| JsValue::from_str("static DH failed"))?;
            let ephemeral_dh = hs
                .ephemeral
                .dh(&server_eph_pub)
                .ok_or_else(|| JsValue::from_str("ephemeral DH failed"))?;

            let session_key_bytes =
                derive_session_key(&static_dh, &ephemeral_dh, &hs.client_nonce, &server_nonce);
            let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
            let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let canon = canonical_aad(&hbuf);
            let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
            aad.extend_from_slice(&canon);
            aad.extend_from_slice(&server_eph_pub);
            aad.extend_from_slice(&server_nonce);
            rx.open(1, PacketType::HelloAck as u8, &aad, tag)
                .map_err(|e| JsValue::from_str(&format!("HELLO_ACK auth failed: {}", e)))?;

            peer.tx = Some(tx);
            peer.rx = Some(rx);
            peer.next_seq = 2;
            (peer.handshake_resolve.take(), peer.handshake_reject.take())
        };

        web_sys::console::log_1(
            &format!("DRIFT handshake complete (peer={})", hex8(&peer_id)).into(),
        );
        if let Some(resolve) = resolve {
            let _ = resolve.call0(&JsValue::NULL);
        }
        Ok(())
    }

    fn handle_data(&self, header: &Header, data: &[u8]) {
        if data.len() < HEADER_LEN + AUTH_TAG_LEN {
            return;
        }
        let peer_id = header.src_id;
        let s = self.state.borrow();
        let peer = match s.peers.get(&peer_id) {
            Some(p) => p,
            None => return,
        };
        let rx = match &peer.rx {
            Some(rx) => rx,
            None => return,
        };
        let body = &data[HEADER_LEN..];
        let hbuf: &[u8; HEADER_LEN] = data[..HEADER_LEN].try_into().unwrap();
        let aad = canonical_aad(hbuf);
        match rx.open(header.seq, PacketType::Data as u8, &aad, body) {
            Ok(plaintext) => {
                if let Some(ref cb) = s.on_message {
                    let src_hex = JsValue::from_str(&hex8(&peer_id));
                    let arr = js_sys::Uint8Array::from(plaintext.as_slice());
                    let _ = cb.call2(&JsValue::NULL, &src_hex, &arr);
                }
            }
            Err(_) => {
                web_sys::console::warn_1(&"DRIFT: DATA decrypt failed".into());
            }
        }
    }
}

pub(crate) fn hex8(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

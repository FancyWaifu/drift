//! Browser WebSocket transport for DRIFT, with mesh-peer support.
//!
//! The WASM client opens a single WebSocket to a DRIFT bridge.
//! All outbound traffic goes over that WebSocket. The bridge
//! accepts on multiple mediums (UDP, TCP, WS, WebRTC) and mesh-
//! forwards our packets to peers on any of those mediums, keyed
//! by peer_id and end-to-end encrypted.
//!
//! This module owns the per-peer crypto state. The direct
//! server (the bridge) is one `PeerSession`; every mesh-routed
//! peer registered via `add_peer(pub)` is another. Incoming
//! packets dispatch on their `src_id` field to the matching
//! session so decryption uses the right key.
//!
//! Wire format on the WebSocket is the real DRIFT wire format —
//! same `Header` struct, same `canonical_aad`, same AEAD. The
//! bridge treats this WS client indistinguishably from any
//! other DRIFT peer.

use crate::peer_session::{PeerSession, PendingHandshake};
use drift_core::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use drift_core::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use drift_core::identity::{derive_session_key, Identity, NONCE_LEN, STATIC_KEY_LEN};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

/// HELLO payload: client_static_pub(32) + client_eph_pub(32) + client_nonce(16) = 80
const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN;
/// HELLO_ACK payload: server_eph_pub(32) + server_nonce(16) + auth_tag(16) = 64
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;
/// Default hop TTL for mesh-routed HELLOs. Native side uses 8
/// too; see drift-core::session::DEFAULT_MESH_TTL.
const MESH_HOP_TTL: u8 = 8;

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("getrandom");
    nonce
}

/// Internal state shared between the WebSocket callback and the
/// public-facing methods.
struct State {
    ws: WebSocket,
    local_secret: [u8; 32],
    local_peer_id: PeerId,
    /// peer_id of our direct WS neighbor — the bridge. Kept
    /// separate so we can tell "DATA addressed to server" apart
    /// from "DATA addressed to a mesh peer."
    server_peer_id: PeerId,
    /// All peers — server included. Keyed by peer_id so an
    /// incoming packet's src_id can look up its session in O(1).
    peers: HashMap<PeerId, PeerSession>,
    /// Callback for incoming DATA, invoked as `cb(srcPeerIdHex, data)`.
    on_message: Option<js_sys::Function>,
}

pub struct WsTransport {
    state: Rc<RefCell<State>>,
}

impl WsTransport {
    /// Connect to a DRIFT server over WebSocket, handshake with
    /// it, and return a ready transport. After this, additional
    /// peers reachable through the server (mesh) can be registered
    /// with `add_peer`.
    pub async fn connect(
        url: &str,
        secret: [u8; 32],
        _public: [u8; 32],
        server_pub: [u8; STATIC_KEY_LEN],
    ) -> Result<Self, JsValue> {
        let ws = WebSocket::new(url)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let local_id = Identity::from_secret_bytes(secret);
        let local_public = local_id.public_bytes();
        let local_peer_id = derive_peer_id(&local_public);
        let server_peer_id = derive_peer_id(&server_pub);

        let mut peers = HashMap::new();
        peers.insert(server_peer_id, PeerSession::new(server_pub));

        let state = Rc::new(RefCell::new(State {
            ws: ws.clone(),
            local_secret: secret,
            local_peer_id,
            server_peer_id,
            peers,
            on_message: None,
        }));

        // Wait for WS open.
        let open_promise = js_sys::Promise::new(&mut |resolve, _reject| {
            let onopen = Closure::once(move || {
                resolve.call0(&JsValue::NULL).unwrap();
            });
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();
        });
        wasm_bindgen_futures::JsFuture::from(open_promise).await?;

        // Install the single unified onmessage handler. It
        // dispatches HELLO_ACK + DATA for any peer.
        let state_recv = state.clone();
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();
            let buf = js_sys::Uint8Array::new(&data);
            let bytes = buf.to_vec();
            Self::handle_incoming(&state_recv, &bytes);
        }) as Box<dyn FnMut(MessageEvent)>);
        state
            .borrow()
            .ws
            .set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // Kick off the handshake with the server. The Promise we
        // return resolves when the matching HELLO_ACK lands in
        // `handle_incoming` and marks the server session
        // Established.
        let handshake_promise = Self::handshake_peer(&state, server_peer_id)?;
        wasm_bindgen_futures::JsFuture::from(handshake_promise).await?;

        Ok(WsTransport { state })
    }

    /// Register and handshake with a mesh peer, known only by
    /// their pubkey. Under the hood this sends a HELLO addressed
    /// to that peer with `hop_ttl = MESH_HOP_TTL`; the bridge
    /// forwards it to wherever that peer lives (UDP / TCP / WS /
    /// WebRTC), the peer handshakes back, and the HELLO_ACK
    /// rides the same mesh in reverse.
    pub async fn add_peer(
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
        let handshake_promise = Self::handshake_peer(&self.state, peer_id)?;
        wasm_bindgen_futures::JsFuture::from(handshake_promise).await?;
        Ok(())
    }

    /// Build + send a HELLO to the given peer and return a JS
    /// Promise that resolves when the matching HELLO_ACK
    /// arrives. Works for both the direct server (hop_ttl=1) and
    /// mesh peers (hop_ttl=MESH_HOP_TTL).
    fn handshake_peer(
        state: &Rc<RefCell<State>>,
        peer_id: PeerId,
    ) -> Result<js_sys::Promise, JsValue> {
        // Store the Promise resolvers in the PeerSession so
        // handle_incoming can fire them when HELLO_ACK lands.
        let state_clone = state.clone();
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let mut s = state_clone.borrow_mut();
            if let Some(peer) = s.peers.get_mut(&peer_id) {
                peer.handshake_resolve = Some(resolve.clone());
                peer.handshake_reject = Some(reject.clone());
            }
        });

        // Send the HELLO outside the borrow so send_with_u8_array
        // doesn't hold the state lock.
        Self::send_hello(state, peer_id)?;
        Ok(promise)
    }

    /// Build and send a HELLO packet to `peer_id`. Uses mesh
    /// hop_ttl if the target isn't our direct server.
    fn send_hello(state: &Rc<RefCell<State>>, peer_id: PeerId) -> Result<(), JsValue> {
        let (wire, local_secret, local_peer_id, server_peer_id) = {
            let s = state.borrow();
            (
                Vec::<u8>::new(), // placeholder, filled below
                s.local_secret,
                s.local_peer_id,
                s.server_peer_id,
            )
        };
        let _ = wire; // silence unused

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
            // FLAG_ROUTED; native side checks this to know the
            // HELLO was sent with mesh intent.
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

        // Stash the handshake material BEFORE sending so a
        // super-fast HELLO_ACK can't race past us.
        {
            let mut s = state.borrow_mut();
            if let Some(peer) = s.peers.get_mut(&peer_id) {
                peer.pending_hs = Some(PendingHandshake {
                    client_nonce,
                    ephemeral,
                });
            } else {
                return Err(JsValue::from_str("unknown peer for HELLO"));
            }
        }

        state
            .borrow()
            .ws
            .send_with_u8_array(&wire)
            .map_err(|e| JsValue::from_str(&format!("ws send HELLO: {:?}", e)))?;

        Ok(())
    }

    /// Dispatch an incoming binary WS message to the right
    /// per-peer handler based on packet type and src_id.
    fn handle_incoming(state: &Rc<RefCell<State>>, data: &[u8]) {
        if data.len() < HEADER_LEN {
            return;
        }
        let header = match Header::decode(&data[..HEADER_LEN]) {
            Ok(h) => h,
            Err(_) => return,
        };

        match header.packet_type {
            PacketType::HelloAck => {
                if let Err(e) = Self::handle_hello_ack(state, &header, data) {
                    web_sys::console::warn_1(
                        &format!("DRIFT hello_ack: {:?}", e).into(),
                    );
                }
            }
            PacketType::Data => {
                Self::handle_data(state, &header, data);
            }
            _ => {
                // Ignore beacons, pings, etc — this minimal
                // client doesn't participate in those flows.
            }
        }
    }

    /// Complete a handshake: verify the AEAD tag, derive session
    /// keys, stash them on the matching PeerSession, resolve the
    /// Promise returned by `handshake_peer`.
    fn handle_hello_ack(
        state: &Rc<RefCell<State>>,
        header: &Header,
        data: &[u8],
    ) -> Result<(), JsValue> {
        if data.len() < HEADER_LEN + HELLO_ACK_PAYLOAD_LEN {
            return Err(JsValue::from_str("HELLO_ACK too short"));
        }
        let body = &data[HEADER_LEN..];
        let mut server_eph_pub = [0u8; STATIC_KEY_LEN];
        server_eph_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag = &body[STATIC_KEY_LEN + NONCE_LEN..STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN];

        // HELLO_ACK's `src_id` is the peer that accepted our
        // HELLO; that's who we're completing a session with.
        let peer_id = header.src_id;

        let (resolve, reject) = {
            let mut s = state.borrow_mut();
            let local_secret = s.local_secret;
            let peer = s
                .peers
                .get_mut(&peer_id)
                .ok_or_else(|| JsValue::from_str("HELLO_ACK for unknown peer"))?;
            let hs = peer
                .pending_hs
                .take()
                .ok_or_else(|| JsValue::from_str("HELLO_ACK with no pending handshake"))?;

            // X25519 DH: static + ephemeral.
            let local_id = Identity::from_secret_bytes(local_secret);
            let static_dh = local_id
                .dh(&peer.peer_pub)
                .ok_or_else(|| JsValue::from_str("static DH failed (low-order)"))?;
            let ephemeral_dh = hs
                .ephemeral
                .dh(&server_eph_pub)
                .ok_or_else(|| JsValue::from_str("ephemeral DH failed (low-order)"))?;

            let session_key_bytes = derive_session_key(
                &static_dh,
                &ephemeral_dh,
                &hs.client_nonce,
                &server_nonce,
            );
            let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
            let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

            // Verify HELLO_ACK's AEAD tag.
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
        let _ = reject; // unused in success path
        Ok(())
    }

    /// Decrypt a DATA packet against the matching session and
    /// hand the plaintext up to the JS on_message callback.
    fn handle_data(state: &Rc<RefCell<State>>, header: &Header, data: &[u8]) {
        if data.len() < HEADER_LEN + AUTH_TAG_LEN {
            return;
        }
        let peer_id = header.src_id;

        let s = state.borrow();
        let peer = match s.peers.get(&peer_id) {
            Some(p) => p,
            None => {
                web_sys::console::warn_1(
                    &format!("DRIFT: DATA from unknown peer {}", hex8(&peer_id)).into(),
                );
                return;
            }
        };
        let rx = match &peer.rx {
            Some(rx) => rx,
            None => return, // not handshaked yet — drop
        };

        let body = &data[HEADER_LEN..];
        let hbuf: &[u8; HEADER_LEN] = data[..HEADER_LEN].try_into().unwrap();
        let aad = canonical_aad(hbuf);

        match rx.open(header.seq, PacketType::Data as u8, &aad, body) {
            Ok(plaintext) => {
                if let Some(ref callback) = s.on_message {
                    let src_hex = JsValue::from_str(&hex8(&peer_id));
                    let arr = js_sys::Uint8Array::from(plaintext.as_slice());
                    let _ = callback.call2(&JsValue::NULL, &src_hex, &arr);
                }
            }
            Err(_) => {
                web_sys::console::warn_1(&"DRIFT: DATA decrypt failed".into());
            }
        }
    }

    /// Encrypt and send a DATA packet to `peer_id`. Uses mesh
    /// hop_ttl if the peer isn't our direct server.
    pub async fn send_data_to(&self, peer_id: PeerId, payload: &[u8]) -> Result<(), JsValue> {
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

        self.state
            .borrow()
            .ws
            .send_with_u8_array(&wire)
            .map_err(|e| JsValue::from_str(&format!("ws send: {:?}", e)))
    }

    pub fn set_on_message(&self, callback: js_sys::Function) {
        self.state.borrow_mut().on_message = Some(callback);
    }

    pub fn close(&self) {
        let _ = self.state.borrow().ws.close();
    }

    pub fn server_peer_id(&self) -> PeerId {
        self.state.borrow().server_peer_id
    }
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

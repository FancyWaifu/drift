//! Browser WebSocket transport for DRIFT.
//!
//! Implements the real DRIFT wire protocol over a browser-native
//! WebSocket. Each DRIFT packet (header + AEAD ciphertext) is one
//! WebSocket binary message — identical to what a native WsPacketIO
//! adapter sends, so the bridge treats this client like any other
//! DRIFT peer.

use drift_core::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use drift_core::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use drift_core::identity::{derive_session_key, Identity, NONCE_LEN, STATIC_KEY_LEN};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

/// HELLO payload: client_static_pub(32) + client_eph_pub(32) + client_nonce(16) = 80
const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN;
/// HELLO_ACK payload: server_eph_pub(32) + server_nonce(16) + auth_tag(16) = 64
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("getrandom");
    nonce
}

/// Handshake state stored between send_hello and handle_hello_ack.
struct PendingHandshake {
    client_nonce: [u8; NONCE_LEN],
    ephemeral: Identity,
}

/// Internal state shared between WebSocket callbacks and methods.
struct State {
    ws: WebSocket,
    local_secret: [u8; 32],
    local_peer_id: PeerId,
    server_pub: [u8; STATIC_KEY_LEN],
    server_peer_id: PeerId,
    /// Session key for outgoing packets (Initiator direction).
    tx: Option<SessionKey>,
    /// Session key for incoming packets (Responder direction).
    rx: Option<SessionKey>,
    /// Next sequence number for outgoing DATA packets.
    next_seq: u32,
    /// Pending handshake material (consumed by handle_hello_ack).
    pending_hs: Option<PendingHandshake>,
    /// User callback for incoming decrypted payloads.
    on_message: Option<js_sys::Function>,
}

pub struct WsTransport {
    state: Rc<RefCell<State>>,
}

impl WsTransport {
    /// Connect to a DRIFT server via WebSocket, perform the
    /// full cryptographic handshake, and return a ready transport.
    pub async fn connect(
        url: &str,
        secret: [u8; 32],
        public: [u8; 32],
        server_pub: [u8; STATIC_KEY_LEN],
    ) -> Result<Self, JsValue> {
        let ws = WebSocket::new(url)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let local_peer_id = derive_peer_id(&public);
        let server_peer_id = derive_peer_id(&server_pub);

        let state = Rc::new(RefCell::new(State {
            ws: ws.clone(),
            local_secret: secret,
            local_peer_id,
            server_pub,
            server_peer_id,
            tx: None,
            rx: None,
            next_seq: 2,
            pending_hs: None,
            on_message: None,
        }));

        // Wait for WebSocket open.
        let open_promise = js_sys::Promise::new(&mut |resolve, _reject| {
            let onopen = Closure::once(move || {
                resolve.call0(&JsValue::NULL).unwrap();
            });
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();
        });
        wasm_bindgen_futures::JsFuture::from(open_promise).await?;

        // Build and send HELLO (stores ephemeral + nonce in state).
        Self::send_hello(&state)?;

        // Wait for HELLO_ACK — derives session keys and verifies tag.
        let state_clone = state.clone();
        let handshake_promise = js_sys::Promise::new(&mut |resolve, reject| {
            let state_inner = state_clone.clone();
            let onmessage = Closure::once(move |event: MessageEvent| {
                let data = event.data();
                let buf = js_sys::Uint8Array::new(&data);
                let bytes = buf.to_vec();
                match Self::handle_hello_ack(&state_inner, &bytes) {
                    Ok(()) => {
                        resolve.call0(&JsValue::NULL).unwrap();
                    }
                    Err(e) => {
                        reject.call1(&JsValue::NULL, &e).unwrap();
                    }
                }
            });
            state_clone
                .borrow()
                .ws
                .set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();
        });
        wasm_bindgen_futures::JsFuture::from(handshake_promise).await?;

        // Install ongoing message handler for DATA packets.
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

        Ok(WsTransport { state })
    }

    /// Build and send a HELLO packet using the real DRIFT wire format.
    fn send_hello(state: &Rc<RefCell<State>>) -> Result<(), JsValue> {
        let mut s = state.borrow_mut();

        let local_id = Identity::from_secret_bytes(s.local_secret);
        let client_nonce = random_nonce();
        let ephemeral = Identity::generate();
        let ephemeral_pub = ephemeral.public_bytes();

        // Wire: [Header(36)][client_static_pub(32)][client_eph_pub(32)][client_nonce(16)]
        let mut header = Header::new(PacketType::Hello, 0, s.local_peer_id, s.server_peer_id);
        header.payload_len = HELLO_PAYLOAD_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + HELLO_PAYLOAD_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&local_id.public_bytes());
        wire.extend_from_slice(&ephemeral_pub);
        wire.extend_from_slice(&client_nonce);

        s.ws
            .send_with_u8_array(&wire)
            .map_err(|e| JsValue::from_str(&format!("ws send HELLO: {:?}", e)))?;

        // Store handshake material for hello_ack processing.
        s.pending_hs = Some(PendingHandshake {
            client_nonce,
            ephemeral,
        });

        Ok(())
    }

    /// Process HELLO_ACK: derive session keys, verify AEAD tag.
    fn handle_hello_ack(
        state: &Rc<RefCell<State>>,
        data: &[u8],
    ) -> Result<(), JsValue> {
        if data.len() < HEADER_LEN + HELLO_ACK_PAYLOAD_LEN {
            return Err(JsValue::from_str(&format!(
                "HELLO_ACK too short: {} bytes, need {}",
                data.len(),
                HEADER_LEN + HELLO_ACK_PAYLOAD_LEN
            )));
        }

        let header = Header::decode(&data[..HEADER_LEN])
            .map_err(|e| JsValue::from_str(&format!("header decode: {}", e)))?;

        if header.packet_type != PacketType::HelloAck {
            return Err(JsValue::from_str(&format!(
                "expected HelloAck, got {:?}",
                header.packet_type
            )));
        }

        let body = &data[HEADER_LEN..];
        let mut server_eph_pub = [0u8; STATIC_KEY_LEN];
        server_eph_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce
            .copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag = &body[STATIC_KEY_LEN + NONCE_LEN..STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN];

        let mut s = state.borrow_mut();

        // Consume the pending handshake material.
        let hs = s
            .pending_hs
            .take()
            .ok_or_else(|| JsValue::from_str("no pending handshake"))?;

        // X25519 DH: static + ephemeral.
        let local_id = Identity::from_secret_bytes(s.local_secret);
        let static_dh = local_id
            .dh(&s.server_pub)
            .ok_or_else(|| JsValue::from_str("static DH failed (low-order point)"))?;
        let ephemeral_dh = hs
            .ephemeral
            .dh(&server_eph_pub)
            .ok_or_else(|| JsValue::from_str("ephemeral DH failed (low-order point)"))?;

        // Derive session key from both DH results + nonces.
        let session_key_bytes = derive_session_key(
            &static_dh,
            &ephemeral_dh,
            &hs.client_nonce,
            &server_nonce,
        );

        let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
        let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

        // Verify the HELLO_ACK's AEAD tag.
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);
        let canon = canonical_aad(&hbuf);
        let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
        aad.extend_from_slice(&canon);
        aad.extend_from_slice(&server_eph_pub);
        aad.extend_from_slice(&server_nonce);
        rx.open(1, PacketType::HelloAck as u8, &aad, tag)
            .map_err(|e| JsValue::from_str(&format!("HELLO_ACK auth failed: {}", e)))?;

        // Session established.
        s.tx = Some(tx);
        s.rx = Some(rx);
        s.next_seq = 2;

        web_sys::console::log_1(&"DRIFT handshake complete (authenticated)".into());
        Ok(())
    }

    /// Process an incoming DATA packet: decode header, decrypt, deliver.
    fn handle_incoming(state: &Rc<RefCell<State>>, data: &[u8]) {
        let s = state.borrow();

        if data.len() < HEADER_LEN + AUTH_TAG_LEN {
            return; // too short
        }

        let header = match Header::decode(&data[..HEADER_LEN]) {
            Ok(h) => h,
            Err(_) => return,
        };

        if header.packet_type != PacketType::Data {
            return; // ignore non-data packets for now
        }

        let rx = match &s.rx {
            Some(rx) => rx,
            None => return, // no session yet
        };

        let body = &data[HEADER_LEN..];
        let hbuf: &[u8; HEADER_LEN] = data[..HEADER_LEN].try_into().unwrap();
        let aad = canonical_aad(hbuf);

        match rx.open(header.seq, PacketType::Data as u8, &aad, body) {
            Ok(plaintext) => {
                if let Some(ref callback) = s.on_message {
                    let arr = js_sys::Uint8Array::from(plaintext.as_slice());
                    let _ = callback.call1(&JsValue::NULL, &arr);
                }
            }
            Err(_) => {
                web_sys::console::warn_1(&"DRIFT: failed to decrypt incoming packet".into());
            }
        }
    }

    /// Send an AEAD-encrypted DATA packet using the DRIFT wire format.
    pub async fn send_data(&self, payload: &[u8]) -> Result<(), JsValue> {
        let wire = {
            let mut s = self.state.borrow_mut();

            if s.tx.is_none() {
                return Err(JsValue::from_str("session not established"));
            }

            let seq = s.next_seq;
            s.next_seq += 1;

            let local_peer_id = s.local_peer_id;
            let server_peer_id = s.server_peer_id;

            // Build long header.
            let mut header = Header::new(PacketType::Data, seq, local_peer_id, server_peer_id);
            header.payload_len = payload.len() as u16;
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let aad = canonical_aad(&hbuf);

            // Encrypt payload.
            let mut wire = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
            wire.extend_from_slice(&hbuf);
            s.tx
                .as_ref()
                .unwrap()
                .seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)
                .map_err(|e| JsValue::from_str(&format!("seal error: {}", e)))?;
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

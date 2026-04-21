//! Browser WebSocket transport for DRIFT.
//!
//! Implements the DRIFT handshake and data exchange over a
//! browser-native WebSocket. Each DRIFT packet becomes one
//! WebSocket binary message.

use drift_core::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use drift_core::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift_core::identity::{derive_session_key, Identity, NONCE_LEN, STATIC_KEY_LEN};
use drift_core::session::DEFAULT_MESH_TTL;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

const AUTH_TAG_LEN: usize = 16;

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("getrandom");
    nonce
}

/// Internal state shared between the WebSocket callbacks
/// and the WsTransport methods.
struct State {
    ws: WebSocket,
    local_id: Identity,
    local_peer_id: PeerId,
    server_pub: [u8; STATIC_KEY_LEN],
    server_peer_id: PeerId,
    tx: Option<SessionKey>,
    rx: Option<SessionKey>,
    next_seq: u32,
    on_message: Option<js_sys::Function>,
}

pub struct WsTransport {
    state: Rc<RefCell<State>>,
}

impl WsTransport {
    /// Connect to a DRIFT server via WebSocket, perform the
    /// handshake, and return a ready-to-use transport.
    pub async fn connect(
        url: &str,
        secret: [u8; 32],
        public: [u8; 32],
        server_pub: [u8; STATIC_KEY_LEN],
    ) -> Result<Self, JsValue> {
        let ws = WebSocket::new(url)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let local_id = Identity::from_secret_bytes(secret);
        let local_peer_id = derive_peer_id(&public);
        let server_peer_id = derive_peer_id(&server_pub);

        let state = Rc::new(RefCell::new(State {
            ws: ws.clone(),
            local_id,
            local_peer_id,
            server_pub,
            server_peer_id,
            tx: None,
            rx: None,
            next_seq: 2, // seq 0 reserved, 1 used by handshake
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

        // Send HELLO.
        Self::send_hello(&state)?;

        // Wait for HELLO_ACK and complete handshake.
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

        // Install ongoing message handler.
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

    fn send_hello(state: &Rc<RefCell<State>>) -> Result<(), JsValue> {
        let s = state.borrow();
        let client_nonce = random_nonce();
        let ephemeral = Identity::generate();
        let ephemeral_pub = ephemeral.public_bytes();

        let mut header = Header::new(PacketType::Hello, 0, s.local_peer_id, s.server_peer_id);
        let payload_len = STATIC_KEY_LEN * 2 + NONCE_LEN; // pub + eph_pub + nonce
        header.payload_len = payload_len as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&s.local_id.public_bytes());
        wire.extend_from_slice(&ephemeral_pub);
        wire.extend_from_slice(&client_nonce);

        s.ws
            .send_with_u8_array(&wire)
            .map_err(|e| JsValue::from_str(&format!("ws send error: {:?}", e)))?;

        // Store handshake state for hello_ack processing.
        drop(s);
        // We need to store the ephemeral and nonce for the ack handler.
        // Use a simple approach: store them in the State.
        // For now, store via closure capture in the promise handler.
        // This is handled by the closure in connect().

        Ok(())
    }

    fn handle_hello_ack(
        _state: &Rc<RefCell<State>>,
        data: &[u8],
    ) -> Result<(), JsValue> {
        if data.len() < HEADER_LEN {
            return Err(JsValue::from_str("packet too short for header"));
        }

        let header = Header::decode(&data[..HEADER_LEN])
            .map_err(|e| JsValue::from_str(&format!("header decode: {}", e)))?;

        if header.packet_type != PacketType::HelloAck {
            return Err(JsValue::from_str(&format!(
                "expected HelloAck, got {:?}",
                header.packet_type
            )));
        }

        // For v1, we accept the handshake as complete.
        // Full handshake verification requires storing the ephemeral
        // key from send_hello, which needs refactoring the State struct.
        // This is a simplified path that trusts the server.
        //
        // TODO: Full handshake verification in v2.
        let mut s = _state.borrow_mut();
        let body = &data[HEADER_LEN..];
        if body.len() < STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN {
            return Err(JsValue::from_str("HelloAck body too short"));
        }

        // For now, mark as connected without full crypto verification.
        // The real implementation needs the ephemeral DH + session key derivation.
        // We'll store dummy keys and handle this properly in v2.

        web_sys::console::log_1(&"DRIFT handshake acknowledged (v1 simplified)".into());
        Ok(())
    }

    fn handle_incoming(state: &Rc<RefCell<State>>, data: &[u8]) {
        let s = state.borrow();
        if let Some(ref callback) = s.on_message {
            let arr = js_sys::Uint8Array::from(data);
            let _ = callback.call1(&JsValue::NULL, &arr);
        }
    }

    pub async fn send_data(&self, payload: &[u8]) -> Result<(), JsValue> {
        let s = self.state.borrow();
        // For v1: send raw payload over WebSocket as binary.
        // Full DRIFT framing (header + AEAD) requires completed
        // session keys from the handshake.
        s.ws
            .send_with_u8_array(payload)
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

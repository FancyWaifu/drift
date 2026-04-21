//! DRIFT protocol for WebAssembly.
//!
//! Provides browser-friendly bindings for identity management
//! and encrypted communication via WebSocket.
//!
//! ```js
//! import { DriftIdentity, DriftClient } from 'drift-wasm';
//!
//! const id = DriftIdentity.generate();
//! console.log(id.publicKeyHex());
//! console.log(id.peerIdHex());
//!
//! const client = await DriftClient.connect("ws://server:9002", id, serverPubHex);
//! await client.send(new TextEncoder().encode("hello"));
//! client.onMessage((data) => console.log(new TextDecoder().decode(data)));
//! ```

mod peer_session;
mod ws_transport;

use drift_core::crypto::derive_peer_id;
use drift_core::identity::Identity;
use wasm_bindgen::prelude::*;

/// Hex-encode bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes.
fn from_hex(s: &str) -> Result<Vec<u8>, JsValue> {
    if s.len() % 2 != 0 {
        return Err(JsValue::from_str("hex string must have even length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| JsValue::from_str("invalid hex"))
        })
        .collect()
}

// ── DriftIdentity ─────────────────────────────────────────

/// An X25519 identity keypair.
#[wasm_bindgen]
pub struct DriftIdentity {
    secret: [u8; 32],
    public: [u8; 32],
    peer_id: [u8; 8],
}

#[wasm_bindgen]
impl DriftIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("getrandom failed");
        let id = Identity::from_secret_bytes(secret);
        let public = id.public_bytes();
        let peer_id = derive_peer_id(&public);
        Self {
            secret,
            public,
            peer_id,
        }
    }

    /// Create from a 32-byte secret key (hex, 64 chars).
    #[wasm_bindgen(js_name = "fromSecretHex")]
    pub fn from_secret_hex(hex_str: &str) -> Result<DriftIdentity, JsValue> {
        let bytes = from_hex(hex_str)?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str("secret must be 64 hex chars"));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let id = Identity::from_secret_bytes(secret);
        let public = id.public_bytes();
        let peer_id = derive_peer_id(&public);
        Ok(Self {
            secret,
            public,
            peer_id,
        })
    }

    /// Public key as hex string (64 chars).
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> String {
        hex(&self.public)
    }

    /// Peer ID as hex string (16 chars).
    #[wasm_bindgen(js_name = "peerIdHex")]
    pub fn peer_id_hex(&self) -> String {
        hex(&self.peer_id)
    }

    /// Secret key as hex string (64 chars). Handle with care.
    #[wasm_bindgen(js_name = "secretHex")]
    pub fn secret_hex(&self) -> String {
        hex(&self.secret)
    }

    /// Raw 32-byte public key.
    #[wasm_bindgen(js_name = "publicKeyBytes")]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    /// Raw 8-byte peer ID.
    #[wasm_bindgen(js_name = "peerIdBytes")]
    pub fn peer_id_bytes(&self) -> Vec<u8> {
        self.peer_id.to_vec()
    }
}

// ── DriftClient ───────────────────────────────────────────

/// A DRIFT client connected via WebSocket.
#[wasm_bindgen]
pub struct DriftClient {
    inner: ws_transport::WsTransport,
}

#[wasm_bindgen]
impl DriftClient {
    /// Connect to a DRIFT node via WebSocket.
    ///
    /// `url`: WebSocket URL (e.g., "ws://server:9002")
    /// `identity`: your DriftIdentity
    /// `server_pub_hex`: the server's public key (64 hex chars)
    pub async fn connect(
        url: &str,
        identity: &DriftIdentity,
        server_pub_hex: &str,
    ) -> Result<DriftClient, JsValue> {
        let server_pub_bytes = from_hex(server_pub_hex)?;
        if server_pub_bytes.len() != 32 {
            return Err(JsValue::from_str("server public key must be 64 hex chars"));
        }
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_pub_bytes);

        let transport = ws_transport::WsTransport::connect(
            url,
            identity.secret,
            identity.public,
            server_pub,
        )
        .await?;

        Ok(DriftClient { inner: transport })
    }

    /// Send a datagram (raw bytes) to the direct server (the
    /// bridge/relay this client is connected to).
    pub async fn send(&self, data: &[u8]) -> Result<(), JsValue> {
        let server_pid = self.inner.server_peer_id();
        self.inner.send_data_to(server_pid, data).await
    }

    /// Register an additional peer reachable through the server
    /// via mesh routing. The handshake with that peer rides the
    /// same WebSocket; the server forwards to wherever that peer
    /// lives (UDP / TCP / WS / WebRTC). Resolves when the new
    /// session is Established.
    #[wasm_bindgen(js_name = "addPeer")]
    pub async fn add_peer(&self, peer_pub_hex: &str) -> Result<String, JsValue> {
        let bytes = from_hex(peer_pub_hex)?;
        if bytes.len() != 32 {
            return Err(JsValue::from_str("peer public key must be 64 hex chars"));
        }
        let mut peer_pub = [0u8; 32];
        peer_pub.copy_from_slice(&bytes);
        self.inner.add_peer(peer_pub).await?;
        Ok(hex(&drift_core::crypto::derive_peer_id(&peer_pub)))
    }

    /// Send an AEAD-encrypted DATA packet to a specific peer
    /// (either the server or a previously-added mesh peer).
    /// The target is identified by its peer_id hex.
    #[wasm_bindgen(js_name = "sendToPeer")]
    pub async fn send_to_peer(
        &self,
        peer_id_hex: &str,
        data: &[u8],
    ) -> Result<(), JsValue> {
        let bytes = from_hex(peer_id_hex)?;
        if bytes.len() != 8 {
            return Err(JsValue::from_str("peer_id must be 16 hex chars"));
        }
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&bytes);
        self.inner.send_data_to(peer_id, data).await
    }

    /// Register a callback for incoming messages. The callback
    /// is invoked as `cb(srcPeerIdHex, Uint8Array)` so the app
    /// can tell which peer a message came from in a multi-peer
    /// setup.
    #[wasm_bindgen(js_name = "onMessage")]
    pub fn on_message(&self, callback: js_sys::Function) {
        self.inner.set_on_message(callback);
    }

    /// Close the connection.
    pub fn close(&self) {
        self.inner.close();
    }

    /// The server's peer ID as hex.
    #[wasm_bindgen(js_name = "serverPeerIdHex")]
    pub fn server_peer_id_hex(&self) -> String {
        hex(&self.inner.server_peer_id())
    }
}

// ── Utility exports ───────────────────────────────────────

/// Derive a peer ID from a public key (both hex).
#[wasm_bindgen(js_name = "derivePeerId")]
pub fn derive_peer_id_hex(pub_key_hex: &str) -> Result<String, JsValue> {
    let bytes = from_hex(pub_key_hex)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("public key must be 64 hex chars"));
    }
    Ok(hex(&derive_peer_id(&bytes)))
}

//! DRIFT protocol for WebAssembly.
//!
//! Browser-facing bindings for identity management and
//! encrypted communication via the three wire transports that
//! browsers actually expose:
//!
//!   * **WebSocket** — the default. Universal browser support.
//!     Reliable+ordered (double-counts against DRIFT CC for
//!     datagrams, but unavoidable for WebSocket).
//!   * **WebRTC data channel** — peer-to-peer, no server in the
//!     data path once SDP is exchanged out of band. The only
//!     adapter that can do browser↔browser direct.
//!   * **WebTransport** — QUIC/HTTP3-based. *Real* UDP-like
//!     unreliable datagrams in the browser. Preserves DRIFT's
//!     deadline-aware/coalesced semantics end to end.
//!
//! ```js
//! import { DriftIdentity, DriftClient } from 'drift-wasm';
//!
//! const id = DriftIdentity.generate();
//!
//! // WebSocket (default)
//! const ws = await DriftClient.connectWebSocket("ws://relay:9002", id, serverPubHex);
//!
//! // WebRTC (caller provides an open RtcDataChannel)
//! const rtc = await DriftClient.connectWebRtc(dataChannel, id, peerPubHex);
//!
//! // WebTransport (HTTPS/HTTP3 endpoint)
//! const wt = await DriftClient.connectWebTransport("https://relay:4433/", id, serverPubHex);
//! ```

mod peer_session;
mod session;
mod wire_webrtc;
mod wire_webtransport;
mod wire_ws;

use drift_core::crypto::derive_peer_id;
use drift_core::identity::Identity;
use session::Session;
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| JsValue::from_str("invalid hex")))
        .collect()
}

fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], JsValue> {
    let bytes = from_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("public key must be 64 hex chars"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
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

    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> String {
        hex(&self.public)
    }

    #[wasm_bindgen(js_name = "peerIdHex")]
    pub fn peer_id_hex(&self) -> String {
        hex(&self.peer_id)
    }

    #[wasm_bindgen(js_name = "secretHex")]
    pub fn secret_hex(&self) -> String {
        hex(&self.secret)
    }

    #[wasm_bindgen(js_name = "publicKeyBytes")]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    #[wasm_bindgen(js_name = "peerIdBytes")]
    pub fn peer_id_bytes(&self) -> Vec<u8> {
        self.peer_id.to_vec()
    }
}

// ── DriftClient ───────────────────────────────────────────

/// A DRIFT client. Talks over whichever wire it was constructed
/// with (WebSocket, WebRTC data channel, or WebTransport). Once
/// connected the API is identical regardless of wire.
#[wasm_bindgen]
pub struct DriftClient {
    session: Session,
}

#[wasm_bindgen]
impl DriftClient {
    /// Connect to a DRIFT node via WebSocket. Back-compat alias
    /// for `connectWebSocket`.
    pub async fn connect(
        url: &str,
        identity: &DriftIdentity,
        server_pub_hex: &str,
    ) -> Result<DriftClient, JsValue> {
        Self::connect_web_socket(url, identity, server_pub_hex).await
    }

    /// Connect over a browser `WebSocket`. Universal-support
    /// baseline. `url` is a `ws://` or `wss://` endpoint.
    #[wasm_bindgen(js_name = "connectWebSocket")]
    pub async fn connect_web_socket(
        url: &str,
        identity: &DriftIdentity,
        server_pub_hex: &str,
    ) -> Result<DriftClient, JsValue> {
        let server_pub = parse_pubkey(server_pub_hex)?;
        let session = wire_ws::connect(url, identity.secret, server_pub).await?;
        Ok(DriftClient { session })
    }

    /// Wrap an already-open browser `RTCDataChannel` as the
    /// transport. Caller is responsible for the SDP/ICE exchange
    /// that produced the data channel — once it's in the `open`
    /// readyState, hand it here and DRIFT will take over.
    ///
    /// The `peer_pub_hex` argument is the DRIFT identity of
    /// whoever's on the other end of the data channel.
    #[wasm_bindgen(js_name = "connectWebRtc")]
    pub async fn connect_web_rtc(
        data_channel: web_sys::RtcDataChannel,
        identity: &DriftIdentity,
        peer_pub_hex: &str,
    ) -> Result<DriftClient, JsValue> {
        let peer_pub = parse_pubkey(peer_pub_hex)?;
        let session =
            wire_webrtc::from_data_channel(data_channel, identity.secret, peer_pub).await?;
        Ok(DriftClient { session })
    }

    /// Connect over WebTransport (HTTP/3 + QUIC). Preserves
    /// DRIFT's UDP-like datagram semantics in the browser —
    /// no TCP retransmit tax on top of DRIFT's own CC. Needs
    /// an `https://` server URL (WebTransport is TLS-only).
    #[wasm_bindgen(js_name = "connectWebTransport")]
    pub async fn connect_web_transport(
        url: &str,
        identity: &DriftIdentity,
        server_pub_hex: &str,
    ) -> Result<DriftClient, JsValue> {
        let server_pub = parse_pubkey(server_pub_hex)?;
        let session = wire_webtransport::connect(url, identity.secret, server_pub).await?;
        Ok(DriftClient { session })
    }

    /// Send a datagram to the direct server.
    pub async fn send(&self, data: &[u8]) -> Result<(), JsValue> {
        let server_pid = self.session.server_peer_id();
        self.session.send_data_to(server_pid, data).await
    }

    /// Register and handshake with a mesh peer reachable through
    /// the server. Returns the new peer's peer_id hex.
    #[wasm_bindgen(js_name = "addPeer")]
    pub async fn add_peer(&self, peer_pub_hex: &str) -> Result<String, JsValue> {
        let peer_pub = parse_pubkey(peer_pub_hex)?;
        self.session.add_peer(peer_pub).await?;
        Ok(hex(&drift_core::crypto::derive_peer_id(&peer_pub)))
    }

    /// Send an AEAD-encrypted DATA packet to a specific peer.
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
        self.session.send_data_to(peer_id, data).await
    }

    /// Register a callback invoked as `cb(srcPeerIdHex, Uint8Array)`
    /// for every decrypted incoming DATA packet.
    #[wasm_bindgen(js_name = "onMessage")]
    pub fn on_message(&self, callback: js_sys::Function) {
        self.session.set_on_message(callback);
    }

    /// The direct server's peer_id hex (i.e. the identity of
    /// whichever wire endpoint this client is attached to).
    #[wasm_bindgen(js_name = "serverPeerIdHex")]
    pub fn server_peer_id_hex(&self) -> String {
        hex(&self.session.server_peer_id())
    }

    /// Close the underlying transport. Whichever wire this client
    /// was built on (WebSocket / RTCDataChannel / WebTransport)
    /// gets closed. Idempotent — safe to call multiple times.
    pub fn close(&self) {
        // No-op for now: the Session doesn't own the wire
        // directly — the sender closure captures whatever the
        // wire adapter handed over. When `DriftClient` is
        // dropped, the closure drops, and the browser-side
        // wire object is garbage-collected shortly after.
        // Applications that need explicit close can just drop
        // the `DriftClient` reference in JS.
    }
}

/// Derive a peer ID from a public key (both hex).
#[wasm_bindgen(js_name = "derivePeerId")]
pub fn derive_peer_id_hex(pub_key_hex: &str) -> Result<String, JsValue> {
    let bytes = from_hex(pub_key_hex)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("public key must be 64 hex chars"));
    }
    Ok(hex(&derive_peer_id(&bytes)))
}

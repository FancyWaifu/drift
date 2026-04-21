//! Per-peer session state for the mesh-capable WASM client.
//!
//! `PeerSession` holds the crypto state for one remote peer. The
//! `WsTransport`'s `State` owns a map of these, keyed by peer_id.
//! The direct server (the relay the WASM connected to via
//! WebSocket) is one entry in that map; every mesh-routed peer
//! added via `add_peer(pub)` is another.

use drift_core::crypto::{PeerId, SessionKey, derive_peer_id};
use drift_core::identity::{Identity, NONCE_LEN, STATIC_KEY_LEN};

/// Ephemeral material stashed between sending a HELLO and
/// processing the matching HELLO_ACK. Consumed (via take) when
/// the ack arrives so the secret ephemeral key is dropped.
pub(crate) struct PendingHandshake {
    pub client_nonce: [u8; NONCE_LEN],
    pub ephemeral: Identity,
}

/// One peer's session state. Lives in the `WsTransport`'s peer
/// map for the lifetime of the connection.
pub(crate) struct PeerSession {
    pub peer_pub: [u8; STATIC_KEY_LEN],
    #[allow(dead_code)]
    pub peer_id: PeerId,
    /// Session key for outbound (we are Initiator). `None` until
    /// handshake completes.
    pub tx: Option<SessionKey>,
    /// Session key for inbound.
    pub rx: Option<SessionKey>,
    /// Next outgoing DATA seq. Starts at 2 (1 was the HELLO_ACK
    /// we received during handshake).
    pub next_seq: u32,
    pub pending_hs: Option<PendingHandshake>,
    /// JS Promise resolver for a pending `add_peer(pub).await`
    /// call — invoked when HELLO_ACK arrives for this peer.
    pub handshake_resolve: Option<js_sys::Function>,
    pub handshake_reject: Option<js_sys::Function>,
}

impl PeerSession {
    pub fn new(peer_pub: [u8; STATIC_KEY_LEN]) -> Self {
        Self {
            peer_pub,
            peer_id: derive_peer_id(&peer_pub),
            tx: None,
            rx: None,
            next_seq: 2,
            pending_hs: None,
            handshake_resolve: None,
            handshake_reject: None,
        }
    }

    pub fn is_established(&self) -> bool {
        self.tx.is_some() && self.rx.is_some()
    }
}

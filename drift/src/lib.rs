//! # DRIFT
//!
//! Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint
//! UDP transport protocol.

// Re-export platform-independent core modules.
pub use drift_core::crypto;
pub use drift_core::directory;
pub use drift_core::error;
pub use drift_core::fec;
pub use drift_core::header;
pub use drift_core::identity;
pub use drift_core::pq;
pub use drift_core::session;
pub use drift_core::short_header;
pub use drift_core::time;

// Platform-specific modules (tokio).
pub mod contacts;
pub mod io;
pub mod multipath;
pub mod streams;
pub mod transport;
pub mod wire_dns;
pub mod wire_doh;
pub mod wire_h2;
pub mod wire_http;
pub mod wire_webrtc;
pub mod wire_webtransport;

// `onion://` adapter — opt-in via `--features onion`. The whole
// Tor protocol stack is heavyweight, so we don't compile it
// into default builds.
#[cfg(feature = "onion")]
pub mod wire_onion;

// `iroh://` adapter — opt-in via `--features iroh`. Pulls in
// n0-computer's QUIC overlay (~30 transitive crates). The joke
// being DRIFT's wire-agnostic-on-top-of-Iroh's-single-wire
// architecture; the practical use being NAT punching as another
// wire in the inventory.
#[cfg(feature = "iroh")]
pub mod wire_iroh;

// Convenience re-exports.
pub use drift_core::{derive_peer_id, Direction, PeerId, SessionKey, KEY_LEN, PEER_ID_LEN};
pub use drift_core::{DriftError, Result};
pub use drift_core::{Header, PacketType, HEADER_LEN};
pub use drift_core::{Identity, STATIC_KEY_LEN};
pub use transport::{FindPeerMode, Metrics, Received, Transport, TransportConfig, MAX_PAYLOAD};

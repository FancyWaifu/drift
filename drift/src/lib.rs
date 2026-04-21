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
pub mod io;
pub mod multipath;
pub mod streams;
pub mod transport;

// Convenience re-exports.
pub use drift_core::{derive_peer_id, Direction, PeerId, SessionKey, KEY_LEN, PEER_ID_LEN};
pub use drift_core::{DriftError, Result};
pub use drift_core::{Header, PacketType, HEADER_LEN};
pub use drift_core::{Identity, STATIC_KEY_LEN};
pub use transport::{Metrics, Received, Transport, TransportConfig, MAX_PAYLOAD};

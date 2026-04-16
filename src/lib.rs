//! # DRIFT
//!
//! Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint
//! UDP transport protocol.

pub mod crypto;
pub mod directory;
pub mod error;
pub mod fec;
pub mod header;
pub mod identity;
pub mod io;
pub mod multipath;
pub mod pq;
pub mod session;
pub mod short_header;
pub mod streams;
pub mod transport;

pub use crypto::{derive_peer_id, Direction, PeerId, SessionKey, KEY_LEN, PEER_ID_LEN};
pub use error::{DriftError, Result};
pub use header::{Header, PacketType, HEADER_LEN};
pub use identity::{Identity, STATIC_KEY_LEN};
pub use transport::{Metrics, Received, Transport, TransportConfig, MAX_PAYLOAD};

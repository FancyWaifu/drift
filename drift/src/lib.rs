//! # DRIFT
//!
//! Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint
//! UDP transport protocol.

// Wire adapter dispatchers (`Pin<Box<dyn Future<Output =
// io::Result<...>> + Send>>`) and a handful of internal lookup
// tables share complex generic types that clippy flags as
// `type_complexity`. Refactoring all of them into named type
// aliases is its own project (~15 sites across the wire_* modules);
// allow crate-wide for now.
#![allow(clippy::type_complexity)]

// Re-export platform-independent core modules. Phase 3 of the
// API lock-down dropped `fec`, `pq`, and `time` from the public
// re-export surface — none had any external consumer through
// the `drift::*` path. They remain accessible via
// `drift_core::*` directly for anything that legitimately needs
// them.
pub use drift_core::crypto;
pub use drift_core::directory;
pub use drift_core::error;
pub use drift_core::header;
pub use drift_core::identity;
pub use drift_core::session;
pub use drift_core::short_header;

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

// Convenience re-exports. Phase 3 of the API lock-down trimmed
// the top-level surface to items with actual external uses
// through the `drift::*` path. Items still reachable but no
// longer at the top level can be imported from their containing
// module (e.g. `drift::crypto::KEY_LEN`,
// `drift::transport::Metrics`).
pub use drift_core::crypto::{Direction, SessionKey};
pub use drift_core::error::{DriftError, Result};
pub use drift_core::header::{Header, PacketType, HEADER_LEN};
pub use drift_core::Identity;
pub use drift_core::{derive_peer_id, PeerId};
pub use transport::{Transport, TransportConfig, MAX_PAYLOAD};

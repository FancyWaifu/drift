//! # drift-core
//!
//! Platform-independent DRIFT protocol primitives.
//! No async runtime dependency — compiles to native and WASM.

pub mod crypto;
pub mod directory;
pub mod error;
pub mod fec;
pub mod header;
pub mod identity;
pub mod pq;
pub mod session;
pub mod short_header;
pub mod time;
pub mod xeddsa;

pub use crypto::{derive_peer_id, Direction, PeerId, SessionKey, KEY_LEN, PEER_ID_LEN};
pub use error::{DriftError, Result};
pub use header::{Header, PacketType, HEADER_LEN};
pub use identity::{Identity, STATIC_KEY_LEN};
// Re-export so downstream crates (drift, drift-wasm) can use
// `Zeroizing` via drift-core without taking a separate zeroize
// dep.
pub use zeroize::Zeroizing;

//! # drift-core
//!
//! Platform-independent DRIFT protocol primitives.
//! No async runtime dependency — compiles to native and WASM.

pub mod crypto;
pub mod directory;
pub mod error;
pub mod header;
pub mod identity;
pub mod pool;
pub mod pq;
pub mod rotation;
pub mod session;
pub mod short_header;
pub mod xeddsa;

// Phase 4 of the API lock-down: `time` demoted to `pub(crate)`
// (only `crate::time::{Duration, Instant}` is used internally;
// no external consumer reached `drift_core::time`). The `fec`
// module was removed entirely — it had been dead code for a
// long time, never wired into the send or receive paths.
pub(crate) mod time;

// Phase 4 trimmed the top-level convenience re-exports to the
// items consumed via `drift_core::*` directly. Items still
// reachable via their module path (`drift_core::crypto::Direction`,
// `drift_core::error::DriftError`, etc.) but no longer at the
// crate root. The `drift` crate now re-exports them through
// module paths in its own lib.rs.
pub use crypto::{derive_peer_id, PeerId};
pub use identity::Identity;
// Re-export so downstream crates (drift, drift-wasm) can use
// `Zeroizing` via drift-core without taking a separate zeroize
// dep.
pub use zeroize::Zeroizing;

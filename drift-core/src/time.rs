//! Platform-agnostic time types.
//!
//! On native targets, re-exports `std::time`. On wasm32,
//! re-exports `web-time` which wraps `performance.now()`.

// Phase 4 trimmed the re-exports to just `Duration` + `Instant` —
// the only items used inside drift-core. `SystemTime` and
// `UNIX_EPOCH` are still available via `std::time::*` /
// `web_time::*` directly for code that needs wall-clock timestamps.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Duration, Instant};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Duration, Instant};

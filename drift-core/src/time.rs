//! Platform-agnostic time types.
//!
//! On native targets, re-exports `std::time`. On wasm32,
//! re-exports `web-time` which wraps `performance.now()`.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

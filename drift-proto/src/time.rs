//! Platform-agnostic time types (same approach as drift-core's
//! private `time` module): native targets use `std::time`; wasm32
//! uses `web-time`, which wraps `performance.now()` /
//! `Date.now()`. Everything in the engine that touches a clock
//! imports from here so the crate compiles for the browser.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

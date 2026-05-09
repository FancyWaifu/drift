//! Library half of `drift-config`. Other DRIFT crates (drift-vpn,
//! future tools) depend on this for the shared schema + file I/O,
//! without pulling in clap or the CLI dispatch.
//!
//! The CLI in `main.rs` is a thin shim that calls into these
//! modules.

pub mod io;
pub mod schema;

pub use schema::{DriftToml, Host, Network, VpnHost, VpnOverlay};

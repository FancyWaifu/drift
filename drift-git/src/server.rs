//! `drift-git-server` binary — a thin dispatcher to the native
//! (tokio, all wires, mesh/bridge) or portable (drift-proto-std,
//! sync, tcp-only) serving daemon, chosen at build time by features.
//!
//!   cargo build -p drift-git                                  # native (default)
//!   cargo build -p drift-git --no-default-features --features portable

#[cfg(feature = "native")]
fn main() -> anyhow::Result<()> {
    drift_git::native_server::run()
}

#[cfg(all(feature = "portable", not(feature = "native")))]
fn main() -> anyhow::Result<()> {
    drift_git::portable_server::run()
}

//! drift-mosh shared library.
//!
//! Contains the types that server, client, and the `drift-mosh`
//! launcher all agree on — the control-plane message format,
//! config, known-hosts (TOFU), and the persistent client key.

pub mod client_key;
pub mod config;
pub mod known_hosts;
// Re-export the TOFU prompt helper at crate root so both
// binaries and external wrappers can use it.
pub mod scrollback;
pub mod wire;

pub use client_key::ClientKey;
pub use config::Config;
pub use known_hosts::{HostKeyStatus, KnownHosts};
pub use scrollback::Scrollback;
pub use wire::{Ctrl, BannerLine, PTY_CHUNK_SIZE, SCROLLBACK_BYTES};

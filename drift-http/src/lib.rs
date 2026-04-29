//! `drift-http` library: shared bits used by both the `serve` and
//! `connect` modes of the `drift-http` binary.
//!
//! Two pieces live here:
//!
//! 1. [`StreamIo`] — adapts a [`drift::streams::Stream`] so it
//!    satisfies tokio's `AsyncRead + AsyncWrite + Unpin + Send`.
//!    This is the linchpin of the whole crate: hyper's connection
//!    builders accept any I/O matching that trait bound, so
//!    plugging a DRIFT stream into hyper is a one-liner once the
//!    adapter exists. We do *not* re-implement HTTP framing, body
//!    handling, ranges, MIME, or any of the other things hyper
//!    already does correctly.
//!
//! 2. [`Identity`] helpers — the persistent X25519 identity at
//!    `~/.config/drift/identity.key` (shared with future DRIFT
//!    tools so a friend's pubkey is the same across drift-mosh,
//!    drift-http, etc.). Auto-created on first call, mode 0600.

pub mod bridge;
pub mod identity;
pub mod io;
pub mod transport_url;

pub use crate::io::StreamIo;

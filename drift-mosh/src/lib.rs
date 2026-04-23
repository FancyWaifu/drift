//! drift-mosh — a mobile-shell replacement over DRIFT.
//!
//! The binaries (`server`, `client`) share the control-plane
//! message format defined here. Pty bytes go as raw payload on
//! a dedicated stream; everything else (window resize, clean
//! shutdown) is a bincode-encoded `Ctrl` message on a control
//! stream.

use serde::{Deserialize, Serialize};

/// Control-plane message. Bincode-encoded and sent as one DRIFT
/// stream frame. Kept small and stable so adding new message
/// types later doesn't break old clients — we use an enum with
/// explicit tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ctrl {
    /// Client → server: the local TTY was resized. Server
    /// forwards this to the pty so the remote shell (and any
    /// full-screen programs) reflow.
    Resize { rows: u16, cols: u16 },
    /// Either direction: polite shutdown. The peer should
    /// close its half of the session without errors.
    Bye,
}

/// Wire-size upper bound for a single pty chunk. Well under
/// DRIFT's MAX_PAYLOAD (1348 B) so every chunk fits in one
/// packet and we don't have to deal with fragmentation on the
/// hot path.
pub const PTY_CHUNK_SIZE: usize = 1024;

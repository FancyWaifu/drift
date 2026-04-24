//! Wire protocol between drift-mosh-server and drift-mosh-client.
//!
//! - **pty stream**: raw bytes both ways. No framing needed —
//!   DRIFT's stream layer preserves order within a stream.
//! - **control stream**: bincode-encoded `Ctrl` messages.
//!
//! Two streams per session. Server accepts first stream as
//! pty, second as control. Client opens in the same order. No
//! in-band negotiation; just a convention.

use serde::{Deserialize, Serialize};

/// Control-plane message, one per DRIFT stream frame.
///
/// The enum is versioned by shape: adding a new variant is a
/// backward-compatible change (old clients ignore unknown
/// variants if we extend `match` properly), but reordering or
/// removing variants is a wire-format break. Keep the tag
/// assignments stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ctrl {
    /// Client → server: the local tty was resized. Server
    /// forwards to the pty so the remote shell (and any
    /// full-screen programs) reflow.
    Resize { rows: u16, cols: u16 },

    /// Client → server at startup: "this is the session id I
    /// had last time; if you still have that session's pty,
    /// reattach me to it. Otherwise start fresh." Session ids
    /// are 16 random bytes minted by the server on first
    /// connect.
    Attach { session_id: [u8; 16] },

    /// Server → client right after a successful Attach:
    /// confirms the session was found (reattach_ok = true) or
    /// that a fresh session was started (reattach_ok = false).
    /// The `session_id` is what the client should remember
    /// for next reconnect.
    AttachAck {
        session_id: [u8; 16],
        reattach_ok: bool,
        /// Bytes of pty output the server buffered since the
        /// last time this client was attached. Client replays
        /// these to stdout before resuming live streaming.
        /// Empty on a brand-new session.
        scrollback: Vec<u8>,
    },

    /// Either direction: polite shutdown. The peer closes its
    /// half of the session without errors.
    Bye,
}

/// Parseable startup banner line. The server prints these
/// key=value pairs one per line to stdout at startup; the
/// `drift-mosh` launcher regexes them out to get the pub + addr.
///
/// Having a fixed enum is overkill for four fields, but it
/// makes the parsing contract explicit for anyone reading
/// either side of the code.
pub enum BannerLine {
    /// `DRIFT_MOSH_PUB=<64 hex chars>`
    Pub,
    /// `DRIFT_MOSH_PEER_ID=<16 hex chars>`
    PeerId,
    /// `DRIFT_MOSH_ADDR=<ip:port>`
    Addr,
    /// `DRIFT_MOSH_READY` — last line, end of banner.
    Ready,
}

impl BannerLine {
    /// Prefix in the banner line, including the equals sign
    /// where applicable.
    pub fn prefix(&self) -> &'static str {
        match self {
            BannerLine::Pub => "DRIFT_MOSH_PUB=",
            BannerLine::PeerId => "DRIFT_MOSH_PEER_ID=",
            BannerLine::Addr => "DRIFT_MOSH_ADDR=",
            BannerLine::Ready => "DRIFT_MOSH_READY",
        }
    }
}

/// Wire-size upper bound for a single pty chunk. Kept well
/// under DRIFT's MAX_PAYLOAD (1348 B) so every chunk fits in
/// one packet without fragmentation.
pub const PTY_CHUNK_SIZE: usize = 1024;

/// How many bytes of recent pty output the server buffers, so
/// a reconnecting client can replay its screen. 32 KB is
/// enough to redraw a full-screen `vim` + a few command
/// outputs without letting memory grow unbounded per session.
pub const SCROLLBACK_BYTES: usize = 32 * 1024;

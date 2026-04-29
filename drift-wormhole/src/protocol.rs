//! Wire protocol — small bincode-encoded messages on a single
//! DRIFT stream.
//!
//! Flow:
//!
//! ```text
//!   sender                                  recipient
//!     │                                          │
//!     │   bincode(Header { name, size, sha256 }) │
//!     ├─────────────────────────────────────────▶│
//!     │                                          │
//!     │   raw file bytes (size bytes total)      │
//!     ├─────────────────────────────────────────▶│
//!     │                                          │
//!     │   bincode(Ack { ok | reject })           │
//!     │◀─────────────────────────────────────────┤
//!     │                                          │
//! ```
//!
//! DRIFT's stream layer already gives us reliable, ordered
//! byte delivery on top of an AEAD-encrypted session, so we
//! don't need framing per chunk — just the metadata header
//! followed by `size` raw bytes followed by the ack.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// File name as the sender would like it saved. Recipient
    /// is free to override with `--out` but defaults to this.
    pub name: String,
    /// Total bytes that will follow on the stream.
    pub size: u64,
    /// SHA-256 of the file content. Recipient verifies after
    /// reading `size` bytes; mismatch → reject.
    pub sha256: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Ack {
    Ok,
    Reject { reason: String },
}

/// Max framed-message size — bincode messages are tiny in
/// practice (filename + 40 bytes), but keeping a sanity cap
/// prevents a hostile peer from claiming a 4 GB filename.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Streaming chunk size for the sender's read-loop. Doesn't
/// affect the wire format (DRIFT chunks segments internally),
/// just how often we update the progress bar.
pub const CHUNK_SIZE: usize = 64 * 1024;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriftError {
    #[error("packet too short: got {got} bytes, need at least {need}")]
    PacketTooShort { got: usize, need: usize },

    #[error("unknown packet type: {0}")]
    UnknownType(u8),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("payload length mismatch: header says {header}, actual {actual}")]
    LengthMismatch { header: usize, actual: usize },

    #[error("authentication failed")]
    AuthFailed,

    #[error("replay detected: seq {0}")]
    Replay(u32),

    #[error("deadline expired")]
    DeadlineExpired,

    #[error("unknown peer")]
    UnknownPeer,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The peer's pending-send queue is at capacity and no more
    /// packets can be buffered until the handshake completes. The app
    /// should back off and retry.
    #[error("peer pending queue full")]
    QueueFull,

    /// The peer's handshake has failed after exhausting all retries
    /// and the session is dead. The app must reset the peer (e.g.
    /// `add_peer` again) to attempt a fresh handshake.
    #[error("peer handshake exhausted all retries")]
    HandshakeExhausted,

    /// The session's seq counter has reached the safety ceiling that
    /// guards against AEAD nonce reuse. The app must tear down and
    /// re-handshake before sending more data.
    #[error("session seq ceiling reached — re-handshake required")]
    SessionExhausted,

    /// A `try_add_peer` call found an existing peer with the same
    /// 64-bit peer id but a different static public key. Peer ids
    /// are BLAKE2b hashes of the pubkey; a collision requires a
    /// ~2^32 birthday-style search and should be treated as an
    /// attempted namespace attack.
    #[error("peer id collision with existing entry")]
    PeerIdCollision,
}

pub type Result<T> = std::result::Result<T, DriftError>;

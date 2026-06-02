//! DRIFT error types — flat `DriftError` umbrella + layered
//! sub-error types per protocol concern.
//!
//! # The design
//!
//! Historically every fallible DRIFT operation returned
//! `Result<T, DriftError>` — a single flat enum across the wire
//! codec, AEAD, session lifecycle, peer table, IO, app-contract,
//! and federation layers. That makes callers either propagate
//! errors blindly via `?` or string-match on the `Display`
//! representation when they want layer-specific handling — there
//! was no type-level way to say "this function can only fail
//! with a codec-layer reason, not an AEAD reason."
//!
//! We're moving to **layered sub-error types** that each cover
//! one protocol concern, while keeping `DriftError` as a top-
//! level umbrella for cross-layer call sites and backward compat.
//! Each sub-error type:
//!
//!   1. Lives in its own sub-module (`codec`, future: `crypto`,
//!      `session`, `peer`, `federation`).
//!   2. Implements `From<SubError> for DriftError` so functions
//!      returning `Result<T, SubError>` flow up through `?` into
//!      functions returning `Result<T, DriftError>` transparently.
//!   3. Has variants narrowed to the failures that layer can
//!      actually produce — so a `Header::decode` signature
//!      `fn decode(b: &[u8]) -> Result<Header, CodecError>`
//!      documents at the type level that AEAD / IO / peer
//!      failures are impossible here.
//!
//! # Migration plan
//!
//!   * **Slice 1 (this PR):** codec layer. `CodecError` exists,
//!     pure-codec functions (`PacketType::from_u8`,
//!     `Header::decode`, `decode_short`, `RotationAnnounce::decode`)
//!     return `Result<T, CodecError>`. `From<CodecError> for
//!     DriftError` keeps every transitive caller working
//!     unchanged.
//!   * **Slice 2 (future PR):** crypto layer. `CryptoError` for
//!     AEAD seal/open failures (`AuthFailed`, `Replay`). Migrate
//!     `SessionKey::seal` / `open` and friends.
//!   * **Slice 3 (future PR):** session lifecycle. `SessionError`
//!     for `SessionExhausted`, `HandshakeExhausted`.
//!   * **Slice 4 (future PR):** peer / federation. `PeerError`
//!     for `UnknownPeer` (the highest-count variant — split this
//!     carefully: "app tried to send to unregistered peer" vs
//!     "incoming packet's src_id is unknown" are distinct
//!     conditions that share a variant today).
//!   * **Slice 5 (future PR):** consolidate `DriftError` to only
//!     the cross-layer variants (`Io`, `QueueFull`,
//!     `DeadlineExpired`, `PayloadTooLarge`) + sub-error wrappers.
//!     Remove the legacy flat variants once no returner is left.
//!
//! Each slice ships independently; the umbrella stays compatible
//! until the final slice.

use thiserror::Error;

/// Codec-layer parse / decode failures.
///
/// Produced by functions that decode raw wire bytes — header
/// decoders, packet-type tag parsers, signed-message decoders.
/// Does NOT include AEAD authentication or any session-layer
/// reasoning; those belong in future `CryptoError` /
/// `SessionError` types.
///
/// Convert into [`DriftError`] via `?` thanks to the
/// `From<CodecError> for DriftError` impl below; callers that
/// want layer-specific handling can match on `CodecError`
/// variants directly.
pub mod codec {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum CodecError {
        /// Buffer is shorter than the minimum the decoder needs
        /// to make any decision. `got` is the buffer size we
        /// received; `need` is the minimum required for this
        /// decode step (often `HEADER_LEN` or a fixed prefix
        /// size). Truncation could be benign (a UDP fragment
        /// lost in transit) or hostile (a probe trying to
        /// trigger a panic in the decoder).
        #[error("packet too short: got {got} bytes, need at least {need}")]
        PacketTooShort { got: usize, need: usize },

        /// The 1-byte `packet_type` tag in the long header
        /// doesn't match any of the enum's known variants.
        /// Almost always a wire-version mismatch or a forged
        /// packet; drift::transport drops these silently at
        /// recv time.
        #[error("unknown packet type: {0}")]
        UnknownType(u8),

        /// The wire-format version field in the header is one
        /// this build doesn't understand. Currently the version
        /// byte is always `1`; any other value is rejected at
        /// header decode.
        #[error("unsupported protocol version: {0}")]
        UnsupportedVersion(u8),

        /// The header's stated `payload_len` doesn't match the
        /// actual buffer length after the header. Indicates wire
        /// corruption or framing desync; the receiver should
        /// drop the packet.
        #[error("payload length mismatch: header says {header}, actual {actual}")]
        LengthMismatch { header: usize, actual: usize },

        /// Generic codec-layer parse failure for sub-decoders
        /// that don't expose a more specific reason (federated
        /// envelope, signed announces, find-peer payloads). Add
        /// a specific variant when the caller actually needs to
        /// distinguish.
        #[error("malformed bytes for this codec")]
        Malformed,
    }
}

pub use codec::CodecError;

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

    /// User payload exceeded the configured maximum. `got` is the
    /// allowed ceiling; `cap` is the actual size the caller tried
    /// to send (yes, the field naming is backwards from what you'd
    /// expect — kept for back-compat with earlier call sites).
    #[error("payload too large: {cap} > allowed {got}")]
    PayloadTooLarge { got: usize, cap: usize },

    /// Generic codec-layer parse failure. Used for the federated
    /// envelope codec when the bytes don't match the expected
    /// `[32][32][32][2][payload]` layout, and for `send_typed`
    /// when called with an unsupported packet type.
    #[error("decode error")]
    DecodeError,
}

/// Map a codec-layer failure into the legacy flat `DriftError`
/// variants so transitive callers using `?` keep working
/// unchanged during the layered-error migration. New code that
/// wants layer-specific handling should match on `CodecError`
/// directly instead of relying on this conversion.
impl From<CodecError> for DriftError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::PacketTooShort { got, need } => DriftError::PacketTooShort { got, need },
            CodecError::UnknownType(v) => DriftError::UnknownType(v),
            CodecError::UnsupportedVersion(v) => DriftError::UnsupportedVersion(v),
            CodecError::LengthMismatch { header, actual } => {
                DriftError::LengthMismatch { header, actual }
            }
            CodecError::Malformed => DriftError::DecodeError,
        }
    }
}

pub type Result<T> = std::result::Result<T, DriftError>;

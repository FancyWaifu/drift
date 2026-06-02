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
//!   * **Slice 1 (PR #21, merged):** codec layer. `CodecError`
//!     exists, pure-codec functions (`PacketType::from_u8`,
//!     `Header::decode`, `decode_short`, `RotationAnnounce::decode`)
//!     return `Result<T, CodecError>`. `From<CodecError> for
//!     DriftError` keeps every transitive caller working
//!     unchanged.
//!   * **Slice 2 (PR #22, merged):** crypto layer. `CryptoError`
//!     with three distinct variants (`AeadAuthFailed`,
//!     `SignatureInvalid`, `Replay { seq }`) that previously
//!     collapsed into the flat `DriftError::AuthFailed` /
//!     `DriftError::Replay` umbrella. Pure-crypto functions
//!     (`xeddsa::verify`, `Session::check_and_update_replay`)
//!     return `Result<(), CryptoError>`. `From<CryptoError> for
//!     DriftError` preserves the old umbrella mapping for
//!     transitive callers. NOTE: `SessionKey::open` and
//!     `verify_against` straddle codec / crypto / identity
//!     layers and intentionally remain on `DriftError` until a
//!     later slice splits them into composable
//!     single-concern primitives.
//!   * **Slice 3 (PR #23, merged):** session lifecycle.
//!     `SessionError` covers `SessionExhausted` (seq counter at
//!     the AEAD-nonce safety ceiling), `HandshakeExhausted`
//!     (retry budget gone), and `QueueFull` (pending-send queue
//!     at capacity). The only pure-session-lifecycle producer in
//!     drift-core is `Peer::next_seq_checked`; it moves from
//!     `Option<u32>` to `Result<u32, SessionError>` so the ~9
//!     transport call sites that did
//!     `.ok_or(DriftError::SessionExhausted)?` collapse into
//!     plain `?`. `HandshakeExhausted` and `QueueFull` are still
//!     produced inline inside cross-layer transport sends and
//!     stay on `DriftError` until later slices split those sends.
//!   * **Slice 4 (this PR + follow-ups):** peer / federation.
//!     `PeerError` splits the flat `DriftError::UnknownPeer`
//!     into FIVE distinct semantic conditions that produce sites
//!     in `drift::transport::*` were silently conflating: peer
//!     not in the table, peer in table but session not ready,
//!     peer in table with handshake-ready session but not fully
//!     Established, incoming packet not addressed to us, and
//!     client resumption-ticket store miss. There are ~102 produce
//!     sites across 7 files; rather than doing them all at once,
//!     this PR (**slice 4a**) establishes the type and migrates
//!     `cookies.rs` (1 site, the `WrongDestination` case). The
//!     sub-series continues per-file: 4b = `mesh.rs` (4 sites),
//!     4c = `rtt.rs` (8), 4d = `path.rs` (10), 4e = `resumption.rs`
//!     (13), 4f = `mod.rs` (69, which may further sub-split).
//!     Note: `multipath.rs:probe_path` is a *misuse* of
//!     `UnknownPeer` for a path-probe deadline; it should be
//!     `DriftError::DeadlineExpired` and gets its own behavior-
//!     fix PR rather than being folded into PeerError. Each
//!     `PeerError` variant maps back to `DriftError::UnknownPeer`
//!     until slice 5 collapses the flat variant.
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

/// Crypto-layer authentication failures.
///
/// Produced by functions that verify cryptographic constructions
/// — AEAD decryption, XEdDSA signature verification, replay
/// window enforcement. Each variant names a distinct failure
/// mode rather than the flat `AuthFailed` umbrella, so callers
/// can distinguish "the signature is invalid" from "we already
/// saw this seq number" without string-matching on `Display`
/// output.
///
/// Convert into [`DriftError`] via `?` thanks to the
/// `From<CryptoError> for DriftError` impl below.
pub mod crypto {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum CryptoError {
        /// AEAD decryption rejected the ciphertext — the
        /// authentication tag didn't match. Means either the
        /// receiver tried the wrong key, or an attacker
        /// modified the ciphertext / forged the AAD in flight.
        /// In session use this almost always means a stale
        /// session entry vs. a peer that has re-handshook (see
        /// `feedback_one_identity_one_process.md`).
        #[error("AEAD authentication failed")]
        AeadAuthFailed,

        /// XEdDSA signature verification rejected the
        /// signature. Either the signed message was tampered
        /// with, the wrong pubkey was used to verify, or the
        /// signature is forged. Distinct from `AeadAuthFailed`
        /// even though both used to collapse into
        /// `DriftError::AuthFailed`.
        #[error("XEdDSA signature verification failed")]
        SignatureInvalid,

        /// The seq number in an incoming packet has already
        /// been seen in this session's replay window, OR seq=0
        /// (the reserved invalid value). The packet must be
        /// dropped without further processing.
        #[error("replay detected at seq {seq}")]
        Replay { seq: u32 },
    }
}

pub use crypto::CryptoError;

/// Session-lifecycle failures.
///
/// Produced by functions that maintain a peer's session-state
/// machine — seq counter exhaustion, handshake retry exhaustion,
/// pending-send queue at capacity. Distinct from `CryptoError`
/// (which covers AEAD / signature failures on individual packets):
/// session-lifecycle failures mean the session as a whole is in a
/// terminal state and the app has to tear it down (re-handshake,
/// drop the peer, back off).
///
/// Convert into [`DriftError`] via `?` thanks to the
/// `From<SessionError> for DriftError` impl below.
pub mod session {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum SessionError {
        /// The session's tx seq counter has reached
        /// `SEQ_SEND_CEILING`. Continuing to send would reuse an
        /// AEAD nonce under the same key, breaking the cipher's
        /// security proof. The app must rekey or re-handshake
        /// before any more packets can flow in this direction.
        #[error("session seq ceiling reached — re-handshake required")]
        SessionExhausted,

        /// The handshake retry budget has been exhausted with no
        /// HELLO_ACK arriving. The session is dead — the app has
        /// to drop and re-`add_peer` to attempt a fresh handshake.
        #[error("peer handshake exhausted all retries")]
        HandshakeExhausted,

        /// The peer's pre-handshake pending-send queue is full;
        /// further `send` calls will be rejected until the
        /// handshake completes and the queue drains. App should
        /// back off and retry.
        #[error("peer pending queue full")]
        QueueFull,
    }
}

pub use session::SessionError;

/// Peer-table + session-state-machine failures.
///
/// Splits what used to be the flat `DriftError::UnknownPeer`
/// umbrella into the distinct semantic conditions that produce
/// sites in `drift::transport::*` were silently conflating.
/// Five variants, all of which map back to
/// `DriftError::UnknownPeer` via the `From` impl below for
/// back-compat until slice 5 collapses the flat variant.
///
/// The split lets callers distinguish "the peer id is unknown
/// to us" (recoverable — register and retry) from "the peer is
/// known but its session isn't ready yet" (transient — retry
/// after handshake) from "this packet wasn't even addressed to
/// us" (almost certainly a routing bug or a misdirected probe).
pub mod peer {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum PeerError {
        /// `peers.get(&id)` returned None — the peer id is not
        /// in our peer table at all. App tried to send to a peer
        /// it never registered, or an incoming packet's src_id
        /// is one we have no entry for. The most common
        /// production reason for `UnknownPeer` today.
        #[error("peer is not registered in the peer table")]
        NotRegistered,

        /// The peer is in the table but `peer.handshake.session()`
        /// returned None — the handshake hasn't completed far
        /// enough to derive session keys. Transient; the caller
        /// should retry once the handshake progresses past
        /// `Pending` / `AwaitingAck`.
        #[error("peer session keys are not yet derived")]
        SessionNotReady,

        /// The peer has a session (keys derived) but is in
        /// `AwaitingData`, not fully `Established`. Stricter
        /// than [`SessionNotReady`](Self::SessionNotReady); used
        /// by paths that must not run before both sides have
        /// authenticated a round-trip (e.g. rekey, path probes
        /// after migration).
        #[error("peer session is not fully established yet")]
        SessionNotEstablished,

        /// The packet's `dst_id` doesn't match the local peer
        /// id — we are not the addressed recipient. Either an
        /// upstream routing bug, a misdirected probe, or an
        /// attacker trying to confuse us. Distinct from
        /// [`NotRegistered`](Self::NotRegistered) because here
        /// it's the *destination* that's wrong, not the source.
        #[error("packet not addressed to this peer")]
        WrongDestination,

        /// The client-side resumption ticket store has no entry
        /// for this peer id, OR the entry exists but has expired.
        /// App must perform a full handshake instead of attempting
        /// 1-RTT resumption. Distinct from
        /// [`NotRegistered`](Self::NotRegistered) because the
        /// *peer* may very well still be registered; only the
        /// *ticket* is missing.
        #[error("no valid resumption ticket for this peer")]
        ResumptionTicketNotFound,
    }
}

pub use peer::PeerError;

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

/// Map a crypto-layer failure into the legacy flat `DriftError`
/// variants so transitive callers using `?` keep working unchanged
/// during the layered-error migration. Both `AeadAuthFailed` and
/// `SignatureInvalid` collapse into the umbrella `AuthFailed`
/// for back-compat — the distinction is preserved at the
/// `CryptoError` level for callers that want it.
impl From<CryptoError> for DriftError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::AeadAuthFailed => DriftError::AuthFailed,
            CryptoError::SignatureInvalid => DriftError::AuthFailed,
            CryptoError::Replay { seq } => DriftError::Replay(seq),
        }
    }
}

/// Map a session-lifecycle failure into the legacy flat `DriftError`
/// variants so transitive callers using `?` keep working unchanged
/// during the layered-error migration. The mapping is 1:1 — every
/// `SessionError` variant has a corresponding `DriftError` variant
/// with the same name and meaning, and a later slice removes the
/// flat variants once no returner is left.
impl From<SessionError> for DriftError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::SessionExhausted => DriftError::SessionExhausted,
            SessionError::HandshakeExhausted => DriftError::HandshakeExhausted,
            SessionError::QueueFull => DriftError::QueueFull,
        }
    }
}

/// Map a peer-layer failure into the legacy flat `DriftError`
/// variant so transitive callers using `?` keep working unchanged
/// during the layered-error migration. Every `PeerError` variant
/// collapses into `DriftError::UnknownPeer` — preserving today's
/// behavior — but new code that wants to distinguish "peer not
/// registered" from "session not ready" can match on `PeerError`
/// directly instead of relying on context to disambiguate the
/// umbrella `UnknownPeer`. Slice 5 will eventually drop the flat
/// variant once no returner is left.
impl From<PeerError> for DriftError {
    fn from(_: PeerError) -> Self {
        DriftError::UnknownPeer
    }
}

pub type Result<T> = std::result::Result<T, DriftError>;

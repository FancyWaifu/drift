//! Sans-IO DRIFT protocol engine.
//!
//! This crate is the protocol state machine extracted from the
//! tokio transport: HELLO / CHALLENGE / HELLO_ACK choreography
//! (classical and X25519+ML-KEM-768 hybrid), DoS-cookie gating,
//! handshake retry/backoff, the 3× amplification budget, and the
//! long-header DATA path with replay protection. It performs **no
//! I/O**: callers feed it datagrams and timestamps, and drain
//! queued transmits and events. See `docs/SANSIO_DESIGN.md` at the
//! repo root for the architecture and the byte-compat invariants.
//!
//! The driver loop a platform has to write:
//!
//! ```no_run
//! use drift_proto::{Config, Endpoint, Event};
//! use drift_core::Identity;
//! use std::time::Instant;
//!
//! let mut ep = Endpoint::new(Identity::generate(), Config::default());
//! let peer = ep.connect(Instant::now(), [0u8; 32], "203.0.113.7:51820".parse().unwrap());
//! ep.send(Instant::now(), &peer, b"hi", 0, 0).ok();
//!
//! let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
//! let mut buf = [0u8; 2048];
//! loop {
//!     while let Some(t) = ep.poll_transmit() {
//!         socket.send_to(&t.contents, t.dst).unwrap();
//!     }
//!     if let Ok((n, src)) = socket.recv_from(&mut buf) {
//!         let _ = ep.handle_datagram(Instant::now(), src, &buf[..n]);
//!     }
//!     ep.handle_timeout(Instant::now());
//!     while let Some(ev) = ep.poll_event() {
//!         if let Event::Data { payload, .. } = ev { /* deliver */ }
//!     }
//! }
//! ```
//!
//! Byte compatibility with `drift::Transport` is enforced by the
//! interop tests in `drift/tests/proto_interop.rs`, which run this
//! engine over a plain `std::net::UdpSocket` against the real tokio
//! transport in both roles.

mod endpoint;
pub mod frame;
mod resumption;
pub mod time;
pub mod wire;

pub use endpoint::{Config, Endpoint, Event, ProtoError, Transmit};
pub use resumption::{ClientTicket, EXPORT_BLOB_LEN, TICKET_DEFAULT_TTL};

// Re-export the drift-core types a driver needs, so simple drivers
// can depend on drift-proto alone.
pub use drift_core::crypto::{Direction, PeerId};
pub use drift_core::{derive_peer_id, Identity};

use drift_core::header::{AUTH_TAG_LEN, HEADER_LEN};

/// Largest datagram the engine will emit. Matches
/// `drift::transport::MAX_PACKET` (conservative IPv6-safe floor).
pub const MAX_PACKET: usize = 1400;

/// Maximum application payload per DATA packet: `MAX_PACKET` minus
/// the long header and the AEAD tag. Matches
/// `drift::transport::MAX_PAYLOAD`.
pub const MAX_PAYLOAD: usize = MAX_PACKET - HEADER_LEN - AUTH_TAG_LEN;

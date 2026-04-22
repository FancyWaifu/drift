//! C ABI for the DRIFT transport.
//!
//! ## Design
//!
//! * **Opaque handles.** C never touches Rust structs directly;
//!   it gets `*mut DriftIdentity`, `*mut DriftTransport`, etc.
//!   Each handle is freed by a paired `drift_*_free` function.
//! * **Shared tokio runtime.** One `Runtime` for the life of the
//!   process, lazily created on first FFI call. Async functions
//!   on `Transport` are wrapped in `runtime.block_on` so C sees
//!   a blocking API.
//! * **Error codes.** Every fallible function returns
//!   `DriftResult` as an integer enum; output parameters fill
//!   in on success. `NULL` handle pointers return
//!   `DRIFT_ERR_INVALID_ARGUMENT`.
//! * **Thread safety.** Individual handles are not thread-safe
//!   (matches the Rust `Transport` API — it's `Send` but not
//!   `Sync` in the free-mutation sense). Wrap in a C mutex if
//!   you share one across threads.
//!
//! ## Memory model
//!
//! Callers own handles; the library owns the memory behind them.
//! `drift_*_free(NULL)` is a no-op (matches libc free). Returned
//! byte slices (e.g. message payloads) live on a `DriftMessage`
//! handle — don't retain pointers into them across a free call.

#![allow(non_camel_case_types)]

use drift::identity::Identity;
use drift::{Direction, Received, Transport};
use once_cell::sync::Lazy;
use std::ffi::CStr;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::Duration;
use tokio::runtime::Runtime;

// ──────────────────────── Shared runtime ────────────────────────

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("drift-ffi")
        .build()
        .expect("failed to build drift-ffi tokio runtime")
});

// ──────────────────────── Result codes ────────────────────────

/// Every fallible entry point returns one of these.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftResultCode {
    DRIFT_OK = 0,
    DRIFT_ERR_INVALID_ADDR = 1,
    DRIFT_ERR_UNKNOWN_PEER = 2,
    DRIFT_ERR_AUTH_FAILED = 3,
    DRIFT_ERR_PACKET_TOO_SHORT = 4,
    DRIFT_ERR_SESSION_EXHAUSTED = 5,
    DRIFT_ERR_HANDSHAKE_EXHAUSTED = 6,
    DRIFT_ERR_QUEUE_FULL = 7,
    DRIFT_ERR_TIMEOUT = 8,
    DRIFT_ERR_IO = 9,
    DRIFT_ERR_INVALID_ARGUMENT = 10,
    DRIFT_ERR_INTERNAL = 99,
}

fn map_err(e: drift::error::DriftError) -> DriftResultCode {
    use drift::error::DriftError as E;
    use DriftResultCode::*;
    match e {
        E::UnknownPeer => DRIFT_ERR_UNKNOWN_PEER,
        E::AuthFailed => DRIFT_ERR_AUTH_FAILED,
        E::PacketTooShort { .. } => DRIFT_ERR_PACKET_TOO_SHORT,
        E::SessionExhausted => DRIFT_ERR_SESSION_EXHAUSTED,
        E::HandshakeExhausted => DRIFT_ERR_HANDSHAKE_EXHAUSTED,
        E::QueueFull => DRIFT_ERR_QUEUE_FULL,
        E::Io(_) => DRIFT_ERR_IO,
        _ => DRIFT_ERR_INTERNAL,
    }
}

// ──────────────────────── Identity ────────────────────────

/// Opaque handle to a DRIFT identity (X25519 keypair).
pub struct DriftIdentity(Identity);

/// Generate a fresh random identity.
#[no_mangle]
pub extern "C" fn drift_identity_generate() -> *mut DriftIdentity {
    Box::into_raw(Box::new(DriftIdentity(Identity::generate())))
}

/// Build an identity deterministically from a 32-byte seed.
/// Returns NULL if `secret` is NULL.
#[no_mangle]
pub unsafe extern "C" fn drift_identity_from_secret(secret: *const u8) -> *mut DriftIdentity {
    if secret.is_null() {
        return ptr::null_mut();
    }
    let slice = std::slice::from_raw_parts(secret, 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(slice);
    Box::into_raw(Box::new(DriftIdentity(Identity::from_secret_bytes(seed))))
}

/// Copy the 32-byte public key into `out`. Returns non-zero on
/// NULL argument.
#[no_mangle]
pub unsafe extern "C" fn drift_identity_public_key(
    id: *const DriftIdentity,
    out: *mut u8,
) -> DriftResultCode {
    if id.is_null() || out.is_null() {
        return DriftResultCode::DRIFT_ERR_INVALID_ARGUMENT;
    }
    let id = &(*id).0;
    let pub_bytes = id.public_bytes();
    let dst = std::slice::from_raw_parts_mut(out, 32);
    dst.copy_from_slice(&pub_bytes);
    DriftResultCode::DRIFT_OK
}

/// Copy the 8-byte peer_id (BLAKE2b-truncated pubkey) into
/// `out`. Returns non-zero on NULL argument.
#[no_mangle]
pub unsafe extern "C" fn drift_identity_peer_id(
    id: *const DriftIdentity,
    out: *mut u8,
) -> DriftResultCode {
    if id.is_null() || out.is_null() {
        return DriftResultCode::DRIFT_ERR_INVALID_ARGUMENT;
    }
    let id = &(*id).0;
    let pid = id.peer_id();
    let dst = std::slice::from_raw_parts_mut(out, 8);
    dst.copy_from_slice(&pid);
    DriftResultCode::DRIFT_OK
}

/// Free an identity. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn drift_identity_free(id: *mut DriftIdentity) {
    if !id.is_null() {
        drop(Box::from_raw(id));
    }
}

// ──────────────────────── Transport ────────────────────────

/// Opaque handle to a DRIFT transport (a bound UDP socket +
/// peer table + handshake state machine).
pub struct DriftTransport(Transport);

/// Bind a UDP socket and return a transport handle.
/// `addr` is a C string like "0.0.0.0:9000" or "127.0.0.1:0".
/// The identity is consumed (freed on failure too — callers
/// should not free it themselves after this call).
#[no_mangle]
pub unsafe extern "C" fn drift_transport_bind(
    addr: *const c_char,
    identity: *mut DriftIdentity,
    out: *mut *mut DriftTransport,
) -> DriftResultCode {
    use DriftResultCode::*;
    if addr.is_null() || identity.is_null() || out.is_null() {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }

    // Take ownership of the identity so it's freed whether we
    // succeed or fail.
    let identity = Box::from_raw(identity).0;

    let addr_str = match CStr::from_ptr(addr).to_str() {
        Ok(s) => s,
        Err(_) => return DRIFT_ERR_INVALID_ARGUMENT,
    };
    let sock_addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return DRIFT_ERR_INVALID_ADDR,
    };

    match RUNTIME.block_on(Transport::bind(sock_addr, identity)) {
        Ok(t) => {
            *out = Box::into_raw(Box::new(DriftTransport(t)));
            DRIFT_OK
        }
        Err(e) => map_err(e),
    }
}

/// Register a peer by its 32-byte public key and remote address.
/// `initiator` is 1 for the client side (the side that sends
/// HELLO first), 0 for the responder side. On success, `out_pid`
/// receives the 8-byte peer_id used for subsequent operations.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_add_peer(
    transport: *mut DriftTransport,
    peer_pub: *const u8,
    addr: *const c_char,
    initiator: c_int,
    out_pid: *mut u8,
) -> DriftResultCode {
    use DriftResultCode::*;
    if transport.is_null() || peer_pub.is_null() || addr.is_null() || out_pid.is_null() {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    let t = &(*transport).0;

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(std::slice::from_raw_parts(peer_pub, 32));

    let addr_str = match CStr::from_ptr(addr).to_str() {
        Ok(s) => s,
        Err(_) => return DRIFT_ERR_INVALID_ARGUMENT,
    };
    let sock_addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return DRIFT_ERR_INVALID_ADDR,
    };

    let direction = if initiator != 0 {
        Direction::Initiator
    } else {
        Direction::Responder
    };

    match RUNTIME.block_on(t.add_peer(pub_bytes, sock_addr, direction)) {
        Ok(pid) => {
            std::slice::from_raw_parts_mut(out_pid, 8).copy_from_slice(&pid);
            DRIFT_OK
        }
        Err(e) => map_err(e),
    }
}

/// Send an encrypted DATA packet to `peer_id`.
/// `deadline_ms` = 0 disables deadline semantics (short-header
/// fast path eligible). `coalesce_group` = 0 disables coalescing.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_send_data(
    transport: *mut DriftTransport,
    peer_id: *const u8,
    payload: *const u8,
    payload_len: usize,
    deadline_ms: u16,
    coalesce_group: u32,
) -> DriftResultCode {
    use DriftResultCode::*;
    if transport.is_null() || peer_id.is_null() || (payload.is_null() && payload_len != 0) {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    let t = &(*transport).0;
    let mut pid = [0u8; 8];
    pid.copy_from_slice(std::slice::from_raw_parts(peer_id, 8));
    let slice = std::slice::from_raw_parts(payload, payload_len);
    match RUNTIME.block_on(t.send_data(&pid, slice, deadline_ms, coalesce_group)) {
        Ok(()) => DRIFT_OK,
        Err(e) => map_err(e),
    }
}

/// Receive one decrypted DATA packet. Blocks up to `timeout_ms`
/// for a packet; pass 0 to wait forever. On success, `out_msg`
/// receives a handle to be freed with `drift_message_free`.
/// On timeout returns `DRIFT_ERR_TIMEOUT` and writes NULL to
/// `*out_msg`.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_recv(
    transport: *mut DriftTransport,
    timeout_ms: u64,
    out_msg: *mut *mut DriftMessage,
) -> DriftResultCode {
    use DriftResultCode::*;
    if transport.is_null() || out_msg.is_null() {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    *out_msg = ptr::null_mut();
    let t = &(*transport).0;

    // Build the future + timeout *inside* block_on — tokio
    // timers are registered at construction time, not at first
    // poll, so calling `tokio::time::timeout(...)` outside a
    // runtime context panics with "there is no reactor
    // running".
    let received = RUNTIME.block_on(async {
        if timeout_ms == 0 {
            Ok(t.recv().await)
        } else {
            tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                t.recv(),
            )
            .await
        }
    });

    let received = match received {
        Ok(v) => v,
        Err(_) => return DRIFT_ERR_TIMEOUT,
    };

    match received {
        Some(msg) => {
            *out_msg = Box::into_raw(Box::new(DriftMessage(msg)));
            DRIFT_OK
        }
        None => DRIFT_ERR_IO, // channel closed — transport was torn down
    }
}

/// Current transport metrics. Lightweight snapshot — atomic
/// loads only, no locks.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_handshakes_completed(
    transport: *const DriftTransport,
) -> u64 {
    if transport.is_null() {
        return 0;
    }
    (*transport).0.metrics().handshakes_completed
}

/// Write the transport's local socket address into `out_buf`
/// as a null-terminated C string (e.g. "127.0.0.1:54321").
/// `buf_len` is the size of `out_buf` including the nul byte
/// (64 bytes is always enough — IPv6 maxes out around 54).
/// On error, `*out_buf` is set to the empty string.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_local_addr(
    transport: *const DriftTransport,
    out_buf: *mut c_char,
    buf_len: usize,
) -> DriftResultCode {
    use DriftResultCode::*;
    if transport.is_null() || out_buf.is_null() || buf_len == 0 {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    let t = &(*transport).0;
    let addr = match t.local_addr() {
        Ok(a) => a,
        Err(_) => return DRIFT_ERR_IO,
    };
    let s = addr.to_string();
    let bytes = s.as_bytes();
    // Leave one byte for the NUL terminator.
    if bytes.len() + 1 > buf_len {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    let dst = std::slice::from_raw_parts_mut(out_buf as *mut u8, buf_len);
    dst[..bytes.len()].copy_from_slice(bytes);
    dst[bytes.len()] = 0;
    DRIFT_OK
}

/// Free a transport. Safe to call with NULL. Aborts all
/// background tasks on drop.
#[no_mangle]
pub unsafe extern "C" fn drift_transport_free(transport: *mut DriftTransport) {
    if !transport.is_null() {
        drop(Box::from_raw(transport));
    }
}

// ──────────────────────── Message ────────────────────────

/// Opaque handle to a received message.
pub struct DriftMessage(Received);

/// Number of bytes in the payload.
#[no_mangle]
pub unsafe extern "C" fn drift_message_payload_len(msg: *const DriftMessage) -> usize {
    if msg.is_null() {
        return 0;
    }
    (*msg).0.payload.len()
}

/// Pointer to the payload bytes. Valid until `drift_message_free`
/// is called on this handle.
#[no_mangle]
pub unsafe extern "C" fn drift_message_payload(msg: *const DriftMessage) -> *const u8 {
    if msg.is_null() {
        return ptr::null();
    }
    (*msg).0.payload.as_ptr()
}

/// Copy the sender peer_id (8 bytes) into `out`.
#[no_mangle]
pub unsafe extern "C" fn drift_message_peer_id(
    msg: *const DriftMessage,
    out: *mut u8,
) -> DriftResultCode {
    use DriftResultCode::*;
    if msg.is_null() || out.is_null() {
        return DRIFT_ERR_INVALID_ARGUMENT;
    }
    let pid = (*msg).0.peer_id;
    std::slice::from_raw_parts_mut(out, 8).copy_from_slice(&pid);
    DRIFT_OK
}

/// Free a received message. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn drift_message_free(msg: *mut DriftMessage) {
    if !msg.is_null() {
        drop(Box::from_raw(msg));
    }
}

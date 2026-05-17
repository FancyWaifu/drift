//! Per-thread wire-buffer pool.
//!
//! Every DRIFT packet send allocates a fresh `Vec<u8>` to hold
//! the encrypted wire bytes (header + ciphertext + AEAD tag).
//! Recycling those buffers eliminates allocator pressure for
//! every adapter equally — the allocation is above the
//! `PacketIO` trait, so UDP/TCP/WS/TLS/HTTP/DNS all pay it.
//!
//! Thread-local + bounded + capacity-aware. No deps, no unsafe.
//! Buffers crossing thread boundaries (tokio migration) just
//! land in a different thread's pool — correct, slightly less
//! optimal, no failure mode.

use std::cell::RefCell;

const POOL_CAP_PER_THREAD: usize = 16;
const TYPICAL_WIRE_SIZE: usize = 1280;

thread_local! {
    static WIRE_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(POOL_CAP_PER_THREAD));
}

/// Take an empty `Vec<u8>` with at least `min_capacity` of
/// pre-allocated space. Reuses a pooled buffer if available.
#[inline]
pub fn take_wire_buf(min_capacity: usize) -> Vec<u8> {
    WIRE_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if let Some(pos) = pool.iter().rposition(|v| v.capacity() >= min_capacity) {
            return pool.swap_remove(pos);
        }
        Vec::with_capacity(min_capacity.max(TYPICAL_WIRE_SIZE))
    })
}

/// Return a buffer to the pool. Clears contents (retains
/// capacity). Drops if pool is at cap.
#[inline]
pub fn return_wire_buf(mut buf: Vec<u8>) {
    buf.clear();
    WIRE_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if pool.len() < POOL_CAP_PER_THREAD {
            pool.push(buf);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_returns_empty_vec_with_capacity() {
        let v = take_wire_buf(512);
        assert_eq!(v.len(), 0);
        assert!(v.capacity() >= 512);
    }

    #[test]
    fn round_trip_reuses_capacity() {
        let mut v1 = take_wire_buf(100);
        v1.extend_from_slice(b"hello world");
        let cap_before = v1.capacity();
        return_wire_buf(v1);
        let v2 = take_wire_buf(50);
        assert_eq!(v2.len(), 0);
        assert_eq!(v2.capacity(), cap_before);
    }

    #[test]
    fn pool_bounded() {
        for _ in 0..(POOL_CAP_PER_THREAD * 4) {
            return_wire_buf(Vec::with_capacity(256));
        }
        WIRE_POOL.with(|p| {
            assert!(p.borrow().len() <= POOL_CAP_PER_THREAD);
        });
    }
}

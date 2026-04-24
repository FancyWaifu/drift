//! Ring-buffer scrollback for reattach.
//!
//! When a client disconnects and reattaches, we want their
//! screen to look the same as when they left — not blank.
//! The simplest way to do that without running a terminal
//! emulator is to keep the most recent N bytes of pty output
//! in a ring buffer and replay them on reattach.
//!
//! That's not a true terminal-state sync (a mid-screen vim
//! session might redraw slightly wrong if the cursor was in
//! an unusual state), but it gets 90% of the user-visible
//! benefit with a few hundred lines of code instead of a few
//! thousand.

use std::collections::VecDeque;

pub struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
}

impl Scrollback {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Append bytes. Drops the oldest bytes if the total
    /// would exceed the cap.
    pub fn push(&mut self, bytes: &[u8]) {
        // Trim `bytes` if it alone exceeds the cap — in that
        // case we only keep the tail.
        let effective = if bytes.len() >= self.cap {
            &bytes[bytes.len() - self.cap..]
        } else {
            bytes
        };

        let room = self.cap.saturating_sub(self.buf.len());
        if effective.len() > room {
            let drop = effective.len() - room;
            for _ in 0..drop.min(self.buf.len()) {
                self.buf.pop_front();
            }
        }
        self.buf.extend(effective);
    }

    /// Drain the buffered bytes as a Vec for replay. Does not
    /// empty the buffer — the data is still useful for
    /// subsequent reattaches within the same session.
    pub fn replay(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_to_cap() {
        let mut s = Scrollback::new(4);
        s.push(b"abcdef");
        assert_eq!(s.replay(), b"cdef");
    }

    #[test]
    fn multi_push_drops_oldest() {
        let mut s = Scrollback::new(4);
        s.push(b"ab");
        s.push(b"cd");
        s.push(b"ef");
        assert_eq!(s.replay(), b"cdef");
    }

    #[test]
    fn handles_exact_fit() {
        let mut s = Scrollback::new(4);
        s.push(b"abcd");
        assert_eq!(s.replay(), b"abcd");
    }

    #[test]
    fn handles_empty() {
        let s = Scrollback::new(4);
        assert!(s.is_empty());
        assert_eq!(s.replay(), b"");
    }
}

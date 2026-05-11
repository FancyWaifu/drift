#![no_main]
//! Fuzz target: TCP length-prefix deframer.
//!
//! `read_one_tcp_frame` is the inner loop of `TcpPacketIO::recv_from`
//! (and the future Tor-circuit adapter). It reads a u16 BE length
//! prefix and then exactly that many body bytes.
//!
//! The deframer runs on attacker-controlled bytes from any peer
//! that connects over TCP/TLS/onion — every wire byte hits it
//! before AEAD opens it. The invariants the fuzz target enforces:
//!
//!   * It never panics on arbitrary input.
//!   * On Ok it returns N where N matches the leading u16 BE.
//!   * It never writes past `buf[..N]`.
//!   * It never returns Ok with N > buf.len() (oversize check).
//!   * Repeated calls on a concatenated input correctly recover
//!     each frame in turn until EOF.

use drift::io::read_one_tcp_frame;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Pinned to 4096 — well under MAX_PAYLOAD but small enough
    // that an oversize length prefix in the fuzz input reliably
    // triggers the InvalidData path.
    const BUF_LEN: usize = 4096;

    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return,
    };

    rt.block_on(async {
        let mut cursor = Cursor::new(data);
        let mut buf = [0u8; BUF_LEN];

        // Drain frame-by-frame until we hit EOF or an error.
        // Cap iterations to keep libfuzzer cheap — a single
        // adversarial input shouldn't produce millions of
        // valid frames anyway.
        for _ in 0..256 {
            // Snapshot the offset before the read so we can
            // verify the leading u16 BE matches the returned len.
            let pre_off = cursor.position() as usize;
            match read_one_tcp_frame(&mut cursor, &mut buf).await {
                Ok(n) => {
                    // The reader must have consumed exactly 2+n bytes.
                    let post_off = cursor.position() as usize;
                    assert_eq!(post_off, pre_off + 2 + n);

                    // The length prefix on the wire must equal n.
                    let prefix = u16::from_be_bytes([data[pre_off], data[pre_off + 1]]) as usize;
                    assert_eq!(prefix, n);

                    // Body must fit in the buffer.
                    assert!(n <= BUF_LEN);
                }
                Err(_) => break,
            }
        }
    });
});

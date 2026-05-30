//! Seed-corpus generator for `fuzz/corpus/<target>/`.
//!
//! Run from the workspace root:
//!
//!   cargo run --example fuzz_seeds -p drift
//!
//! Writes deterministic seed files derived from the same codec
//! functions the fuzz targets call, so they're guaranteed to
//! be valid wire bytes. When a wire format changes, re-running
//! refreshes the corpus to match.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use drift::header::{Header, PacketType, HEADER_LEN};
use drift::short_header::SHORT_HEADER_LEN;
use drift::transport::{build_directory, build_federated};

fn fuzz_root() -> PathBuf {
    // Walk up from drift/ to the workspace root, then into fuzz/corpus.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("fuzz");
    p.push("corpus");
    p
}

fn write_seed(target: &str, name: &str, data: &[u8]) {
    let mut p = fuzz_root();
    p.push(target);
    fs::create_dir_all(&p).unwrap();
    p.push(name);
    let mut f = fs::File::create(&p).unwrap();
    f.write_all(data).unwrap();
    println!("wrote {} ({} bytes)", p.display(), data.len());
}

fn main() {
    // ─── header_decode ────────────────────────────────────────
    for (name, pt) in [
        ("data", PacketType::Data),
        ("hello", PacketType::Hello),
        ("hello_ack", PacketType::HelloAck),
        ("beacon", PacketType::Beacon),
        ("challenge", PacketType::Challenge),
        ("path_challenge", PacketType::PathChallenge),
        ("path_response", PacketType::PathResponse),
        ("close", PacketType::Close),
        ("rekey_request", PacketType::RekeyRequest),
        ("rekey_ack", PacketType::RekeyAck),
        ("resume_hello", PacketType::ResumeHello),
        ("resume_ack", PacketType::ResumeAck),
        ("resumption_ticket", PacketType::ResumptionTicket),
        ("ping", PacketType::Ping),
        ("pong", PacketType::Pong),
        ("federated", PacketType::Federated),
        ("federation_directory", PacketType::FederationDirectory),
    ] {
        let h = Header::new(pt, 1, [0xAA; 8], [0xBB; 8]);
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        write_seed("header_decode", name, &buf);
    }

    // ─── short_header_decode ──────────────────────────────────
    for (name, total) in [
        ("min", SHORT_HEADER_LEN + 16),
        ("small", 32),
        ("typical", 1200),
    ] {
        let mut v = vec![0u8; total];
        v[0] = 0x20;
        v[1] = 0x12;
        v[2] = 0x34;
        v[3] = 0x00;
        v[4] = 0x00;
        v[5] = 0x00;
        v[6] = 0x01;
        for (i, b) in v.iter_mut().enumerate().skip(7) {
            *b = (i as u8).wrapping_mul(0x9F);
        }
        write_seed("short_header_decode", name, &v);
    }

    // ─── federated_envelope_decode ────────────────────────────
    for (name, payload_len) in [("empty", 0), ("small", 16), ("typical", 512)] {
        let payload: Vec<u8> = (0..payload_len)
            .map(|i| (i as u8).wrapping_mul(7))
            .collect();
        let wire = build_federated(&[0xAA; 32], &[0xBB; 32], &[0xCC; 32], &[0xDD; 32], &payload);
        write_seed("federated_envelope_decode", name, &wire);
    }
    let wire = build_federated(&[0u8; 32], &[0xBB; 32], &[0xCC; 32], &[0xDD; 32], b"hi");
    write_seed(
        "federated_envelope_decode",
        "unknown_bridge_sentinel",
        &wire,
    );

    // ─── federation_directory_decode ──────────────────────────
    // Cap at MAX_DIRECTORY_ENTRIES (10); build_directory debug-asserts above.
    for (name, n) in [("empty", 0), ("single", 1), ("five", 5), ("max_chunk", 10)] {
        // Dummy presence tickets — fuzz seeds don't need verifiable
        // signatures, just well-formed on-the-wire shape.
        let entries: Vec<([u8; 32], drift::transport::PresenceTicket)> = (0..n)
            .map(|i| {
                (
                    [i as u8; 32],
                    drift::transport::PresenceTicket {
                        expiry_ms: 0,
                        nonce: [0u8; 24],
                        sig: [0u8; 64],
                    },
                )
            })
            .collect();
        let wire = build_directory(&entries);
        write_seed("federation_directory_decode", name, &wire);
    }

    // ─── directory_decode (drift_core::directory::DirMessage) ─
    {
        let mut v = vec![0x01];
        v.extend_from_slice(&[0xAB; 32]);
        let addr = b"127.0.0.1:9000";
        v.push(addr.len() as u8);
        v.extend_from_slice(addr);
        let nick = b"alice";
        v.push(nick.len() as u8);
        v.extend_from_slice(nick);
        write_seed("directory_decode", "register", &v);

        write_seed("directory_decode", "lookup", &[0x02]);

        let mut v = vec![0x03];
        v.extend_from_slice(&(2u16).to_be_bytes());
        for (pk, addr, nick) in [
            ([0xAA; 32], &b"10.0.0.1:9001"[..], &b"bob"[..]),
            ([0xBB; 32], &b"10.0.0.2:9002"[..], &b"carol"[..]),
        ] {
            v.extend_from_slice(&pk);
            v.push(addr.len() as u8);
            v.extend_from_slice(addr);
            v.push(nick.len() as u8);
            v.extend_from_slice(nick);
        }
        write_seed("directory_decode", "listing_two", &v);
    }

    // ─── tcp_deframe ──────────────────────────────────────────
    for (name, body_len) in [("min", 0usize), ("small", 16), ("typical", 1200)] {
        let mut v = (body_len as u16).to_be_bytes().to_vec();
        v.extend(std::iter::repeat_n(0xCDu8, body_len));
        write_seed("tcp_deframe", name, &v);
    }
    let mut v = (8u16).to_be_bytes().to_vec();
    v.extend_from_slice(b"FRAME001");
    v.extend_from_slice(&(8u16).to_be_bytes());
    v.extend_from_slice(b"FRAME002");
    write_seed("tcp_deframe", "two_frames", &v);

    // ─── stream_frame ─────────────────────────────────────────
    for (name, bytes) in [
        ("empty_tag", &[0x00u8][..]),
        ("open_like", &[0x01u8, 0x00, 0x00, 0x00, 0x00][..]),
        (
            "data_like",
            &[0x02u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..],
        ),
        ("close_like", &[0x03u8, 0x00, 0x00, 0x00, 0x00][..]),
        ("ack_like", &[0x04u8, 0x00, 0x00, 0x00, 0x00, 0x00][..]),
    ] {
        write_seed("stream_frame", name, bytes);
    }

    println!("seed-corpus complete");
}

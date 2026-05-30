//! ML-KEM-768 per-operation latency bench (#[test] form — no
//! criterion dep). Useful for checking that PQ-default-on is
//! affordable on weak hardware. Print-only; not pass/fail
//! unless an operation is wildly slow (>10ms/op).
//!
//! Run with:
//!   cargo test --release -p drift-core --test pq_bench -- --nocapture

use drift_core::pq::{
    client_generate_keypair, derive_hybrid_key, server_encapsulate, ML_KEM_SS_LEN,
};
use std::time::Instant;

const ITERS: u32 = 200;

fn avg_us<F: FnMut()>(label: &str, mut f: F) -> f64 {
    // 50-iter warmup to settle caches.
    for _ in 0..50 {
        f();
    }
    let t0 = Instant::now();
    for _ in 0..ITERS {
        f();
    }
    let elapsed = t0.elapsed();
    let us_per = elapsed.as_secs_f64() * 1_000_000.0 / ITERS as f64;
    eprintln!(
        "  {:<35} {:>8.2} µs/op  ({:>5.0} ops/s)",
        label,
        us_per,
        1_000_000.0 / us_per
    );
    us_per
}

#[test]
fn ml_kem_per_op_latency() {
    eprintln!();
    eprintln!(
        "ML-KEM-768 per-op latency ({} iters, post-50 warmup):",
        ITERS
    );

    // 1. Client keygen
    let keygen = avg_us("client_generate_keypair (keygen)", || {
        let _ = client_generate_keypair();
    });

    // 2. Server encap (needs a real ek)
    let (ek, _dk) = client_generate_keypair();
    let encap = avg_us("server_encapsulate (encap)", || {
        let _ = server_encapsulate(&ek).expect("encap");
    });

    // 3. Client decap (needs a real ct + dk)
    let (ek, dk) = client_generate_keypair();
    let (ct, _) = server_encapsulate(&ek).expect("encap");
    let decap = avg_us("dk.decapsulate (decap)", || {
        let _ = dk.decapsulate(&ct).expect("decap");
    });

    // 4. Hybrid KDF (BLAKE2b on the combined material)
    let static_dh = [0x11u8; 32];
    let eph_dh = [0x22u8; 32];
    let mlkem_ss = [0x33u8; ML_KEM_SS_LEN];
    let cnonce = [0x44u8; 16];
    let snonce = [0x55u8; 16];
    let kdf = avg_us("derive_hybrid_key (BLAKE2b mix)", || {
        let _ = derive_hybrid_key(&static_dh, &eph_dh, &mlkem_ss, &cnonce, &snonce);
    });

    eprintln!();
    eprintln!(
        "Per-handshake cost (client side):  keygen + decap + kdf = {:.0} µs",
        keygen + decap + kdf
    );
    eprintln!(
        "Per-handshake cost (server side):  encap + kdf          = {:.0} µs",
        encap + kdf
    );
    eprintln!();

    // Sanity ceiling: refuse to ship anything insanely slow on
    // any platform. ML-KEM-768 reference impl should clock in
    // well under 1ms/op on any modern CPU and well under 10ms
    // on the slowest router-class chip we'd target.
    assert!(
        keygen < 10_000.0,
        "keygen too slow ({} µs): would dominate handshake budget",
        keygen
    );
    assert!(encap < 10_000.0, "encap too slow ({} µs)", encap);
    assert!(decap < 10_000.0, "decap too slow ({} µs)", decap);
}

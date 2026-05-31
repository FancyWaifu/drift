//! Regression test: every iroh listener binding in one process
//! shares the same underlying `Endpoint`.
//!
//! Background: the K=3 federation BEACON-asymmetry bug was caused
//! by a bridge having TWO iroh `Endpoint`s — one for its listener,
//! one for its outbound `--federate` dial. With two endpoints, iroh
//! can't dedup connections across them, so mutual dials (bridge A
//! dials B AND B dials A simultaneously) both succeed; DRIFT's
//! dual-init handler merges sessions but the federation routing
//! table only records one direction.
//!
//! The fix in `wire_iroh.rs` is the process-wide `SHARED_ENDPOINT`
//! OnceCell. This test asserts that two listener binds in the same
//! process share an endpoint id — meaning a single bridge with both
//! `--listen iroh://` and `--federate iroh://` will use one Endpoint,
//! and iroh's per-peer connection dedup applies across accept and
//! connect paths.

#![cfg(feature = "iroh")]

use drift::io::Listener;
use drift::wire_iroh::{IrohListenerIO, IrohPreset};
use std::net::SocketAddr;

#[tokio::test]
async fn two_binds_share_one_endpoint() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let hint: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let a = IrohListenerIO::bind_with_preset(hint, IrohPreset::Minimal)
        .await
        .expect("first bind");
    let b = IrohListenerIO::bind_with_preset(hint, IrohPreset::Minimal)
        .await
        .expect("second bind");

    // Listener::local_addr returns the first IPv4 bound socket of
    // the shared Endpoint. If two distinct Endpoints existed, they'd
    // each pick a distinct ephemeral UDP port — equality of these
    // sockets is a proxy for "we're sharing one endpoint."
    let a_addr = a.local_addr().expect("a local_addr");
    let b_addr = b.local_addr().expect("b local_addr");
    assert_eq!(
        a_addr, b_addr,
        "two IrohListenerIO binds in one process must share the same \
         underlying iroh Endpoint (same bound UDP socket). Got a={a_addr} b={b_addr}. \
         SHARED_ENDPOINT regression — without this, K=3+ mutual-init federation \
         loses BEACONs in one direction."
    );
}

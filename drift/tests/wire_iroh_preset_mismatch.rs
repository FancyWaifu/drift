//! Regression test: a single bridge process cannot mix the `iroh://`
//! and `iroh-n0://` schemes.
//!
//! Background: `wire_iroh.rs` builds one process-wide
//! `SHARED_ENDPOINT` (per iroh's own recommendation — single
//! Endpoint per app) and locks it to whichever preset bound first.
//! The K=3 federation BEACON-asymmetry bug was caused by two
//! iroh Endpoints in one process, so this constraint isn't just
//! ergonomic. Mixing schemes must fail loudly at bind time, not
//! silently produce two endpoints.
//!
//! This test runs in its own integration-test binary because the
//! `SHARED_ENDPOINT` `OnceCell` is process-global — first bind in
//! the process determines the preset forever.

#![cfg(feature = "iroh")]

use drift::io::Listener;
use drift::wire_iroh::{IrohListenerIO, IrohPreset};
use std::net::SocketAddr;

#[tokio::test]
async fn mixing_iroh_and_iroh_n0_in_one_process_errors() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let hint: SocketAddr = "0.0.0.0:0".parse().unwrap();

    // First bind: Minimal preset (iroh:// scheme). Should succeed.
    let listener_minimal = IrohListenerIO::bind_with_preset(hint, IrohPreset::Minimal)
        .await
        .expect("first bind (Minimal) should succeed");
    // Force the bind to fully take effect.
    let _ = listener_minimal.local_addr();

    // Second bind: N0 preset (iroh-n0:// scheme). Same process,
    // same SHARED_ENDPOINT → must error with the preset-mismatch
    // message.
    let result = IrohListenerIO::bind_with_preset(hint, IrohPreset::N0).await;
    let err = match result {
        Ok(_) => panic!(
            "second bind with a different preset MUST fail — \
             SHARED_ENDPOINT is process-global and the first preset \
             determines the rest of the process"
        ),
        Err(e) => e,
    };

    let msg = err.to_string();
    assert!(
        msg.contains("preset mismatch"),
        "preset-mismatch error has the wrong shape: {msg}"
    );
    assert!(
        msg.contains("Minimal") && msg.contains("N0"),
        "error should name both presets so the operator can fix \
         their config: {msg}"
    );
}

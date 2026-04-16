#![no_main]
//! Fuzz target: stream-layer frame handling. Feeds arbitrary
//! bytes to `StreamManager::test_handle_frame` and asserts no
//! panics or unbounded allocations.
//!
//! Each iteration spins up a fresh Transport+StreamManager pair
//! on an unused UDP port — slow, but libfuzzer runs for as long
//! as you let it, so correctness matters more than raw
//! iterations/sec.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::Transport;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use tokio::runtime::Runtime;

fuzz_target!(|data: &[u8]| {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let id = Identity::from_secret_bytes([0x42; 32]);
        let transport = Arc::new(
            Transport::bind("127.0.0.1:0".parse().unwrap(), id)
                .await
                .unwrap(),
        );
        let mgr = StreamManager::bind(transport.clone()).await;
        // Synthetic peer id — doesn't need to exist in the peer
        // table since `test_handle_frame` only touches the
        // stream-layer maps keyed by (peer, stream_id).
        let fake_peer = [0xABu8; 8];
        mgr.test_handle_frame(fake_peer, data).await;
        // If we got here without panic, the frame was handled
        // safely.
    });
});

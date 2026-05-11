#![no_main]
//! Fuzz target: stream-layer frame handling (v2).
//!
//! Feeds arbitrary bytes to `StreamManager::test_handle_frame`
//! and asserts the per-peer state stays bounded regardless of
//! input. v1 spun a fresh Transport+StreamManager per iteration —
//! correct but expensive (sub-100 iter/s). v2 holds a single
//! shared StreamManager in `OnceLock` and wipes the per-peer
//! state between iterations via `wipe_peer_streams`, so each
//! call only pays the cost of dispatching a frame.
//!
//! Invariants asserted at the end of each iteration:
//!   * `live_streams_for(fake_peer) <= MAX_STREAMS_PER_PEER` (1024)
//!   * `total_buffered_segments()` stays bounded — we use 64×1024
//!     as the soft ceiling (well above MAX_STREAMS_PER_PEER and
//!     well below any value that would indicate runaway buffering).

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::Transport;
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;

static MGR: OnceLock<(Arc<Runtime>, Arc<StreamManager>)> = OnceLock::new();

/// Maximum live streams the manager will hold per peer (must
/// match `MAX_STREAMS_PER_PEER` in `drift/src/streams.rs`).
/// If that constant ever changes, update this — the fuzz target
/// will surface a divergence either way.
const MAX_STREAMS_PER_PEER: usize = 1024;
/// Soft ceiling on total buffered segments across all streams.
/// Each stream's recv_buf is bounded internally; this is the
/// product of the per-stream cap and the stream-count cap with
/// generous slack.
const BUFFERED_SEGMENTS_CEILING: usize = 64 * 1024;

fn mgr() -> (Arc<Runtime>, Arc<StreamManager>) {
    MGR.get_or_init(|| {
        let rt = Arc::new(Runtime::new().expect("build tokio runtime"));
        let mgr = rt.block_on(async {
            let id = Identity::from_secret_bytes([0x42; 32]);
            let transport = Arc::new(
                Transport::bind("127.0.0.1:0".parse().unwrap(), id)
                    .await
                    .expect("bind transport"),
            );
            StreamManager::bind(transport).await
        });
        (rt, mgr)
    })
    .clone()
}

fuzz_target!(|data: &[u8]| {
    let (rt, mgr) = mgr();
    rt.block_on(async {
        let fake_peer = [0xABu8; 8];
        mgr.test_handle_frame(fake_peer, data).await;

        // State must stay bounded regardless of input.
        let live = mgr.live_streams_for(&fake_peer).await;
        assert!(
            live <= MAX_STREAMS_PER_PEER,
            "live_streams_for={} exceeds cap {}",
            live,
            MAX_STREAMS_PER_PEER
        );
        let buffered = mgr.total_buffered_segments().await;
        assert!(
            buffered <= BUFFERED_SEGMENTS_CEILING,
            "total_buffered_segments={} exceeds soft ceiling {}",
            buffered,
            BUFFERED_SEGMENTS_CEILING
        );

        // Reset per-peer state for the next iteration — cheap.
        mgr.wipe_peer_streams(&fake_peer).await;
    });
});

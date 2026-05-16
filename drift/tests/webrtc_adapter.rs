//! End-to-end test: DRIFT over the WebRTC native adapter.
//!
//! Two `RTCPeerConnection`s are created in-process and negotiate
//! SDP directly via tokio channels — no STUN, no signaling
//! server. Once a DataChannel is open on both ends, each side
//! wraps it in `WebRTCPacketIO` and brings up a DRIFT
//! `Transport`. We then run a full HELLO/HELLO_ACK/DATA round-
//! trip to confirm the adapter speaks DRIFT correctly over
//! WebRTC's reliable, ordered DataChannel.
//!
//! This is the in-process equivalent of `drift-chat`'s
//! browser-style flow — same peer connection setup, same
//! data-channel handshake — but without the TCP signaling
//! detour, so we can run it as a standard `cargo test`.

use drift::identity::Identity;
use drift::io::{PacketIO, WebRTCPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

async fn new_peer_connection(
) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
    let api = APIBuilder::new().build();
    // No STUN — host candidates only, fine for loopback.
    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    Ok(Arc::new(api.new_peer_connection(cfg).await?))
}

/// Wait for ICE gathering to finish (so the local description
/// contains all host candidates before we hand it to the peer).
async fn wait_for_ice_complete(pc: Arc<RTCPeerConnection>) {
    let mut gather = pc.gathering_complete_promise().await;
    let _ = gather.recv().await;
}

/// Offerer-side: create the DataChannel up front and return a
/// future that resolves when `on_open` fires.
async fn offerer_dc(
    pc: Arc<RTCPeerConnection>,
) -> Result<
    tokio::sync::oneshot::Receiver<Arc<RTCDataChannel>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let dc = pc.create_data_channel("drift", None).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    let dc_clone = dc.clone();
    let tx_clone = tx.clone();
    dc.on_open(Box::new(move || {
        let tx = tx_clone.clone();
        let dc = dc_clone.clone();
        Box::pin(async move {
            if let Some(sender) = tx.lock().await.take() {
                let _ = sender.send(dc);
            }
        })
    }));
    Ok(rx)
}

/// Answerer-side: wait for the inbound `on_data_channel` event,
/// then wait for that channel's `on_open`.
fn answerer_dc(
    pc: Arc<RTCPeerConnection>,
) -> tokio::sync::oneshot::Receiver<Arc<RTCDataChannel>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let tx = tx.clone();
        Box::pin(async move {
            let dc_clone = dc.clone();
            let tx_clone = tx.clone();
            dc.on_open(Box::new(move || {
                let tx = tx_clone.clone();
                let dc = dc_clone.clone();
                Box::pin(async move {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(dc);
                    }
                })
            }));
        })
    }));
    rx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    target_os = "macos",
    ignore = "webrtc-rs ICE gathering hangs on macOS in loopback mode; \
              see Quick Win 1 in the session retrospective"
)]
async fn handshake_and_data_over_webrtc() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info".into()),
        )
        .try_init();

    // ── 1. Build two peer connections ─────────────────────────
    let pc_a = new_peer_connection().await.unwrap();
    let pc_b = new_peer_connection().await.unwrap();

    // A is the offerer (creates the DataChannel), B the answerer.
    let dc_a_rx = offerer_dc(pc_a.clone()).await.unwrap();
    let dc_b_rx = answerer_dc(pc_b.clone());

    // ── 2. SDP exchange ───────────────────────────────────────
    // Direct in-process: A's offer → B; B's answer → A.
    let offer = pc_a.create_offer(None).await.unwrap();
    pc_a.set_local_description(offer).await.unwrap();
    wait_for_ice_complete(pc_a.clone()).await;
    let a_local = pc_a.local_description().await.unwrap();

    pc_b
        .set_remote_description(RTCSessionDescription::offer(a_local.sdp).unwrap())
        .await
        .unwrap();
    let answer = pc_b.create_answer(None).await.unwrap();
    pc_b.set_local_description(answer).await.unwrap();
    wait_for_ice_complete(pc_b.clone()).await;
    let b_local = pc_b.local_description().await.unwrap();

    pc_a
        .set_remote_description(RTCSessionDescription::answer(b_local.sdp).unwrap())
        .await
        .unwrap();

    // ── 3. Wait for both data channels to open ────────────────
    let dc_a = tokio::time::timeout(Duration::from_secs(15), dc_a_rx)
        .await
        .expect("DC A open timeout")
        .expect("DC A oneshot dropped");
    let dc_b = tokio::time::timeout(Duration::from_secs(15), dc_b_rx)
        .await
        .expect("DC B open timeout")
        .expect("DC B oneshot dropped");

    // ── 4. Wrap each side in WebRTCPacketIO ───────────────────
    // The "addr" field is a placeholder — DataChannels are
    // point-to-point so there's nothing meaningful to put here.
    let placeholder_a: std::net::SocketAddr = "127.0.0.1:60001".parse().unwrap();
    let placeholder_b: std::net::SocketAddr = "127.0.0.1:60002".parse().unwrap();
    let io_a: Arc<dyn PacketIO> = Arc::new(WebRTCPacketIO::new(dc_a, placeholder_a));
    let io_b: Arc<dyn PacketIO> = Arc::new(WebRTCPacketIO::new(dc_b, placeholder_b));

    // ── 5. Build DRIFT Transports on each side ────────────────
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB2; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let alice = Arc::new(
        Transport::bind_with_io(io_a, alice_id, cfg.clone())
            .await
            .unwrap(),
    );
    let bob = Arc::new(
        Transport::bind_with_io(io_b, bob_id, cfg.clone()).await.unwrap(),
    );

    // Pre-register peers (placeholder addrs, since WebRTC
    // doesn't have a meaningful "address" for routing).
    let bob_peer = alice
        .add_peer(bob_pub, placeholder_b, Direction::Initiator)
        .await
        .unwrap();
    bob.add_peer(alice_pub, placeholder_a, Direction::Responder)
        .await
        .unwrap();

    // ── 6. Send DATA, expect it on the other side ─────────────
    alice.send_data(&bob_peer, b"hello-over-webrtc", 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(10), bob.recv())
        .await
        .expect("HELLO/HELLO_ACK/DATA over WebRTC timed out")
        .unwrap();
    assert_eq!(pkt.payload, b"hello-over-webrtc");

    // Send a few more to make sure the established session is
    // healthy after the handshake completes.
    for i in 0..5u32 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    for _ in 0..5 {
        let p = tokio::time::timeout(Duration::from_secs(5), bob.recv())
            .await
            .expect("post-handshake DATA timed out")
            .unwrap();
        assert_eq!(p.payload.len(), 4);
    }
}

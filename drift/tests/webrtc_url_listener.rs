//! End-to-end test for `webrtc://` listener.
//!
//! A `drift bridge`-style server listens on `webrtc://127.0.0.1:0`.
//! A test client opens a WebSocket to the signaling URL, runs the
//! mirror of `wire_webrtc.rs`'s server-side dance (server is
//! offerer, client is answerer), waits for the data channel to
//! open, wraps it in `WebRTCPacketIO`, and runs a full DRIFT
//! HELLO/HELLO_ACK/DATA round-trip against the server.
//!
//! Proves the listener works without needing a browser. The
//! browser harness in `drift-wasm/test/browser/tests/webrtc.spec.ts`
//! exercises the same wire from real browsers in CI.

use drift::identity::Identity;
use drift::io::WebRTCPacketIO;
use drift::{Direction, Transport, TransportConfig};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

#[derive(serde::Serialize, serde::Deserialize)]
struct SignalMsg {
    kind: String,
    sdp: String,
}

async fn new_peer_connection() -> Arc<RTCPeerConnection> {
    let api = APIBuilder::new().build();
    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    Arc::new(api.new_peer_connection(cfg).await.unwrap())
}

async fn wait_for_ice_complete(pc: Arc<RTCPeerConnection>) {
    let mut gather = pc.gathering_complete_promise().await;
    let _ = gather.recv().await;
}

/// Mirror of the wasm-side flow: connect to signaling, receive
/// offer, send answer, wait for the data channel to open via
/// `ondatachannel`. Returns the opened channel.
async fn connect_client(ws_url: &str) -> Arc<RTCDataChannel> {
    let (ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let pc = new_peer_connection().await;
    // Register the data-channel-open future before SDP exchange:
    // ondatachannel fires when remote SDP describes the channel,
    // which happens during setRemoteDescription below.
    let (dc_tx, dc_rx) = tokio::sync::oneshot::channel();
    let dc_tx = Arc::new(tokio::sync::Mutex::new(Some(dc_tx)));
    pc.on_data_channel(Box::new({
        let dc_tx = dc_tx.clone();
        move |dc: Arc<RTCDataChannel>| {
            let dc_tx = dc_tx.clone();
            Box::pin(async move {
                let dc_for_open = dc.clone();
                let tx_for_open = dc_tx.clone();
                dc.on_open(Box::new(move || {
                    let dc_tx = tx_for_open.clone();
                    let dc = dc_for_open.clone();
                    Box::pin(async move {
                        if let Some(sender) = dc_tx.lock().await.take() {
                            let _ = sender.send(dc);
                        }
                    })
                }));
            })
        }
    }));

    // Receive offer from server.
    let offer_text = loop {
        match ws_rx.next().await.expect("ws closed").unwrap() {
            Message::Text(t) => break t,
            _ => continue,
        }
    };
    let offer: SignalMsg = serde_json::from_str(&offer_text).unwrap();
    assert_eq!(offer.kind, "offer");
    pc.set_remote_description(RTCSessionDescription::offer(offer.sdp).unwrap())
        .await
        .unwrap();

    // Create + send answer.
    let answer = pc.create_answer(None).await.unwrap();
    pc.set_local_description(answer).await.unwrap();
    wait_for_ice_complete(pc.clone()).await;
    let local = pc.local_description().await.unwrap();
    let answer_json = serde_json::to_string(&SignalMsg {
        kind: "answer".into(),
        sdp: local.sdp,
    })
    .unwrap();
    ws_tx.send(Message::Text(answer_json)).await.unwrap();

    timeout(Duration::from_secs(15), dc_rx)
        .await
        .expect("data channel didn't open within 15s")
        .expect("dc oneshot dropped")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    target_os = "macos",
    ignore = "webrtc-rs ICE gathering hangs on macOS in loopback mode; \
              same root cause as drift/tests/webrtc_adapter.rs"
)]
async fn webrtc_url_listener_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=info".into()),
        )
        .try_init();

    let server_id = Identity::from_secret_bytes([0xA1; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    };
    let (server, bound_url) = Transport::bind_url("webrtc://127.0.0.1:0", server_id, cfg)
        .await
        .unwrap();
    let server = Arc::new(server);
    eprintln!("[test] server bound at {}", bound_url);

    // bound_url is like "webrtc://127.0.0.1:54321"; client speaks WS.
    let ws_url = bound_url.replace("webrtc://", "ws://");

    // Client side: SDP exchange + open data channel.
    let dc = connect_client(&ws_url).await;

    // Wrap the data channel in a DRIFT Transport (responder
    // side from DRIFT's POV — server initiates HELLO, this
    // client responds).
    //
    // Actually wait — drift's `webrtc://` listener treats the
    // wrapped data channel as if it were any other accepted
    // PacketIO. The server's `accept_any_peer = true` means it
    // auto-registers the client when the client's HELLO
    // arrives.
    let client_id = Identity::from_secret_bytes([0xB1; 32]);
    let client_pub = client_id.public_bytes();
    let placeholder_addr: std::net::SocketAddr = "127.0.0.1:60001".parse().unwrap();
    let client_io = Arc::new(WebRTCPacketIO::new(dc, placeholder_addr));
    let client = Arc::new(
        Transport::bind_with_io(
            client_io,
            client_id,
            TransportConfig {
                accept_any_peer: true,
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );

    // The client's HELLO targets the server's identity via the
    // single PacketIO it has (the data channel). The server
    // recognises us via accept_any_peer.
    let server_peer = client
        .add_peer(server_pub, placeholder_addr, Direction::Initiator)
        .await
        .unwrap();
    // Hand-register the client side on the server so the
    // server's add_peer auto-rule is bypassed (and so the
    // server's send path resolves to the right interface).
    server
        .add_peer(client_pub, placeholder_addr, Direction::Responder)
        .await
        .unwrap();

    client
        .send_data(&server_peer, b"hello-over-webrtc-url", 0, 0)
        .await
        .unwrap();
    let pkt = timeout(Duration::from_secs(15), server.recv())
        .await
        .expect("DRIFT handshake over webrtc:// didn't complete")
        .expect("server recv returned None");
    assert_eq!(pkt.payload, b"hello-over-webrtc-url");
}

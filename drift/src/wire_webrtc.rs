//! `webrtc://` listener adapter.
//!
//! Server side of a WebRTC-data-channel transport. Browsers
//! (and other peers without a fixed routable address) can dial
//! `webrtc://host:port`, which connects to a tiny WebSocket
//! signaling endpoint that exchanges SDP, then upgrades to a
//! direct WebRTC RTCDataChannel. From that point on DRIFT
//! traffic rides the data channel — peer-to-peer through any
//! NAT via DTLS-over-ICE.
//!
//! Wire shape:
//!
//!   1. Client opens a WebSocket to `ws://host:port` (the same
//!      port we bound for `webrtc://`).
//!   2. Server sends a text frame `{"kind":"offer","sdp":"..."}`
//!      — full SDP (no trickle ICE; we wait for gathering to
//!      complete first because loopback / LAN cases finish in
//!      a few hundred ms and the simpler model avoids signaling-
//!      side state).
//!   3. Client replies with `{"kind":"answer","sdp":"..."}`.
//!   4. Server completes the WebRTC handshake. The data channel
//!      named "drift" opens on both sides.
//!   5. Signaling WebSocket closes; server wraps the data
//!      channel as `WebRTCPacketIO` and yields it to the
//!      Transport as a new interface.
//!
//! Browser-side note: the WASM `DriftClient.connectWebRtc`
//! takes an already-open `RTCDataChannel` — the SDP exchange is
//! the caller's responsibility. The browser harness in
//! `drift-wasm/test/browser/tests/webrtc.spec.ts` shows the
//! corresponding client flow (open WS, set remote, create
//! answer, wait for ondatachannel, hand the channel to
//! connectWebRtc).
//!
//! Pattern cribbed from `drift/examples/drift_chat.rs`'s
//! `accept_webrtc_peer`, which uses raw TCP signaling. We swap
//! TCP for WebSocket so browsers can drive the signaling step.

use crate::io::{Listener, PacketIO, WebRTCPacketIO};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Default timeout for the SDP-and-ICE-complete round trip.
/// Loopback gathers in <300ms; LAN paths in <1s; WAN with
/// real STUN servers can be a few seconds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// JSON wire format on the signaling WebSocket. One text
/// frame per message; `kind` is either `"offer"` or
/// `"answer"`.
#[derive(serde::Serialize, serde::Deserialize)]
struct SignalMsg {
    kind: String,
    sdp: String,
}

/// `webrtc://host:port` listener. The bind port is the
/// WebSocket signaling endpoint; once SDP exchange completes,
/// the data plane moves to the WebRTC data channel (separate
/// UDP/DTLS ports negotiated by ICE).
pub(crate) struct WebRtcListenerIO {
    tcp: TcpListener,
}

impl WebRtcListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self { tcp })
    }
}

#[async_trait]
impl Listener for WebRtcListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    fn is_multi(&self) -> bool {
        true
    }

    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let (stream, remote) = self.tcp.accept().await?;
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .map_err(io::Error::other)?;
        let dc = tokio::time::timeout(HANDSHAKE_TIMEOUT, run_signaling(ws))
            .await
            .map_err(|_| io::Error::other("webrtc signaling timeout"))?
            .map_err(io::Error::other)?;
        Ok(Arc::new(WebRTCPacketIO::new(dc, remote)))
    }
}

/// Server-side SDP exchange. Server is the OFFERER: it
/// creates the data channel up front (so the client's
/// `ondatachannel` handler fires on the answerer side), emits
/// the SDP offer, waits for the answer, and returns once the
/// data channel reaches the `open` state.
async fn run_signaling(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error + Send + Sync>> {
    let pc = new_peer_connection().await?;
    let dc_ready = spawn_data_channel_opener(pc.clone()).await?;

    let offer = pc.create_offer(None).await?;
    pc.set_local_description(offer).await?;
    wait_for_ice_complete(pc.clone()).await;
    let local = pc
        .local_description()
        .await
        .ok_or("no local description after ICE")?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    let offer_json = serde_json::to_string(&SignalMsg {
        kind: "offer".into(),
        sdp: local.sdp,
    })?;
    ws_tx.send(Message::Text(offer_json)).await?;

    // Wait for the answerer's text frame. Drop binary /
    // control frames; they're not part of the protocol but
    // some clients send pings.
    let answer_text = loop {
        match ws_rx.next().await {
            Some(Ok(Message::Text(t))) => break t,
            Some(Ok(Message::Binary(_))) => continue,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                return Err("signaling closed before answer".into())
            }
            Some(Ok(Message::Frame(_))) => continue,
            Some(Err(e)) => return Err(Box::new(e)),
        }
    };
    let answer: SignalMsg = serde_json::from_str(&answer_text)?;
    if answer.kind != "answer" {
        return Err(format!("expected answer, got {}", answer.kind).into());
    }
    let rtc_answer = RTCSessionDescription::answer(answer.sdp)?;
    pc.set_remote_description(rtc_answer).await?;

    let dc = dc_ready.await?;
    // Signaling is done. The data channel carries everything
    // from here on; ws_tx / ws_rx drop and the WebSocket
    // closes naturally.
    Ok(dc)
}

async fn new_peer_connection(
) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
    let api = APIBuilder::new().build();
    let cfg = RTCConfiguration {
        // Google's public STUN servers. We include them by
        // default because:
        //   - WAN bridges need server-reflexive candidates to
        //     be reachable behind NAT.
        //   - On macOS loopback, webrtc-rs's host-candidate
        //     gathering hangs (a known issue — see the
        //     `cfg_attr(ignore, target_os = "macos")` gates on
        //     drift/tests/webrtc_adapter.rs etc.); adding STUN
        //     gives ICE *something* to work with so the
        //     handshake completes even from a Mac dev host.
        // For air-gapped LAN deployments where STUN is
        // unreachable, ICE will time out on the STUN candidate
        // gathering (a few seconds) and fall back to host
        // candidates — that's acceptable.
        ice_servers: vec![webrtc::ice_transport::ice_server::RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }],
        ..Default::default()
    };
    Ok(Arc::new(api.new_peer_connection(cfg).await?))
}

async fn spawn_data_channel_opener(
    pc: Arc<RTCPeerConnection>,
) -> Result<
    impl std::future::Future<Output = Result<Arc<RTCDataChannel>, &'static str>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let dc = pc.create_data_channel("drift", None).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    let dc_for_open = dc.clone();
    let tx_for_open = tx.clone();
    dc.on_open(Box::new(move || {
        let tx = tx_for_open.clone();
        let dc = dc_for_open.clone();
        Box::pin(async move {
            if let Some(sender) = tx.lock().await.take() {
                let _ = sender.send(dc);
            }
        })
    }));
    Ok(async move { rx.await.map_err(|_| "data channel sender dropped") })
}

async fn wait_for_ice_complete(pc: Arc<RTCPeerConnection>) {
    let mut gather = pc.gathering_complete_promise().await;
    let _ = gather.recv().await;
}

// ─── Scheme registration ───────────────────────────────────────────
//
// `webrtc://host:port` URLs route here. No connector — the
// native side currently has no programmatic WebRTC client; raw
// peers wanting to dial a `webrtc://` listener can use the
// `drift-chat` example's `connect_webrtc_peer` pattern as a
// reference.

fn webrtc_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = crate::io::parse_ip_addr(&addr_str).await?;
        Ok(Box::new(WebRtcListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn webrtc_connector_factory(
    _addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no programmatic WebRTC client (yet); use the \
             drift-chat example's connect_webrtc_peer for now",
        ))
    })
}

inventory::submit! {
    crate::io::SchemeRegistration {
        scheme: "webrtc",
        listener: webrtc_listener_factory,
        connector: webrtc_connector_factory,
    }
}

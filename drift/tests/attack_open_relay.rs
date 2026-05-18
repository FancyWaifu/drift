//! SEC.FIX.1 — open-relay guard.
//!
//! Before the fix, an unauthenticated host could send bytes to a
//! `drift bridge` carrying a crafted DRIFT header whose `dst_id`
//! matched a peer the bridge had a direct session with (and
//! `hop_ttl > 1`), and the bridge would re-emit those bytes to the
//! victim with the bridge's IP as source — a reflection /
//! amplification primitive that also breaks accountability
//! (operators couldn't distinguish forged traffic from legit
//! forwarded traffic).
//!
//! The fix lives in `Inner::forward_packet_inner`: when the
//! bridge's `require_src_for_forward` config flag is set (default
//! on for `drift bridge`), forwards are gated by source address
//! against the peer table. `drift bridge`'s CLI exposes
//! `--allow-open-relay` as an opt-out escape hatch for
//! trusted-mesh fixtures.
//!
//! The attack primitive is wire-agnostic (any adapter that
//! delivers bytes into `process_incoming` is in scope), and the
//! gate is too, because it operates on the post-decode `src`
//! address. The per-wire tests prove each adapter's listener
//! correctly propagates the source identity into the gate.
//!
//! Live coverage in this file:
//!   - udp://    raw `UdpSocket::send_to`
//!   - tcp://    raw `TcpStream` + `[len:be16][packet]` framing
//!   - tls://    rustls client + same length-prefix framing
//!   - ws://     `tokio-tungstenite` binary frames
//!   - http://   GET /drift-sse → POST /drift-send?sid=
//!
//! Adapters not live-tested here but covered by the same gate:
//!   - webtransport://, webrtc://  native client side is
//!     intentionally browser-only in drift (per
//!     `webtransport_connector_factory`); a Rust-native attacker
//!     would need to replicate the WASM-side client harness.
//!     Listeners use `incoming.remote_address()` / post-ICE addr
//!     for the per-connection `src`, so the gate fires identically.
//!   - dns://, doh://, onion://  tunneled-adapter schemes whose
//!     `src` is the resolver / hop addr, not the original
//!     attacker. The gate still fires (no resolver completes a
//!     HELLO with the bridge under normal use), but the granularity
//!     of "what gets blocked" differs and is documented as
//!     architecture rather than tested here.

use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{derive_peer_id, Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

fn bridge_config() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        require_src_for_forward: true,
        ..TransportConfig::default()
    }
}

fn legacy_open_config() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        require_src_for_forward: false,
        ..TransportConfig::default()
    }
}

/// Encode one DRIFT packet (header + body) ready for any adapter
/// that takes whole-packet bytes (UDP datagram, one TCP frame
/// payload, one WS binary frame, etc.).
fn forge_packet(dst_id: [u8; 8], body: &[u8], pkt_type: PacketType) -> Vec<u8> {
    let mut header = Header::new(pkt_type, 0xDEAD_BEEF, [0u8; 8], dst_id);
    header = header.with_hop_ttl(8);
    header.payload_len = body.len() as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&hbuf);
    out.extend_from_slice(body);
    out
}

/// Pull the `host:port` out of a `scheme://host:port` URL.
fn parse_bound_addr(url: &str) -> SocketAddr {
    url.splitn(2, "://")
        .nth(1)
        .expect("bound URL has scheme")
        .parse()
        .expect("bound URL ends in valid socketaddr")
}

/// Build the topology used by every wire test: bridge + victim
/// federated via the same scheme. Returns (bridge_transport,
/// bridge_listen_addr, victim_peer_id). Victim's handshake is
/// driven to completion before returning, so the bridge has both
/// a peer-table entry and (after the next beacon tick) a route
/// entry for `victim_peer_id` — both forwarding paths are armed
/// for the gate to potentially fire.
async fn build_topology(
    scheme: &str,
    cfg: TransportConfig,
) -> (Arc<Transport>, SocketAddr, [u8; 8]) {
    let bind_url = format!("{}://127.0.0.1:0", scheme);
    let bridge_id = Identity::from_secret_bytes([0xB0; 32]);
    let (bridge, bridge_url) = Transport::bind_url(&bind_url, bridge_id, cfg)
        .await
        .unwrap();
    let bridge = Arc::new(bridge);
    let bridge_addr = parse_bound_addr(&bridge_url);
    let bridge_pub = bridge.local_public();

    let victim_id = Identity::from_secret_bytes([0xC1; 32]);
    let victim_pub = victim_id.public_bytes();
    let victim_peer_id = derive_peer_id(&victim_pub);
    let (victim, peer_addr) =
        Transport::connect_url(&bridge_url, victim_id, TransportConfig::default())
            .await
            .unwrap();
    let victim = Arc::new(victim);
    let bridge_handle = victim
        .add_peer(bridge_pub, peer_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = victim.send_data(&bridge_handle, b"x", 1000, 0).await;
    // Hold the victim transport alive across the rest of the
    // test by leaking the Arc — dropping it would tear down the
    // session and the peer entry, which the gate test depends
    // on. Test process exits when the runtime ends, so this is
    // benign.
    Box::leak(Box::new(victim));
    tokio::time::sleep(Duration::from_millis(500)).await;
    (bridge, bridge_addr, victim_peer_id)
}

// ─── UDP attacker ────────────────────────────────────────────────

async fn udp_attacker_fires(bridge_addr: SocketAddr, dst_id: [u8; 8], n: usize) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = forge_packet(dst_id, b"FORGED-UDP", PacketType::Data);
    for _ in 0..n {
        sock.send_to(&pkt, bridge_addr).await.unwrap();
    }
}

#[tokio::test]
async fn udp_open_relay_attack_is_blocked() {
    let (bridge, bridge_addr, victim_id) = build_topology("udp", bridge_config()).await;
    let before = bridge.metrics();
    udp_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "udp: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "udp: bridge forwarded {} attack packets",
        after.forwarded - before.forwarded
    );
}

#[tokio::test]
async fn udp_open_relay_attack_succeeds_with_legacy_opt_in() {
    let (bridge, bridge_addr, victim_id) =
        build_topology("udp", legacy_open_config()).await;
    let before = bridge.metrics();
    udp_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        0,
        "udp legacy: guard should be off — saw {} drops",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert!(
        after.forwarded - before.forwarded >= 1,
        "udp legacy: bridge should reflect — saw {} forwards",
        after.forwarded - before.forwarded
    );
}

#[tokio::test]
async fn udp_federated_packet_type_is_also_blocked() {
    // Confirms the gate fires regardless of packet type. The
    // open-relay primitive originally exploited PacketType::Data,
    // but PacketType::Federated rides the same forward path
    // (which is what made the attack type-agnostic).
    let (bridge, bridge_addr, victim_id) = build_topology("udp", bridge_config()).await;
    let before = bridge.metrics();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = forge_packet(victim_id, b"FORGED-FED", PacketType::Federated);
    for _ in 0..5 {
        sock.send_to(&pkt, bridge_addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "fed: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "fed: bridge forwarded {} packets",
        after.forwarded - before.forwarded
    );
}

#[tokio::test]
async fn udp_random_dst_ids_dont_leak_peer_membership() {
    // Peer-enumeration regression. Pre-fix, the bridge forwarded
    // only packets whose dst_id matched a known peer, which let
    // an on-path observer (or the bridge's own log scraper) tell
    // "real peer" from "random guess" by counting forwards.
    // Post-fix, both buckets produce identical guard-drops — no
    // side channel.
    let (bridge, bridge_addr, victim_id) = build_topology("udp", bridge_config()).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let before = bridge.metrics();
    // 1 real dst_id + 9 random ones. Pre-fix only the 1 real
    // would have forwarded; post-fix all 10 hit the same drop
    // path so the count is 10, not 1.
    let real_pkt = forge_packet(victim_id, b"REAL", PacketType::Data);
    sock.send_to(&real_pkt, bridge_addr).await.unwrap();
    for i in 0..9 {
        let mut fake_dst = [0u8; 8];
        fake_dst[0] = 0xAA;
        fake_dst[7] = i;
        let p = forge_packet(fake_dst, b"FAKE", PacketType::Data);
        sock.send_to(&p, bridge_addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        10,
        "enum: expected 10 identical guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "enum: real dst should also drop — saw {} forwards",
        after.forwarded - before.forwarded
    );
}

// ─── TCP attacker ────────────────────────────────────────────────
//
// TCP framing per `wire_tcp` / `TcpPacketIO::send_to`: 2-byte
// big-endian length prefix + packet bytes. One DRIFT packet per
// frame.

async fn tcp_attacker_fires(bridge_addr: SocketAddr, dst_id: [u8; 8], n: usize) {
    use tokio::io::AsyncWriteExt;
    let mut stream = TcpStream::connect(bridge_addr).await.unwrap();
    for _ in 0..n {
        let pkt = forge_packet(dst_id, b"FORGED-TCP", PacketType::Data);
        let len = (pkt.len() as u16).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&pkt).await.unwrap();
    }
    stream.flush().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_open_relay_attack_is_blocked() {
    let (bridge, bridge_addr, victim_id) = build_topology("tcp", bridge_config()).await;
    let before = bridge.metrics();
    tcp_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "tcp: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "tcp: bridge forwarded {} attack packets",
        after.forwarded - before.forwarded
    );
}

// ─── WebSocket attacker ──────────────────────────────────────────
//
// WS framing per `wire_ws` / `WsPacketIO`: one DRIFT packet per
// binary WebSocket message — no length prefix, the WS layer
// handles message framing.

async fn ws_attacker_fires(bridge_addr: SocketAddr, dst_id: [u8; 8], n: usize) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let url = format!("ws://{}/", bridge_addr);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
    for _ in 0..n {
        let pkt = forge_packet(dst_id, b"FORGED-WS", PacketType::Data);
        ws.send(Message::Binary(pkt)).await.unwrap();
    }
    ws.close(None).await.ok();
}

// ─── TLS attacker ────────────────────────────────────────────────
//
// TLS framing per `wire_tls` / `TlsPacketIO`: same 2-byte length
// prefix as TCP, just wrapped in a TLS record. The bridge's TLS
// listener uses a self-signed cert and does not request a client
// cert, so the attacker can complete the handshake with a no-cert-
// verify client.

async fn tls_attacker_fires(bridge_addr: SocketAddr, dst_id: [u8; 8], n: usize) {
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::TlsConnector;

    // Mirror drift's own NoCertVerifier from drift/src/io.rs.
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(bridge_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    for _ in 0..n {
        let pkt = forge_packet(dst_id, b"FORGED-TLS", PacketType::Data);
        let len = (pkt.len() as u16).to_be_bytes();
        tls.write_all(&len).await.unwrap();
        tls.write_all(&pkt).await.unwrap();
    }
    tls.flush().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_open_relay_attack_is_blocked() {
    let (bridge, bridge_addr, victim_id) = build_topology("tls", bridge_config()).await;
    let before = bridge.metrics();
    tls_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "tls: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "tls: bridge forwarded {} attack packets",
        after.forwarded - before.forwarded
    );
}

// ─── HTTP attacker ───────────────────────────────────────────────
//
// HTTP framing per `wire_http`: client opens an SSE stream
// (`GET /drift-sse`) — server allocates a PacketIO keyed by the
// SSE connection's TCP peer, and sends back `SID:<u64hex>`. Then
// the client posts packets to `POST /drift-send?sid=<sid>` with
// the raw packet as the request body. The bridge's gate sees
// `src` = SSE connection's TCP peer addr (not the POST's), so
// an unauthenticated attacker still presents a unique tuple
// that doesn't match any known peer.

async fn http_attacker_fires(bridge_addr: SocketAddr, dst_id: [u8; 8], n: usize) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // Step 1: open SSE stream, read SID.
    let mut sse = TcpStream::connect(bridge_addr).await.unwrap();
    sse.write_all(
        format!(
            "GET /drift-sse HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\n\r\n",
            bridge_addr
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let (sse_read, mut sse_write) = sse.into_split();
    let mut sse_reader = BufReader::new(sse_read);
    // Skip response head until blank line.
    let mut line = String::new();
    loop {
        line.clear();
        let read = sse_reader.read_line(&mut line).await.unwrap();
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    // Read first SSE event: "data: SID:<hex>\n\n"
    let sid_hex = loop {
        line.clear();
        sse_reader.read_line(&mut line).await.unwrap();
        if let Some(rest) = line.strip_prefix("data: SID:") {
            break rest.trim().to_string();
        }
        assert!(!line.is_empty(), "SSE stream closed before SID");
    };

    // Step 2: POST forged packets on a separate connection.
    for _ in 0..n {
        let pkt = forge_packet(dst_id, b"FORGED-HTTP", PacketType::Data);
        let mut post = TcpStream::connect(bridge_addr).await.unwrap();
        let req = format!(
            "POST /drift-send?sid={} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
            sid_hex,
            bridge_addr,
            pkt.len()
        );
        post.write_all(req.as_bytes()).await.unwrap();
        post.write_all(&pkt).await.unwrap();
        post.flush().await.ok();
        // Drain the response so the server doesn't see a TCP
        // RST mid-write.
        let mut sink = [0u8; 256];
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::io::AsyncReadExt::read(&mut post, &mut sink),
        )
        .await;
    }

    // Keep SSE alive long enough for the packets to flow through.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = sse_write.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_open_relay_attack_is_blocked() {
    let (bridge, bridge_addr, victim_id) = build_topology("http", bridge_config()).await;
    let before = bridge.metrics();
    http_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "http: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "http: bridge forwarded {} attack packets",
        after.forwarded - before.forwarded
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_open_relay_attack_is_blocked() {
    let (bridge, bridge_addr, victim_id) = build_topology("ws", bridge_config()).await;
    let before = bridge.metrics();
    ws_attacker_fires(bridge_addr, victim_id, 5).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = bridge.metrics();
    assert_eq!(
        after.forward_unauth_drops - before.forward_unauth_drops,
        5,
        "ws: expected 5 guard-drops, got {}",
        after.forward_unauth_drops - before.forward_unauth_drops
    );
    assert_eq!(
        after.forwarded, before.forwarded,
        "ws: bridge forwarded {} attack packets",
        after.forwarded - before.forwarded
    );
}

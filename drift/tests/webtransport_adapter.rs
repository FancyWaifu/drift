//! End-to-end test: DRIFT over the WebTransport native adapter.
//!
//! Two DRIFT transports, one acting as the WebTransport server
//! and the other as client. Both wrap their `wtransport::Connection`
//! as a `WebTransportPacketIO` and run the full DRIFT protocol
//! (handshake, AEAD, DATA delivery) over QUIC datagrams.
//!
//! This proves the native WebTransport adapter interops with
//! itself; the browser-side adapter (drift-wasm::wire_webtransport)
//! speaks the same wire (one DRIFT packet per QUIC datagram, same
//! `drift-core` protocol code), so a browser-to-native WebTransport
//! handshake follows the same logic without additional changes to
//! this crate — what it needs is a browser harness + cert handoff,
//! which is out of scope for this test.

use drift::identity::Identity;
use drift::io::WebTransportPacketIO;
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use wtransport::{ClientConfig, Endpoint, Identity as WtIdentity, ServerConfig};

#[tokio::test]
async fn handshake_and_data_over_webtransport() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wtransport=debug,drift=info".into()),
        )
        .try_init();

    // Self-signed localhost identity for the server.
    let server_identity = WtIdentity::self_signed(["localhost", "127.0.0.1"]).unwrap();

    // Server endpoint on a random localhost port. The example
    // server uses `with_bind_default(0)` + keep_alive — both
    // matter for a connection to come up cleanly on loopback.
    let server_config = ServerConfig::builder()
        .with_bind_default(0)
        .with_identity(server_identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();
    let server = Endpoint::server(server_config).unwrap();
    let server_addr: SocketAddr = server.local_addr().unwrap();

    // Test-only: disable cert validation so we don't have to
    // plumb the self-signed cert hash through the client config
    // builder. A real deployment uses `with_server_certificate_hashes`
    // (for localhost + dev) or `with_native_certs` (for public CAs).
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client = Endpoint::client(client_config).unwrap();

    // Use `localhost` in the URL so TLS SNI matches the cert's
    // first Subject Alt Name.
    let url = format!("https://localhost:{}/", server_addr.port());

    let (client_conn, server_conn) = tokio::join!(
        async {
            let c = client.connect(url).await.expect("client connect");
            tracing::info!("client connected");
            c
        },
        async {
            let incoming = server.accept().await;
            tracing::info!("server incoming");
            let req = incoming.await.expect("session request");
            tracing::info!(
                "server session request: authority={} path={}",
                req.authority(),
                req.path()
            );
            let c = req.accept().await.expect("session accept");
            tracing::info!("server accepted");
            c
        },
    );

    let client_remote: SocketAddr = client_conn.remote_address();
    let server_remote: SocketAddr = server_conn.remote_address();

    // Wrap each wtransport::Connection as a PacketIO.
    let alice_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(WebTransportPacketIO::new(client_conn, client_remote));
    let bob_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(WebTransportPacketIO::new(server_conn, server_remote));

    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    // Build the two DRIFT transports on top of the WebTransport
    // adapters.
    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, client_remote, Direction::Responder)
        .await
        .unwrap();

    let alice_t = Arc::new(
        Transport::bind_with_io(alice_io, alice_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    let bob_peer_on_alice = alice_t
        .add_peer(bob_pub, server_remote, Direction::Initiator)
        .await
        .unwrap();

    // Fire a payload; the handshake is implicit in the first send.
    alice_t
        .send_data(&bob_peer_on_alice, b"hello-over-webtransport", 0, 0)
        .await
        .unwrap();

    let pkt = tokio::time::timeout(Duration::from_secs(5), bob_t.recv())
        .await
        .expect("webtransport recv timeout")
        .expect("channel closed");
    assert_eq!(pkt.payload, b"hello-over-webtransport");
    assert_eq!(pkt.peer_id, alice_t.local_peer_id());

    // Sanity on metrics.
    assert_eq!(bob_t.metrics().auth_failures, 0);
    assert!(bob_t.metrics().handshakes_completed >= 1);
}

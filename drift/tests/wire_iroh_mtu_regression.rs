//! Regression test: DRIFT-over-iroh can transmit DRIFT's standard
//! 1300-byte packets.
//!
//! Background: the default iroh `initial_mtu` is 1200, which makes
//! `Connection::max_datagram_size()` settle at ~1162 — smaller than
//! a DRIFT packet. With that default, every DATA-bearing send fails
//! with "iroh datagram too large: 1300 > 1162 max", and bridge
//! federation can't move user traffic. `wire_iroh.rs` sets
//! `initial_mtu = 1400`, which lets the negotiated ceiling land
//! around 1362 — comfortably above 1300.
//!
//! If anyone reverts that bump, this test fails at the
//! `max_datagram_size` assertion before the send even runs.

#![cfg(feature = "iroh")]

use drift::io::PacketIO;
use drift::wire_iroh::IrohPacketIO;
use iroh::endpoint::{presets, QuicTransportConfig};
use iroh::{Endpoint, EndpointAddr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const ALPN: &[u8] = b"drift/iroh/1";
const DRIFT_MAX_PACKET: usize = 1300;

/// The minimum initial MTU we need for DRIFT's 1300-byte packets.
/// 1400 leaves ~60-80 B of QUIC + UDP headroom so `max_datagram_size`
/// lands at ~1362. Below this, `max_datagram_size` settles around 1162.
const REQUIRED_INITIAL_MTU: u16 = 1400;

/// Test endpoints use the same initial MTU as the deployed code
/// reads from `drift::wire_iroh::INITIAL_MTU`. The const-equality
/// check below pins this — if anyone bumps one without the other,
/// the test fails.
fn drift_iroh_cfg() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .initial_mtu(drift::wire_iroh::INITIAL_MTU)
        .build()
}

// Compile-time check: the deployed wire_iroh INITIAL_MTU stays
// above the required floor. A regression to 1200 (or anything
// below 1400) makes this fail at `cargo build --tests`, before
// the runtime test even runs. The runtime test below then proves
// what that MTU actually buys us in negotiation.
const _: () = assert!(
    drift::wire_iroh::INITIAL_MTU >= REQUIRED_INITIAL_MTU,
    "drift::wire_iroh::INITIAL_MTU dropped below the floor needed \
     to carry DRIFT's 1300-byte packets. Bumping it back above 1400 \
     fixes federation under load."
);

#[tokio::test]
async fn drift_1300_byte_datagram_round_trips_over_iroh() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .transport_config(drift_iroh_cfg())
        .bind()
        .await
        .expect("server bind");
    let client = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .transport_config(drift_iroh_cfg())
        .bind()
        .await
        .expect("client bind");

    let server_id = server.id();
    // iroh binds to 0.0.0.0:<picked_port> when given 0.0.0.0:0. For
    // loopback dialing we need the actual reachable addr, so rewrite
    // the wildcard IP to 127.0.0.1.
    let server_sock_raw = server
        .bound_sockets()
        .into_iter()
        .find(|s| matches!(s, SocketAddr::V4(_)))
        .expect("server has an ipv4 bound socket");
    let server_sock: SocketAddr = SocketAddr::from(([127, 0, 0, 1], server_sock_raw.port()));
    let target = EndpointAddr::new(server_id).with_ip_addr(server_sock);

    let (server_conn, client_conn) = tokio::join!(
        async {
            server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("server accept")
        },
        async { client.connect(target, ALPN).await.expect("client connect") },
    );

    let max = client_conn
        .max_datagram_size()
        .expect("client negotiated QUIC datagram support");
    assert!(
        max >= DRIFT_MAX_PACKET,
        "negotiated max_datagram_size={} < DRIFT_MAX_PACKET={} — \
         wire_iroh INITIAL_MTU regression: bump it back to ≥1400 \
         or DRIFT-over-iroh can't carry DATA packets",
        max,
        DRIFT_MAX_PACKET
    );

    // Wrap both ends with the production IrohPacketIO and verify
    // the 1300-byte payload survives a real send_to + recv_from.
    let server_io: Arc<dyn PacketIO> = Arc::new(IrohPacketIO::new(
        server_conn,
        SocketAddr::from(([192, 0, 2, 1], 51820)),
        server.clone(),
    ));
    let client_io: Arc<dyn PacketIO> = Arc::new(IrohPacketIO::new(
        client_conn,
        SocketAddr::from(([192, 0, 2, 2], 51820)),
        client.clone(),
    ));

    // Pseudo-random non-zero pattern so a "send sent zeros" bug
    // would fail loudly.
    let payload: Vec<u8> = (0..DRIFT_MAX_PACKET)
        .map(|i| ((i as u32).wrapping_mul(0x9E37_79B1) >> 8) as u8)
        .collect();

    client_io
        .send_to(&payload, server_sock)
        .await
        .expect("send_to 1300B");

    let mut buf = vec![0u8; 4096];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), server_io.recv_from(&mut buf))
        .await
        .expect("recv timeout — datagram never arrived")
        .expect("recv_from io error");

    assert_eq!(n, DRIFT_MAX_PACKET, "wrong byte count");
    assert_eq!(&buf[..n], payload.as_slice(), "payload corrupted");
}

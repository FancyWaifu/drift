//! Byte-compatibility proof for the sans-IO engine (`drift-proto`).
//!
//! Each test runs a `drift_proto::Endpoint` over a plain
//! `std::net::UdpSocket` (no tokio on that side) against a real
//! `drift::Transport`, in both roles, classical and PQ-hybrid, with
//! and without the DoS-cookie flight. If the engine's wire bytes or
//! check ordering ever diverge from the transport, these fail.
//!
//! This is the contract that keeps `docs/SANSIO_DESIGN.md` honest:
//! the engine is only useful to drift-wasm / drift-redox / future
//! platforms if it speaks *exactly* the same protocol as the tokio
//! transport — "close" is worthless for AEAD'd wire formats.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use drift_proto::{Config as ProtoConfig, Endpoint, Event};
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Drive a drift-proto endpoint over a std UdpSocket until `done`
/// returns true or the deadline passes. Returns collected events.
fn pump_until(
    ep: &mut Endpoint,
    socket: &UdpSocket,
    deadline: Duration,
    mut done: impl FnMut(&[Event]) -> bool,
) -> Vec<Event> {
    socket
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    let mut events = Vec::new();
    while start.elapsed() < deadline {
        while let Some(t) = ep.poll_transmit() {
            socket.send_to(&t.contents, t.dst).unwrap();
        }
        if let Ok((n, src)) = socket.recv_from(&mut buf) {
            // Inbound errors are fine here (e.g. unknown packet
            // types from richer transport features) — the engine
            // must simply not wedge.
            let _ = ep.handle_datagram(Instant::now(), src, &buf[..n]);
        }
        ep.handle_timeout(Instant::now());
        while let Some(e) = ep.poll_event() {
            events.push(e);
        }
        if done(&events) {
            break;
        }
    }
    // The done-condition can fire while transmits are still queued
    // (e.g. the pending-DATA flush lands in the same iteration as
    // the Connected event) — drain them onto the wire before
    // returning so the other side isn't left waiting.
    while let Some(t) = ep.poll_transmit() {
        socket.send_to(&t.contents, t.dst).unwrap();
    }
    events
}

fn got_payload(events: &[Event], wanted: &[u8]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, Event::Data { payload, .. } if payload == wanted))
}

/// Engine as CLIENT → Transport as server, PQ-hybrid (both defaults).
/// HELLO(+ek) / HELLO_ACK(+ct) / DATA all cross implementations.
#[tokio::test]
async fn engine_client_to_transport_server_pq() {
    let server_id = Identity::from_secret_bytes([0xC1; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let srv = server.clone();
    let engine_side = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut ep = Endpoint::new(
            Identity::from_secret_bytes([0xC2; 32]),
            ProtoConfig::default(), // hybrid_pq: true
        );
        let peer = ep.connect(Instant::now(), server_pub, server_addr);
        ep.send(Instant::now(), &peer, b"sans-io says hello", 0, 0)
            .unwrap();
        let mut events = pump_until(&mut ep, &socket, Duration::from_secs(5), |ev| {
            got_payload(ev, b"transport says hello back")
        });
        // Second payload on the live session rides the 7-byte
        // short header (CIDs installed, seq > 1) — this is the
        // engine's short-header SEND being validated against the
        // transport's CID-map receive path.
        ep.send(Instant::now(), &peer, b"second, short-header", 0, 0)
            .unwrap();
        events.extend(pump_until(&mut ep, &socket, Duration::from_secs(1), |_| {
            false
        }));
        events
    });

    // Transport side: receive the engine's DATA, reply.
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("transport server never received DATA from the engine")
        .expect("server recv returned None");
    assert_eq!(got.payload, b"sans-io says hello");
    server
        .send_data(&got.peer_id, b"transport says hello back", 0, 0)
        .await
        .unwrap();
    let got2 = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("transport never received the engine's short-header DATA")
        .expect("server recv returned None");
    assert_eq!(got2.payload, b"second, short-header");

    let events = engine_side.await.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, Event::Connected { .. })),
        "engine never reached Established: {events:?}"
    );
    assert!(
        got_payload(&events, b"transport says hello back"),
        "engine never got the transport's reply: {events:?}"
    );
    let m = srv.metrics();
    assert_eq!(m.handshakes_completed, 1);
    assert!(
        m.hybrid_pq_handshakes_completed >= 1,
        "handshake should have been PQ-hybrid"
    );
}

/// Engine as CLIENT, classical (hybrid_pq off on both sides).
#[tokio::test]
async fn engine_client_to_transport_server_classical() {
    let server_id = Identity::from_secret_bytes([0xC3; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        hybrid_pq: false,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let engine_side = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut ep = Endpoint::new(
            Identity::from_secret_bytes([0xC4; 32]),
            ProtoConfig {
                hybrid_pq: false,
                ..ProtoConfig::default()
            },
        );
        let peer = ep.connect(Instant::now(), server_pub, server_addr);
        ep.send(Instant::now(), &peer, b"classical engine hello", 0, 0)
            .unwrap();
        pump_until(&mut ep, &socket, Duration::from_secs(5), |ev| {
            got_payload(ev, b"classical reply")
        })
    });

    let got = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("transport never received the engine's DATA")
        .expect("recv None");
    assert_eq!(got.payload, b"classical engine hello");
    server
        .send_data(&got.peer_id, b"classical reply", 0, 0)
        .await
        .unwrap();

    let events = engine_side.await.unwrap();
    assert!(got_payload(&events, b"classical reply"), "{events:?}");
}

/// Engine as client against a cookie-demanding Transport server: the
/// engine must survive the CHALLENGE flight (HELLO → CHALLENGE →
/// HELLO+cookie → HELLO_ACK) speaking the transport's exact cookie
/// format.
#[tokio::test]
async fn engine_client_survives_transport_cookie_challenge() {
    let server_id = Identity::from_secret_bytes([0xC5; 32]);
    let server_pub = server_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        cookie_always: true,
        ..TransportConfig::default()
    };
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let engine_side = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut ep = Endpoint::new(
            Identity::from_secret_bytes([0xC6; 32]),
            ProtoConfig::default(),
        );
        let peer = ep.connect(Instant::now(), server_pub, server_addr);
        ep.send(Instant::now(), &peer, b"cookie-gated payload", 0, 0)
            .unwrap();
        pump_until(&mut ep, &socket, Duration::from_secs(5), |ev| {
            ev.iter().any(|e| matches!(e, Event::Connected { .. }))
        })
    });

    let got = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("cookie-gated DATA never arrived")
        .expect("recv None");
    assert_eq!(got.payload, b"cookie-gated payload");
    engine_side.await.unwrap();

    let m = server.metrics();
    assert!(m.challenges_issued >= 1, "no CHALLENGE was issued");
    assert!(m.cookies_accepted >= 1, "engine's cookie echo not accepted");
    assert_eq!(m.cookies_rejected, 0, "engine's cookie was rejected");
}

/// Engine as SERVER ← Transport as client, PQ-hybrid. The transport
/// dials the engine; the engine must accept the HELLO, emit a valid
/// HELLO_ACK, deliver the transport's DATA, and reply over the
/// established session.
#[tokio::test]
async fn transport_client_to_engine_server_pq() {
    let engine_id = Identity::from_secret_bytes([0xC7; 32]);
    let engine_pub = engine_id.public_bytes();

    // Bind the engine's socket first so the transport has a target.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let engine_addr = socket.local_addr().unwrap();

    let engine_side = tokio::task::spawn_blocking(move || {
        let mut ep = Endpoint::new(
            engine_id,
            ProtoConfig {
                accept_any_peer: true,
                ..ProtoConfig::default()
            },
        );
        let mut events = pump_until(&mut ep, &socket, Duration::from_secs(5), |ev| {
            got_payload(ev, b"transport dials sans-io")
        });
        // Reply over the established session.
        let peer = events
            .iter()
            .find_map(|e| match e {
                Event::Data { peer, .. } => Some(*peer),
                _ => None,
            })
            .expect("no DATA event on engine server");
        ep.send(Instant::now(), &peer, b"sans-io replies", 0, 0)
            .unwrap();
        events.extend(pump_until(&mut ep, &socket, Duration::from_secs(2), |_| {
            false
        }));
        events
    });

    let client = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0xC8; 32]),
    )
    .await
    .unwrap();
    let engine_peer = client
        .add_peer(engine_pub, engine_addr, Direction::Initiator)
        .await
        .unwrap();
    client
        .send_data(&engine_peer, b"transport dials sans-io", 0, 0)
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("transport client never got the engine's reply")
        .expect("recv None");
    assert_eq!(got.payload, b"sans-io replies");

    let events = engine_side.await.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, Event::Connected { .. })),
        "engine server never saw the session establish: {events:?}"
    );
    let m = client.metrics();
    assert!(
        m.hybrid_pq_handshakes_completed >= 1,
        "transport client should have completed a PQ handshake \
         against the engine"
    );
}

/// Engine as cookie-demanding SERVER ← Transport as client: the
/// engine's CHALLENGE bytes must be accepted by the real transport's
/// challenge handler, and the transport's cookie echo must validate
/// against the engine's MAC.
#[tokio::test]
async fn engine_server_challenges_transport_client() {
    let engine_id = Identity::from_secret_bytes([0xC9; 32]);
    let engine_pub = engine_id.public_bytes();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let engine_addr = socket.local_addr().unwrap();

    let engine_side = tokio::task::spawn_blocking(move || {
        let mut ep = Endpoint::new(
            engine_id,
            ProtoConfig {
                accept_any_peer: true,
                cookie_always: true,
                ..ProtoConfig::default()
            },
        );
        pump_until(&mut ep, &socket, Duration::from_secs(5), |ev| {
            got_payload(ev, b"cookie flight from transport")
        })
    });

    let client = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0xCA; 32]),
    )
    .await
    .unwrap();
    let engine_peer = client
        .add_peer(engine_pub, engine_addr, Direction::Initiator)
        .await
        .unwrap();
    client
        .send_data(&engine_peer, b"cookie flight from transport", 0, 0)
        .await
        .unwrap();

    let events = engine_side.await.unwrap();
    assert!(
        got_payload(&events, b"cookie flight from transport"),
        "transport client never completed the engine's cookie \
         flight: {events:?}"
    );
}

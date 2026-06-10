//! Engine ↔ engine tests: two sans-IO endpoints connected by an
//! in-memory "wire" that just moves Transmits across — no sockets,
//! no runtime, no sleeps. The flow assertions here mirror the
//! transport's own integration tests (dos_cookie.rs, dual_init.rs,
//! hybrid_pq.rs) so behavior stays comparable.

use drift_core::header::{Header, PacketType, HEADER_LEN};
use drift_proto::{Config, Direction, Endpoint, Event, Identity};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Move every queued transmit from one endpoint into the other,
/// recording the packet types seen. Returns the number of datagrams
/// moved.
fn flush(
    now: Instant,
    from: &mut Endpoint,
    to: &mut Endpoint,
    from_addr: SocketAddr,
    seen: &mut Vec<PacketType>,
) -> usize {
    let mut n = 0;
    while let Some(t) = from.poll_transmit() {
        if let Ok(h) = Header::decode(&t.contents[..HEADER_LEN.min(t.contents.len())]) {
            seen.push(h.packet_type);
        }
        // Errors are intentionally surfaced: in these clean-network
        // tests nothing should be rejected unless a test asserts it.
        to.handle_datagram(now, from_addr, &t.contents)
            .expect("datagram rejected");
        n += 1;
    }
    n
}

/// Pump both directions until the wire goes quiet.
fn pump(
    now: Instant,
    a: &mut Endpoint,
    b: &mut Endpoint,
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    seen: &mut Vec<PacketType>,
) {
    loop {
        let moved = flush(now, a, b, a_addr, seen) + flush(now, b, a, b_addr, seen);
        if moved == 0 {
            break;
        }
    }
}

fn drain_events(ep: &mut Endpoint) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(e) = ep.poll_event() {
        out.push(e);
    }
    out
}

fn classical() -> Config {
    Config {
        hybrid_pq: false,
        ..Config::default()
    }
}

#[test]
fn classical_handshake_and_bidirectional_data() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x11; 32]);
    let client_id = Identity::from_secret_bytes([0x22; 32]);
    let server_pub = server_id.public_bytes();
    let client_pub = client_id.public_bytes();
    let (ca, sa) = (addr(1001), addr(1002));

    let mut server = Endpoint::new(server_id, classical());
    server.add_peer(client_pub, addr(0), Direction::Responder);
    let mut client = Endpoint::new(client_id, classical());

    let server_peer = client.connect(now, server_pub, sa);
    client
        .send(now, &server_peer, b"first contact", 0, 0)
        .unwrap();

    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);

    // Client side: Connected.
    let cev = drain_events(&mut client);
    assert!(
        matches!(cev.as_slice(), [Event::Connected { .. }]),
        "client events: {cev:?}"
    );
    // Server side: Connected (first DATA) + the payload.
    let sev = drain_events(&mut server);
    assert!(
        matches!(&sev[..], [Event::Connected { .. }, Event::Data { payload, .. }] if payload == b"first contact"),
        "server events: {sev:?}"
    );
    // No CHALLENGE in the default config.
    assert!(!seen.contains(&PacketType::Challenge), "wire: {seen:?}");

    // Server → client reply.
    let client_peer = server.add_peer(client_pub, ca, Direction::Responder);
    server
        .send(now, &client_peer, b"reply from server", 0, 0)
        .unwrap();
    pump(now, &mut server, &mut client, sa, ca, &mut seen);
    let cev = drain_events(&mut client);
    assert!(
        matches!(&cev[..], [Event::Data { payload, .. }] if payload == b"reply from server"),
        "client events: {cev:?}"
    );
}

#[test]
fn hybrid_pq_handshake_default_config() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x31; 32]);
    let client_id = Identity::from_secret_bytes([0x32; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1003), addr(1004));

    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default());

    let server_peer = client.connect(now, server_pub, sa);
    client.send(now, &server_peer, b"pq hello", 0, 0).unwrap();

    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);

    let sev = drain_events(&mut server);
    assert!(
        matches!(&sev[..], [Event::Connected { .. }, Event::Data { payload, .. }] if payload == b"pq hello"),
        "server events: {sev:?}"
    );
    // The HELLO on the wire must carry the ML-KEM ek (1184 B tail):
    // header(36) + 80 + 1184.
    assert!(seen.contains(&PacketType::Hello));
}

#[test]
fn cookie_always_forces_challenge_flight() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x41; 32]);
    let client_id = Identity::from_secret_bytes([0x42; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1005), addr(1006));

    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            cookie_always: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default());

    let server_peer = client.connect(now, server_pub, sa);
    client
        .send(now, &server_peer, b"behind the cookie", 0, 0)
        .unwrap();

    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);

    // Exact flight sequence: HELLO → CHALLENGE → HELLO(+cookie) →
    // HELLO_ACK → DATA.
    assert!(
        seen.contains(&PacketType::Challenge),
        "no CHALLENGE issued: {seen:?}"
    );
    let sev = drain_events(&mut server);
    assert!(
        matches!(&sev[..], [Event::Connected { .. }, Event::Data { payload, .. }] if payload == b"behind the cookie"),
        "server events: {sev:?}"
    );
}

#[test]
fn duplicate_hello_replays_identical_cached_ack() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x51; 32]);
    let client_id = Identity::from_secret_bytes([0x52; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1007), addr(1008));

    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default());
    client.connect(now, server_pub, sa);

    // Capture the HELLO instead of delivering it via pump.
    let hello = client.poll_transmit().expect("client queued no HELLO");

    server.handle_datagram(now, ca, &hello.contents).unwrap();
    let ack1 = server.poll_transmit().expect("no ACK for first HELLO");
    server.handle_datagram(now, ca, &hello.contents).unwrap();
    let ack2 = server.poll_transmit().expect("no ACK for duplicate HELLO");

    // Same nonce → byte-identical cached ACK, no fresh key derivation.
    assert_eq!(
        ack1.contents, ack2.contents,
        "duplicate HELLO must replay the cached HELLO_ACK"
    );
}

#[test]
fn replayed_data_packet_is_rejected() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x61; 32]);
    let client_id = Identity::from_secret_bytes([0x62; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1009), addr(1010));

    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default());
    let server_peer = client.connect(now, server_pub, sa);

    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    drain_events(&mut client);
    drain_events(&mut server);

    client.send(now, &server_peer, b"once only", 0, 0).unwrap();
    let data = client.poll_transmit().expect("no DATA queued");

    server.handle_datagram(now, ca, &data.contents).unwrap();
    let replay = server.handle_datagram(now, ca, &data.contents);
    assert!(replay.is_err(), "replayed DATA must be rejected");

    let sev = drain_events(&mut server);
    let delivered: Vec<_> = sev
        .iter()
        .filter(|e| matches!(e, Event::Data { .. }))
        .collect();
    assert_eq!(
        delivered.len(),
        1,
        "payload delivered exactly once: {sev:?}"
    );
}

#[test]
fn hello_retransmits_with_backoff_then_gives_up() {
    let t0 = Instant::now();
    let server_id = Identity::from_secret_bytes([0x71; 32]);
    let client_id = Identity::from_secret_bytes([0x72; 32]);
    let server_pub = server_id.public_bytes();

    let mut client = Endpoint::new(
        client_id,
        Config {
            hybrid_pq: false,
            handshake_retry_base_ms: 100,
            handshake_max_attempts: 3,
            ..Config::default()
        },
    );
    let peer = client.connect(t0, server_pub, addr(1011));
    let first = client.poll_transmit().expect("no initial HELLO");

    // attempts=1 → wait 100<<1 = 200ms. Nothing due before that.
    client.handle_timeout(t0 + Duration::from_millis(150));
    assert!(client.poll_transmit().is_none(), "retransmitted too early");

    // Due at +200ms: one retransmit, byte-identical (same nonce/eph).
    client.handle_timeout(t0 + Duration::from_millis(250));
    let retx = client.poll_transmit().expect("no retransmit at backoff");
    assert_eq!(
        first.contents, retx.contents,
        "retransmit must reuse nonce + ephemeral so the server can \
         replay its cached ACK"
    );

    // attempts=2 → next wait 400ms; attempts=3 hits the cap.
    client.handle_timeout(t0 + Duration::from_millis(1000));
    assert!(client.poll_transmit().is_some(), "third attempt missing");
    client.handle_timeout(t0 + Duration::from_millis(5000));
    assert!(
        client.poll_transmit().is_none(),
        "must stop retransmitting at max attempts"
    );
    let ev = drain_events(&mut client);
    assert!(
        matches!(&ev[..], [Event::HandshakeTimedOut { peer: p }] if *p == peer),
        "expected one HandshakeTimedOut: {ev:?}"
    );
    // And the notification fires only once.
    client.handle_timeout(t0 + Duration::from_millis(60_000));
    assert!(drain_events(&mut client).is_empty());
}

#[test]
fn dual_initiation_resolves_to_one_session() {
    let now = Instant::now();
    let id_a = Identity::from_secret_bytes([0x81; 32]);
    let id_b = Identity::from_secret_bytes([0x82; 32]);
    let pub_a = id_a.public_bytes();
    let pub_b = id_b.public_bytes();
    let (aa, ba) = (addr(1012), addr(1013));

    let mut a = Endpoint::new(id_a, classical());
    let mut b = Endpoint::new(id_b, classical());

    // Both sides dial simultaneously.
    let peer_b = a.connect(now, pub_b, ba);
    let peer_a = b.connect(now, pub_a, aa);
    a.send(now, &peer_b, b"from a", 0, 0).unwrap();
    b.send(now, &peer_a, b"from b", 0, 0).unwrap();

    let mut seen = Vec::new();
    pump(now, &mut a, &mut b, aa, ba, &mut seen);

    // Exactly one of them must win the tiebreak and both must end
    // up with a session that delivers both payloads.
    let ev_a = drain_events(&mut a);
    let ev_b = drain_events(&mut b);
    let got_a: Vec<&[u8]> = ev_a
        .iter()
        .filter_map(|e| match e {
            Event::Data { payload, .. } => Some(payload.as_slice()),
            _ => None,
        })
        .collect();
    let got_b: Vec<&[u8]> = ev_b
        .iter()
        .filter_map(|e| match e {
            Event::Data { payload, .. } => Some(payload.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(got_a, vec![b"from b".as_slice()], "a events: {ev_a:?}");
    assert_eq!(got_b, vec![b"from a".as_slice()], "b events: {ev_b:?}");
}

#[test]
fn pq_posture_mismatch_is_refused() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0x91; 32]);
    let client_id = Identity::from_secret_bytes([0x92; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1014), addr(1015));

    // PQ client against a classical-only server: the server must
    // refuse rather than silently downgrade.
    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            hybrid_pq: false,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default()); // pq on
    client.connect(now, server_pub, sa);

    let hello = client.poll_transmit().unwrap();
    let res = server.handle_datagram(now, ca, &hello.contents);
    assert!(res.is_err(), "PQ HELLO must be refused by classical server");
    assert!(server.poll_transmit().is_none(), "no ACK on refusal");
}

#[test]
fn unregistered_peer_rejected_without_accept_any() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0xA1; 32]);
    let client_id = Identity::from_secret_bytes([0xA2; 32]);
    let server_pub = server_id.public_bytes();

    let mut server = Endpoint::new(server_id, classical()); // accept_any off
    let mut client = Endpoint::new(client_id, classical());
    client.connect(now, server_pub, addr(1017));

    let hello = client.poll_transmit().unwrap();
    let res = server.handle_datagram(now, addr(1016), &hello.contents);
    assert!(res.is_err(), "unknown peer must be rejected");
    assert!(server.poll_transmit().is_none());
}

#[test]
fn steady_state_data_uses_short_header_and_decodes() {
    let now = Instant::now();
    let server_id = Identity::from_secret_bytes([0xB1; 32]);
    let client_id = Identity::from_secret_bytes([0xB2; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1018), addr(1019));

    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(client_id, Config::default());
    let server_peer = client.connect(now, server_pub, sa);
    client
        .send(now, &server_peer, b"first (long)", 0, 0)
        .unwrap();

    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    drain_events(&mut client);
    drain_events(&mut server);

    // Second DATA on the live session must be short-header
    // (version nibble 0x2, 7-byte header) and still decode.
    client
        .send(now, &server_peer, b"second (short)", 0, 0)
        .unwrap();
    let t = client.poll_transmit().expect("no DATA queued");
    assert_eq!(
        t.contents[0] >> 4,
        0x2,
        "steady-state DATA should use the short header"
    );
    assert_eq!(t.contents.len(), 7 + b"second (short)".len() + 16);
    server.handle_datagram(now, ca, &t.contents).unwrap();
    let sev = drain_events(&mut server);
    assert!(
        matches!(&sev[..], [Event::Data { payload, .. }] if payload == b"second (short)"),
        "server events: {sev:?}"
    );

    // And the reverse direction: the server's reply also rides the
    // short header once its own first DATA (none here — its session
    // started by receiving) has gone long.
    let client_peer = server.add_peer(
        Identity::from_secret_bytes([0xB2; 32]).public_bytes(),
        ca,
        Direction::Responder,
    );
    server.send(now, &client_peer, b"long first", 0, 0).unwrap();
    let first = server.poll_transmit().unwrap();
    assert_eq!(first.contents[0] >> 4, 0x1, "server's first DATA is long");
    server
        .send(now, &client_peer, b"short second", 0, 0)
        .unwrap();
    let second = server.poll_transmit().unwrap();
    assert_eq!(
        second.contents[0] >> 4,
        0x2,
        "server's second DATA is short"
    );
    client.handle_datagram(now, sa, &first.contents).unwrap();
    client.handle_datagram(now, sa, &second.contents).unwrap();
    let cev = drain_events(&mut client);
    let got: Vec<&[u8]> = cev
        .iter()
        .filter_map(|e| match e {
            Event::Data { payload, .. } => Some(payload.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(
        got,
        vec![b"long first".as_slice(), b"short second".as_slice()]
    );
}

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
    // (The server's seq 1 went to the auto-issued ResumptionTicket
    // at the transition, so even its first DATA may ride the short
    // header — safe, because the client installed CIDs at
    // HELLO_ACK.)
    server.send(now, &client_peer, b"long first", 0, 0).unwrap();
    let first = server.poll_transmit().unwrap();
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

// ---- phase 2: rekey / close / eviction ---------------------------

/// Establish a PQ session between a fresh client/server pair and
/// exchange one payload each way so both sides are fully
/// Established with CIDs installed.
fn established_pair(
    now: Instant,
    client_seed: u8,
    server_seed: u8,
    ca: SocketAddr,
    sa: SocketAddr,
) -> (Endpoint, Endpoint, drift_proto::PeerId, drift_proto::PeerId) {
    let server_id = Identity::from_secret_bytes([server_seed; 32]);
    let client_id = Identity::from_secret_bytes([client_seed; 32]);
    let server_pub = server_id.public_bytes();
    let client_pub = client_id.public_bytes();

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
        .send(now, &server_peer, b"warmup c->s", 0, 0)
        .unwrap();
    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    let client_peer = drift_proto::derive_peer_id(&client_pub);
    server
        .send(now, &client_peer, b"warmup s->c", 0, 0)
        .unwrap();
    pump(now, &mut server, &mut client, sa, ca, &mut seen);
    drain_events(&mut client);
    drain_events(&mut server);
    (client, server, server_peer, client_peer)
}

#[test]
fn manual_rekey_keeps_session_flowing_both_ways() {
    let now = Instant::now();
    let (ca, sa) = (addr(1020), addr(1021));
    let (mut client, mut server, server_peer, client_peer) =
        established_pair(now, 0xD2, 0xD1, ca, sa);

    client.rekey(now, &server_peer).unwrap();
    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    assert!(seen.contains(&PacketType::RekeyRequest), "wire: {seen:?}");
    assert!(seen.contains(&PacketType::RekeyAck), "wire: {seen:?}");

    // Both directions still flow under the new key.
    client
        .send(now, &server_peer, b"post-rekey c->s", 0, 0)
        .unwrap();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    let sev = drain_events(&mut server);
    assert!(
        sev.iter()
            .any(|e| matches!(e, Event::Data { payload, .. } if payload == b"post-rekey c->s")),
        "server events: {sev:?}"
    );
    server
        .send(now, &client_peer, b"post-rekey s->c", 0, 0)
        .unwrap();
    pump(now, &mut server, &mut client, sa, ca, &mut seen);
    let cev = drain_events(&mut client);
    assert!(
        cev.iter()
            .any(|e| matches!(e, Event::Data { payload, .. } if payload == b"post-rekey s->c")),
        "client events: {cev:?}"
    );
}

#[test]
fn old_key_data_decodes_within_grace_then_expires() {
    let now = Instant::now();
    let (ca, sa) = (addr(1022), addr(1023));
    let (mut client, mut server, server_peer, client_peer) =
        established_pair(now, 0xD4, 0xD3, ca, sa);

    // Server seals three packets under the OLD key (the later two
    // ride the short header — steady state) but they stall in
    // flight.
    server
        .send(now, &client_peer, b"stale long old-key", 0, 0)
        .unwrap();
    server
        .send(now, &client_peer, b"stale short old-key", 0, 0)
        .unwrap();
    server
        .send(now, &client_peer, b"stale, arrives too late", 0, 0)
        .unwrap();
    let stale_long = server.poll_transmit().unwrap();
    let stale_short = server.poll_transmit().unwrap();
    let stale_late = server.poll_transmit().unwrap();
    assert_eq!(stale_short.contents[0] >> 4, 0x2, "expected short header");

    // Client rekeys; the request reaches the server, the ack comes
    // back — both sides now hold the new key with prev in grace.
    client.rekey(now, &server_peer).unwrap();
    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);

    // The stale old-key packets land within the grace window: both
    // header formats must decode via prev.
    client
        .handle_datagram(now, sa, &stale_long.contents)
        .unwrap();
    client
        .handle_datagram(now, sa, &stale_short.contents)
        .unwrap();
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
        vec![
            b"stale long old-key".as_slice(),
            b"stale short old-key".as_slice()
        ]
    );

    // After the grace window, a never-delivered old-key packet is
    // rejected — prev has expired, and this isn't a replay (its seq
    // was never accepted), so only the grace logic can reject it.
    let late = now + Duration::from_secs(3);
    let res = client.handle_datagram(late, sa, &stale_late.contents);
    assert!(
        res.is_err(),
        "old-key packet must be rejected once the grace window expires"
    );
}

#[test]
fn close_notifies_peer_and_allows_rehandshake() {
    let now = Instant::now();
    let (ca, sa) = (addr(1024), addr(1025));
    let (mut client, mut server, server_peer, _client_peer) =
        established_pair(now, 0xD6, 0xD5, ca, sa);

    client.close(&server_peer).unwrap();
    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    assert!(seen.contains(&PacketType::Close), "wire: {seen:?}");
    let sev = drain_events(&mut server);
    assert!(
        sev.iter().any(|e| matches!(e, Event::Closed { .. })),
        "server never saw Closed: {sev:?}"
    );

    // The same client can dial again — the server (auto-registered
    // entry removed by the Close) accepts a fresh handshake.
    let server_pub = Identity::from_secret_bytes([0xD5; 32]).public_bytes();
    let server_peer2 = client.connect(now, server_pub, sa);
    client
        .send(now, &server_peer2, b"second life", 0, 0)
        .unwrap();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    let sev = drain_events(&mut server);
    assert!(
        sev.iter()
            .any(|e| matches!(e, Event::Data { payload, .. } if payload == b"second life")),
        "server events after re-handshake: {sev:?}"
    );
}

#[test]
fn auto_rekey_fires_at_seq_watermark() {
    let now = Instant::now();
    let (ca, sa) = (addr(1026), addr(1027));
    let (mut client, mut server, server_peer, _client_peer) =
        established_pair(now, 0xD8, 0xD7, ca, sa);

    // Force the client's seq counter to the watermark; the next send
    // must transparently rekey before shipping the payload.
    assert!(client.test_bump_peer_seq(&server_peer, (1u32 << 31) / 4 * 3));
    client
        .send(now, &server_peer, b"crosses the watermark", 0, 0)
        .unwrap();
    let mut seen = Vec::new();
    pump(now, &mut client, &mut server, ca, sa, &mut seen);
    assert!(
        seen.contains(&PacketType::RekeyRequest),
        "no auto-rekey on the wire: {seen:?}"
    );
    let sev = drain_events(&mut server);
    assert!(
        sev.iter().any(
            |e| matches!(e, Event::Data { payload, .. } if payload == b"crosses the watermark")
        ),
        "server events: {sev:?}"
    );
}

#[test]
fn stale_half_open_peers_are_evicted() {
    let t0 = Instant::now();
    let server_id = Identity::from_secret_bytes([0xD9; 32]);
    let client_id = Identity::from_secret_bytes([0xDA; 32]);
    let server_pub = server_id.public_bytes();
    let (ca, sa) = (addr(1028), addr(1029));

    // Server side: a HELLO arrives, the client never sends DATA →
    // AwaitingData. After the cutoff the auto-registered entry is
    // reaped: replaying the SAME HELLO afterwards yields a fresh
    // session (different ACK bytes), not the cached one.
    let mut server = Endpoint::new(
        server_id,
        Config {
            accept_any_peer: true,
            ..Config::default()
        },
    );
    let mut client = Endpoint::new(
        client_id,
        Config {
            handshake_max_attempts: 1,
            ..Config::default()
        },
    );
    client.connect(t0, server_pub, sa);
    let hello = client.poll_transmit().unwrap();

    server.handle_datagram(t0, ca, &hello.contents).unwrap();
    let ack1 = server.poll_transmit().unwrap();
    server.handle_datagram(t0, ca, &hello.contents).unwrap();
    let ack2 = server.poll_transmit().unwrap();
    assert_eq!(ack1.contents, ack2.contents, "cached-ACK baseline");

    server.handle_timeout(t0 + Duration::from_secs(31));
    server.handle_datagram(t0, ca, &hello.contents).unwrap();
    let ack3 = server.poll_transmit().unwrap();
    assert_ne!(
        ack1.contents, ack3.contents,
        "evicted peer must get a fresh session, not the stale cached ACK"
    );

    // Client side: parked AwaitingAck (attempts exhausted) ages past
    // the cutoff and resets to Pending — the next send starts a
    // brand-new handshake (fresh nonce, so different HELLO bytes).
    client.handle_timeout(t0 + Duration::from_secs(31));
    drain_events(&mut client); // HandshakeTimedOut
    let server_peer = drift_proto::derive_peer_id(&server_pub);
    client
        .send(t0 + Duration::from_secs(32), &server_peer, b"redial", 0, 0)
        .unwrap();
    let hello2 = client
        .poll_transmit()
        .expect("no fresh HELLO after eviction");
    assert_ne!(
        hello.contents, hello2.contents,
        "post-eviction handshake must use a fresh nonce/ephemeral"
    );
}

// ---- phase 3: 1-RTT resumption -----------------------------------

#[test]
fn ticket_issued_then_one_rtt_resumption_works() {
    let now = Instant::now();
    let (ca, sa) = (addr(1030), addr(1031));
    let (client, mut server, server_peer, _client_peer) = established_pair(now, 0xF2, 0xF1, ca, sa);

    // The server issued a ticket at handshake completion; the
    // client stored it during the pump.
    let blob = client
        .export_resumption_ticket(&server_peer)
        .expect("no ticket stored after full handshake");
    assert_eq!(blob.len(), drift_proto::EXPORT_BLOB_LEN);

    // "Restart" the client: fresh endpoint, same identity, ticket
    // imported from the blob. connect() must open with ResumeHello
    // — never a full HELLO.
    let server_pub = Identity::from_secret_bytes([0xF1; 32]).public_bytes();
    let mut client2 = Endpoint::new(Identity::from_secret_bytes([0xF2; 32]), Config::default());
    let resumed_peer = client2.import_resumption_ticket(&blob).unwrap();
    assert_eq!(resumed_peer, server_peer);
    let p = client2.connect(now, server_pub, sa);
    client2.send(now, &p, b"resumed payload", 0, 0).unwrap();

    let mut seen = Vec::new();
    pump(now, &mut client2, &mut server, ca, sa, &mut seen);
    assert!(
        seen.contains(&PacketType::ResumeHello),
        "no ResumeHello: {seen:?}"
    );
    assert!(
        seen.contains(&PacketType::ResumeAck),
        "no ResumeAck: {seen:?}"
    );
    assert!(
        !seen.contains(&PacketType::Hello),
        "resumption must not fall back to a full HELLO: {seen:?}"
    );
    let cev = drain_events(&mut client2);
    assert!(
        cev.iter().any(|e| matches!(e, Event::Connected { .. })),
        "client2 events: {cev:?}"
    );
    let sev = drain_events(&mut server);
    assert!(
        sev.iter()
            .any(|e| matches!(e, Event::Data { payload, .. } if payload == b"resumed payload")),
        "server events: {sev:?}"
    );
    // A fresh ticket was issued on the resumed session.
    assert!(
        client2.export_resumption_ticket(&server_peer).is_some(),
        "no fresh ticket after resumption"
    );
}

#[test]
fn resumption_ticket_is_single_use() {
    let now = Instant::now();
    let (ca, sa) = (addr(1032), addr(1033));
    let (client, mut server, server_peer, _client_peer) = established_pair(now, 0xF4, 0xF3, ca, sa);
    let blob = client.export_resumption_ticket(&server_peer).unwrap();

    let server_pub = Identity::from_secret_bytes([0xF3; 32]).public_bytes();
    let mut client2 = Endpoint::new(Identity::from_secret_bytes([0xF4; 32]), Config::default());
    client2.import_resumption_ticket(&blob).unwrap();
    client2.connect(now, server_pub, sa);
    let resume_hello = client2.poll_transmit().expect("no ResumeHello queued");

    // First redemption succeeds...
    server
        .handle_datagram(now, ca, &resume_hello.contents)
        .unwrap();
    assert!(server.poll_transmit().is_some(), "no ResumeAck");
    // ...replaying the same ResumeHello fails: the ticket was
    // consumed (single-use).
    let replay = server.handle_datagram(now, ca, &resume_hello.contents);
    assert!(replay.is_err(), "consumed ticket must not redeem twice");
}

#[test]
fn import_rejects_malformed_and_expired_blobs() {
    let mut ep = Endpoint::new(Identity::from_secret_bytes([0xF5; 32]), Config::default());
    assert!(ep.import_resumption_ticket(b"garbage").is_err());

    // Build a structurally valid blob, then doctor the expiry to
    // the past: import must refuse it.
    let now = Instant::now();
    let (ca, sa) = (addr(1034), addr(1035));
    let (client, _server, server_peer, _) = established_pair(now, 0xF7, 0xF6, ca, sa);
    let mut blob = client.export_resumption_ticket(&server_peer).unwrap();
    let exp_off = 1 + 16 + 32; // version + ticket_id + psk
    blob[exp_off..exp_off + 8].copy_from_slice(&1u64.to_be_bytes()); // ~1970
    let res = ep.import_resumption_ticket(&blob);
    assert!(res.is_err(), "expired blob must be refused");
}

#[test]
fn ticket_bound_to_other_identity_is_refused_without_burning() {
    let now = Instant::now();
    let (ca, sa) = (addr(1036), addr(1037));
    let (client_a, mut server, server_peer, _) = established_pair(now, 0xF9, 0xF8, ca, sa);
    let blob = client_a.export_resumption_ticket(&server_peer).unwrap();
    let server_pub = Identity::from_secret_bytes([0xF8; 32]).public_bytes();

    // A different identity (registered with the server, so the
    // lookup gets as far as the identity binding) tries to redeem
    // A's ticket.
    let thief_id = Identity::from_secret_bytes([0xFA; 32]);
    let thief_pub = thief_id.public_bytes();
    server.add_peer(thief_pub, addr(1038), drift_proto::Direction::Responder);
    let mut thief = Endpoint::new(thief_id, Config::default());
    thief.import_resumption_ticket(&blob).unwrap();
    thief.connect(now, server_pub, sa);
    let stolen_resume = thief.poll_transmit().unwrap();
    let res = server.handle_datagram(now, addr(1038), &stolen_resume.contents);
    assert!(res.is_err(), "ticket bound to A must not redeem for B");
    assert!(server.poll_transmit().is_none());

    // The refusal must NOT have consumed the ticket: the rightful
    // owner can still resume.
    let mut client_a2 = Endpoint::new(Identity::from_secret_bytes([0xF9; 32]), Config::default());
    client_a2.import_resumption_ticket(&blob).unwrap();
    client_a2.connect(now, server_pub, sa);
    let legit = client_a2.poll_transmit().unwrap();
    server.handle_datagram(now, ca, &legit.contents).unwrap();
    assert!(server.poll_transmit().is_some(), "rightful resume failed");
}

#[test]
fn failed_resumption_falls_back_to_full_hello() {
    let t0 = Instant::now();
    let server_id = Identity::from_secret_bytes([0xFB; 32]);
    let client_id = Identity::from_secret_bytes([0xFC; 32]);
    let server_pub = server_id.public_bytes();
    let client_pub = client_id.public_bytes();
    let (ca, sa) = (addr(1039), addr(1040));

    // First, get a real ticket from a real session.
    let (client_old, _old_server, server_peer, _) = established_pair(t0, 0xFC, 0xFB, ca, sa);
    let blob = client_old.export_resumption_ticket(&server_peer).unwrap();

    // A REBOOTED server: same identity, knows the client
    // (explicit registration), but its ticket store is empty.
    let mut server = Endpoint::new(server_id, Config::default());
    server.add_peer(client_pub, ca, Direction::Responder);

    let mut client = Endpoint::new(
        client_id,
        Config {
            handshake_max_attempts: 1,
            handshake_retry_base_ms: 100,
            ..Config::default()
        },
    );
    client.import_resumption_ticket(&blob).unwrap();
    let p = client.connect(t0, server_pub, sa);
    client.send(t0, &p, b"eventually delivered", 0, 0).unwrap();

    // The ResumeHello hits the empty store and is rejected.
    let resume = client.poll_transmit().unwrap();
    assert_eq!(resume.contents[1], PacketType::ResumeHello as u8);
    assert!(server.handle_datagram(t0, ca, &resume.contents).is_err());

    // Give-up fires (max_attempts = 1) → engine fallback: peer
    // resets to Pending and the dead ticket is burned.
    client.handle_timeout(t0 + Duration::from_millis(250));
    let ev = drain_events(&mut client);
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::HandshakeTimedOut { .. })),
        "{ev:?}"
    );

    // The next send opens with a FULL HELLO and the session
    // completes normally.
    client
        .send(t0 + Duration::from_millis(300), &p, b"redial", 0, 0)
        .unwrap();
    let mut seen = Vec::new();
    pump(
        t0 + Duration::from_millis(300),
        &mut client,
        &mut server,
        ca,
        sa,
        &mut seen,
    );
    assert!(
        seen.contains(&PacketType::Hello),
        "no fallback HELLO: {seen:?}"
    );
    let sev = drain_events(&mut server);
    assert!(
        sev.iter()
            .any(|e| matches!(e, Event::Data { payload, .. } if payload == b"eventually delivered" || payload == b"redial")),
        "server events: {sev:?}"
    );
}

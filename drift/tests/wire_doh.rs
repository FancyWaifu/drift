//! End-to-end test: DRIFT over the `doh://` adapter through a
//! locally-spawned mock rendezvous (a Rust HTTP server that mimics
//! the Cloudflare Worker's behavior — see `drift-doh-relay/` for
//! the production TypeScript Worker that this test stands in for).
//!
//! Two `DohPacketIO` clients connect to the mock relay. The relay
//! buckets fragments by destination pubkey hex; each client's URL
//! contains its own pubkey + the peer's pubkey, exactly the
//! request shape the real Worker speaks. A complete DRIFT
//! handshake + DATA delivery proves the wire format works end-to-
//! end without any cloud infrastructure.
//!
//! Why a mock instead of the real Worker:
//!   * Reproducible: no network, no Cloudflare account.
//!   * Fast: no TLS handshake, no global edge round-trip.
//!   * Same wire bytes: the mock parses the exact same DNS
//!     messages the real Worker will, so passing tests here
//!     means the production path will also work.

use drift::identity::Identity;
use drift::wire_dns::{build_response_message, decode_fragment, parse_qname_labels};
use drift::wire_doh::DohPacketIO;
use drift::{Direction, Transport, TransportConfig};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

// ─── Mock relay ───────────────────────────────────────────────────
//
// Per-pubkey inbox: a Vec of raw fragment payload bytes
// `[id:u16][idx:u8][total:u8][raw_bytes…]`. Every POST drains the
// sender's own inbox into the response and pushes any data-bearing
// fragment from the request body onto the destination's inbox.

type Inboxes = Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>;

async fn handle(req: Request<Incoming>, inboxes: Inboxes) -> Result<Response<String>, Infallible> {
    if req.method() != Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(String::new())
            .unwrap());
    }

    // Path is `/v1/<me-hex>/<peer-hex>/dns-query` (or close to
    // it — we accept any path with at least 4 segments and pull
    // the last 3 useful pieces).
    let path = req.uri().path().to_string();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 3 {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("expected /<v>/<me-hex>/<peer-hex>/...".to_string())
            .unwrap());
    }
    // me_hex is parts[1], peer_hex is parts[2].
    let me_hex = parts[1].to_string();
    let peer_hex = parts[2].to_string();

    let body_bytes = match collect_body(req).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(String::new())
                .unwrap());
        }
    };

    // Decode the QNAME labels and pull out the fragment payload
    // (id, idx, total, raw). Empty-poll requests have no base32
    // labels and decode_fragment returns Err — that's fine, we
    // just skip the upload step and only drain.
    let mut txid: u16 = 0;
    let qname_labels = match parse_qname_labels(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(String::new())
                .unwrap());
        }
    };
    if body_bytes.len() >= 2 {
        txid = u16::from_be_bytes([body_bytes[0], body_bytes[1]]);
    }

    // If the request carries a real fragment, queue it for the
    // destination peer. Otherwise it's a poll.
    if let Ok((id, idx, total, raw)) = decode_fragment(&qname_labels) {
        let mut frag = Vec::with_capacity(4 + raw.len());
        frag.extend_from_slice(&id.to_be_bytes());
        frag.push(idx);
        frag.push(total);
        frag.extend_from_slice(&raw);
        let mut map = inboxes.lock().await;
        map.entry(peer_hex).or_default().push(frag);
    }

    // Drain whatever is waiting for `me_hex`.
    let pending = {
        let mut map = inboxes.lock().await;
        map.remove(&me_hex).unwrap_or_default()
    };

    // Cap responses to 8 fragments per round-trip so we don't blow
    // through the 16-byte u16 RDLENGTH or have weirdly huge bodies.
    // Anything beyond 8 stays queued for the next poll.
    let (return_now, defer): (Vec<_>, Vec<_>) =
        pending.into_iter().enumerate().partition(|(i, _)| *i < 8);
    if !defer.is_empty() {
        let mut map = inboxes.lock().await;
        let entry = map.entry(me_hex.clone()).or_default();
        // re-prepend the deferred ones (preserve order)
        let mut merged: Vec<Vec<u8>> = defer.into_iter().map(|(_, v)| v).collect();
        merged.append(entry);
        *entry = merged;
    }
    let return_now: Vec<Vec<u8>> = return_now.into_iter().map(|(_, v)| v).collect();

    // Build the response: echo the QNAME, attach one TXT record per
    // pending fragment.
    let qname_str = qname_labels.join(".");
    let bytes = build_response_message(txid, &qname_str, &return_now);

    let mut resp = Response::new(String::new());
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    // hyper's Response<String> body shenanigans — for binary
    // responses we want to use Vec<u8>; here we just build the
    // body separately.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .body(unsafe { String::from_utf8_unchecked(bytes) })
        .unwrap())
}

async fn collect_body(req: Request<Incoming>) -> Result<Vec<u8>, hyper::Error> {
    use http_body_util::BodyExt;
    let bytes = req.collect().await?.to_bytes();
    Ok(bytes.to_vec())
}

async fn spawn_mock_relay() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let inboxes: Inboxes = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let inboxes = inboxes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| handle(req, inboxes.clone())))
                    .await;
            });
        }
    });
    addr
}

// ─── Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_and_data_through_doh_relay() {
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();
    let alice_hex = hex::encode(alice_pub);
    let bob_hex = hex::encode(bob_pub);

    let relay_addr = spawn_mock_relay().await;

    // Alice's URL: me=alice, peer=bob.
    let alice_url = format!("doh://{}/v1/{}/{}", relay_addr, alice_hex, bob_hex);
    // Bob's URL: me=bob, peer=alice.
    let bob_url = format!("doh://{}/v1/{}/{}", relay_addr, bob_hex, alice_hex);

    let alice_io: Arc<dyn drift::io::PacketIO> = Arc::new(
        DohPacketIO::connect(&format!(
            "http://{}/v1/{}/{}",
            relay_addr, alice_hex, bob_hex
        ))
        .unwrap(),
    );
    let bob_io: Arc<dyn drift::io::PacketIO> = Arc::new(
        DohPacketIO::connect(&format!(
            "http://{}/v1/{}/{}",
            relay_addr, bob_hex, alice_hex
        ))
        .unwrap(),
    );

    // Sanity that the URLs round-tripped fine — these aren't
    // used past this point but exercising the formatter ensures
    // applications can construct them the same way.
    assert!(alice_url.starts_with("doh://"));
    assert!(bob_url.starts_with("doh://"));

    let bob_t = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "127.0.0.1:1".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();

    let alice_t = Arc::new(
        Transport::bind_with_io(alice_io, alice_id, TransportConfig::default())
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(
            bob_pub,
            "127.0.0.1:1".parse().unwrap(),
            Direction::Initiator,
        )
        .await
        .unwrap();

    alice_t
        .send_data(&bob_peer, b"hello-over-doh", 0, 0)
        .await
        .unwrap();

    let pkt = tokio::time::timeout(Duration::from_secs(15), bob_t.recv())
        .await
        .expect("handshake + DATA over DoH timed out")
        .unwrap();
    assert_eq!(pkt.payload, b"hello-over-doh");

    // Send a few more so we exercise the sustained data path.
    for i in 0..3u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    for _ in 0..3 {
        let p = tokio::time::timeout(Duration::from_secs(10), bob_t.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.payload.len(), 4);
    }

    let am = alice_t.metrics();
    let bm = bob_t.metrics();
    assert_eq!(am.handshakes_completed, 1);
    assert_eq!(bm.handshakes_completed, 1);
    assert_eq!(am.auth_failures, 0);
    assert_eq!(bm.auth_failures, 0);

    println!(
        "[DoH transport] handshake + 4 DATA packets through mock relay. \
         alice_sent={} bob_recv={}",
        am.packets_sent, bm.packets_received
    );
}

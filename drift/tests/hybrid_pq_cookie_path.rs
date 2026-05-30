//! Hybrid PQ + DoS-cookie interaction.
//!
//! When the server's `cookie_always` is true, every HELLO goes
//! through the Challenge → cookie-echo → real HELLO_ACK dance.
//! Adding the ML-KEM ek to that flow means the cookie tail and
//! the PQ tail coexist in the body, in that order. This test
//! verifies the ordering is correct and the server doesn't
//! either:
//!   - run ML-KEM encapsulation before validating the cookie
//!     (would defeat the DoS-mitigation purpose), or
//!   - mis-parse the cookie when PQ bytes are appended.
//!
//! Tests both halves of the cookie protocol:
//!   1. First HELLO arrives without a cookie → Challenge back.
//!   2. Second HELLO arrives WITH cookie + PQ ek → handshake
//!      completes via hybrid path.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn pq_cookie_always_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        cookie_always: true,
        ..Default::default()
    }
}

fn pq_client_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn hybrid_pq_handshake_with_always_cookies() {
    let server_id = Identity::from_secret_bytes([0xC1; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            server_id,
            pq_cookie_always_cfg(),
        )
        .await
        .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let client_id = Identity::from_secret_bytes([0xC2; 32]);
    let client_pub = client_id.public_bytes();
    let client = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), client_id, pq_client_cfg())
            .await
            .unwrap(),
    );

    server
        .add_peer(
            client_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let server_handle = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();

    client
        .send_data(&server_handle, b"hello-pq-with-cookies", 0, 0)
        .await
        .unwrap();

    let pkt = timeout(Duration::from_secs(8), server.recv())
        .await
        .expect("PQ+cookie handshake DATA timed out")
        .expect("recv returned None");
    assert_eq!(pkt.payload, b"hello-pq-with-cookies");

    let m = server.metrics();
    // The DoS-mitigation path MUST have fired: at least one
    // challenge issued, at least one cookie accepted.
    assert!(
        m.challenges_issued >= 1,
        "cookie path didn't engage — challenges_issued = {}",
        m.challenges_issued
    );
    assert!(
        m.cookies_accepted >= 1,
        "second-round cookie wasn't accepted — cookies_accepted = {}",
        m.cookies_accepted
    );
    // And the resulting handshake MUST be on the PQ track.
    assert!(
        m.hybrid_pq_handshakes_completed >= 1,
        "server says it completed a classical handshake, not a hybrid one: {:?}",
        m
    );
}

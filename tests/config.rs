//! Verify TransportConfig presets bind successfully and preserve
//! functionality across different parameter regimes.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;

#[tokio::test]
async fn default_config_works() {
    let cfg = TransportConfig::default();
    assert_eq!(cfg.handshake_retry_base_ms, 50);
    assert_eq!(cfg.handshake_max_attempts, 10);
    assert_eq!(cfg.beacon_interval_ms, 2000);
}

#[tokio::test]
async fn iot_preset_works() {
    let cfg = TransportConfig::iot();
    assert_eq!(cfg.beacon_interval_ms, 60_000);
    assert_eq!(cfg.handshake_retry_base_ms, 500);

    let bob = Identity::from_secret_bytes([0xA0; 32]);
    let alice = Identity::from_secret_bytes([0xA1; 32]);

    let bob_t = Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob, cfg.clone())
        .await
        .unwrap();
    bob_t
        .add_peer(
            alice.public_bytes(),
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice, cfg)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(
            Identity::from_secret_bytes([0xA0; 32]).public_bytes(),
            bob_addr,
            Direction::Initiator,
        )
        .await
        .unwrap();

    alice_t
        .send_data(&bob_peer, b"iot hello", 0, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(3), bob_t.recv())
        .await
        .expect("timed out")
        .expect("channel closed");
    assert_eq!(pkt.payload, b"iot hello");
}

#[tokio::test]
async fn realtime_preset_works() {
    let cfg = TransportConfig::realtime();
    assert_eq!(cfg.handshake_retry_base_ms, 25);
    assert_eq!(cfg.handshake_max_attempts, 12);

    let bob = Identity::from_secret_bytes([0xB0; 32]);
    let alice = Identity::from_secret_bytes([0xB1; 32]);

    let bob_t = Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob, cfg.clone())
        .await
        .unwrap();
    bob_t
        .add_peer(
            alice.public_bytes(),
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice, cfg)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(
            Identity::from_secret_bytes([0xB0; 32]).public_bytes(),
            bob_addr,
            Direction::Initiator,
        )
        .await
        .unwrap();

    for i in 0..5u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    let mut got = 0;
    for _ in 0..5 {
        if tokio::time::timeout(Duration::from_millis(500), bob_t.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            got += 1;
        }
    }
    assert!(got >= 3);
}

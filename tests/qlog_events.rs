//! Integration test for qlog event logging.
//!
//! Enables qlog on a client, does a minimal handshake +
//! DATA round trip against a peer, then parses the resulting
//! newline-delimited JSON file and checks that the expected
//! event types show up.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn qlog_writes_packet_and_handshake_events() {
    let tmp = std::env::temp_dir()
        .join(format!("drift_qlog_int_{}.jsonl", std::process::id()));

    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    // Alice's transport has qlog enabled.
    let cfg = TransportConfig {
        qlog_path: Some(tmp.clone()),
        ..TransportConfig::default()
    };
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, cfg)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice.send_data(&bob_peer, b"qlog-hello", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    // Give any async file writes a beat to flush.
    tokio::time::sleep(Duration::from_millis(100)).await;

    drop(alice);

    let contents = fs::read_to_string(&tmp).expect("qlog file should exist");
    let lines: Vec<&str> = contents.lines().collect();
    assert!(
        lines.len() >= 3,
        "expected at least 3 qlog events (trace_start, Hello send, handshake), got {}: {}",
        lines.len(),
        contents
    );

    // Every line must be valid-looking JSON (starts '{', ends '}').
    for line in &lines {
        assert!(line.starts_with('{') && line.ends_with('}'), "bad line: {}", line);
        assert!(line.contains("\"time\":"), "missing time: {}", line);
        assert!(line.contains("\"category\":"), "missing category: {}", line);
    }

    // Check expected event types are present somewhere.
    assert!(contents.contains("\"trace_start\""), "missing trace_start");
    assert!(
        contents.contains("\"packet_sent\"") || contents.contains("\"packet_received\""),
        "no packet events recorded"
    );
    assert!(
        contents.contains("\"handshake_complete\""),
        "no handshake_complete event recorded"
    );

    let _ = fs::remove_file(&tmp);
}

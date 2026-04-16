//! Rekey while a stream is actively flowing bytes.
//!
//! The existing rekey tests only exercise raw transport DATA
//! packets. This one runs the stream layer on top: we push
//! 256 KB through a stream, call `rekey()` while the push is
//! in flight, and verify that the receiver gets byte-for-byte
//! identical content. If the rekey grace window or the
//! `prev` rx-key fallback has a bug, segments sealed under
//! the old key would fail to decrypt and the byte count or
//! content would diverge.
//!
//! Also tests the interaction between resumption and rekey:
//! after a 1-RTT resume, rekey should still work on the
//! resumed session.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn rekey_midway_through_256k_push() {
    let alice_id = Identity::from_secret_bytes([0x61; 32]);
    let bob_id = Identity::from_secret_bytes([0x62; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up so the session is established.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = alice_mgr.open(bob_peer).await.unwrap();
    let stream_b = tokio::time::timeout(Duration::from_secs(2), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();

    // Build a deterministic payload so we can check byte-by-byte.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i & 0xFF) as u8).collect();
    let payload_for_sender = payload.clone();

    // Fire the sender task.
    let sender = tokio::spawn(async move {
        for chunk in payload_for_sender.chunks(1024) {
            stream_a.send(chunk).await.unwrap();
        }
    });

    // Fire the receiver task.
    let drain = tokio::spawn(async move {
        let mut out = Vec::with_capacity(256 * 1024);
        while out.len() < 256 * 1024 {
            match tokio::time::timeout(Duration::from_secs(10), stream_b.recv()).await {
                Ok(Some(chunk)) => out.extend_from_slice(&chunk),
                _ => break,
            }
        }
        out
    });

    // Let some bytes fly, then trigger a rekey MIDWAY. The
    // grace-window prev-key fallback has to catch any
    // segments that were in flight under the old key.
    tokio::time::sleep(Duration::from_millis(20)).await;
    alice_t.rekey(&bob_peer).await.unwrap();

    sender.await.unwrap();
    let received = drain.await.unwrap();
    assert_eq!(received.len(), payload.len(), "received byte count wrong");
    assert_eq!(
        received, payload,
        "received bytes do not match sent bytes after mid-stream rekey"
    );

    // Sanity: no auth failures on either side. If the prev-key
    // fallback had a bug, segments would have failed AEAD and
    // this counter would be non-zero.
    assert_eq!(
        alice_t.metrics().auth_failures,
        0,
        "alice should not see auth failures during mid-stream rekey"
    );
    assert_eq!(bob_t.metrics().auth_failures, 0);
    // And bob is still on handshake #1 — rekey isn't a new
    // handshake.
    assert_eq!(bob_t.metrics().handshakes_completed, 1);
}

#[tokio::test]
async fn rekey_on_resumed_session() {
    // Resume → rekey → DATA. Each step should work cleanly.
    let alice_bytes = [0x75u8; 32];
    let bob_bytes = [0x76u8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_bytes).public_bytes();

    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(bob_bytes),
        )
        .await
        .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    // First session → ticket.
    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, b"hello", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ticket = alice.export_resumption_ticket(&bob_peer).await.unwrap();
    drop(alice);

    // Fresh client, imports ticket, resumes.
    let alice2 = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer2 = alice2
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice2
        .import_resumption_ticket(&bob_peer2, &ticket)
        .await
        .unwrap();

    alice2.send_data(&bob_peer2, b"resumed-1", 0, 0).await.unwrap();
    let p = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"resumed-1");
    assert_eq!(alice2.metrics().resumptions_completed, 1);

    // Now rekey the resumed session.
    alice2.rekey(&bob_peer2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Traffic should still flow after the rekey-on-resumed.
    alice2.send_data(&bob_peer2, b"after-rekey-on-resumed", 0, 0).await.unwrap();
    let p2 = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p2.payload, b"after-rekey-on-resumed");

    // No auth failures either side.
    assert_eq!(alice2.metrics().auth_failures, 0);
    assert_eq!(bob.metrics().auth_failures, 0);
    // Bob still has only the one full handshake (with the
    // original alice). Resumption doesn't bump
    // handshakes_completed, nor does rekey.
    assert_eq!(bob.metrics().handshakes_completed, 1);
}

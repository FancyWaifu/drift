//! Scale test: spin up N client transports against a single
//! server and let them all handshake + exchange one DATA packet
//! concurrently. Stresses the peer-table, cookie threshold, and
//! eviction reaper against many simultaneous in-flight sessions.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn thousand_concurrent_handshakes() {
    const N: usize = 1000;

    let server_id = Identity::from_secret_bytes([0xAB; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Pre-register all N client pubkeys on the server — this is
    // the "known peers" path, so cookie mode stays disabled and
    // the test measures raw handshake throughput.
    let mut client_secrets = Vec::with_capacity(N);
    for i in 0..N {
        let mut secret = [0u8; 32];
        secret[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        secret[31] = 0xAA;
        client_secrets.push(secret);
        let pub_bytes = Identity::from_secret_bytes(secret).public_bytes();
        server
            .add_peer(
                pub_bytes,
                "0.0.0.0:0".parse().unwrap(),
                Direction::Responder,
            )
            .await
            .unwrap();
    }

    // Fire all N clients concurrently.
    let mut handles = Vec::with_capacity(N);
    for secret in client_secrets {
        let server_pub = server_pub;
        handles.push(tokio::spawn(async move {
            let client = Transport::bind(
                "127.0.0.1:0".parse().unwrap(),
                Identity::from_secret_bytes(secret),
            )
            .await
            .unwrap();
            let peer = client
                .add_peer(server_pub, server_addr, Direction::Initiator)
                .await
                .unwrap();
            client.send_data(&peer, b"scale", 0, 0).await.unwrap();
            // Keep the client alive long enough for the handshake
            // to reach the server; drop triggers socket close.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }));
    }

    // Drain the server side, counting deliveries.
    let mut delivered = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while delivered < N && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), server.recv()).await {
            Ok(Some(_)) => delivered += 1,
            _ => continue,
        }
    }

    // Wait for client tasks to finish cleanly.
    for h in handles {
        let _ = h.await;
    }

    // We expect the vast majority to make it through. A few may
    // lose the handshake race against eviction or be dropped by
    // the OS UDP buffer under extreme burst — allow 5% slack.
    assert!(
        delivered >= (N * 95) / 100,
        "only {}/{} handshakes delivered (need >= 95%)",
        delivered,
        N
    );

    let m = server.metrics();
    assert!(
        m.handshakes_completed >= (N as u64 * 95) / 100,
        "server reports only {} completed handshakes",
        m.handshakes_completed
    );
    // No path probes should have fired — fresh handshakes set
    // peer.addr during regenerate_session, not handle_data.
    assert_eq!(m.path_probes_sent, 0);
}

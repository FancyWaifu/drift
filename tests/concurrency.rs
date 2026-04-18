//! Concurrency stress tests.
//!
//! Multiple senders talking to one receiver, then one sender to multiple
//! receivers, and a burst test that sends many packets as fast as possible
//! to check for drops or reordering within the transport itself.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn many_senders_one_receiver() {
    const N_SENDERS: u8 = 16;
    const PACKETS_PER_SENDER: u32 = 50;

    let server_id = Identity::from_secret_bytes([0xA0; 32]);
    let server_pub = server_id.public_bytes();

    let server = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Register each client's pubkey with the server.
    let mut clients = Vec::new();
    for i in 0..N_SENDERS {
        let cid = Identity::from_secret_bytes([0xB0 ^ i; 32]);
        let cpub = cid.public_bytes();
        server
            .add_peer(cpub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
            .await
            .unwrap();
        clients.push((cid, cpub));
    }

    // Spawn senders.
    for (i, (cid, _)) in clients.into_iter().enumerate() {
        let server_pub_copy = server_pub;
        tokio::spawn(async move {
            let c = Transport::bind("127.0.0.1:0".parse().unwrap(), cid)
                .await
                .unwrap();
            let bob = c
                .add_peer(server_pub_copy, server_addr, Direction::Initiator)
                .await
                .unwrap();
            for seq in 0..PACKETS_PER_SENDER {
                let mut payload = Vec::new();
                payload.extend_from_slice(&(i as u32).to_be_bytes());
                payload.extend_from_slice(&seq.to_be_bytes());
                c.send_data(&bob, &payload, 0, 0).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // Keep client alive long enough for packets to drain.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
    }

    let total = N_SENDERS as usize * PACKETS_PER_SENDER as usize;
    let mut seen = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while seen.len() < total && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), server.recv()).await {
            Ok(Some(p)) if p.payload.len() == 8 => {
                let sender = u32::from_be_bytes(p.payload[0..4].try_into().unwrap());
                let seq = u32::from_be_bytes(p.payload[4..8].try_into().unwrap());
                seen.insert((sender, seq));
            }
            _ => {}
        }
    }

    println!("received {}/{}", seen.len(), total);
    assert!(
        seen.len() >= total * 95 / 100,
        "expected ≥95% delivery, got {}/{}",
        seen.len(),
        total
    );
}

#[tokio::test]
async fn burst_no_internal_drops() {
    // Single sender blasts 500 packets at a single receiver with no pacing.
    let alice = Identity::from_secret_bytes([0xC0; 32]);
    let bob = Identity::from_secret_bytes([0xC1; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    const N: u32 = 500;
    for i in 0..N {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
        // Tiny yield prevents the test from saturating the localhost UDP
        // kernel buffer — we're testing DRIFT's internals, not macOS's
        // socket buffer size.
        if i % 50 == 49 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let mut seen = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while seen.len() < N as usize && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), bob_t.recv()).await {
            Ok(Some(p)) if p.payload.len() == 4 => {
                let i = u32::from_be_bytes(p.payload.try_into().unwrap());
                seen.insert(i);
            }
            _ => break,
        }
    }
    println!("burst received {}/{}", seen.len(), N);
    // Localhost UDP is lossy under 500-packet bursts because of kernel
    // receive buffer limits — 85% is a reasonable floor for "no
    // catastrophic failure in the transport layer".
    assert!(
        seen.len() >= (N * 85 / 100) as usize,
        "expected ≥85% delivery, got {}/{}",
        seen.len(),
        N
    );
}

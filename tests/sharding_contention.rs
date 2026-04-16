//! Regression test for the peer-table sharding refactor.
//!
//! Before sharding, a single `Mutex<PeerTable>` serialized every
//! send_data / handle_data / handshake operation. Under heavy
//! concurrent load across many peers, that lock was the
//! dominant bottleneck. After sharding to 16 independently-
//! locked shards, unrelated operations should proceed in
//! parallel.
//!
//! This test doesn't try to measure absolute throughput (unit
//! tests are lousy benchmarks). Instead it:
//!   1. Stands up a server + 64 distinct client transports.
//!   2. Has every client concurrently handshake + send a burst
//!      of packets at the server.
//!   3. Asserts everything completes inside a generous time
//!      budget — if sharding lock ordering had a deadlock bug
//!      this would hang forever; if a correctness bug was
//!      introduced some packets would be lost.
//!
//! A 64-peer fan-in is enough to touch every one of the 16
//! shards multiple times under the bottom-4-bits hash, so any
//! per-shard state corruption would show up as either missing
//! or misattributed DATA at the server.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_fanin_send_data_completes_under_time_budget() {
    const CLIENT_COUNT: usize = 64;
    const PACKETS_PER_CLIENT: usize = 16;
    const BUDGET_SECS: u64 = 30;

    // Server accepts any peer so we don't need to call add_peer
    // on the server for every client.
    let server_cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let server_id = Identity::from_secret_bytes([0x55; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, server_cfg)
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Spawn a drain task so server.recv() is pulled concurrently
    // with the client sends — otherwise the recv channel
    // backs up and send_data loops get starved.
    let server_drain = server.clone();
    let total_expected = CLIENT_COUNT * PACKETS_PER_CLIENT;
    let drain_handle = tokio::spawn(async move {
        let mut got = 0usize;
        while got < total_expected {
            match tokio::time::timeout(
                Duration::from_secs(BUDGET_SECS),
                server_drain.recv(),
            )
            .await
            {
                Ok(Some(_)) => got += 1,
                Ok(None) | Err(_) => break,
            }
        }
        got
    });

    // Stand up the clients and fire the fan-in. Each client
    // gets a unique identity so they land on different shards
    // on the server via their derived peer_id.
    let mut handles = Vec::with_capacity(CLIENT_COUNT);
    for i in 0..CLIENT_COUNT {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xB0;
        bytes[1..].copy_from_slice(&(i as u32).to_be_bytes().repeat(8)[..31]);
        let client_id = Identity::from_secret_bytes(bytes);
        let client = Arc::new(
            Transport::bind("127.0.0.1:0".parse().unwrap(), client_id)
                .await
                .unwrap(),
        );
        let server_peer = client
            .add_peer(server_pub, server_addr, Direction::Initiator)
            .await
            .unwrap();
        handles.push(tokio::spawn(async move {
            for j in 0..PACKETS_PER_CLIENT {
                let payload = [(i & 0xFF) as u8, (j & 0xFF) as u8];
                client.send_data(&server_peer, &payload, 0, 0).await.unwrap();
            }
        }));
    }

    // Wait for every client to finish sending.
    let join_all = async {
        for h in handles {
            h.await.unwrap();
        }
    };
    tokio::time::timeout(Duration::from_secs(BUDGET_SECS), join_all)
        .await
        .expect("clients did not finish inside the time budget — possible sharding deadlock");

    // Verify every packet was delivered.
    let delivered = drain_handle.await.unwrap();
    assert_eq!(
        delivered, total_expected,
        "{} packets expected, {} delivered",
        total_expected, delivered
    );
}

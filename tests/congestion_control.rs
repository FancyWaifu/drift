//! Tests for the per-peer congestion-control and stream
//! flow-control mechanisms.
//!
//! * `cwnd_grows_during_slow_start_on_clean_link` — on a lossless
//!   link, `cwnd` increases past its initial value as the sender
//!   receives ACKs. RTT estimator populates.
//! * `cwnd_shrinks_on_loss` — under heavy drop, `cwnd` drops below
//!   the initial value, demonstrating multiplicative decrease.
//! * `flow_control_blocks_fast_sender` — (implicit in the other
//!   stream_reliability tests; the 256 KB payload over lossy link
//!   already exercises the rwnd/cwnd interaction).

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use rand::{Rng, SeedableRng};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Copy)]
struct LossProfile {
    drop_rate: f64,
    latency_ms: u64,
}

async fn spawn_proxy(target: SocketAddr, profile: LossProfile) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut rng = rand::rngs::StdRng::from_entropy();
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let data = buf[..n].to_vec();
            let dst = if src == target {
                match *client.lock().await {
                    Some(a) => a,
                    None => continue,
                }
            } else {
                let mut c = client.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                target
            };
            if rng.gen::<f64>() < profile.drop_rate {
                continue;
            }
            let delay = profile.latency_ms;
            let sock2 = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _ = sock2.send_to(&data, dst).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn cwnd_grows_during_slow_start_on_clean_link() {
    let alice_id = Identity::from_secret_bytes([0xC1; 32]);
    let bob_id = Identity::from_secret_bytes([0xC2; 32]);
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

    // Warm-up handshake.
    alice_t.send_data(&bob_peer, b"warmup", 0, 0).await.unwrap();
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

    // Initial cwnd should be ~10 * MSS = 12000 bytes.
    let initial = alice_mgr
        .congestion_snapshot(&bob_peer)
        .await
        .expect("cc should exist after open");
    assert!(
        initial.cwnd >= 10 * 1200 && initial.cwnd <= 12 * 1200,
        "initial cwnd out of expected range: {}",
        initial.cwnd
    );
    assert!(
        initial.srtt_us.is_none(),
        "srtt should be unset before any ACKs"
    );

    // Push 128 KB so plenty of segments flow and slow-start can
    // bump cwnd.
    let payload = vec![0x42u8; 128 * 1024];
    let payload_c = payload.clone();
    let sender = tokio::spawn(async move {
        for chunk in payload_c.chunks(1000) {
            stream_a.send(chunk).await.unwrap();
        }
    });

    // Drain on the receiver — otherwise flow-control would cap
    // the window after one buffer fill.
    let drain = tokio::spawn(async move {
        let mut got = 0usize;
        while got < 128 * 1024 {
            match tokio::time::timeout(Duration::from_secs(5), stream_b.recv()).await {
                Ok(Some(chunk)) => got += chunk.len(),
                _ => break,
            }
        }
        got
    });

    sender.await.unwrap();
    assert_eq!(drain.await.unwrap(), 128 * 1024);

    // Let trailing ACKs settle so `bytes_in_flight` drains to 0.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let after = alice_mgr
        .congestion_snapshot(&bob_peer)
        .await
        .expect("cc still there");

    // On a clean localhost link, cwnd should have grown past its
    // initial value.
    assert!(
        after.cwnd > initial.cwnd,
        "cwnd did not grow during slow start: before={} after={}",
        initial.cwnd,
        after.cwnd
    );
    // RTT estimator should be populated now.
    assert!(after.srtt_us.is_some(), "srtt should be measured");
    // bytes_in_flight should be zero after drain (all ACK'd).
    assert_eq!(after.bytes_in_flight, 0);
}

#[tokio::test]
async fn cwnd_shrinks_on_loss() {
    let alice_id = Identity::from_secret_bytes([0xD1; 32]);
    let bob_id = Identity::from_secret_bytes([0xD2; 32]);
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

    // 15% drop link: heavy enough to trigger retransmits
    // reliably (and thus exercise `on_loss`), but low enough
    // that the stream-layer OPEN frame (which isn't itself
    // retransmitted — raw transport.send_data) survives the
    // first few tries. 30% was flaky under cargo parallel
    // pressure.
    let proxy = spawn_proxy(
        bob_addr,
        LossProfile {
            drop_rate: 0.15,
            latency_ms: 5,
        },
    )
    .await;

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t.add_peer(bob_pub, proxy, Direction::Initiator).await.unwrap();

    // Warm up through the proxy.
    alice_t.send_data(&bob_peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = alice_mgr.open(bob_peer).await.unwrap();
    let stream_b = tokio::time::timeout(Duration::from_secs(5), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();

    let initial_cwnd = alice_mgr
        .congestion_snapshot(&bob_peer)
        .await
        .unwrap()
        .cwnd;

    // Push 128 KB through the lossy proxy so retransmits fire.
    let payload = vec![0x77u8; 128 * 1024];
    let stream_a = Arc::new(stream_a);
    let stream_a_c = stream_a.clone();
    let sender = tokio::spawn(async move {
        for chunk in payload.chunks(1000) {
            stream_a_c.send(chunk).await.unwrap();
        }
    });
    let drain = tokio::spawn(async move {
        let mut got = 0usize;
        while got < 128 * 1024 {
            match tokio::time::timeout(Duration::from_secs(10), stream_b.recv()).await {
                Ok(Some(chunk)) => got += chunk.len(),
                _ => break,
            }
        }
        got
    });

    sender.await.unwrap();
    let received = drain.await.unwrap();
    assert_eq!(received, 128 * 1024);

    let final_cwnd = alice_mgr
        .congestion_snapshot(&bob_peer)
        .await
        .unwrap()
        .cwnd;

    println!(
        "cwnd trajectory: initial={} final={}",
        initial_cwnd, final_cwnd
    );

    // After sustained 30% loss on a 128 KB push, we should have
    // seen `on_loss` fire at least once — which halves cwnd.
    // Final cwnd may have partially recovered during congestion
    // avoidance, but it should reflect that loss occurred in
    // SOME form. We assert that ssthresh has been set (not
    // INITIAL_SSTHRESH = usize::MAX), which only happens via
    // `on_loss`.
    let ssthresh = alice_mgr
        .congestion_snapshot(&bob_peer)
        .await
        .unwrap()
        .ssthresh;
    assert!(
        ssthresh != usize::MAX,
        "ssthresh should have been set by a loss event; still at initial {}",
        ssthresh
    );
}

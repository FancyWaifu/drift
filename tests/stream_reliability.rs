//! Positive-path reliability tests for the stream layer.
//!
//! * `large_payload_over_lossy_link_arrives_intact` — push 256 KB
//!   through a single stream across a 10%-drop + reorder proxy and
//!   verify byte-for-byte equality at the other end.
//! * `many_concurrent_streams_interleave_correctly` — open 50
//!   streams and fire 1000 messages round-robin across them;
//!   assert every message lands in the right stream in order.
//! * `close_during_active_send_is_safe` — concurrently call
//!   `send` and `close` on the same stream; neither side should
//!   panic and any delivered bytes should be consistent.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// ---- shared lossy proxy ----
#[derive(Clone, Copy)]
struct LossProfile {
    drop_rate: f64,
    reorder_rate: f64,
    latency_ms: u64,
    jitter_ms: u64,
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

            let base = profile.latency_ms;
            let jitter = rng.gen_range(0..=profile.jitter_ms.saturating_add(1)) as u64;
            let mut delay = base + jitter;
            if rng.gen::<f64>() < profile.reorder_rate {
                delay += rng.gen_range(10..=50);
            }

            let sock2 = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _ = sock2.send_to(&data, dst).await;
            });
        }
    });

    addr
}

// ---- test 1: large payload over lossy link ----

#[tokio::test]
async fn large_payload_over_lossy_link_arrives_intact() {
    let alice_id = Identity::from_secret_bytes([0x01; 32]);
    let bob_id = Identity::from_secret_bytes([0x02; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
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

    let proxy = spawn_proxy(
        bob_addr,
        LossProfile {
            drop_rate: 0.10,
            reorder_rate: 0.20,
            latency_ms: 5,
            jitter_ms: 10,
        },
    )
    .await;

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, proxy, Direction::Initiator)
        .await
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = alice_mgr.open(bob_peer).await.unwrap();

    // 256 KB deterministic payload.
    let mut payload = Vec::with_capacity(256 * 1024);
    for i in 0..payload.capacity() {
        payload.push(((i * 31 + 7) % 251) as u8);
    }

    // Chunked send so each DRIFT DATA stays under MAX_SEGMENT.
    // Start the sender BEFORE waiting on accept — if the
    // one-shot OPEN frame is dropped on the lossy link, the
    // reliable-OPEN fallback on the receiver side creates
    // the stream implicitly from the first inbound DATA.
    // That only works if DATA is actually flowing, so the
    // sender has to race the accept.
    let payload_clone = payload.clone();
    let send_task = tokio::spawn(async move {
        for chunk in payload_clone.chunks(1000) {
            stream_a.send(chunk).await.unwrap();
        }
    });

    let stream_b = tokio::time::timeout(Duration::from_secs(5), bob_mgr.accept())
        .await
        .expect("accept timeout")
        .unwrap();

    // Drain on the receiver side until we've seen every byte.
    let recv_task = tokio::spawn(async move {
        let mut got = Vec::new();
        while got.len() < 256 * 1024 {
            match tokio::time::timeout(Duration::from_secs(15), stream_b.recv()).await {
                Ok(Some(chunk)) => got.extend_from_slice(&chunk),
                _ => break,
            }
        }
        got
    });

    send_task.await.unwrap();
    let got = recv_task.await.unwrap();
    assert_eq!(got.len(), payload.len(), "short receive");
    assert_eq!(got, payload, "byte mismatch over lossy link");
}

// ---- test 2: many concurrent streams ----

#[tokio::test]
async fn many_concurrent_streams_interleave_correctly() {
    let alice_id = Identity::from_secret_bytes([0x10; 32]);
    let bob_id = Identity::from_secret_bytes([0x11; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
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

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up the handshake BEFORE binding StreamManagers so the
    // session is Established by the time OPEN frames fly — otherwise
    // the 1000 queued sends can overflow the pre-handshake pending
    // queue (default cap 256).
    alice_t.send_data(&bob_peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    const N: usize = 50;
    const PER: usize = 20;

    // Open N streams on Alice, then spawn accept loop on Bob.
    let mut alice_streams = Vec::with_capacity(N);
    for _ in 0..N {
        alice_streams.push(alice_mgr.open(bob_peer).await.unwrap());
    }

    // Accept N streams on Bob and collect them by id.
    let bob_mgr_c = bob_mgr.clone();
    let accept = tokio::spawn(async move {
        let mut streams: HashMap<u32, drift::streams::Stream> = HashMap::new();
        for _ in 0..N {
            let s = tokio::time::timeout(Duration::from_secs(5), bob_mgr_c.accept())
                .await
                .expect("accept timeout")
                .unwrap();
            streams.insert(s.id(), s);
        }
        streams
    });

    // Send PER messages per stream, round-robin by time order.
    let mut senders = Vec::new();
    for (i, s) in alice_streams.into_iter().enumerate() {
        senders.push(tokio::spawn(async move {
            for j in 0..PER {
                let tag = format!("s{}-m{}", i, j);
                s.send(tag.as_bytes()).await.unwrap();
            }
            s.id()
        }));
    }

    // Drive senders to completion and collect each stream's id.
    let mut sent_ids = Vec::new();
    for t in senders {
        sent_ids.push(t.await.unwrap());
    }

    // Collect Bob's streams.
    let bob_streams = accept.await.unwrap();

    // Verify: for every Alice stream id, Bob has a matching one,
    // and every message arrives in order.
    for (i, id) in sent_ids.iter().enumerate() {
        let b = bob_streams
            .get(id)
            .unwrap_or_else(|| panic!("Bob missing stream id {}", id));
        for j in 0..PER {
            let msg = tokio::time::timeout(Duration::from_secs(5), b.recv())
                .await
                .unwrap_or_else(|_| panic!("stream {} msg {} timeout", i, j))
                .expect("recv None");
            let expected = format!("s{}-m{}", i, j);
            assert_eq!(
                std::str::from_utf8(&msg).unwrap(),
                expected,
                "stream {} msg {}",
                i,
                j
            );
        }
    }
}

// ---- test 3: close during active send ----

#[tokio::test]
async fn close_during_active_send_is_safe() {
    let alice_id = Identity::from_secret_bytes([0x20; 32]);
    let bob_id = Identity::from_secret_bytes([0x21; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
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

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = Arc::new(alice_mgr.open(bob_peer).await.unwrap());
    let _stream_b = tokio::time::timeout(Duration::from_secs(3), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();

    // Spawn a task that sends as fast as possible.
    let sender = {
        let s = stream_a.clone();
        tokio::spawn(async move {
            for i in 0..200u32 {
                // Ignore errors — once close() lands on the other
                // goroutine, further sends may legitimately return
                // StreamError::Closed.
                let _ = s.send(&i.to_be_bytes()).await;
            }
        })
    };

    // Let a handful of messages get queued first.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Race a close() against the in-flight sends.
    let closer = {
        let s = stream_a.clone();
        tokio::spawn(async move {
            let _ = s.close().await;
        })
    };

    // Both tasks must finish without panicking.
    let (s_res, c_res) = tokio::join!(sender, closer);
    s_res.unwrap();
    c_res.unwrap();

    // No assertion on exact byte delivery count — the point is
    // "no panic, no deadlock under racy close+send".
}

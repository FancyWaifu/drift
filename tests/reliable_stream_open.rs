//! Reliable stream OPEN: even when the explicit OPEN frame is
//! dropped on a lossy link, the receiver should auto-create the
//! stream from the first arriving DATA segment, so the stream
//! still becomes acceptable and traffic flows. Without this
//! fallback, a single OPEN drop would silently stall the entire
//! stream.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Proxy that drops the FIRST `drop_first_n` packets it sees in
/// either direction, then forwards everything cleanly. This
/// reliably knocks out the OPEN frame (which is normally the
/// first stream-layer payload after the warmup handshake) without
/// being randomly flaky.
async fn spawn_head_drop_proxy(target: SocketAddr, drop_first_n: usize) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let dropped = Arc::new(AtomicUsize::new(0));

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
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

            // Only drop client→target traffic so server replies
            // (cookies, hello-acks, ACKs) always make it through.
            if dst == target && dropped.fetch_add(1, AtomicOrdering::Relaxed) < drop_first_n {
                continue;
            }

            let _ = sock.send_to(&data, dst).await;
        }
    });
    addr
}

#[tokio::test]
async fn data_creates_stream_when_open_is_lost() {
    let alice_id = Identity::from_secret_bytes([0xF1; 32]);
    let bob_id = Identity::from_secret_bytes([0xF2; 32]);
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

    // Drop the first 2 client→server packets after warmup completes.
    // We warm up directly first (bypassing the proxy) so the
    // handshake doesn't get clobbered, then point Alice at the
    // drop-proxy for stream traffic.
    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up via direct path so handshake completes.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    // Now route Alice through a proxy that eats the next packet.
    // Stream-layer OPEN goes via raw transport.send_data with no
    // retransmission, so the very first stream packet (the OPEN)
    // will be dropped. The first DATA segment that follows must
    // implicitly create the stream on Bob's side.
    let proxy = spawn_head_drop_proxy(bob_addr, 1).await;
    assert!(alice_t.update_peer_addr(&bob_peer, proxy).await);

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = alice_mgr.open(bob_peer).await.unwrap();
    // Push some bytes — the OPEN was dropped, but the DATA
    // segments will retransmit through the proxy and Bob's
    // handle_data will auto-create the stream.
    stream_a.send(b"hello-after-lost-open").await.unwrap();

    let stream_b = tokio::time::timeout(Duration::from_secs(5), bob_mgr.accept())
        .await
        .expect("accept timed out — implicit OPEN failed")
        .expect("accept returned None");

    let chunk = tokio::time::timeout(Duration::from_secs(5), stream_b.recv())
        .await
        .expect("recv timed out")
        .expect("stream closed");
    assert_eq!(chunk, b"hello-after-lost-open");
}

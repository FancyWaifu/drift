//! SEC.PEN.3 — PQ downgrade via FLAG_PQ_HYBRID strip.
//!
//! Threat model: both Alice and Bob are PQ-capable and have
//! `hybrid_pq=true` in their config. An on-path attacker (MITM
//! sitting between their wire addresses) strips `FLAG_PQ_HYBRID`
//! from Alice's HELLO and truncates the trailing 1184-byte
//! ML-KEM encapsulation key. Bob sees a "classical" HELLO and
//! responds with a classical HELLO_ACK (no PQ ciphertext).
//!
//! If Alice silently accepted the classical HELLO_ACK she'd
//! complete a session that, while confidential today, has no
//! post-quantum guarantee — an attacker recording the wire would
//! be able to decrypt it once a CRQC exists. That's a downgrade.
//!
//! Defense (drift/src/transport/mod.rs handle_hello_ack, around
//! the "PQ posture mismatch" check): the client refuses to
//! complete the handshake when its own `pq_dk_opt.is_some()` !=
//! the responder's `FLAG_PQ_HYBRID`. The mismatch is counted in
//! `metrics().hybrid_pq_handshakes_refused`.
//!
//! This test runs a UDP proxy in-process, mangles every Hello
//! packet flowing client→server, and asserts the client refuses.

use drift::header::{Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const ML_KEM_EK_LEN: usize = 1184;
const FLAG_PQ_HYBRID: u8 = 1 << 2;

fn pq_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        handshake_max_attempts: 3,
        handshake_retry_base_ms: 200,
        ..TransportConfig::default()
    }
}

/// Strip FLAG_PQ_HYBRID from byte 0 and truncate the trailing
/// 1184-byte ML-KEM EK from the HELLO body. Mutates `pkt` in
/// place. Returns whether a strip happened (so the test can
/// count attempts).
fn strip_pq_flag_if_hello(pkt: &mut Vec<u8>) -> bool {
    if pkt.len() < HEADER_LEN {
        return false;
    }
    let header = match Header::decode(&pkt[..HEADER_LEN]) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if header.packet_type != PacketType::Hello {
        return false;
    }
    let flag_set = (pkt[0] & FLAG_PQ_HYBRID) != 0;
    if !flag_set {
        return false;
    }
    // Clear bit 2 of byte[0] (the FLAG_PQ_HYBRID position).
    pkt[0] &= !FLAG_PQ_HYBRID;
    // Truncate the PQ tail. If the packet has cookie, the PQ tail
    // is still the last ML_KEM_EK_LEN bytes (cookie sits between
    // base body and PQ tail).
    if pkt.len() >= ML_KEM_EK_LEN {
        pkt.truncate(pkt.len() - ML_KEM_EK_LEN);
    }
    true
}

/// Bidirectional UDP proxy that strips PQ flags from client→server
/// HELLOs. Returns (proxy_listen_addr, strip_counter).
async fn spawn_strip_proxy(server: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let strip_count = Arc::new(AtomicUsize::new(0));
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let strip_count_inner = strip_count.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut pkt = buf[..n].to_vec();
            let to_server = src != server;
            let dst = if to_server {
                // First packet from client side — remember the addr
                // so server-→client traffic finds its way back.
                let mut c = client_addr.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                server
            } else {
                match *client_addr.lock().await {
                    Some(a) => a,
                    None => continue,
                }
            };
            if to_server && strip_pq_flag_if_hello(&mut pkt) {
                strip_count_inner.fetch_add(1, Ordering::Relaxed);
            }
            let _ = sock.send_to(&pkt, dst).await;
        }
    });
    (addr, strip_count)
}

#[tokio::test]
async fn pq_downgrade_via_flag_strip_is_refused() {
    // Bob (responder): PQ-enabled bridge-like server.
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, pq_cfg())
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    // MITM proxy in front of Bob.
    let (proxy_addr, strip_count) = spawn_strip_proxy(bob_addr).await;

    // Alice (initiator): PQ-enabled. Knows Bob's pubkey, dials
    // through the proxy.
    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, pq_cfg())
            .await
            .unwrap(),
    );
    let bob_handle = alice
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = alice.send_data(&bob_handle, b"trigger", 1000, 0).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let alice_m = alice.metrics();
    let strips = strip_count.load(Ordering::Relaxed);
    assert!(
        strips >= 1,
        "MITM proxy never observed a Hello to strip — handshake \
         never reached the wire. metrics: {:?}",
        alice_m
    );
    assert!(
        alice_m.hybrid_pq_handshakes_refused >= 1,
        "PQ downgrade NOT detected. {} HELLOs were stripped of \
         FLAG_PQ_HYBRID, but Alice didn't bump \
         hybrid_pq_handshakes_refused. metrics: \
         auth_failures={}, handshakes_completed={}, \
         hybrid_pq_handshakes_completed={}, \
         hybrid_pq_handshakes_refused={}",
        strips,
        alice_m.auth_failures,
        alice_m.handshakes_completed,
        alice_m.hybrid_pq_handshakes_completed,
        alice_m.hybrid_pq_handshakes_refused,
    );
    let peer_ready = alice
        .peer_metrics(&bob_handle)
        .await
        .map(|m| m.is_established)
        .unwrap_or(false);
    assert!(
        !peer_ready,
        "PQ downgrade silently succeeded — Alice's session to Bob \
         is established despite the flag being stripped on the wire."
    );
}

#[tokio::test]
async fn pq_handshake_works_when_proxy_passes_through_unmodified() {
    // Positive control — same proxy minus the strip logic.
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, pq_cfg())
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = sock.local_addr().unwrap();
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let dst = if src != bob_addr {
                let mut c = client_addr.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                bob_addr
            } else {
                match *client_addr.lock().await {
                    Some(a) => a,
                    None => continue,
                }
            };
            let _ = sock.send_to(&buf[..n], dst).await;
        }
    });

    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, pq_cfg())
            .await
            .unwrap(),
    );
    let bob_handle = alice
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();
    alice
        .send_data(&bob_handle, b"hello-pq", 1000, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("recv timeout — positive control PQ handshake broken")
        .expect("recv returned None");
    assert_eq!(pkt.payload, b"hello-pq");
    let alice_m = alice.metrics();
    assert!(
        alice_m.hybrid_pq_handshakes_completed >= 1,
        "positive control: Alice didn't complete a PQ handshake; \
         metrics: {:?}",
        alice_m
    );
}

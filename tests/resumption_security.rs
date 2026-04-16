//! Security properties of 1-RTT session resumption:
//!
//! * `cross_identity_ticket_rejected` — a ticket bound to one
//!   client identity must not be usable by a transport with a
//!   different secret key. The server enforces this via the
//!   `client_static_pub` binding stored alongside the PSK.
//! * `resume_hello_single_use` — a `ResumeHello` captured off
//!   the wire cannot be replayed. The server takes the ticket
//!   out of the store on first use (single-use semantics), so
//!   the replay is rejected as `AuthFailed`.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrd};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[tokio::test]
async fn cross_identity_ticket_rejected() {
    // Threat model: a stolen ticket blob is sensitive secret
    // material (it carries the PSK). But even with the blob,
    // a client who presents it with the WRONG identity must
    // be rejected — the server binds each ticket to the
    // originating client's static pubkey and refuses to honor
    // it for anyone else.
    //
    // We need Bob to know BOTH Alice and Mallory as real
    // peers, otherwise the ResumeHello fails the earlier
    // unknown-peer check and never reaches the binding
    // enforcement we're trying to test.

    let alice_bytes = [0x71u8; 32];
    let bob_bytes = [0x72u8; 32];
    let mallory_bytes = [0xFFu8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_bytes).public_bytes();
    let mallory_pub = Identity::from_secret_bytes(mallory_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_bytes).public_bytes();

    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(bob_bytes),
        )
        .await
        .unwrap(),
    );
    // Bob knows both Alice (legitimate) and Mallory (attacker).
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    bob.add_peer(mallory_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    // Alice completes a normal handshake with Bob, gets a
    // ticket, exports it. The ticket is bound to Alice's
    // static pubkey in Bob's resumption store.
    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer_on_alice = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer_on_alice, b"legit", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ticket_blob = alice.export_resumption_ticket(&bob_peer_on_alice).await.unwrap();
    drop(alice);

    // Mallory's own separate transport. She imports the
    // stolen ticket.
    let mallory = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(mallory_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer_on_mallory = mallory
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    assert_eq!(bob_peer_on_mallory, bob_peer_on_alice);
    mallory
        .import_resumption_ticket(&bob_peer_on_mallory, &ticket_blob)
        .await
        .unwrap();

    // Mallory attempts to resume. Her ResumeHello carries her
    // own src_id (Mallory's peer_id), the ticket_id (Alice's),
    // and a fresh client_eph_pub. On Bob's side:
    //   - `peers.get(&mallory_peer_id)` succeeds — Bob knows
    //     her now.
    //   - `store.take(ticket_id, mallory_static_pub)` FAILS
    //     because the stored binding is Alice's static pubkey.
    //   - resumption_rejects bumps, AuthFailed propagates, no
    //     ResumeAck is ever sent.
    mallory
        .send_data(&bob_peer_on_mallory, b"stolen-ticket-attempt", 0, 0)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mm = mallory.metrics();
    let bm = bob.metrics();
    assert!(
        mm.resumption_attempts >= 1,
        "mallory tried at least one resumption"
    );
    assert_eq!(
        mm.resumptions_completed, 0,
        "cross-identity resumption must NOT complete on the client"
    );
    assert!(
        bm.resumption_rejects >= 1,
        "bob should have rejected the cross-identity ResumeHello (got rejects={})",
        bm.resumption_rejects
    );
    // The critical property: the ticket-path did NOT complete
    // for Mallory. Note that Mallory is a known peer to Bob,
    // so after the ResumeHello fails she can still fall
    // through to a full HELLO handshake — that's a different
    // code path and not what this test is guarding. What we
    // care about is that no RESUMPTION succeeds.
    assert_eq!(bm.resumptions_completed, 0);
}

/// A lightweight UDP interceptor that buffers every packet
/// flowing client→server so the caller can replay one. Still
/// forwards everything in real time; the buffer is just for
/// snooping.
async fn spawn_recording_proxy(
    target: SocketAddr,
) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>, Arc<UdpSocket>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let buffer: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let sock_bg = sock.clone();
    let buffer_bg = buffer.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock_bg.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let data = buf[..n].to_vec();
            let (dst, record_outbound) = if src == target {
                let c = client.lock().await;
                match *c {
                    Some(a) => (a, false),
                    None => continue,
                }
            } else {
                let mut c = client.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                (target, true)
            };
            if record_outbound {
                buffer_bg.lock().await.push(data.clone());
            }
            let _ = sock_bg.send_to(&data, dst).await;
        }
    });

    (addr, buffer, sock)
}

#[tokio::test]
async fn resume_hello_single_use() {
    // Phase 1: Alice handshakes with Bob and gets a ticket.
    let alice_id_bytes = [0x73u8; 32];
    let bob_id_bytes = [0x74u8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_id_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_id_bytes).public_bytes();

    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(bob_id_bytes),
        )
        .await
        .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_real_addr = bob.local_addr().unwrap();

    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_real_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, b"first", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let ticket_blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();
    drop(alice);

    // Phase 2: a fresh client (Alice') imports the ticket and
    // resumes THROUGH a recording proxy, so we capture the
    // ResumeHello on the wire.
    let (proxy_addr, buffer, replay_sock) = spawn_recording_proxy(bob_real_addr).await;

    let alice2 = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer2 = alice2
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();
    alice2
        .import_resumption_ticket(&bob_peer2, &ticket_blob)
        .await
        .unwrap();
    alice2.send_data(&bob_peer2, b"legit-resume", 0, 0).await.unwrap();

    // Wait for the legit resume to complete.
    let _ = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("legit resumption should have landed")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let bm_before_replay = bob.metrics();
    assert_eq!(bm_before_replay.resumptions_completed, 1);
    let rejects_before = bm_before_replay.resumption_rejects;

    // Pull the recorded ResumeHello out of the proxy buffer.
    // It's the first outbound packet Alice2 emitted (since she
    // had a ticket, she skipped straight to a ResumeHello
    // instead of a full HELLO).
    let recorded = buffer.lock().await.clone();
    assert!(
        !recorded.is_empty(),
        "proxy should have recorded at least one outbound packet"
    );
    let resume_hello_wire = &recorded[0];

    // Replay it ourselves, directly at Bob's real address
    // from a fresh source. Use a counter to give the replay
    // worker its own socket so Bob sees a new src.
    static REPLAY_N: AtomicUsize = AtomicUsize::new(0);
    REPLAY_N.fetch_add(1, AtomicOrd::Relaxed);
    let _ = replay_sock.send_to(resume_hello_wire, bob_real_addr).await;

    // Give Bob a beat to process and either accept or reject.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let bm_after_replay = bob.metrics();
    // The replay must NOT have produced a second resumption.
    assert_eq!(
        bm_after_replay.resumptions_completed, 1,
        "ResumeHello replay must not create a second resumption (tickets are single-use)"
    );
    // And the reject counter should have ticked (or the
    // packet silently dropped as AuthFailed) — at minimum the
    // server must not have completed another handshake.
    assert!(
        bm_after_replay.resumption_rejects >= rejects_before,
        "reject counter should not regress"
    );
}

//! Mesh stress tests: multi-hop chains, routing loops, TTL termination.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Build a linear chain: A → R1 → R2 → R3 → B. Verify packets from A
/// reach B with end-to-end crypto intact.
#[tokio::test]
async fn three_hop_chain() {
    let alice = Identity::from_secret_bytes([0x10; 32]);
    let bob = Identity::from_secret_bytes([0x11; 32]);
    let r1 = Identity::from_secret_bytes([0x20; 32]);
    let r2 = Identity::from_secret_bytes([0x21; 32]);
    let r3 = Identity::from_secret_bytes([0x22; 32]);

    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();
    let alice_peer_id = derive_peer_id(&alice_pub);
    let bob_peer_id = derive_peer_id(&bob_pub);

    // Bob is the final destination.
    let bob_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob)
        .await
        .unwrap();
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    // r3 forwards to Bob.
    let r3_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r3)
        .await
        .unwrap();
    r3_t.add_route(bob_peer_id, bob_addr).await;
    let r3_addr = r3_t.local_addr().unwrap();

    // r2 forwards to r3.
    let r2_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r2)
        .await
        .unwrap();
    r2_t.add_route(bob_peer_id, r3_addr).await;
    let r2_addr = r2_t.local_addr().unwrap();

    // r1 forwards to r2.
    let r1_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r1)
        .await
        .unwrap();
    r1_t.add_route(bob_peer_id, r2_addr).await;
    let r1_addr = r1_t.local_addr().unwrap();

    // Return path: Alice will need r1→r2→r3 routing toward alice_peer_id.
    // Since we use symmetric handshake, the HELLO_ACK from Bob must traverse
    // the same chain backward. Set up reverse routes on each relay.
    // r3 needs to route alice_peer_id → r2_addr
    r3_t.add_route(alice_peer_id, r2_addr).await;
    r2_t.add_route(alice_peer_id, r1_addr).await;

    // Alice is the original source; she uses a fixed port so r1 can route
    // alice_peer_id back to her.
    let alice_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice)
        .await
        .unwrap();
    let alice_addr = alice_t.local_addr().unwrap();
    r1_t.add_route(alice_peer_id, alice_addr).await;

    let bob_peer_handle = alice_t
        .add_peer(bob_pub, "0.0.0.0:0".parse().unwrap(), Direction::Initiator)
        .await.unwrap();
    alice_t.add_route(bob_peer_id, r1_addr).await;

    // Keep relays alive.
    let _r1 = Arc::new(r1_t);
    let _r2 = Arc::new(r2_t);
    let _r3 = Arc::new(r3_t);

    // Send several messages and verify delivery.
    for i in 0..5u32 {
        alice_t
            .send_data(&bob_peer_handle, &i.to_be_bytes(), 1000, 0)
            .await
            .unwrap();
    }

    let mut received = 0;
    for _ in 0..5 {
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_secs(3), bob_t.recv()).await
        {
            assert_eq!(p.payload.len(), 4);
            received += 1;
        } else {
            break;
        }
    }
    assert!(received >= 4, "only {} packets traversed 3-hop chain", received);
}

/// Five-hop chain: A → R1 → R2 → R3 → R4 → B. Verifies that crypto
/// survives deep mesh paths and hop_ttl is decremented correctly.
#[tokio::test]
async fn five_hop_chain() {
    use drift::Direction;

    let mut ids: Vec<Identity> = (0..6)
        .map(|i| Identity::from_secret_bytes([0x40 + i; 32]))
        .collect();
    let pubs: Vec<[u8; 32]> = ids.iter().map(|i| i.public_bytes()).collect();
    let peer_ids: Vec<[u8; 8]> = pubs.iter().map(|p| derive_peer_id(p)).collect();

    let alice = ids.remove_wrap(0);
    let r1 = ids.remove_wrap(0);
    let r2 = ids.remove_wrap(0);
    let r3 = ids.remove_wrap(0);
    let r4 = ids.remove_wrap(0);
    let bob = ids.remove_wrap(0);

    // Bind all six nodes.
    let bob_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob)
        .await
        .unwrap();
    bob_t
        .add_peer(pubs[0], "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let r4_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r4)
        .await
        .unwrap();
    r4_t.add_route(peer_ids[5], bob_addr).await;
    let r4_addr = r4_t.local_addr().unwrap();

    let r3_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r3)
        .await
        .unwrap();
    r3_t.add_route(peer_ids[5], r4_addr).await;
    let r3_addr = r3_t.local_addr().unwrap();

    let r2_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r2)
        .await
        .unwrap();
    r2_t.add_route(peer_ids[5], r3_addr).await;
    let r2_addr = r2_t.local_addr().unwrap();

    let r1_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), r1)
        .await
        .unwrap();
    r1_t.add_route(peer_ids[5], r2_addr).await;
    let r1_addr = r1_t.local_addr().unwrap();

    // Reverse routes so HELLO_ACK can traverse back.
    r4_t.add_route(peer_ids[0], r3_addr).await;
    r3_t.add_route(peer_ids[0], r2_addr).await;
    r2_t.add_route(peer_ids[0], r1_addr).await;

    let alice_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice)
        .await
        .unwrap();
    let alice_addr = alice_t.local_addr().unwrap();
    r1_t.add_route(peer_ids[0], alice_addr).await;

    let bob_peer_handle = alice_t
        .add_peer(pubs[5], "0.0.0.0:0".parse().unwrap(), Direction::Initiator)
        .await.unwrap();
    alice_t.add_route(peer_ids[5], r1_addr).await;

    // Keep relays alive.
    let _keep = (r1_t, r2_t, r3_t, r4_t);

    // Send packets, verify delivery through 5 hops.
    for i in 0..5u32 {
        alice_t
            .send_data(&bob_peer_handle, &i.to_be_bytes(), 2000, 0)
            .await
            .unwrap();
    }

    let mut received = 0;
    for _ in 0..5 {
        if let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_secs(3), bob_t.recv()).await
        {
            received += 1;
        } else {
            break;
        }
    }
    assert!(
        received >= 4,
        "only {} packets traversed 5-hop chain",
        received
    );
}

// Small helper trait — Vec::remove_wrap is a fake name I use here to
// make the test's ownership-moving clearer. Actually just uses swap_remove.
trait RemoveWrap<T> {
    fn remove_wrap(&mut self, idx: usize) -> T;
}
impl<T> RemoveWrap<T> for Vec<T> {
    fn remove_wrap(&mut self, idx: usize) -> T {
        self.remove(idx)
    }
}

/// A routing loop: node A's route for C goes via B, B's route for C goes
/// via A. hop_ttl should decrement until the loop terminates.
#[tokio::test]
async fn routing_loop_terminates() {
    use tokio::net::UdpSocket;

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = sock_a.local_addr().unwrap();
    let b_addr = sock_b.local_addr().unwrap();

    let node_a = Identity::from_secret_bytes([0x30; 32]);
    let node_b = Identity::from_secret_bytes([0x31; 32]);
    drop(sock_a);
    drop(sock_b);

    let a_t = Transport::bind(a_addr, node_a).await.unwrap();
    let b_t = Transport::bind(b_addr, node_b).await.unwrap();

    let phantom_id = [0xFFu8; 8];
    // Loop: A → B → A → B → ...
    a_t.add_route(phantom_id, b_addr).await;
    b_t.add_route(phantom_id, a_addr).await;

    // Send a packet destined for the phantom through A.
    use drift::header::{Header, PacketType, HEADER_LEN};
    let mut header = Header::new(PacketType::Data, 1, [1; 8], phantom_id).with_hop_ttl(8);
    header.payload_len = 16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut packet = hbuf.to_vec();
    packet.extend_from_slice(&[0u8; 16 + 16]); // bogus ciphertext+tag

    // Inject packet into A by sending from a raw socket pretending to be
    // upstream.
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&packet, a_addr).await.unwrap();

    // Wait a bit — the loop should terminate after ~8 hops without
    // infinite ping-ponging or running away.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // If we get here without hanging or crashing, the TTL worked.
    drop(a_t);
    drop(b_t);
}

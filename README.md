# DRIFT

**Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint transport protocol.**

DRIFT is an encrypted, identity-based transport protocol that runs over UDP (and now TCP, WebSocket, serial, or any medium that can carry packets). It takes inspiration from [Reticulum](https://reticulum.network/)'s identity-first philosophy -- your address IS your public key, encryption is non-negotiable, mesh routing is built in -- but is designed to work *with* existing IP infrastructure rather than replace it.

Where Reticulum targets off-grid mesh networks over LoRa and serial links, DRIFT targets production IP deployments where you want Reticulum's security model with QUIC-grade performance: congestion control, stream multiplexing, session resumption, pacing, and connection migration.

**The positioning:** Reticulum proved the identity-first model works. DRIFT proves it can also be fast.

## Key Features

### Identity & Security
- **Identity-based addressing** -- peer IDs are derived from X25519 public keys (BLAKE2b hash). No DNS, no certificates, no CA.
- **Always encrypted** -- every packet is ChaCha20-Poly1305 AEAD-sealed. There is no plaintext mode.
- **Post-quantum ready** -- optional X25519 + ML-KEM-768 (Kyber) hybrid handshake. Traffic captured today stays private even against future quantum computers.
- **DoS cookies** -- adaptive stateless challenge-response prevents amplification attacks before any crypto work.
- **3x amplification limit** -- RFC 9000-style cap on pre-handshake outbound bytes.

### Transport
- **Reliable streams** -- TCP-like multiplexed streams with per-stream flow control, retransmission, and ordering. No head-of-line blocking between streams.
- **Unreliable datagrams** -- fire-and-forget messages on the same session (like QUIC's DATAGRAM frame, RFC 9221).
- **Congestion control** -- NewReno (default) or BBR-lite, with HyStart++ slow-start exit, pacing, and ECN CE-mark feedback.
- **Deadline-aware delivery** -- packets carry a `deadline_ms`; receivers drop stale data automatically. For real-time apps where late is worse than lost.
- **Semantic coalescing** -- packets in a `supersedes` group replace older ones. Only the freshest game-state update is delivered.

### Session Management
- **1-RTT session resumption** -- PSK-based reconnect skips X25519 on repeat connections. Export/import tickets for cross-restart persistence.
- **Auto-rekey** -- transparent key rotation when the sequence counter approaches the 2^31 ceiling. No app intervention needed.
- **Graceful connection migration** -- preemptive path validation for mobile handoff (wifi -> cellular) with no traffic stall.

### Mesh & Routing
- **Multi-hop forwarding** -- packets addressed to non-local peers get forwarded through intermediate nodes without breaking end-to-end encryption (`hop_ttl` is zeroed in the AEAD AAD).
- **RTT-weighted routing** -- distance-vector beacons with per-neighbor latency measurement. Routes pick the lowest-RTT path, not just the fewest hops.
- **Stability mechanisms** -- hold-down timers, hysteresis thresholds, staleness expiry, infinity-cost rejection. Prevents oscillation and count-to-infinity.

### Wire Efficiency
- **Compact short headers** -- established direct sessions use a 7-byte header (vs 36-byte long header) with 2-byte Connection IDs derived from the session key. 56% overhead reduction.
- **Long headers** -- full 36-byte headers for handshakes, mesh forwarding, and feature-tagged traffic (deadlines, coalescing).
- **UDP GSO / sendmmsg** -- batched send path on Linux for high-throughput senders.

### Medium Agnostic
- **PacketIO trait** -- the transport layer talks through a trait, not a concrete socket type. Ship with UDP and TCP adapters; plug in WebSocket, serial, BLE, or anything else that can move packets.
- **TCP adapter** -- length-prefix framing over TCP for networks that block UDP. Full DRIFT protocol stack works identically.

### Observability
- **30+ metrics** -- packets sent/received, handshakes, retries, auth failures, replays, coalesce drops, deadline drops, congestion state, resumption counts, amplification blocks, and more.
- **qlog event logging** -- structured NDJSON event log (packet_sent, packet_received, handshake_complete) compatible with qlog tooling.
- **FEC** -- XOR-based forward error correction for single-loss recovery on lossy links.

## Quick Start

```rust
use drift::identity::Identity;
use drift::{Direction, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate or load identities.
    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_pub = bob.public_bytes();

    // Bob listens.
    let bob_t = Transport::bind("0.0.0.0:9000".parse()?, bob).await?;
    bob_t.add_peer(alice.public_bytes(), "0.0.0.0:0".parse()?, Direction::Responder).await?;

    // Alice connects and sends.
    let alice_t = Transport::bind("0.0.0.0:0".parse()?, alice).await?;
    let bob_peer = alice_t.add_peer(bob_pub, "127.0.0.1:9000".parse()?, Direction::Initiator).await?;
    alice_t.send_data(&bob_peer, b"hello drift", 0, 0).await?;

    // Bob receives.
    let pkt = bob_t.recv().await.unwrap();
    assert_eq!(pkt.payload, b"hello drift");
    Ok(())
}
```

## TCP Transport (Firewall Traversal)

```rust
use drift::io::TcpPacketIO;
use std::sync::Arc;

// Connect via TCP instead of UDP.
let tcp = tokio::net::TcpStream::connect("10.0.0.5:443").await?;
let io = Arc::new(TcpPacketIO::new(tcp)?);
let transport = Transport::bind_with_io(io, identity, config).await?;
// Same API from here -- the app doesn't know or care which medium is underneath.
```

## Tunneling TCP Apps Over DRIFT

```bash
# Server side: forward DRIFT streams to a local nginx.
drift-tun listen --name myserver --drift-port 9000 --forward 127.0.0.1:80

# Client side: accept local TCP, tunnel through DRIFT.
drift-tun dial --name myclient --peer myserver@10.0.0.5:9000 --listen-port 8080

# Now: curl http://localhost:8080 -> DRIFT tunnel -> nginx
# Encrypted, identity-authenticated, multiplexed, mesh-routable.
```

## Architecture

```
src/
  lib.rs              Module exports
  crypto.rs           ChaCha20-Poly1305 AEAD, X25519 DH, SipHash cookies
  identity.rs         X25519 keypairs, session key derivation, rekey KDF
  header.rs           36-byte long header, 20 packet types, canonical AAD
  short_header.rs     7-byte compact header with Connection IDs
  session.rs          Handshake state machine, peer table, replay protection
  streams.rs          Reliable stream multiplexing, congestion control (NewReno + BBR)
  io.rs               PacketIO trait, UdpPacketIO, TcpPacketIO adapters
  pq.rs               X25519 + ML-KEM-768 post-quantum hybrid KDF
  fec.rs              XOR-based forward error correction
  multipath.rs        Multi-path manager with RTT-weighted path selection
  transport/
    mod.rs            Transport struct, send/recv, handshake, rekey, resumption dispatch
    cookies.rs        Adaptive DoS cookie challenge-response
    mesh.rs           Routing table, BEACON emission/ingestion, hop-TTL forwarding
    path.rs           Path validation (PathChallenge/PathResponse), graceful migration
    peer_shards.rs    16-shard peer table for reduced lock contention
    resumption.rs     1-RTT PSK session resumption with ticket export/import
    rtt.rs            Ping/Pong RTT measurement for routing
    ecn.rs            ECN (RFC 3168) outbound marking + CE-mark feedback
    batch.rs          sendmmsg batching for high-throughput senders
    qlog.rs           Structured NDJSON event logging
```

## Wire Format

### Long Header (36 bytes) -- handshakes, mesh forwarding, feature-tagged DATA

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver(4)|Flg(4) | PacketType    |        deadline_ms            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        seq (u32)                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     supersedes (u32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     src_id (8 bytes)                          +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     dst_id (8 bytes)                          +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  hop_ttl      |  reserved     |       payload_len             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     send_time_ms (u32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Short Header (7 bytes) -- established direct sessions

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0x2  | flags |     connection_id (u16)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   seq (u32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Overhead comparison:**

| Format | Header | AEAD tag | Total |
|--------|--------|----------|-------|
| Long header | 36 B | 16 B | 52 B |
| Short header | 7 B | 16 B | 23 B |

## Packet Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| Hello | 1 | C -> S | Initiate handshake |
| HelloAck | 2 | S -> C | Complete handshake |
| Data | 3 | Both | Application payload |
| Beacon | 6 | Both | Mesh route advertisement |
| Challenge | 8 | S -> C | DoS cookie challenge |
| PathChallenge | 9 | Both | Path validation probe |
| PathResponse | 10 | Both | Path validation echo |
| Close | 11 | Both | Graceful session teardown |
| RekeyRequest | 12 | C -> S | Session rekey initiation |
| RekeyAck | 13 | S -> C | Rekey confirmation |
| ResumeHello | 14 | C -> S | 1-RTT session resumption |
| ResumeAck | 15 | S -> C | Resumption confirmation |
| ResumptionTicket | 16 | S -> C | Opaque ticket for future resumption |
| Ping | 17 | Both | RTT measurement probe |
| Pong | 18 | Both | RTT measurement echo |

## Comparison with Reticulum

DRIFT shares Reticulum's core philosophy -- identity-based addressing, always-encrypted, mesh-capable -- but targets a different deployment model:

| | Reticulum | DRIFT |
|---|---|---|
| **Target medium** | Any (LoRa, serial, UDP, TCP) | Layer 4+ (UDP default, TCP/WS/serial via trait) |
| **Target bandwidth** | 300 bps -- 10 Mbps | 1 Mbps -- 10 Gbps |
| **Identity model** | Ed25519 pubkey hash | X25519 pubkey hash (BLAKE2b) |
| **Encryption** | X25519 + AES-CBC + HMAC | X25519 + ChaCha20-Poly1305 |
| **Congestion control** | None | NewReno, BBR-lite, HyStart++, pacing, ECN |
| **Reliable delivery** | Links (message-level) | Streams (TCP-like, multiplexed) |
| **Session resumption** | No | 1-RTT PSK with exportable tickets |
| **Post-quantum** | No | X25519 + ML-KEM-768 hybrid (opt-in) |
| **Compact headers** | ~8 B minimal | 7 B short / 36 B long |
| **Implementation** | Python | Rust |

## Testing

197 tests across 56 test files covering:

- **Protocol correctness**: wire format KAT, header proptests, handshake state machine, rekey, resumption
- **Security**: 17+ attack tests (replay, hijack, amplification, flood, poisoning, weak keys)
- **Reliability**: lossy links (10-65% drop), satellite latency (2s RTT), bandwidth caps (10 Kbps), intermittent connectivity
- **Scale**: 1000 concurrent handshakes, 64-client fan-in, 5-node full mesh, 10-cycle reconnect
- **Features**: congestion control, streams, datagrams, ECN, FEC, BBR, short headers, TCP transport, qlog

Docker integration tests: 5-node mesh, reconnect cycle, peer churn -- all running across real container networks.

```bash
# Run the full test suite
cargo test

# Run Docker integration tests
docker build -t drift:latest -f docker/Dockerfile .
docker compose -f compose/five_node_mesh.yml up -d
docker compose -f compose/reconnect_cycle.yml up --exit-code-from client
docker compose -f compose/peer_churn.yml up -d
```

## Extreme Conditions (vs Reticulum)

Stress-tested under conditions Reticulum is designed for:

| Scenario | Result |
|----------|--------|
| 50% packet loss, 16 KB stream | Delivered intact at 1.7 KB/s |
| 90% packet loss, handshake | Protocol limit -- needs >50 retries |
| 2s RTT (satellite), 8 KB stream | Handshake in 3.2s, stream at 156 KB/s |
| 10 Kbps bandwidth cap | 9/10 paced packets delivered |
| 5-hop chain (~65% cumulative loss) | 4 KB stream delivered intact |
| Intermittent link (2s up / 3s down) | Session survived, 40% delivery during up windows |

## Inspiration

DRIFT draws heavily from:

- **[Reticulum](https://reticulum.network/)** -- identity-first addressing, always-encrypted philosophy, mesh architecture. DRIFT is "Reticulum for production IP networks."
- **[QUIC](https://www.rfc-editor.org/rfc/rfc9000)** -- congestion control, stream multiplexing, connection migration, 0/1-RTT handshakes, short headers with Connection IDs.
- **[WireGuard](https://www.wireguard.com/)** -- minimal crypto surface (X25519 + ChaCha20-Poly1305), small codebase, Noise-like handshake simplicity.

## License

MIT

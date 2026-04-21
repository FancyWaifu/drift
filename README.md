# DRIFT

**Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint transport protocol.**

DRIFT is an encrypted transport protocol where your address IS your public key, encryption is non-negotiable, and mesh routing is built in. Inspired by [Reticulum](https://reticulum.network/)'s identity-first philosophy, but designed for production IP networks with QUIC-grade performance.

## Why DRIFT

Reticulum proved identity-first networking works. DRIFT proves it can also be fast — congestion control, stream multiplexing, session resumption, and connection migration over any medium that can carry packets.

## Features

**Crypto** — X25519 + ChaCha20-Poly1305 (WireGuard-style minimal surface). Optional post-quantum hybrid (X25519 + ML-KEM-768). Adaptive DoS cookies. RFC 9000-style 3× amplification limit. No plaintext mode.

**Transport** — Reliable multiplexed streams. Unreliable datagrams. NewReno or BBR-lite congestion control with ECN feedback. Deadline-aware delivery (`deadline_ms`). Semantic coalescing (`supersedes` groups — only the freshest update is delivered).

**Sessions** — 1-RTT PSK resumption with exportable tickets. Auto-rekey at the 2³¹ sequence ceiling. Graceful connection migration (wifi → cellular) via path validation probes.

**Mesh** — Multi-hop forwarding with end-to-end encryption preserved. RTT-weighted distance-vector routing. Hold-down timers, hysteresis, staleness expiry.

**Medium-agnostic** — `PacketIO` trait with built-in adapters for UDP, TCP (length-prefix framing), WebSocket (binary messages), WebRTC data channels (browser-to-browser, no server in the data path), WebTransport (QUIC/HTTP3, UDP-like datagrams in the browser), and in-memory channels. Plug in TLS, serial, BLE, or anything else.

**Observability** — 30+ runtime metrics. Structured NDJSON qlog. XOR-based FEC for lossy links.

## Quick Start

```rust
use drift::identity::Identity;
use drift::{Direction, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Identity::generate();
    let bob = Identity::generate();

    let bob_t = Transport::bind("0.0.0.0:9000".parse()?, bob).await?;
    let alice_t = Transport::bind("0.0.0.0:0".parse()?, alice).await?;

    let bob_peer = alice_t.add_peer(
        bob_t.local_public(), "127.0.0.1:9000".parse()?, Direction::Initiator,
    ).await?;

    alice_t.send_data(&bob_peer, b"hello drift", 0, 0).await?;
    let pkt = bob_t.recv().await.unwrap();
    assert_eq!(pkt.payload, b"hello drift");
    Ok(())
}
```

### Non-UDP Transports

```rust
use drift::io::{TcpPacketIO, WebRTCPacketIO, WsPacketIO};

// TCP (firewall traversal)
let tcp = tokio::net::TcpStream::connect("10.0.0.5:443").await?;
let transport = Transport::bind_with_io(Arc::new(TcpPacketIO::new(tcp)?), identity, config).await?;

// WebSocket (browser-to-server, CDN-friendly)
let (ws, _) = tokio_tungstenite::connect_async("ws://10.0.0.5:8080").await?;
let transport = Transport::bind_with_io(Arc::new(WsPacketIO::new(ws, addr)), identity, config).await?;

// WebRTC (browser-to-browser after SDP exchange — no server in the data path)
let dc: Arc<RTCDataChannel> = /* exchange SDP offer/answer, open data channel */;
let transport = Transport::bind_with_io(Arc::new(WebRTCPacketIO::new(dc, addr)), identity, config).await?;
```

### Multi-Interface Bridging

A single node can bridge across mediums — UDP peers talk to TCP peers talk to WebSocket peers talk to WebRTC peers through one bridge, zero medium-specific routing code:

```rust
let bridge = Transport::bind("0.0.0.0:9000".parse()?, bridge_id).await?;
bridge.add_interface("tcp", Arc::new(TcpPacketIO::new(tcp_stream)?));
bridge.add_interface("websocket", Arc::new(WsPacketIO::new(ws_stream, addr)));
bridge.add_interface("webrtc", Arc::new(WebRTCPacketIO::new(data_channel, addr)));
// Packets route by identity, not by medium.
```

### Runnable Examples

- **`drift-chat`** (`examples/drift_chat.rs`) — four-node chat, one per medium (UDP / TCP / WebSocket / WebRTC) on distinct loopback IPs, all talking through a bridge. Auto mode or interactive stdin.
- **`drift-shell`** (`examples/drift_shell.rs`) — tiny command server (`time`, `count`, `whoami`, `echo`, …) reachable over DRIFT. Used by `demo-shell.sh` to demonstrate server mobility: one identity migrates across IPs, clients keep reaching it by peer_id.
- **`drift-medium-demo`** (`examples/medium_demo.rs`) — three distinct source IPs on three mediums bridged end to end.

## Wire Format

| Format | Header | AEAD tag | Total | Used for |
|--------|--------|----------|-------|----------|
| Long | 36 B | 16 B | 52 B | Handshakes, mesh forwarding, deadlines, coalescing |
| Short | 7 B | 16 B | 23 B | Established direct sessions (56% reduction) |

15 packet types: Hello/HelloAck, Data, Beacon, Challenge, PathChallenge/Response, Close, RekeyRequest/Ack, ResumeHello/Ack/Ticket, Ping/Pong.

## Architecture

```
src/
  crypto.rs            X25519 DH, ChaCha20-Poly1305, SipHash cookies
  identity.rs          Keypairs, session key derivation, rekey KDF
  header.rs            36-byte long header, 15 packet types
  short_header.rs      7-byte compact header with Connection IDs
  session.rs           Handshake state machine, replay protection
  streams.rs           Reliable streams, NewReno + BBR congestion control
  io.rs                PacketIO trait + UDP/TCP/WebSocket/WebRTC/Memory adapters
  pq.rs                Post-quantum hybrid (X25519 + ML-KEM-768)
  fec.rs               XOR forward error correction
  multipath.rs         RTT-weighted path selection
  transport/
    mod.rs             Core engine: send/recv, handshake, rekey, resumption
    mesh.rs            Routing table, beacons, hop-TTL forwarding
    cookies.rs         Adaptive DoS challenge-response
    path.rs            PathChallenge/Response, connection migration
    peer_shards.rs     16-shard peer table (lock contention reduction)
    resumption.rs      1-RTT PSK session resumption
    rtt.rs             Ping/Pong RTT measurement
    ecn.rs             ECN marking + CE feedback
    batch.rs           sendmmsg batching (Linux)
    qlog.rs            Structured NDJSON event logging
```

## Testing

~200 tests across 61 integration files + 68 lib tests:

- **Correctness**: wire format KAT, header proptests, handshake state machine, rekey, resumption, route migration at equal cost
- **Security**: 17+ attack scenarios (replay, hijack, amplification, flood, beacon poisoning, weak keys)
- **Reliability**: 10–65% packet loss, 2s RTT satellite links, 10 Kbps bandwidth caps, intermittent connectivity
- **Scale**: 1000 concurrent handshakes, 64-client fan-in, 5-node full mesh
- **Cross-medium**: four-medium bridge (UDP + TCP + Memory + WebSocket) with streams, datagrams, and coalescing; five-medium extended via WebRTC through the `drift-chat` example
- **Mesh mobility**: post-handshake beacon discipline, stale-route invalidation on send failure, peer self-migration at equal cost
- **Docker**: 30+ compose scenarios (mesh, NAT, chaos, extreme loss)

```bash
cargo test                # full suite
cargo bench               # throughput benchmarks
./demo-shell.sh           # live multi-IP rotation + multi-identity demo (needs lo0 aliases)
```

## vs Reticulum

| | Reticulum | DRIFT |
|---|---|---|
| **Bandwidth** | 300 bps – 10 Mbps | 1 Mbps – 10 Gbps |
| **Encryption** | X25519 + AES-CBC + HMAC | X25519 + ChaCha20-Poly1305 |
| **Congestion control** | None | NewReno, BBR, ECN |
| **Reliable delivery** | Message-level | Multiplexed streams |
| **Session resumption** | No | 1-RTT PSK |
| **Post-quantum** | No | ML-KEM-768 hybrid |
| **Transport mediums** | Any | Any (via PacketIO trait): UDP, TCP, WebSocket, WebRTC, memory, serial-ready |
| **Implementation** | Python | Rust |

## Inspiration

- **[Reticulum](https://reticulum.network/)** — identity-first addressing, always-encrypted, mesh architecture
- **[QUIC](https://www.rfc-editor.org/rfc/rfc9000)** — congestion control, streams, connection migration, short headers
- **[WireGuard](https://www.wireguard.com/)** — minimal crypto surface, small codebase

## License

MIT

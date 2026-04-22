# DRIFT

**Deadline-aware, Routed, Identity-based, Fresh-over-stale, Tiny-footprint transport protocol.**

DRIFT is an encrypted transport protocol where your address IS your public key, encryption is non-negotiable, and mesh routing is built in. Inspired by [Reticulum](https://reticulum.network/)'s identity-first philosophy, but designed for production IP networks with QUIC-grade performance — and for the browser, via a WASM implementation that speaks the same wire protocol byte-for-byte.

## Why DRIFT

Reticulum proved identity-first networking works. DRIFT proves it can also be fast — congestion control, stream multiplexing, session resumption, connection migration — and that the same protocol can run everywhere from a Rust binary on a server to a WASM blob in a browser tab.

## Features

**Crypto** — X25519 + ChaCha20-Poly1305 (WireGuard-style minimal surface). Optional post-quantum hybrid (X25519 + ML-KEM-768). Adaptive DoS cookies. RFC 9000-style 3× amplification limit. No plaintext mode.

**Transport** — Reliable multiplexed streams. Unreliable datagrams. NewReno or BBR-lite congestion control with ECN feedback. Deadline-aware delivery (`deadline_ms`). Semantic coalescing (`supersedes` groups — only the freshest update is delivered).

**Sessions** — 1-RTT PSK resumption with exportable tickets. Auto-rekey at the 2³¹ sequence ceiling. Graceful connection migration (wifi → cellular) via path validation probes.

**Mesh** — Multi-hop forwarding with end-to-end encryption preserved. RTT-weighted distance-vector routing. Hold-down timers, hysteresis, staleness expiry. Peer self-migration at equal cost.

**Medium-agnostic** — `PacketIO` trait with built-in adapters for UDP, TCP (length-prefix framing), WebSocket (binary messages), WebRTC data channels (browser-to-browser, no server in the data path), WebTransport (QUIC/HTTP3, UDP-like datagrams in the browser), and in-memory channels. Plug in TLS, serial, BLE, or anything else.

**Browser-native** — `drift-wasm` compiles the full DRIFT protocol to WebAssembly. Same `drift-core` code as the native stack; interoperates with native peers through a bridge. Supports all three browser wire transports (WebSocket, WebRTC data channel, WebTransport) behind one `DriftClient` API.

**Observability** — 30+ runtime metrics. Structured NDJSON qlog. XOR-based FEC for lossy links.

## Workspace layout

```
drift-core/      sans-io protocol engine (WASM-safe, no tokio, no I/O)
  crypto.rs          X25519 DH, ChaCha20-Poly1305, SipHash cookies
  identity.rs        Keypairs, session key derivation, rekey KDF
  header.rs          36-byte long header, 15 packet types
  short_header.rs    7-byte compact header with Connection IDs
  session.rs         Handshake state machine, replay protection, Peer::make_header helper
  fec.rs             XOR forward error correction
  pq.rs              Post-quantum hybrid (X25519 + ML-KEM-768)

drift/           native tokio-based stack built on drift-core
  src/
    lib.rs           Transport re-exports
    main.rs          `drift` CLI (keygen, info, send, listen, relay)
    io.rs            PacketIO trait + UDP / TCP / WebSocket / WebRTC / WebTransport / Memory adapters
    streams.rs       Reliable streams, NewReno + BBR congestion control
    multipath.rs     RTT-weighted path selection
    transport/
      mod.rs         Core engine: send/recv, handshake, rekey, resumption
      mesh.rs        Routing table, beacons, hop-TTL forwarding, self-migration
      cookies.rs     Adaptive DoS challenge-response
      path.rs        PathChallenge/Response, connection migration
      peer_shards.rs 16-shard peer table (lock contention reduction)
      resumption.rs  1-RTT PSK session resumption
      rtt.rs         Ping/Pong RTT measurement
      ecn.rs         ECN marking + CE feedback
      batch.rs       sendmmsg batching (Linux)
      qlog.rs        Structured NDJSON event logging

drift-wasm/      browser-side stack, same drift-core compiled to wasm32
  src/
    lib.rs                JS bindings: DriftIdentity, DriftClient
    session.rs            Wire-agnostic protocol state + mesh handshake flow
    peer_session.rs       Per-peer crypto state
    wire_ws.rs            WebSocket adapter
    wire_webrtc.rs        Browser WebRTC RTCDataChannel adapter
    wire_webtransport.rs  Browser WebTransport HTTP/3 adapter (cert-hash pinnable)
```

## Quick Start (native)

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
use drift::io::{TcpPacketIO, WebRTCPacketIO, WebTransportPacketIO, WsPacketIO};

// TCP (firewall traversal)
let tcp = tokio::net::TcpStream::connect("10.0.0.5:443").await?;
let transport = Transport::bind_with_io(Arc::new(TcpPacketIO::new(tcp)?), identity, config).await?;

// WebSocket (browser-to-server, CDN-friendly)
let (ws, _) = tokio_tungstenite::connect_async("ws://10.0.0.5:8080").await?;
let transport = Transport::bind_with_io(Arc::new(WsPacketIO::new(ws, addr)), identity, config).await?;

// WebRTC (browser-to-browser after SDP exchange — no server in the data path)
let dc: Arc<RTCDataChannel> = /* exchange SDP offer/answer, open data channel */;
let transport = Transport::bind_with_io(Arc::new(WebRTCPacketIO::new(dc, addr)), identity, config).await?;

// WebTransport (QUIC/HTTP3, unreliable datagrams, browser-reachable)
let conn: wtransport::Connection = /* accept an incoming WebTransport session */;
let transport = Transport::bind_with_io(Arc::new(WebTransportPacketIO::new(conn, addr)), identity, config).await?;
```

### Multi-Interface Bridging

A single node can bridge across mediums — UDP peers talk to TCP peers talk to WebSocket peers talk to WebRTC peers talk to WebTransport peers through one bridge, zero medium-specific routing code. The bridge sees only ciphertext; DRIFT's end-to-end crypto stays between the real endpoints:

```rust
let bridge = Transport::bind("0.0.0.0:9000".parse()?, bridge_id).await?;
bridge.add_interface("tcp", Arc::new(TcpPacketIO::new(tcp_stream)?));
bridge.add_interface("websocket", Arc::new(WsPacketIO::new(ws_stream, addr)));
bridge.add_interface("webrtc", Arc::new(WebRTCPacketIO::new(data_channel, addr)));
bridge.add_interface("webtransport", Arc::new(WebTransportPacketIO::new(wt_conn, addr)));
// Packets route by identity, not by medium.
```

## Quick Start (browser / WASM)

```bash
# Build the browser bundle (requires wasm-pack + rustup target add wasm32-unknown-unknown)
wasm-pack build drift-wasm --target web --out-dir pkg-web
```

```js
import { DriftIdentity, DriftClient } from './pkg-web/drift_wasm.js';

const id = DriftIdentity.generate();

// Connect via the wire that fits your deployment:
const ws  = await DriftClient.connectWebSocket   ("ws://relay:9002", id, serverPubHex);
const rtc = await DriftClient.connectWebRtc      (dataChannel,       id, peerPubHex);
const wt  = await DriftClient.connectWebTransport("https://relay:9204/", id, serverPubHex, certHashHex);

// Identical mesh-capable API on all three transports:
await ws.addPeer(remotePeerPubHex);              // handshake with a peer behind the relay
await ws.sendToPeer(remotePeerIdHex, bytes);     // encrypt + send to them end-to-end
ws.onMessage((srcPeerIdHex, data) => { /* ... */ });
```

## The `drift` CLI

```bash
drift keygen [--out identity.key]         # generate a keypair file
drift info   [--file identity.key]        # show peer_id / pubkey hex
drift listen [bind_addr] [--accept-any]   # receive messages / files
drift send   --name target <peer>         # send a message
drift relay                               # run a mesh relay node
```

## Runnable Examples

- **`drift-chat`** (`drift/examples/drift_chat.rs`) — four-node chat, one per medium (UDP / TCP / WebSocket / WebRTC) on distinct loopback IPs, all talking through a bridge that also accepts WebTransport. Auto mode or interactive stdin.
- **`drift-shell`** (`drift/examples/drift_shell.rs`) — tiny command server (`time`, `count`, `whoami`, `echo`, …) reachable over DRIFT. Used by `demo-shell.sh` to demonstrate server mobility: one identity migrates across IPs, clients keep reaching it by peer_id.
- **`drift-kv`** (`drift/examples/drift_kv.rs`) — port of the Tokio team's `mini-redis` to run over DRIFT. Implements the Redis RESP protocol (PING / GET / SET / DEL) with the bridge accepting clients on UDP / TCP / WS / WebRTC simultaneously.
- **`drift-medium-demo`** (`drift/examples/medium_demo.rs`) — three distinct source IPs on three mediums bridged end to end.
- **`drift-wasm-test/`** — end-to-end Node harness that loads the compiled WASM and verifies (a) a direct DRIFT handshake against a native bridge over WebSocket, and (b) full mesh routing — a browser-equivalent client sending to a UDP peer through the bridge with DRIFT's E2E crypto intact.

## Wire Format

| Format | Header | AEAD tag | Total | Used for |
|--------|--------|----------|-------|----------|
| Long | 36 B | 16 B | 52 B | Handshakes, mesh forwarding, deadlines, coalescing |
| Short | 7 B | 16 B | 23 B | Established direct sessions (56% reduction) |

15 packet types: Hello/HelloAck, Data, Beacon, Challenge, PathChallenge/Response, Close, RekeyRequest/Ack, ResumeHello/Ack/Ticket, Ping/Pong.

## Adapter availability matrix

| Transport | Native | Browser (WASM) | End-to-end verified |
|-----------|:------:|:-------:|-------------------|
| UDP | ✅ | ❌ (browser sandbox) | ✅ |
| TCP | ✅ | ❌ (browser sandbox) | ✅ |
| WebSocket | ✅ | ✅ | ✅ WASM↔native + mesh-through-bridge to any medium |
| WebRTC data channel | ✅ | ✅ | Native↔native ✅; browser↔native needs app-supplied SDP signaling |
| WebTransport | ✅ | ✅ | Native↔native ✅; browser↔native ships and is cert-hash-pinnable |
| In-memory | ✅ | ❌ | ✅ |

## Testing

~206 tests across 61 integration files + 43 drift-core + 162 drift lib tests:

- **Correctness**: wire format KAT, header proptests, handshake state machine, rekey, resumption, route migration at equal cost
- **Security**: 17+ attack scenarios (replay, hijack, amplification, flood, beacon poisoning, weak keys)
- **Reliability**: 10–65% packet loss, 2s RTT satellite links, 10 Kbps bandwidth caps, intermittent connectivity
- **Scale**: 1000 concurrent handshakes, 64-client fan-in, 5-node full mesh
- **Cross-medium**: four-medium bridge (UDP + TCP + Memory + WebSocket) with streams, datagrams, and coalescing; five-medium extended via WebRTC + WebTransport through the `drift-chat` bridge
- **Mesh mobility**: post-handshake beacon discipline, stale-route invalidation on send failure, peer self-migration at equal cost
- **WASM interop**: `drift-wasm-test/` — compiled WASM handshakes with native bridge + mesh-routes to a UDP peer
- **WebTransport**: `drift/tests/webtransport_adapter.rs` — native↔native handshake + DATA round-trip over QUIC datagrams
- **Docker**: 30+ compose scenarios (mesh, NAT, chaos, extreme loss)

```bash
cargo test                # full suite
cargo bench               # throughput benchmarks
./demo-shell.sh           # live multi-IP rotation + multi-identity demo (needs lo0 aliases)
cd drift-wasm-test && npm install && node test-mesh.mjs ...  # WASM↔native E2E
```

## Performance

### Cross-protocol benchmark harness

`drift-bench/` is a single binary that speaks DRIFT, QUIC ([quinn](https://docs.rs/quinn)), and WireGuard ([boringtun](https://docs.rs/boringtun)) with identical workloads (handshake, RTT ping-pong, sustained throughput). `bench/docker/run.sh` builds a two-container harness on a shared bridge network and reports each protocol's numbers side-by-side as a Markdown table.

```bash
cd bench/docker
./run.sh                                    # default: 1024 B payload, 1000 RTT samples
NETEM_DELAY=20ms NETEM_LOSS=1% ./run.sh     # simulate WAN with tc/netem
```

### Results (two Docker containers, shared bridge, Apple Silicon host)

**Cold handshake** (connect → first byte acked, 30 samples):

| Protocol   | p50      | p95      | p99      |
|------------|----------|----------|----------|
| **DRIFT**  | **330 µs** | 715 µs   | 795 µs   |
| WireGuard  | 396 µs   | 826 µs   | 1,150 µs |
| QUIC       | 2,832 µs | 3,847 µs | 4,208 µs |

DRIFT's X25519-only handshake is 1.2× faster than WireGuard's Noise_IKpsk2 and 8.6× faster than QUIC's TLS 1.3 + transport-params negotiation.

**RTT** (ping-pong, 1 KB payload, 1000 samples):

| Protocol   | p50      | p95      | p99      |
|------------|----------|----------|----------|
| WireGuard  | 57 µs    | 115 µs   | 183 µs   |
| **DRIFT**  | **93 µs** | 143 µs   | 275 µs   |
| QUIC       | 152 µs   | 192 µs   | 338 µs   |

DRIFT beats QUIC 1.6×; loses to WireGuard ~1.6× on the hot path — the gap is Tokio's mpsc + task-wakeup tax, not protocol work. A sync `poll_recv` variant is on the roadmap to close most of it.

**Throughput** (sustained 1 KB sends, 10 s, real flow control):

| Protocol   | Throughput   |
|------------|--------------|
| WireGuard  | 1,746 Mbps   |
| **DRIFT**  | **1,672 Mbps** |
| QUIC       | 1,020 Mbps   |

DRIFT matches WireGuard on throughput (same AEAD primitive, same UDP-syscall rate); QUIC's per-packet ACK + stream flow-control machinery drops it ~40%.

### Crypto micro-benchmarks

With NEON-accelerated ChaCha20-Poly1305 from [ring](https://docs.rs/ring) (automatically enabled on every aarch64 target via workspace `.cargo/config.toml`):

| Op                    | Size   | Throughput  |
|-----------------------|--------|-------------|
| AEAD seal             | 1 KB   | 1.41 GiB/s  |
| AEAD open             | 1 KB   | 1.31 GiB/s  |
| DRIFT loopback short-hdr RTT | 1 KB | 13.9 µs |

The bench suite also includes `cargo bench --bench throughput` (header encode/decode, AEAD seal/open, loopback RTT short vs long header), `cargo bench --bench handshake` (cold + 1-RTT PSK resumption), and `cargo bench --bench comparative` (DRIFT vs raw UDP vs QUIC vs WireGuard entirely in-process via criterion).

## vs Reticulum

| | Reticulum | DRIFT |
|---|---|---|
| **Bandwidth** | 300 bps – 10 Mbps | 1 Mbps – 10 Gbps |
| **Encryption** | X25519 + AES-CBC + HMAC | X25519 + ChaCha20-Poly1305 |
| **Congestion control** | None | NewReno, BBR, ECN |
| **Reliable delivery** | Message-level | Multiplexed streams |
| **Session resumption** | No | 1-RTT PSK |
| **Post-quantum** | No | ML-KEM-768 hybrid |
| **Transport mediums** | Any | Any (via PacketIO trait): UDP, TCP, WebSocket, WebRTC, WebTransport, memory, serial-ready |
| **Browser client** | Third-party only | First-party WASM (drift-wasm), same wire protocol |
| **Implementation** | Python | Rust (+ WASM) |

## Inspiration

- **[Reticulum](https://reticulum.network/)** — identity-first addressing, always-encrypted, mesh architecture
- **[QUIC](https://www.rfc-editor.org/rfc/rfc9000)** — congestion control, streams, connection migration, short headers
- **[WireGuard](https://www.wireguard.com/)** — minimal crypto surface, small codebase

## License

MIT

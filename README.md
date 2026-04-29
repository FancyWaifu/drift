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

**Medium-agnostic** — `PacketIO` trait with built-in adapters for UDP, TCP (length-prefix framing), WebSocket (binary messages), TLS-wrapped TCP (length-prefix inside a TLS record stream — DRIFT shaped to look like HTTPS), WebRTC data channels (browser-to-browser, no server in the data path), WebTransport (QUIC/HTTP3, UDP-like datagrams in the browser), and in-memory channels. Plug in serial, BLE, Tor, or anything else.

**Plug-and-play transports** — Adapters self-register at link time via `inventory::submit!`. The URL dispatcher (`Transport::bind_url("tcp://0.0.0.0:9100")`, `Transport::connect_url("ws://example.com:443")`) finds them at runtime. Adding a new transport means writing one `Listener` impl + one `inventory::submit!` block — drift-mosh, drift-http, drift-bench, and any other tool gain that wire for free, with zero source edits.

**Browser-native** — `drift-wasm` compiles the full DRIFT protocol to WebAssembly. Same `drift-core` code as the native stack; interoperates with native peers through a bridge. Supports all three browser wire transports (WebSocket, WebRTC data channel, WebTransport) behind one `DriftClient` API.

**Observability** — 30+ runtime metrics. Structured NDJSON qlog. XOR-based FEC for lossy links.

## Tools built on DRIFT

End-user binaries shipped from this repo. Each has its own README with install + usage.

| Tool | What it is | Install |
|---|---|---|
| **[drift-mosh](drift-mosh/README.md)** | Mobile-shell replacement (mosh-style) — survives wifi-to-cellular, laptop suspend, client crash. UDP / TCP / WebSocket. | `cargo install --path drift-mosh --bin drift-mosh` or [release tarballs](https://github.com/FancyWaifu/drift/releases) |
| **[drift-http](drift-http/README.md)** | Apache-style file server + Jellyfin-style proxy + system-wide `drift://` URL handler. Pubkey-addressed; no DDNS, no reverse proxy, no TLS cert. | `cargo install --path drift-http --bin drift-http` or [release tarballs](https://github.com/FancyWaifu/drift/releases) |
| **[drift](drift/src/main.rs)** | Core CLI — `keygen`, `info`, `listen`, `send`, `relay`. | `cargo install --path drift` |
| **[drift-wormhole](drift-wormhole/README.md)** | Magic-Wormhole-shaped file transfer over DRIFT — pubkey-addressed, no rendezvous server. | `cargo install --path drift-wormhole --bin drift-wormhole` |
| **[drift-bench](drift-bench/)** | Cross-protocol benchmark: DRIFT vs QUIC vs WireGuard, identical workloads. | `cargo build --release -p drift-bench` |
| **[drift-ffi](drift-ffi/README.md)** | C ABI — call DRIFT from C, C++, Python, Go, Swift, anything. | `cargo build --release -p drift-ffi` |

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
    io.rs            PacketIO + Listener traits, UDP / TCP / WebSocket / TLS /
                       WebRTC / WebTransport / Memory adapters, inventory-based
                       scheme registry (Transport::bind_url / connect_url /
                       add_listener)
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

drift-mosh/      Mobile-shell replacement built on DRIFT. Multi-transport CLI,
                   restart migration, scrollback reattach, TOFU known-hosts.
drift-http/      HTTP-over-DRIFT: Apache-style file server, opaque proxy,
                   drift:// URL handler with macOS / Linux registration.
drift-wormhole/  Magic-Wormhole-shaped file transfer over DRIFT. SHA-256
                   byte-fidelity, progress bar, scheme-prefixed peer URLs.
drift-bench/     Cross-protocol benchmark harness (DRIFT vs QUIC vs WireGuard).
drift-ffi/       C ABI for invoking DRIFT from C / Python / Go / Swift / anywhere
                   that speaks the C ABI.
drift-wasm-test/ Node harness verifying drift-wasm interops with the native stack
                   over WebSocket (and through a bridge to a UDP peer).
docker/two-bridge/ 12-container demo: 2 DRIFT bridges + 10 clients (5 per bridge),
                   end-to-end mesh routing across the bridge link.
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

### URL-shaped transports

The same scheme-prefixed addresses work everywhere — drift-mosh, drift-http, drift-bench, the `drift` CLI, and library callers all use `Transport::bind_url` / `Transport::connect_url`. The URL dispatcher resolves the scheme to a registered adapter at runtime; bare `host:port` (no scheme) defaults to UDP for back-compat.

```rust
// Server: bind to whichever transport(s) you want. First call uses
// bind_url; subsequent listeners attach via add_listener so one
// server can be reachable on UDP + TCP + WS simultaneously.
let (transport, primary_url) =
    Transport::bind_url("udp://0.0.0.0:9100", identity, cfg).await?;
let transport = Arc::new(transport);
transport.add_listener("tcp://0.0.0.0:9100").await?;
transport.add_listener("ws://0.0.0.0:9100").await?;

// Client: pick whichever wire is reachable in your environment.
let (transport, peer_addr) =
    Transport::connect_url("tcp://example.com:9100", identity, cfg).await?;
transport.add_peer(server_pub, peer_addr, Direction::Initiator).await?;
```

Lower-level `Transport::bind_with_io(io, ...)` still exists for cases where the adapter has out-of-band setup (WebRTC's SDP exchange, WebTransport's TLS-cert handoff). It accepts any `Arc<dyn PacketIO>` directly.

### Multi-Interface Bridging

A single node can bridge across mediums — UDP peers talk to TCP peers talk to WebSocket peers talk to WebRTC peers talk to WebTransport peers through one bridge, zero medium-specific routing code. The bridge sees only ciphertext; DRIFT's end-to-end crypto stays between the real endpoints:

```rust
let (bridge, _) = Transport::bind_url("udp://0.0.0.0:9000", bridge_id, cfg).await?;
let bridge = Arc::new(bridge);
bridge.add_listener("tcp://0.0.0.0:9001").await?;
bridge.add_listener("ws://0.0.0.0:9002").await?;
// Packets route by identity, not by medium.
```

### Adding a new transport

Drop a new adapter into any file (drift's source tree, your own crate, a downstream consumer's crate — anywhere). The URL dispatcher finds it via `inventory::iter` at runtime; nothing in drift core needs editing.

#### The three pieces

Every adapter implements two traits and submits one registration. The shapes of the two traits are:

- **`PacketIO`** — a packet-oriented I/O object. Two methods: `send_to(&self, buf, dest)` and `recv_from(&self, buf) -> (n, src)`. DRIFT calls these for every wire-going packet. Datagram transports (UDP) implement them naively. Stream transports (TCP, WebSocket, TLS) need to invent their own packet boundaries — see "Framing" below.
- **`Listener`** — a server-side acceptor. One method: `accept(&mut self) -> Arc<dyn PacketIO>`. Plus `is_multi() -> bool`: return `true` if one `PacketIO` services many peers (UDP-style — one socket, peers distinguished by `recv_from`'s addr); `false` if each accept yields a per-peer `PacketIO` (TCP-style — one stream per peer).

`SchemeRegistration` ties them together with a string scheme name and a connector factory (the client-side dialer).

#### Framing for stream transports

Stream transports have no message boundaries — DRIFT packets must be re-delineated on top of the byte stream. The convention used by every built-in stream adapter (TCP, WebSocket, TLS): **2-byte big-endian length prefix per packet.** `recv_from` reads 2 bytes, then exactly that many. `send_to` writes 2 bytes + the packet, then `flush()`. Cap packets at `u16::MAX` (65 535 bytes) — DRIFT packets are well under that ceiling.

Datagram transports (UDP, WebRTC data channel, WebTransport datagrams) preserve message boundaries natively and don't need framing at all.

#### Reference adapters

Match your transport's shape against one of the existing built-ins and copy the pattern:

| Shape | Reference | What to copy |
|---|---|---|
| Connectionless datagram | `UdpPacketIO` / `UdpListenerIO` in `drift/src/io.rs` | Single shared `PacketIO`, `is_multi() = true` |
| Reliable byte stream (per-peer) | `TcpPacketIO` / `TcpListenerIO` | Length-prefix framing, `tokio::io::split`, `is_multi() = false` |
| Reliable byte stream over TLS | `TlsPacketIO` / `TlsListenerIO` | Same as TCP + `tokio_rustls::TlsAcceptor` wrapping each accept |
| Browser-friendly framed stream | `WsPacketIO` / `WsListenerIO` | tungstenite `Message::Binary` per packet |
| Out-of-band signaling | WebRTC / WebTransport adapters | Skip the URL-dispatch path; use `Transport::bind_with_io` directly |

#### Sketch

```rust
use drift::io::{Listener, PacketIO, SchemeRegistration};

// 1. Implement PacketIO for the wire object (a connection / socket / channel).
pub struct MyPacketIO { /* ... */ }
#[async_trait::async_trait]
impl PacketIO for MyPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> { /* frame + write */ }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> { /* read + unframe */ }
    fn local_addr(&self) -> io::Result<SocketAddr> { /* ... */ }
}

// 2. Implement Listener for the server side.
pub struct MyListener { /* ... */ }
#[async_trait::async_trait]
impl Listener for MyListener {
    fn local_addr(&self) -> io::Result<SocketAddr> { /* ... */ }
    fn is_multi(&self) -> bool { false }  // true for datagram-shaped transports
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> { /* handshake + wrap */ }
}

// 3. Register it under a scheme name. Both factories are plain `fn`
//    pointers — no captured state — so they fit in `inventory::submit!`.
//    The address is passed as an opaque `String`; each adapter
//    parses it however its address space requires (IP host:port
//    for UDP/TCP/WS/TLS, base32 .onion:port for Tor, etc.).
fn my_listener_factory(addr_str: String)
    -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>>
{
    Box::pin(async move {
        let addr = my_parse(&addr_str)?;  // your parser (or `parse_ip_addr` for host:port)
        Ok(Box::new(MyListener::bind(addr).await?) as Box<dyn Listener>)
    })
}
fn my_connector_factory(addr_str: String)
    -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>>
{
    Box::pin(async move {
        // Non-IP transports synthesize a unique loopback `SocketAddr`
        // for the peer-table key — the actual destination is held
        // inside the `PacketIO`.
        let io: Arc<dyn PacketIO> = Arc::new(MyPacketIO::dial(&addr_str).await?);
        let peer_key = my_synthesize_peer_addr(&addr_str);
        Ok((io, peer_key))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "mytransport",
        listener: my_listener_factory,
        connector: my_connector_factory,
    }
}
```

#### Don't add a second crypto layer

DRIFT already authenticates peers by X25519 pubkey and AEAD-seals every packet. Adapters that wrap a "secure" wire (TLS, Noise, Tor) **should not** validate the wire's authentication — the cert / static key / circuit identity is camouflage, not security. The TLS adapter generates a fresh self-signed cert per `bind` and the client uses a `NoCertVerifier` that accepts anything. This is intentional: it lets the wire shape match what middleboxes expect (an HTTPS handshake) without requiring users to provision real certs. DRIFT's own crypto is what actually secures the channel.

#### One-time process init

If your transport's underlying library needs a global one-shot setup (rustls's crypto provider, a logger registration, a thread pool), wrap it in `std::sync::Once`. See `install_default_crypto_provider` in `drift/src/io.rs` for the pattern. Don't put the init inside the adapter constructor naively — adapters can be constructed many times per process.

#### Testing

Add a script under `drift-http/tests/multi_transport_*.sh` (or a Rust integration test under `drift/tests/`) that spins up a server listening on `myscheme://127.0.0.1:0` plus the existing transports, then has clients fetch the same content via every scheme and compares bytes. The 4-way test (`drift-http/tests/multi_transport_4way.sh`) is the current template — adding your scheme means adding one bind line and one row to the loop.

That's it. From now on `Transport::bind_url("mytransport://addr")` and `Transport::connect_url("mytransport://...")` work, and every drift-shaped tool (`drift-mosh`, `drift-http`, `drift-wormhole`, `drift-bench`, the `drift` CLI) can route over it without a single line of source change.

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
- **`two-bridge-demo`** (`drift/examples/two_bridge_demo.rs`, run via [`docker/two-bridge/run.sh`](docker/two-bridge/run.sh)) — 12 Docker containers: 2 DRIFT bridges + 10 clients (5 connected to each bridge). 90 directed messages all-to-all; cross-bridge sends prove mesh routing forwards through chained bridges with E2E AEAD intact.
- **`drift-wasm-test/`** — end-to-end Node harness that loads the compiled WASM and verifies (a) a direct DRIFT handshake against a native bridge over WebSocket, and (b) full mesh routing — a browser-equivalent client sending to a UDP peer through the bridge with DRIFT's E2E crypto intact.

## Wire Format

| Format | Header | AEAD tag | Total | Used for |
|--------|--------|----------|-------|----------|
| Long | 36 B | 16 B | 52 B | Handshakes, mesh forwarding, deadlines, coalescing |
| Short | 7 B | 16 B | 23 B | Established direct sessions (56% reduction) |

15 packet types: Hello/HelloAck, Data, Beacon, Challenge, PathChallenge/Response, Close, RekeyRequest/Ack, ResumeHello/Ack/Ticket, Ping/Pong.

## Adapter availability matrix

| Transport | Native | Browser (WASM) | URL dispatch (`bind_url`) | End-to-end verified |
|-----------|:------:|:-------:|:----:|-------------------|
| UDP | ✅ | ❌ (browser sandbox) | ✅ `udp://` | ✅ |
| TCP | ✅ | ❌ (browser sandbox) | ✅ `tcp://` | ✅ |
| TLS over TCP | ✅ | ❌ (browser sandbox) | ✅ `tls://` | ✅ (`multi_transport_4way.sh`) |
| WebSocket | ✅ | ✅ | ✅ `ws://` | ✅ WASM↔native + mesh-through-bridge to any medium |
| WebRTC data channel | ✅ | ✅ | ❌ (signaling out-of-band) | Native↔native ✅ (`webrtc_adapter` test); browser↔native needs app-supplied SDP signaling |
| WebTransport | ✅ | ✅ | ❌ (cert handoff out-of-band) | Native↔native ✅ (`webtransport_adapter` test); browser↔native ships and is cert-hash-pinnable |
| In-memory | ✅ | ❌ | n/a (no addr) | ✅ (used internally by tests + bridge placeholders) |

External crates can register their own adapters via `inventory::submit!` from anywhere — drift core has no allowlist of acceptable schemes.

## Testing

Extensive coverage across 60+ integration test files, drift-core unit tests, and tool-level e2e tests:

- **Correctness**: wire format KAT, header proptests, handshake state machine, rekey, resumption, route migration at equal cost
- **Security**: 17+ attack scenarios (replay, hijack, amplification, flood, beacon poisoning, weak keys)
- **Reliability**: 10–65% packet loss, 2s RTT satellite links, 10 Kbps bandwidth caps, intermittent connectivity
- **Scale**: 1000 concurrent handshakes, 64-client fan-in, 5-node full mesh
- **Cross-medium full mesh**: `loopback_full_mesh.rs` — 4 peers on 127.0.0.1–.4, every message lands across UDP / TCP / WebSocket / WebRTC / WebTransport / mixed-protocol topologies
- **Per-adapter end-to-end**: every `PacketIO` impl has a dedicated test (`tcp_transport`, `webtransport_adapter`, `webrtc_adapter`, `four_medium_bridge`, etc.)
- **Restart migration**: drift-mosh client SIGKILL'd on one IP, reconnects on another, scrollback intact
- **Mesh mobility**: post-handshake beacon discipline, stale-route invalidation on send failure, peer self-migration at equal cost
- **WASM interop**: `drift-wasm-test/` — compiled WASM handshakes with native bridge + mesh-routes to a UDP peer
- **Multi-bridge Docker mesh**: `docker/two-bridge/` — 12 containers, 90 directed messages, 5 of which cross between two bridges
- **Tool-level**: drift-mosh's `smoke.exp` / `tcp_transport.exp` / `ws_transport.exp` / `reattach.exp`; drift-http's `serve_static.sh` / `serve_proxy.sh` / `open_url.sh` / `multi_transport_3way.sh`

```bash
cargo test                # full Rust suite
cargo bench               # throughput benchmarks
./demo-shell.sh           # live multi-IP rotation + multi-identity demo (needs lo0 aliases)
docker/two-bridge/run.sh  # 12-container two-bridge mesh demo
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

## Releases

Tagged releases of the user-facing tools fire a GitHub Actions matrix that builds for macOS arm64 + amd64 and Linux amd64 + arm64:

- **`drift-mosh-vX.Y.Z`** → [`Release drift-mosh`](.github/workflows/release-drift-mosh.yml) → tarballs at [github.com/FancyWaifu/drift/releases](https://github.com/FancyWaifu/drift/releases)
- **`drift-http-vX.Y.Z`** → [`Release drift-http`](.github/workflows/release-drift-http.yml) → same matrix, same release page

```bash
TARGET=aarch64-apple-darwin   # pick yours
TAG=drift-mosh-v0.1.0
curl -L -o pkg.tar.gz \
  https://github.com/FancyWaifu/drift/releases/download/$TAG/drift-mosh-$TAG-$TARGET.tar.gz
tar xzf pkg.tar.gz
sudo mv drift-mosh-$TAG-$TARGET/drift-mosh* /usr/local/bin/
```

## Inspiration

- **[Reticulum](https://reticulum.network/)** — identity-first addressing, always-encrypted, mesh architecture
- **[QUIC](https://www.rfc-editor.org/rfc/rfc9000)** — congestion control, streams, connection migration, short headers
- **[WireGuard](https://www.wireguard.com/)** — minimal crypto surface, small codebase

## License

MIT

# DRIFT

**DRIFT is the identity-based transport that works through every middlebox, with Matrix-style federation built in.**

Your address is your public key. The same wire protocol runs over UDP, TCP, TLS, WebSocket, HTTP/2, HTTP/3 (WebTransport), Tor onion services, DNS, DoH-over-Cloudflare-Worker, WebRTC, and in-memory channels — pick whichever your network actually permits. Bridges federate Matrix-style so two peers behind separate NATs find each other through a shared bridge with no port forwarding. A WASM build of the same protocol runs in browsers, byte-for-byte wire-compatible with native peers.

## Why DRIFT

| If you need...                                                       | DRIFT                          | Iroh                          | Tailscale            | Reticulum              |
| -------------------------------------------------------------------- | ------------------------------ | ----------------------------- | -------------------- | ---------------------- |
| Pubkey-addressed transport (no DNS, no accounts)                     | ✅                              | ✅                             | ❌ (account-tied)     | ✅                      |
| 12+ wire transports including DoH-over-Worker, Tor, WebTransport     | ✅                              | ❌ (QUIC-only)                 | ❌ (UDP/TCP only)     | ✅ (radio-first)        |
| Matrix-style federation with discovery primitives                    | ✅                              | ❌ (relay-only)                | ❌                    | partial (mesh routing) |
| Browser WASM shipping (not roadmapped)                               | ✅                              | roadmap                       | ❌                    | ❌                      |
| Production-internet IP throughput                                    | ✅                              | ✅                             | ✅                    | ❌ (LoRa/radio range)   |
| Differential-privacy-noised discovery + cover traffic                | ✅                              | ❌                             | ❌                    | partial                |
| Owner-driven identity rotation                                       | ✅                              | ❌                             | partial              | ❌                      |

**Head-to-head protocol overhead (loopback, single Mac, 1 KB payload, fresh client per handshake iter):**

| Workload                           | DRIFT       | Iroh        | QUIC (quinn)  |
| ---------------------------------- | ----------- | ----------- | ------------- |
| Handshake p50 (connect→first byte) | **1650 µs** | 2527 µs     | 1926 µs       |
| RTT p50                            | **68 µs**   | 65 µs       | 104 µs        |
| RTT p99 (tail latency)             | **132 µs**  | 302 µs      | 2033 µs       |

These measure the protocol's own per-packet overhead — the fair head-to-head. DRIFT wins handshake p50 and has the tightest tail by ~3–15×.

**Throughput is wire-dependent, not protocol-dependent.** DRIFT runs over twelve different wires. The same DRIFT protocol, same payload, same loopback — different wire underneath each time:

| DRIFT over... | Mbps     | vs raw QUIC (1935 Mbps) |
| ------------- | -------- | ----------------------- |
| **h2**        | **7061** | **3.6× faster**         |
| **h2s**       | **7052** | **3.6× faster**         |
| ws            | 3551     | 1.8× faster             |
| tcp           | 2298     | 1.2× faster             |
| tls           | 1949     | comparable              |
| udp           | 1524     | comparable              |
| webtransport  | 931      | slower                  |

DRIFT does not have a single throughput number. The spread between wires on the same hardware is **7.5×** (931 → 7061 Mbps). Pick the wire that fits your environment; the protocol layer is the same. Iroh, by contrast, is QUIC-only at 1691 Mbps — you can't pick a faster wire. Full methodology: [`drift-bench/RESULTS-2026-05-27.md`](drift-bench/RESULTS-2026-05-27.md).

## What DRIFT actually is (one paragraph)

A custom 36-byte long-header / 7-byte short-header wire format with X25519 + ChaCha20-Poly1305 (WireGuard primitives) and optional X25519+ML-KEM-768 hybrid for post-quantum. On top: reliable multiplexed streams with NewReno/BBR congestion control, deadline-aware delivery, semantic coalescing, 1-RTT PSK session resumption, RTT-weighted multi-hop mesh routing, federation with bridge-to-bridge directory announcements (XEdDSA-signed presence tickets), and a federation-discovery layer that supports differential-privacy-noised bloom filters + Poisson-timed cover traffic + signed hop attestations. Plus a `PacketIO` trait so any byte-shaped wire — UDP socket, TLS stream, h2 bidi stream, WebTransport datagram, Tor hidden service — can carry the protocol.

## Federation discovery (the privacy story)

The federation layer mentioned above is the result of a six-phase implementation that lets a DRIFT client reach any peer in a multi-bridge federation **by pubkey alone**, with privacy controls applied to the lookup itself. Before this work, `drift.toml` host entries needed an explicit `via_bridge` pointing at the bridge holding the target. After it, a host entry can carry only a pubkey and the local bridge handles the routing.

### The mental model

Three layers of cache, narrowing the cost of each lookup:

1. **Proactive announce** — every ~7 seconds each bridge broadcasts a `FederationDirectory v3/v4` to its federation peers listing its local clients (with XEdDSA presence tickets attesting that those clients actually authorized the relay). Steady-state lookups hit a warm cache.
2. **Reactive discovery** — if the cache misses, the bridge originates a `FindPeer` query across federation. Up to 4 hops with loop prevention, signed hop attestations on every intermediate, and `PeerHere` chains as replies. Cold-path resolution in ≤2 seconds.
3. **Instant invalidation** — when a client disconnects, `PeerGone` broadcasts evict cached routes immediately rather than waiting for the next announce.

Phase F added a privacy layer on top: bridges announce a **DP-noised bloom filter** of their local clients, so originators can locally test "could this bridge host the target?" before sending any query. A bridge whose filter says "definitely not" never sees the query at all.

### What landed

| Phase | What it shipped |
|---|---|
| **A** | `FindPeer` / `PeerHere` / `PeerGone` packet types + 1-hop discovery between directly-federated bridges |
| **B** | Multi-hop forwarding (TTL=4), loop prevention, path extension on re-emit |
| **C** | `FederationDirectory v3` with `hops` field for proactive transitive announces |
| **D** | `via_bridge` becomes optional in `drift.toml` (host entries can carry just a pubkey, falls through to `default_bridge` + UNKNOWN sentinel) |
| **E v1** | `find_peer_disabled` flag — opt out of discovery entirely |
| **E v2** | `FindPeerHashed` (`SHA-256(target ‖ salt)`) + `FindPeerMode` enum (`Open` / `NoForward` / `OriginateHashed` / `Disabled`) |
| **F** | `FederationDirectory v4` with DP-noised bloom filter; cover-traffic decoys at Poisson intervals; per-bridge fault tracking on unfulfilled bloom claims |
| Hop signing | Replaced Phase B's stub tickets with XEdDSA bridge-self-signed attestations — `"DRIFT-HOP" ‖ bridge_pub ‖ query_id ‖ expiry ‖ nonce` domain-separated from presence tickets |
| Background GC | Sweep loop bounds memory across `pending_finds`, `recent_queries`, `neg_cache`, `forwarded_queries` |

### Bugs caught + fixed live

- **`UNKNOWN_BRIDGE_PUB` missed local clients** — single-bridge federations couldn't resolve their own clients via discovery; pinned by integration test (`unknown_bridge_pub_resolves_to_local_client`).
- **Native HTTP connector vs server base64** — listener used `STANDARD_NO_PAD`, my native connector used padding-strict `STANDARD`. Silent decode failure, "unknown peer" timeouts. Fixed + load-bearing comment.
- **drift-mosh-server watchdog over-aggressive** — restarted handshake every 6 s on data-plane silence, even when the bridge was healthy. Caused mosh-server on LXC to be unreachable from clients. Relaxed to 60 s.
- **drift-vpn macOS broken** — utun device picked a bogus point-to-point destination (no kernel route) AND tun reads/writes were missing macOS BSD framing (`AF_INET` 4-byte prefix). Both gated with `#[cfg(target_os = "macos")]`. Verified end-to-end Mac → router → Drift1 VPN tunnel.

### Where to look in the source

| Component | File |
|---|---|
| Wire codecs (FindPeer / PeerHere / PeerGone / FindPeerHashed / hop attestations) | [`drift/src/transport/find_peer.rs`](drift/src/transport/find_peer.rs) |
| Directory codec (v2 / v3 / v4) + presence tickets | [`drift/src/transport/federated.rs`](drift/src/transport/federated.rs) |
| DP bloom filter | [`drift/src/transport/dp_bloom.rs`](drift/src/transport/dp_bloom.rs) |
| Discovery state + handlers + cover traffic + GC | [`drift/src/transport/mod.rs`](drift/src/transport/mod.rs) (search `handle_find_peer`, `run_cover_traffic_loop`) |
| Authoritative wire-format spec | [`SPEC.md` §10](SPEC.md) |
| Design doc + threat model + algorithm sketches | [`FEDERATION_DISCOVERY.md`](FEDERATION_DISCOVERY.md) |
| Integration tests (11 cases covering all phases) | [`drift/tests/federation_discovery.rs`](drift/tests/federation_discovery.rs) |
| WASM cross-stack smoke (Node 22+ runs the browser-side adapters against the native bridge) | [`drift-wasm/test/network-ws-node.js`](drift-wasm/test/network-ws-node.js), [`network-http-node.js`](drift-wasm/test/network-http-node.js) |

### Privacy controls — `TransportConfig` knobs

```rust
TransportConfig {
    // Phase E v2
    find_peer_mode: FindPeerMode::OriginateHashed, // hash targets; transit bridges see only hashes
    // or NoForward to answer-but-not-relay; Disabled to opt out.

    // Phase F
    bloom_announce_noise: Some(0.05),  // emit v4 bloom with 5% one-sided DP noise
    cover_traffic_rate_hz: Some(0.1),  // decoy FindPeer ~every 10 seconds, Poisson-timed

    // ..rest of TransportConfig
}
```

Stacked, these defeat bulk traffic analysis: transit bridges see only hashed targets, can't tell decoy from real, never receive queries for pubkeys their filter rejects. The remaining leak is to the **answering** bridge (which by construction has to learn the target to deliver the route). Closing that gap properly requires lattice-based PIR — multi-week project, multi-megabyte per query, deferred.

### Open work

- **drift-vpn Windows daemon** (Wintun) — pre-existing pending task, never started.
- **Browser test harness shipped** — `drift-wasm/test/browser/` runs Playwright across Chromium / Firefox / WebKit for the WS, HTTP, WebTransport, and WebRTC adapters against a real `drift bridge` subprocess on ephemeral ports.
- **drift-mosh-client WASM build** — would give an in-browser remote shell with no system install, riding on the cross-stack story this session validated.
- **PIR-based "high-privacy" lookup mode** — lattice-based homomorphic PIR for the case where you can't trust even the answering bridge. See the trade-off discussion in [`FEDERATION_DISCOVERY.md`](FEDERATION_DISCOVERY.md).
- **`webrtc://` URL scheme** — currently programmatic-only on the native side; adding a CLI-accessible scheme needs a signaling protocol. (`webtransport://` shipped as a CLI scheme in the federation-backbone arc — see below.)

### Test totals (latest workspace run, 2026-05-27)

```
cargo test --workspace --release --lib --bins --tests
→  108 suites, 458 passed, 0 failed, 26 ignored
   (ignored = onion / browser tests gated behind env vars + features)
```

Plus a live Mac↔LXC drift-vpn tunnel and a 17-bridge corporate-federation
benchmark on a 2-core/512MB Proxmox LXC ([`docker/federation-corporate/`](docker/federation-corporate/RESULTS.md))
proving end-to-end usability.

## How — capability map

Concrete pieces that back the positioning sentence above, grouped by what they do.

**Crypto** — X25519 + ChaCha20-Poly1305 (WireGuard-style minimal surface). Optional post-quantum hybrid (X25519 + ML-KEM-768). Adaptive DoS cookies. RFC 9000-style 3× amplification limit. No plaintext mode.

**Transport** — Reliable multiplexed streams. Unreliable datagrams. NewReno or BBR-lite congestion control with ECN feedback. Deadline-aware delivery (`deadline_ms`). Semantic coalescing (`supersedes` groups — only the freshest update is delivered).

**Sessions** — 1-RTT PSK resumption with exportable tickets. Auto-rekey at the 2³¹ sequence ceiling. Graceful connection migration (wifi → cellular) via path validation probes.

**Mesh** — Multi-hop forwarding with end-to-end encryption preserved. RTT-weighted distance-vector routing. Hold-down timers, hysteresis, staleness expiry. Peer self-migration at equal cost.

**Federation** — Matrix/XMPP-style bridge-to-bridge forwarding for the cases where mesh discovery doesn't fit: explicit `--federate` links between bridges plus pubkey-addressed envelopes (`PacketType::Federated`) that target a `(remote_bridge_pub, remote_client_pub)` tuple. Bridges see ciphertext only; end-to-end crypto stays between the real client endpoints. Heterogeneous-transport chains work end-to-end — UDP client → TCP federation link → WebSocket client (and any other permutation across UDP / TCP / TLS / WS) all share the same envelope.

**Medium-agnostic** — `PacketIO` trait with built-in adapters for UDP, TCP (length-prefix framing), WebSocket (binary messages), WebSocketStream (Chromium-only, automatic backpressure), TLS-wrapped TCP (length-prefix inside a TLS record stream — DRIFT shaped to look like HTTPS), plain HTTP/SSE (`GET /drift-sse` downstream + `POST /drift-send` per-packet upstream — fallback for proxies that strip WS upgrades), HTTP/2 cleartext (`h2://` — one TCP + one HTTP/2 bidi stream pair carrying length-prefixed DRIFT packets), HTTP/2 over TLS (`h2s://` — same as `h2://` with ALPN=h2, federation-grade over HTTPS), WebTransport (`webtransport://` — QUIC + HTTP/3, one DRIFT packet per QUIC datagram, native CLI-accessible and browser-shipping), Tor onion services (opt-in via `--features onion`, hidden-service hosting + dialing via [arti](https://gitlab.torproject.org/tpo/core/arti)), WebRTC data channels (browser-to-browser, no server in the data path), and in-memory channels. Plug in serial, BLE, I2P, or anything else.

**Plug-and-play transports** — Adapters self-register at link time via `inventory::submit!`. The URL dispatcher (`Transport::bind_url("tcp://0.0.0.0:9100")`, `Transport::connect_url("ws://example.com:443")`) finds them at runtime. Adding a new transport means writing one `Listener` impl + one `inventory::submit!` block — drift-mosh, drift-http, and any other tool gain that wire for free, with zero source edits.

**Browser-native** — `drift-wasm` compiles the full DRIFT protocol to WebAssembly. Same `drift-core` code as the native stack; interoperates with native peers through a bridge. Supports all three browser wire transports (WebSocket, WebRTC data channel, WebTransport) behind one `DriftClient` API.

**Observability** — 30+ runtime metrics. Structured NDJSON qlog. XOR-based FEC for lossy links.

## Tools built on DRIFT

End-user binaries shipped from this repo. Each has its own README with install + usage.

| Tool | What it is | Install |
|---|---|---|
| **[drift-vpn](drift-vpn/README.md)** | Identity-routed multi-transport VPN. WireGuard-shaped config, but with cross-scheme runtime failover (UDP→TCP/TLS/WS), hub-and-spoke mesh routing, **bridge-fallback peers (two NAT'd peers find each other through a shared federation bridge, no port forwarding either side)**, `drift-vpn doctor` preflight, **one-command service install (`drift-vpn install --start` writes systemd unit / launchd plist, enables for boot)**, **owner-driven identity rotation (`drift-vpn rotate` / `rotate-verify`)**, and built-in Prometheus metrics. Linux + macOS daemon. See [QUICKSTART.md](drift-vpn/QUICKSTART.md) and [ROTATION.md](drift-vpn/ROTATION.md). | `cargo install --path drift-vpn --bin drift-vpn` or [release tarballs](https://github.com/FancyWaifu/drift/releases) |
| **[drift-mosh](drift-mosh/README.md)** | Mobile-shell replacement (mosh-style) — survives wifi-to-cellular, laptop suspend, client crash. UDP / TCP / WebSocket. | `cargo install --path drift-mosh --bin drift-mosh` or [release tarballs](https://github.com/FancyWaifu/drift/releases) |
| **[drift-http](drift-http/README.md)** | Apache-style file server + Jellyfin-style proxy + system-wide `drift://` URL handler. Pubkey-addressed; no DDNS, no reverse proxy, no TLS cert. | `cargo install --path drift-http --bin drift-http` or [release tarballs](https://github.com/FancyWaifu/drift/releases) |
| **[drift-git](drift-git/README.md)** | `git push drift://<peerhex>@<host>:<port>/<repo>` over DRIFT — git remote helper + serving daemon. No SSH keys, no GitHub. UDP / TCP / TLS / WS. | `cargo install --path drift-git --bins` |
| **[drift](drift/src/main.rs)** | Core CLI — `keygen`, `info`, `listen`, `send`, `relay`, `bridge`. | `cargo install --path drift` |
| **[drift-config](drift-config/README.md)** | Identity + inventory manager — one declarative `drift.toml` per host that every DRIFT tool reads. Eliminates manual pubkey cross-filling. | `cargo install --path drift-config` |
| **[drift-wormhole](drift-wormhole/README.md)** | Magic-Wormhole-shaped file transfer over DRIFT — pubkey-addressed, no rendezvous server. | `cargo install --path drift-wormhole --bin drift-wormhole` |
| **[drift-ffi](drift-ffi/README.md)** | C ABI — call DRIFT from C, C++, Python, Go, Swift, anything. | `cargo build --release -p drift-ffi` |

## Workspace layout

```
drift-core/      sans-io protocol engine (WASM-safe, no tokio, no I/O)
  crypto.rs          X25519 DH, ChaCha20-Poly1305, SipHash cookies
  identity.rs        Keypairs, session key derivation, rekey KDF
  header.rs          36-byte long header, 18 packet types
  short_header.rs    7-byte compact header with Connection IDs
  session.rs         Handshake state machine, replay protection, Peer::make_header helper
  fec.rs             XOR forward error correction
  pq.rs              Post-quantum hybrid (X25519 + ML-KEM-768)
  xeddsa.rs          XEdDSA signatures on the existing X25519 identity
                       keys — used for federation presence tickets and
                       identity-rotation announces
  rotation.rs        Owner-driven identity rotation: signed RotationAnnounce
                       (168 bytes) asserting OLD pubkey → NEW pubkey,
                       authenticated by XEdDSA from the OLD secret

drift/           native tokio-based stack built on drift-core
  src/
    lib.rs           Transport re-exports
    main.rs          `drift` CLI (keygen, info, send, listen, relay, bridge)
    io.rs            PacketIO + Listener traits, UDP / TCP / WebSocket / TLS /
                       Memory adapters, inventory-based scheme registry
                       (Transport::bind_url / connect_url / add_listener).
                       h2://, h2s://, webtransport://, webrtc://, http://,
                       dns://, doh://, onion:// each live in their own
                       wire_*.rs file and self-register through the same
                       inventory.
    cli/bridge.rs    `drift bridge` runner; --listen (repeatable) +
                       --federate <url>@<pub> (repeatable) for cross-
                       bridge client routing via Transport::connect_federate
                       (honest outbound connect on the federate scheme,
                        not a listener-socket reuse)
    wire_http.rs     `http://` adapter — Server-Sent Events downstream + per-
                       packet POST upstream. Browser-fallback wire when WS is
                       blocked by middleboxes
    wire_dns.rs      `dns://` adapter — DRIFT packets shaped as DNS queries
                       (base32-encoded QNAME, fragmentation header). Direct
                       peer-to-peer over UDP, no resolver in the loop.
    wire_doh.rs      `doh://` adapter — DRIFT-over-DoH-over-Cloudflare-Worker.
                       HTTPS to your own Worker; Worker routes fragments by
                       destination pubkey via Durable Objects.
    wire_onion.rs    `onion://` Tor adapter via arti — hidden-service hosting
                       + dialing (gated behind `--features onion`)
    streams.rs       Reliable streams, NewReno + BBR congestion control
    multipath.rs     RTT-weighted path selection
    transport/
      mod.rs         Core engine: send/recv, handshake, rekey, resumption,
                       Transport::add_federated_peer / connect_federate
      mesh.rs        Routing table, beacons, hop-TTL forwarding, self-migration
      federated.rs   PacketType::Federated envelope (130-byte bridge-routing
                       wrapper) + FederationDirectory v2 codec (128-byte
                       entries: 32-byte pubkey + 96-byte XEdDSA presence
                       ticket) + PresenceTicket packet codec + ticket
                       sign/verify helpers
      cookies.rs     Adaptive DoS challenge-response
      path.rs        PathChallenge/Response, connection migration
      peer_shards.rs 16-shard peer table (lock contention reduction)
      resumption.rs  1-RTT PSK session resumption
      rtt.rs         Ping/Pong RTT measurement
      ecn.rs         ECN marking + CE feedback
      batch.rs       sendmmsg + UDP_SEGMENT (GSO) sender, UDP_GRO receiver
                       (Linux); single-send fallback on other platforms
      qlog.rs        Structured NDJSON event logging

drift-wasm/      browser-side stack, same drift-core compiled to wasm32
  src/
    lib.rs                JS bindings: DriftIdentity, DriftClient
    session.rs            Wire-agnostic protocol state + mesh handshake flow
    peer_session.rs       Per-peer crypto state
    wire_ws.rs            WebSocket adapter
    wire_ws_stream.rs     WebSocketStream adapter (Chromium-only, streams API
                            with automatic backpressure)
    wire_http.rs          HTTP/SSE fallback adapter — EventSource downstream +
                            fetch() POST upstream
    wire_webrtc.rs        Browser WebRTC RTCDataChannel adapter
    wire_webtransport.rs  Browser WebTransport HTTP/3 adapter (cert-hash pinnable)

drift-vpn/       Identity-routed multi-transport VPN. WireGuard-shaped TOML config,
                   cross-scheme runtime failover, hub-and-spoke mesh routing,
                   via_bridge fallback, `drift-vpn doctor` preflight, one-command
                   `install`/`uninstall` (systemd + launchd), owner-driven identity
                   `rotate`/`rotate-verify` via XEdDSA-signed announce,
                   `drift-vpn status`, Prometheus /metrics endpoint. Linux + macOS.
drift-mosh/      Mobile-shell replacement built on DRIFT. Multi-transport CLI,
                   restart migration, scrollback reattach, TOFU known-hosts.
drift-http/      HTTP-over-DRIFT: Apache-style file server, opaque proxy,
                   drift:// URL handler with macOS / Linux registration.
drift-git/       Git over DRIFT: `git push drift://<peerhex>@<host>:<port>/<repo>`.
                   Git remote helper + bare-repo serving daemon, ACL'd by pubkey.
drift-wormhole/  Magic-Wormhole-shaped file transfer over DRIFT. SHA-256
                   byte-fidelity, progress bar, scheme-prefixed peer URLs.
drift-config/    Identity + inventory manager. One declarative drift.toml per
                   host; every DRIFT tool reads from it. Eliminates the manual
                   pubkey cross-filling pain on multi-node deployments.
drift-doh-relay/ Cloudflare Worker rendezvous for the `doh://` adapter. Five-
                   minute deploy, $0/month, no infrastructure. Run your own.
drift-ffi/       C ABI for invoking DRIFT from C / Python / Go / Swift / anywhere
                   that speaks the C ABI.
drift-wasm-test/ Node harness verifying drift-wasm interops with the native stack
                   over WebSocket (and through a bridge to a UDP peer).
docker/          Docker test infrastructure for the workspace.
  Dockerfile         Image build for compose/ scenarios (drift:latest)
  compose/           ~30 docker-compose scenarios (NAT, mesh, packet loss, scale)
  scripts/           Runners that orchestrate compose/ scenarios
  two-bridge/        Standalone 12-container demo: 2 bridges + 10 clients,
                       cross-bridge mesh routing
```

## Setting up a real DRIFT deployment

Want to actually deploy DRIFT — a bridge for friends, a multi-host VPN, a few peers using drift-mosh together? **Start with [`drift-config/README.md`](drift-config/README.md).**

It's the entry-point doc for operators: install instructions, two complete walkthroughs (5-min single-bridge + client; 10-min 3-node VPN), the full schema reference for `drift.toml`, and a clear map of which DRIFT tool reads what. drift-config owns the inventory of identities and endpoints; every other DRIFT tool (`drift bridge`, `drift-vpn`, `drift-mosh`, `drift-http`) reads from the same file, so you never cross-fill 64-char pubkeys by hand.

## Quick Start (library API)

For embedding DRIFT directly inside another Rust program (not a tool deployment), the library API looks like:

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

The same scheme-prefixed addresses work everywhere — drift-mosh, drift-http, the `drift` CLI, and library callers all use `Transport::bind_url` / `Transport::connect_url`. The URL dispatcher resolves the scheme to a registered adapter at runtime; bare `host:port` (no scheme) defaults to UDP for back-compat.

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

### Hostile-network transports: `dns://` and `doh://`

Two adapters specifically built for environments where every "normal" wire (UDP, TCP, WS, even TLS) is filtered.

**`dns://` — direct peer-to-peer, DNS-shaped UDP**

DRIFT packets ride as DNS queries between two peers who can reach each other on UDP. Looks like a stub resolver pounding an authoritative server to any middlebox or `tcpdump` listener — a stealth profile for networks that allow DNS but block other UDP.

```rust
let (server, url) = Transport::bind_url("dns://0.0.0.0:5354", id, cfg).await?;
// peer side: connect_url("dns://server-host:5354", ...)
```

Same encoding both directions: 4-byte fragment header + base32 payload across ≤3 QNAME labels + `drift.local` suffix. 1400-byte DRIFT packets fragment into ~13 queries. See `drift/src/wire_dns.rs`.

**`doh://` — relayed through a Cloudflare Worker**

The "always works" wire. Both DRIFT peers POST DoH-shaped requests to a Cloudflare Worker you deploy in five minutes (free tier, no domain, no VPS, no public IP). The Worker buckets fragments by destination pubkey via a Durable Object and shuttles them between peers. To DPI middleboxes, the wire is plain HTTPS to a Cloudflare hostname — indistinguishable from any browser running DoH.

```rust
let url = format!(
    "doh://drift-doh-relay.<your-subdomain>.workers.dev/v1/{}/{}/dns-query",
    hex::encode(my_id.public_bytes()),
    hex::encode(peer_pubkey),
);
let (transport, addr) = Transport::connect_url(&url, my_id, cfg).await?;
```

Deploy your own relay in five minutes — see [`drift-doh-relay/README.md`](drift-doh-relay/README.md). **Don't share Workers** — each user should run their own to keep their pubkey routing patterns private and avoid exhausting someone else's free-tier quota.

End-to-end demos: `drift/examples/doh_chat.rs` (interactive two-peer chat), `drift/examples/doh_chat_demo.rs` (self-driving full-handshake test against a deployed Worker).

### Multi-Interface Bridging

A single node can bridge across mediums — UDP peers talk to TCP peers talk to WebSocket peers talk to WebRTC peers talk to WebTransport peers through one bridge, zero medium-specific routing code. The bridge sees only ciphertext; DRIFT's end-to-end crypto stays between the real endpoints:

```rust
let (bridge, _) = Transport::bind_url("udp://0.0.0.0:9000", bridge_id, cfg).await?;
let bridge = Arc::new(bridge);
bridge.add_listener("tcp://0.0.0.0:9001").await?;
bridge.add_listener("ws://0.0.0.0:9002").await?;
// Packets route by identity, not by medium.
```

### Federation — bridges that bridge each other

Mesh routing discovers paths via beacons; federation is the explicit-config flavor for the cases where you want bridges in different networks to relay client traffic for each other without burning beacon bandwidth on the long-haul link. Modeled on Matrix and XMPP server-to-server.

**Federation trust is symmetric and explicit.** Each bridge declares its peer bridges with `--federate <url>@<pub>`, on both sides. Inbound Federated envelopes from a peer not in the federation table are dropped — without this rule, any client of an `accept_any_peer` bridge could (a) spoof other clients' identities by forging the envelope's `source_client_pub`, and (b) poison the bridge's routing table by claiming arbitrary `source_bridge_pub`. Regression-locked in `drift/tests/adversarial_federation.rs`.

Clients address far-side peers by `(remote_bridge_pub, remote_client_pub)` and the wire envelope is `PacketType::Federated`:

```bash
# Bridge A: listens for clients on UDP; federates to B over TLS.
drift bridge --listen udp://0.0.0.0:51820 \
             --federate tls://bridge-b.example:51821@<B_PUBHEX>

# Bridge B: listens for clients on WebSocket + TLS for the federation
# link from A. Also --federate's back to A.
drift bridge --listen tls://0.0.0.0:51821 \
             --listen ws://0.0.0.0:51822 \
             --federate udp://bridge-a.example:51820@<A_PUBHEX>
```

Symmetric `--federate` on connection-oriented schemes (TCP/TLS/WS) creates a startup race: each side tries to connect before the other is listening. `bridge.rs` handles this by retrying initial-connect failures on a background task with exponential backoff — start order doesn't matter.

A client connected to A reaches a client connected to B with one extra call:

```rust
let bridge_a = transport.add_peer(bridge_a_pub, bridge_a_addr, Direction::Initiator).await?;
let remote   = transport.add_federated_peer(remote_client_pub, bridge_a, bridge_b_pub).await?;
transport.send_data(&remote, b"hello across bridges", 0, 0).await?;
```

After `add_federated_peer`, normal `send_data(&remote, ...)` is transparently wrapped in a Federated envelope and shipped via `bridge_a`. The receiving client's `recv()` yields a `Received` whose `peer_id` matches the original sender (the bridge is invisible to the application).

Internally, federation uses `Transport::connect_federate(url, pubkey)` to open an honest outbound connection on the URL's scheme — TCP/TLS/WS work as bridge-to-bridge links, not just UDP. Verified end-to-end across UDP, TCP, TLS, and WebSocket combinations (`drift-mosh/tests/mixed_transport_federation_test.sh`).

### Zero-config client dial — inventory-driven discovery

When the target's pubkey is registered in `drift.toml` (see [`drift-config/README.md`](drift-config/README.md)), DRIFT tools fill in the rest of the routing themselves:

```bash
# Operator side: register the server's reachability once.
drift-config peer add bridge-b --pubkey <B_PUB> \
  --endpoint "tls://bridge-b.example:51821"
drift-config peer add my-server --pubkey <SERVER_PUB> \
  --via-bridge <B_PUB>

# User side: dial by pubkey, no routing flags needed.
drift-mosh-client --server-pub <SERVER_PUB> --exec uptime
```

The inventory entry's `endpoints` (direct dial) or `via_bridge` (federation route) is consulted automatically; direct wins when both are present. `drift-mosh-server --bridge <url>@<pub>` reconnects on a 2 s watchdog if the bridge it's connected to restarts — so a bridge bouncing doesn't strand the server.

### Dynamic discovery — `default_bridge` + bridge announcements

The fully-zero-config case: the operator doesn't even know which bridge hosts a particular target. Drift.toml just declares "if you don't know how to reach a host, ask this bridge":

```toml
# /etc/drift/drift.toml
default_bridge = "<bridge-pubkey-hex>"

[hosts.bridge-x]
pubkey = "<bridge-pubkey-hex>"
endpoints = ["udp://bridge-x.example:51820"]
```

```bash
drift-mosh-client --server-pub <ANY_PUB> --exec uptime
# → dials bridge-x, sends Federated envelope with the all-zero
#   sentinel as target_bridge_pub; bridge-x looks up <ANY_PUB>
#   in its federation directory and re-routes to whichever
#   federated bridge announced it.
```

Bridges (`drift bridge`) announce their connected clients to every federation peer every 7 s via `PacketType::FederationDirectory` (v2). Each announcement is the COMPLETE current set of that bridge's clients (idempotent-set semantics), so a client disconnecting from its bridge drops out of peer directories within one announce interval. Each entry carries a 96-byte XEdDSA presence ticket the client signed for the announcing bridge. Receiving bridges record `client_pubkey → (announcer_bridge, last_announced_at)` with a 20 s TTL. Multiple defenses limit what a malicious federated bridge can do:

- **Only federation peers may write.** Random clients of `accept_any_peer` bridges can't inject entries — see `drift/tests/adversarial_federation.rs::federation_directory_rejects_non_bridge_announcer`.
- **Cryptographic presence proof per entry.** Each v2 directory entry carries an XEdDSA signature the announced client made over `(announcing_bridge_pub ‖ expiry_ms ‖ nonce)` using its X25519 identity key. A federated bridge that doesn't actually have a session with the claimed client can't produce a valid signature — entries that fail verification are dropped (`metrics.federation_invalid_tickets_dropped`). Locked in by `drift/tests/adversarial_presence_tickets.rs`.
- **First-write-wins on cross-announcer conflicts.** If B already holds the entry for client X, a later announcement from C claiming X is silently dropped — kills race-to-hijack attacks. Locked in by `drift/tests/federation_directory_semantics.rs::cross_announcer_conflict_keeps_first_writer`.
- **Evict on send failure.** When a forwarding attempt to a directory next-hop errors out, every entry attributed to that next-hop is dropped immediately — so a dead bridge stops attracting traffic without waiting out the TTL.

What's still trusted to the operator's `--federate` choices: a malicious federated bridge can refuse to forward, delay, or omit clients from its announcements (denial of service against its own users). What it can no longer do is announce pubkeys it doesn't actually host — XEdDSA presence tickets close that gap. Federation security is now at parity with Matrix/XMPP server-to-server: trust your federation partners not to be malicious, but you don't have to trust them not to be sloppy.

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
| Non-IP-addressed (Tor, BLE, etc.) | `OnionPacketIO` / `OnionListenerIO` in `drift/src/wire_onion.rs` | Synthesize a loopback `SocketAddr` per peer; lazy-bootstrap heavy global state once via `tokio::sync::OnceCell` |
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

That's it. From now on `Transport::bind_url("mytransport://addr")` and `Transport::connect_url("mytransport://...")` work, and every drift-shaped tool (`drift-mosh`, `drift-http`, `drift-wormhole`, the `drift` CLI) can route over it without a single line of source change.

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
- **`drift-shell`** (`drift/examples/drift_shell.rs`) — tiny command server (`time`, `count`, `whoami`, `echo`, …) reachable over DRIFT.
- **`drift-kv`** (`drift/examples/drift_kv.rs`) — port of the Tokio team's `mini-redis` to run over DRIFT. Implements the Redis RESP protocol (PING / GET / SET / DEL) with the bridge accepting clients on UDP / TCP / WS / WebRTC simultaneously.
- **`drift-medium-demo`** (`drift/examples/medium_demo.rs`) — three distinct source IPs on three mediums bridged end to end.
- **`drift-wasm-test/`** — end-to-end Node harness that loads the compiled WASM and verifies (a) a direct DRIFT handshake against a native bridge over WebSocket, and (b) full mesh routing — a browser-equivalent client sending to a UDP peer through the bridge with DRIFT's E2E crypto intact.

## Wire Format

| Format | Header | AEAD tag | Total | Used for |
|--------|--------|----------|-------|----------|
| Long | 36 B | 16 B | 52 B | Handshakes, mesh forwarding, deadlines, coalescing |
| Short | 7 B | 16 B | 23 B | Established direct sessions (56% reduction) |

18 packet types: Hello/HelloAck, Data, Beacon, Challenge, PathChallenge/Response, Close, RekeyRequest/Ack, ResumeHello/Ack/Ticket, Ping/Pong, **Federated** (bridge-routing envelope), **FederationDirectory** (bridge-to-bridge client announcements with XEdDSA presence tickets), **PresenceTicket** (client → bridge ticket emission).

## Adapter availability matrix

| Transport | Native | Browser (WASM) | URL dispatch (`bind_url`) | End-to-end verified |
|-----------|:------:|:-------:|:----:|-------------------|
| UDP | ✅ | ❌ (browser sandbox) | ✅ `udp://` | ✅ |
| TCP | ✅ | ❌ (browser sandbox) | ✅ `tcp://` | ✅ |
| TLS over TCP | ✅ | ❌ (browser sandbox) | ✅ `tls://` | ✅ (`multi_transport_4way.sh`) |
| Tor onion service | ✅ (opt-in via `--features onion`) | ❌ | ✅ `onion://` | ✅ self-dial through live Tor in 117s (`onion_self_dial`, gated `#[ignore]`) |
| WebSocket | ✅ | ✅ | ✅ `ws://` | ✅ WASM↔native + mesh-through-bridge to any medium |
| WebSocketStream | ❌ (no native peer needed — same wire as WS) | ✅ Chromium-only | n/a (uses WS server) | Wire-shared with `ws://` (already covered) |
| HTTP/SSE | ✅ (server-only — `http://` listener; native dial is browser's job) | ✅ | ✅ `http://` (server side) | ✅ WASM client → native bridge: `test-http.mjs` |
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
- **WASM interop**: `drift-wasm-test/` — compiled WASM handshakes with native bridge + mesh-routes to a UDP peer. Confirmed: bridge log shows `recv from peer=<wasm-id> 16B: "hello from wasm!"` (test-wasm) and the cross-medium UDP peer's log shows `RECV <- ?peer=<wasm-id>: hello-from-wasm-through-bridge-to-udp-peer` (test-mesh — bridge never sees plaintext).
- **HTTP/SSE fallback**: `drift-wasm-test/test-http.mjs` — WASM client (no WebSocket, no streams, just `EventSource` + `fetch()` POST) handshakes with the native bridge over plain HTTP/1.1. Confirmed: bridge log shows `recv from peer=<wasm-id> 26B: "hello from wasm over http!"`. Routes through anything that proxies HTTP at all.
- **Onion over Tor**: `drift/tests/onion_self_dial.rs` — gated `#[ignore]`, opt-in via `--features onion`. Hosts an onion service in-process, retrieves its `<base32>.onion` address, dials it back through the live Tor network, runs a full handshake + DATA exchange. Confirmed end-to-end in 117s on a real network.
- **Federation, heterogeneous transports**: `drift-mosh/tests/mixed_transport_federation_test.sh` — runs a full `drift-mosh --exec` shell command end-to-end across `D1 ──UDP──▶ D2 ──TLS──▶ D3 ──WS──▶ D4` (real Proxmox LXCs). Bytes traverse three different DRIFT transports in one chain; the federation envelope is identical regardless of the underlying wire. Also covered with TCP and WebSocket variants — every connection-oriented bridge link now works via `Transport::connect_federate`.
- **Federation adversarial**: `drift/tests/adversarial_federation.rs` — pure in-process tests (~0.5 s) that lock in three defenses: (1) the bridge rejects envelopes whose `source_client_pub` doesn't match the session-authenticated sender (identity-spoofing prevention); (2) the bridge refuses to insert routing-table entries for `source_bridge_pub` claims that don't match the sender's own pubkey (table-poisoning prevention); (3) only federation peers (entries in our `federation_table`) may write to the peer directory (no random-client directory poisoning).
- **Federation directory semantics**: `drift/tests/federation_directory_semantics.rs` — three-Transport tests that lock in (1) first-write-wins on cross-announcer conflicts (kills race-to-hijack attacks where a malicious federated bridge tries to steal a pubkey from a legitimate announcer); (2) idempotent-set semantics on announcements (a bridge's announce is the complete current set of its clients, so disconnections propagate to peer directories in one announce interval rather than waiting out the TTL); (3) legitimate client migration is still allowed once the prior announcer cleanly retracts.
- **Federation presence tickets**: `drift/tests/adversarial_presence_tickets.rs` — five tests covering a malicious federated bridge attempting to announce a victim pubkey with (a) no ticket, (b) a forged ticket signed by the attacker, (c) a real ticket signed for a different bridge, (d) an expired ticket. Plus a sanity-counterpart test confirming legitimate tickets are accepted.
- **Federation triangle topology**: `drift-mosh/tests/federation_triangle_test.sh` (LXC) — three bridges fully federated in a triangle, every cross-bridge routing direction exercised. Caught the `federated_via` stale-path bug that was fixed in `handle_federated` case 1.
- **Tool-level**: drift-mosh's `smoke.exp` / `tcp_transport.exp` / `ws_transport.exp` / `reattach.exp`; drift-http's `serve_static.sh` / `serve_proxy.sh` / `open_url.sh` / `multi_transport_3way.sh` / `multi_transport_4way.sh` (4/4 transports including TLS pass)

```bash
cargo test                # full Rust suite
cargo bench               # throughput benchmarks (drift/benches)
cd drift-wasm-test && npm install && node test-mesh.mjs ...  # WASM↔native E2E
cargo test --features onion --release --test onion_self_dial -- --ignored --nocapture  # DRIFT over live Tor (~3 min)
```

## Performance

The headline cross-protocol numbers (DRIFT vs Iroh vs QUIC, 1024 B payload, loopback) live in the opening table. Methodology, raw results, and the four-way bench runner: [`drift-bench/RESULTS-2026-05-27.md`](drift-bench/RESULTS-2026-05-27.md) and [`drift-bench/scripts/run-local-four.sh`](drift-bench/scripts/run-local-four.sh).

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

Tagged releases of the user-facing tools fire a GitHub Actions matrix that builds platform-specific binaries:

- **`drift-vpn-vX.Y.Z`** → [`Release drift-vpn`](.github/workflows/release-drift-vpn.yml) → Linux amd64/arm64 + macOS arm64/x86_64 + Windows x86_64 (`keygen` / `show` only on Windows; daemon needs WSL2 today)
- **`drift-mosh-vX.Y.Z`** → [`Release drift-mosh`](.github/workflows/release-drift-mosh.yml) → macOS arm64/x86_64 + Linux amd64/arm64
- **`drift-http-vX.Y.Z`** → [`Release drift-http`](.github/workflows/release-drift-http.yml) → same matrix as drift-mosh

All artifacts land at [github.com/FancyWaifu/drift/releases](https://github.com/FancyWaifu/drift/releases).

```bash
TARGET=aarch64-apple-darwin   # pick yours
TAG=drift-vpn-v0.14.0
curl -L -o pkg.tar.gz \
  https://github.com/FancyWaifu/drift/releases/download/$TAG/drift-vpn-$TAG-$TARGET.tar.gz
tar xzf pkg.tar.gz
sudo mv drift-vpn-$TAG-$TARGET/drift-vpn /usr/local/bin/
```

## Inspiration

- **[Reticulum](https://reticulum.network/)** — identity-first addressing, always-encrypted, mesh architecture
- **[QUIC](https://www.rfc-editor.org/rfc/rfc9000)** — congestion control, streams, connection migration, short headers
- **[WireGuard](https://www.wireguard.com/)** — minimal crypto surface, small codebase

## License

MIT

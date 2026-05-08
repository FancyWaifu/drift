# drift-wasm-test

End-to-end verification that **the drift-wasm crate, compiled to
WebAssembly, interops with native DRIFT** — three scenarios:

* `test-wasm.mjs` — WASM client handshakes with a native DRIFT
  bridge over WebSocket and sends one encrypted DATA packet.
  Proves WASM↔server interop.
* `test-mesh.mjs` — WASM client connects to the bridge, then
  mesh-handshakes with a **UDP peer** that's also connected to
  the bridge. Sends a DATA packet addressed to that UDP peer.
  Proves **WASM → bridge → UDP peer** end-to-end with DRIFT's
  end-to-end crypto intact (the bridge never sees plaintext of
  the mesh message).
* `test-http.mjs` — WASM client handshakes with a native DRIFT
  bridge over **plain HTTP/1.1** — Server-Sent Events downstream,
  per-packet `fetch()` POST upstream. The fallback wire for
  middleboxes that strip WebSocket upgrades. Same drift-wasm
  bytes; just `http://` instead of `ws://`.

All three execute the *same* `drift-core` code compiled to
different targets. If the handshakes complete and the native
peers decrypt the DATA packets, the two are wire-compatible.

## Supported browser transports

drift-wasm ships three wire adapters, all pluggable into the
same `DriftClient`:

| Wire | `DriftClient` constructor | Best for |
|------|--------------------------|----------|
| **WebSocket** | `connectWebSocket(url, id, serverPubHex)` | Universal, works everywhere |
| **WebRTC data channel** | `connectWebRtc(dataChannel, id, peerPubHex)` | Browser↔browser, no server in data path |
| **WebTransport** | `connectWebTransport(url, id, serverPubHex)` | UDP-like datagrams, preserves DRIFT's deadline/coalesce semantics |

The Node-based test harness below only exercises the WebSocket
adapter (Node's WebSocket polyfill is easiest to wire). A real
browser harness would use any of the three.

## Prerequisites

```bash
# Rust target (one-time):
rustup target add wasm32-unknown-unknown

# Tool to build the wasm package (one-time):
cargo install wasm-pack

# The ws polyfill (one-time):
cd drift-wasm-test && npm install
```

## Build the WASM client

```bash
# From the repo root:
wasm-pack build drift-wasm --target nodejs --out-dir pkg-node
```

This produces `drift-wasm/pkg-node/drift_wasm.js` and the
companion `.wasm` that `test-wasm.mjs` loads.

## Run test-wasm (WASM → bridge)

```bash
# Terminal 1 — native DRIFT bridge with a WS listener.
# It prints its pubkey hex at startup — copy that.
cargo run -p drift --example drift-chat -- bridge
# [bridge] pubkey=6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b
# [bridge] WS listening on 127.0.0.1:9202
# ...

# Terminal 2 — the wasm client connects + handshakes + sends.
cd drift-wasm-test
node test-wasm.mjs ws://127.0.0.1:9202 <bridge-pub-hex>
```

## Run test-mesh (WASM → bridge → UDP peer)

```bash
# Terminal 1 — bridge
cargo run -p drift --example drift-chat -- bridge

# Terminal 2 — a native UDP peer at 127.0.0.1 (connected to the bridge).
cargo run -p drift --example drift-chat -- 127.0.0.1 --for 30

# Terminal 3 — wasm client mesh-handshakes with the UDP peer
# through the bridge and sends a DATA packet to it.
cd drift-wasm-test
node test-mesh.mjs ws://127.0.0.1:9202 <bridge-pub-hex>
```

Expected: the UDP peer's log shows
`RECV <- ?peer=XXXXXXXX: hello-from-wasm-through-bridge-to-udp-peer`
— the native UDP peer decrypted a payload sealed by the WASM,
which never spoke UDP and only ever sent bytes over its one
WebSocket to the bridge.

## Run test-http (WASM → bridge over plain HTTP/SSE)

The wire-of-last-resort: an `http://` listener handles
EventSource (server → client streaming) and `POST /drift-send`
(per-packet uplink). Survives anything that proxies HTTP at
all — corporate filters, captive portals, anywhere WebSocket
upgrades are stripped.

```bash
# Terminal 1 — bridge with an HTTP listener instead of WS.
# (drift-chat exposes whichever scheme its bridge mode selects;
# any drift binary that calls add_listener("http://...") works.)
cargo run -p drift --example drift-chat -- bridge

# Terminal 2 — wasm client over plain HTTP. Pulls in the
# `eventsource` npm polyfill since Node ships fetch() but not
# EventSource. (Browsers have both natively.)
cd drift-wasm-test
node test-http.mjs http://127.0.0.1:9205 <bridge-pub-hex>
```

Expected: bridge log shows `recv from peer=<wasm-id> 26B:
"hello from wasm over http!"`. The drift-wasm side calls the
exact same `DriftClient` API as the WS test — only the wire
adapter underneath changed.

Expected output:

```
[wasm-test] our peer_id: fcbf8135f51e0878
[wasm-test] connecting + handshaking...
DRIFT handshake complete (authenticated)      ← from inside the wasm
[wasm-test] handshake OK (server peer_id=31efc056aa97b8f8)
[wasm-test] sent: "hello from wasm!"
[wasm-test] done.
```

And on the bridge:

```
[bridge] WS iface 1 wired (peer 127.0.0.1:53731)
[bridge] recv from peer=fcbf8135 16B: "hello from wasm!"
```

The server-side log line is the proof: the native server
decrypted a DRIFT-encrypted payload that was sealed inside the
WASM. AEAD auth tag validated, session keys matched, wire
format interop confirmed.

## Why Node + polyfill instead of a browser?

The real deployment is browser-to-server (or browser-to-
browser). Browsers drive `web-sys::WebSocket` through their
native WebSocket implementation. Under Node, the `ws` npm
package emits browser-shaped `MessageEvent`s with `.data` being
an `ArrayBuffer`, which is exactly what the wasm-bindgen glue
wants. So the same `.wasm` that a browser would run also runs
here with a three-line polyfill — easier to exercise in CI.

A browser harness would swap `wasm-pack build --target nodejs`
for `wasm-pack build --target web` and load the output from an
`<script type="module">` in an HTML page. No other changes to
`drift-wasm` itself.

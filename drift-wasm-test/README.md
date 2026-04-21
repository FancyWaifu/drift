# drift-wasm-test

End-to-end verification that **the drift-wasm crate, compiled to
WebAssembly, can handshake and exchange encrypted data with a
native DRIFT server** — by running the WASM under Node with a
WebSocket polyfill and pointing it at a live `drift-chat bridge`.

Both sides execute the *same* `drift-core` code compiled to
different targets. If the handshake completes and the native
server decrypts a DATA packet from the WASM client, the two
are genuinely wire-compatible.

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

## Run the end-to-end test

```bash
# Terminal 1 — native DRIFT bridge with a WS listener.
# It prints its pubkey hex at startup — copy that.
cargo run -p drift --example drift-chat -- bridge
# [bridge] pubkey=6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b
# [bridge] WS listening on 127.0.0.1:9202
# ...

# Terminal 2 — the wasm client connects + handshakes + sends.
cd drift-wasm-test
node test-wasm.mjs ws://127.0.0.1:9202 6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b
```

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

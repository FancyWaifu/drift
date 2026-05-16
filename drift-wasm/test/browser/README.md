# drift-wasm browser harness

End-to-end Playwright tests that load the same `drift-wasm` bundle a
real browser ships, point it at a fresh `drift bridge` subprocess on
ephemeral ports, and run each WASM adapter through a real DRIFT
handshake. Each spec is one wire — no mocks, no stubs.

## What runs

| Spec | Adapter | Chromium | Firefox | WebKit |
|---|---|---|---|---|
| `tests/ws.spec.ts` | `connectWebSocket` | ✓ | ✓ | ✓ |
| `tests/http.spec.ts` | `connectHttp` (SSE + POST) | ✓ | ✓ | ✓ |
| `tests/webtransport.spec.ts` | `connectWebTransport` | ✓ | skip | skip |
| `tests/webrtc.spec.ts` | `connectWebRtc` (WS sig → DTLS) | ✓ | skip | skip |
| `tests/ws_stream.spec.ts` | `connectWebSocketStream` | live-skip | skip | skip |

`webtransport` runs against a native `webtransport://` listener
(`drift/src/wire_webtransport.rs`) that generates an ephemeral
ECDSA-P256 self-signed cert at bind time and prints its SHA-256
digest to STDERR — the harness captures the digest and the browser
pins it via `serverCertificateHashes`. Chromium-only; Firefox shipped
WebTransport in 114 but it's still gated, WebKit hasn't implemented it.

`ws_stream` soft-skips in headless Chromium because `WebSocketStream` is
still gated behind an Origin Trial and its `opened` promise never
resolves there — the test races a 4s timeout and reports the skip.
Run against full Chrome to actually exercise the adapter.

`webrtc` runs against a native `webrtc://` listener
(`drift/src/wire_webrtc.rs`) that exposes a tiny WebSocket
signaling endpoint on the bound port. The browser opens the
WS, receives the SDP offer, replies with an answer, and the
data channel opens once ICE/DTLS converges. From that point
DRIFT runs over the channel like any other adapter. STUN
(`stun.l.google.com:19302`) is included in the server's
RTCConfiguration to unblock ICE on macOS loopback paths.

Browser↔browser WebRTC (P2P, no server in the data path) is
a future feature — the WASM `Session` is currently strictly
client-side. The `webrtc://` listener gives browsers a
straightforward path to dial native bridges over WebRTC,
which is the common case.

## Running

```sh
cd drift-wasm/test/browser
npm install
npx playwright install chromium firefox webkit
npm test
```

The harness auto-rebuilds `pkg-web` and `target/release/drift` if
either is missing or older than its source. First run takes minutes;
subsequent runs ~10s for the whole suite.

## How it's wired up

`fixtures/global-setup.ts` runs once before the suite:

1. `wasm-pack build --target web` if `pkg-web/` is stale.
2. `cargo build --release -p drift` if the binary is stale relative
   to `drift/src/cli/bridge.rs`.
3. Picks ephemeral ports for UDP, TCP, WS, HTTP listeners.
4. Spawns `drift bridge --listen udp://... --listen tcp://... ...`,
   parses its STDERR banner for the pubkey.
5. Spawns a tiny static-file HTTP server inline (same Node process)
   that serves `index.html` and the `pkg-web/` bundle.
6. Writes the bridge pubkey + URLs to a tmpfile JSON state. Tests
   read it via `loadHarness()`.

`fixtures/global-teardown.ts` SIGTERMs the bridge.

Tests `page.goto("/")`, wait for `window.driftReady`, then drive the
WASM API via `page.evaluate(...)`. Cross-browser assertions stay in
TS land; only the actual adapter call runs in the browser.

## Why this exists

The native test suite proves the protocol works. Node-hosted WASM
tests prove the WASM build's API shape works. Neither catches
browser-specific regressions: a `web-sys` ABI mismatch, a CORS
preflight that headless allows but real Chrome blocks, a
`ReadableStream` quirk in WebKit, a polyfill drift after a wasm-bindgen
bump. This harness is the layer that catches those.

// WASM-on-Node network test: WebSocket client → native bridge.
//
// Loads the same browser-side `DriftClient` that runs in
// browsers, but hosted by Node 22's built-in `WebSocket` global.
// This proves the WASM `ws://` adapter wire-interops with the
// native `wire_ws` listener — i.e., a browser DRIFT client could
// dial the bridge over the same socket the way we just did from
// Node.
//
// Usage:
//   BRIDGE_URL=ws://192.0.2.1:51821 \
//   BRIDGE_PUB=<64-hex> \
//   node drift-wasm/test/network-ws-node.js
//
// Both env vars default to the home-router bridge if unset.

const path = require("path");
const wasm = require(path.join(__dirname, "..", "pkg-node"));

const BRIDGE_URL = process.env.BRIDGE_URL || "ws://192.0.2.1:51821";
const BRIDGE_PUB = process.env.BRIDGE_PUB ||
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Node 22+ exposes `WebSocket` as a global, which is what
// wasm-bindgen's `web_sys::WebSocket` shim looks for. Assert
// before we even try — fail-fast with a clear message.
if (typeof WebSocket !== "function") {
  console.error("✗ Node WebSocket global is not defined. Need Node 22+.");
  process.exit(1);
}
console.log(`✓ Node WebSocket global is available (type: ${typeof WebSocket})`);

(async () => {
  console.log(`\nDialing bridge:  ${BRIDGE_URL}`);
  console.log(`Bridge pubkey:   ${BRIDGE_PUB.slice(0, 16)}…${BRIDGE_PUB.slice(-8)}`);

  const id = wasm.DriftIdentity.generate();
  console.log(`Our pubkey:      ${id.publicKeyHex().slice(0, 16)}…${id.publicKeyHex().slice(-8)}`);
  console.log(`Our peerId:      ${id.peerIdHex()}`);

  const t0 = Date.now();
  let client;
  try {
    client = await Promise.race([
      wasm.DriftClient.connect(BRIDGE_URL, id, BRIDGE_PUB),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("connect timeout (10s)")), 10_000)
      ),
    ]);
  } catch (e) {
    console.error(`\n✗ DriftClient.connect failed: ${e.message || e}`);
    process.exit(1);
  }
  const dt = Date.now() - t0;
  console.log(`\n✓ Session established in ${dt}ms`);
  console.log(`  WASM ↔ native ws://${BRIDGE_URL.replace('ws://','')} handshake complete`);

  // Clean shutdown.
  try {
    client.close();
    console.log("✓ Session closed cleanly");
  } catch (e) {
    console.error(`✗ close() threw: ${e.message || e}`);
    process.exit(1);
  }

  console.log("\nWASM-on-Node ↔ native bridge over WebSocket: PASS");
  process.exit(0);
})();

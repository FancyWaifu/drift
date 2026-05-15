// WASM-on-Node network test: HTTP/SSE client → native bridge.
//
// Mirrors network-ws-node.js but uses `DriftClient.connectHttp`
// — the same code path a browser uses when WebSocket upgrades
// get blocked by a captive portal or hostile proxy.
//
// Usage:
//   node --experimental-eventsource drift-wasm/test/network-http-node.js
//
// (Node 22 hides EventSource behind --experimental-eventsource;
//  Node 23+ has it as a global. Either way the WASM module's
//  web_sys::EventSource shim resolves to it.)

const path = require("path");
const wasm = require(path.join(__dirname, "..", "pkg-node"));

const BRIDGE_URL = process.env.BRIDGE_URL || "http://192.168.50.1:51823";
const BRIDGE_PUB = process.env.BRIDGE_PUB ||
  "426b136d6f8ce128a4b632f8c2bc979a458ab4776ba2bd9f9ba9a1e724bfc025";

if (typeof EventSource !== "function") {
  console.error(
    "✗ Node EventSource global is not defined. Run with " +
    "`node --experimental-eventsource ...` on Node 22, or use Node 23+."
  );
  process.exit(1);
}
if (typeof fetch !== "function") {
  console.error("✗ Node fetch global is not defined. Need Node 18+.");
  process.exit(1);
}
console.log("✓ Node globals available (EventSource + fetch)");

(async () => {
  console.log(`\nDialing bridge:  ${BRIDGE_URL}`);
  console.log(`Bridge pubkey:   ${BRIDGE_PUB.slice(0, 16)}…${BRIDGE_PUB.slice(-8)}`);

  const id = wasm.DriftIdentity.generate();
  console.log(`Our pubkey:      ${id.publicKeyHex().slice(0, 16)}…${id.publicKeyHex().slice(-8)}`);

  const t0 = Date.now();
  let client;
  try {
    client = await Promise.race([
      wasm.DriftClient.connectHttp(BRIDGE_URL, id, BRIDGE_PUB),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("connectHttp timeout (10s)")), 10_000)
      ),
    ]);
  } catch (e) {
    console.error(`\n✗ DriftClient.connectHttp failed: ${e.message || e}`);
    process.exit(1);
  }
  const dt = Date.now() - t0;
  console.log(`\n✓ Session established in ${dt}ms`);
  console.log(`  WASM ↔ native http://${BRIDGE_URL.replace('http://','')} handshake complete`);

  try {
    client.close();
    console.log("✓ Session closed cleanly");
  } catch (e) {
    console.error(`✗ close() threw: ${e.message || e}`);
    process.exit(1);
  }

  console.log("\nWASM-on-Node ↔ native bridge over HTTP/SSE: PASS");
  process.exit(0);
})();

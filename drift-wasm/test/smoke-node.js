// Node.js smoke test for drift-wasm's public API.
//
// Exercises the surface that browser apps would use — generates
// identities, round-trips secret/public/peer-id hex, and confirms
// derivePeerId() agrees with what DriftIdentity reports. No
// network, no transport — pure crypto + serialization correctness.
//
// Run via: node drift-wasm/test/smoke-node.js
// Requires: drift-wasm/pkg-node built first (wasm-pack build
//           --target nodejs --out-dir pkg-node).

const path = require("path");
const wasm = require(path.join(__dirname, "..", "pkg-node"));

let pass = 0;
let fail = 0;

function check(label, cond, detail) {
  if (cond) {
    console.log(`  ✓ ${label}`);
    pass++;
  } else {
    console.log(`  ✗ ${label}` + (detail ? ` — ${detail}` : ""));
    fail++;
  }
}

// 1. Generate a fresh identity. The constructor should not panic
//    and the derived fields should be self-consistent.
console.log("[1] DriftIdentity.generate()");
const id = wasm.DriftIdentity.generate();
check("publicKeyHex is 64 hex chars", /^[0-9a-f]{64}$/.test(id.publicKeyHex()));
check("secretHex is 64 hex chars",     /^[0-9a-f]{64}$/.test(id.secretHex()));
check("peerIdHex is 16 hex chars (8 bytes)", /^[0-9a-f]{16}$/.test(id.peerIdHex()));
check("publicKeyBytes is 32 bytes", id.publicKeyBytes().length === 32);
check("peerIdBytes is 8 bytes",     id.peerIdBytes().length === 8);

// 2. Round-trip: build a second identity from the first's secret
//    and verify pub + peer-id match.
console.log("\n[2] DriftIdentity round-trip (fromSecretHex)");
const secret = id.secretHex();
const id2 = wasm.DriftIdentity.fromSecretHex(secret);
check("publicKey matches after round-trip",  id2.publicKeyHex() === id.publicKeyHex());
check("peerId matches after round-trip",     id2.peerIdHex()    === id.peerIdHex());

// 3. derivePeerId() agrees with DriftIdentity.peerIdHex().
console.log("\n[3] derivePeerId() consistency");
const derived = wasm.derivePeerId(id.publicKeyHex());
check("derivePeerId matches peerIdHex",  derived === id.peerIdHex());

// 4. Distinct identities produce distinct pubkeys + peer IDs.
console.log("\n[4] distinct identities are distinct");
const other = wasm.DriftIdentity.generate();
check("fresh generate gives different pubkey", other.publicKeyHex() !== id.publicKeyHex());
check("fresh generate gives different peerId", other.peerIdHex()    !== id.peerIdHex());

// 5. fromSecretHex rejects invalid hex.
console.log("\n[5] fromSecretHex input validation");
let threw = false;
try { wasm.DriftIdentity.fromSecretHex("not-hex"); } catch (_) { threw = true; }
check("fromSecretHex rejects non-hex input", threw);

threw = false;
try { wasm.DriftIdentity.fromSecretHex("ab".repeat(31)); } catch (_) { threw = true; }
check("fromSecretHex rejects wrong-length input", threw);

// 6. DriftClient class is exported (just check it exists — full
//    network exercise is out of scope for a Node smoke test).
console.log("\n[6] DriftClient export surface");
check("DriftClient is a function/class", typeof wasm.DriftClient === "function");

console.log(`\n  ${pass} passed · ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);

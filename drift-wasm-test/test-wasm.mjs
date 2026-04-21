// End-to-end test: the drift-wasm client (compiled to WASM from
// drift-core) handshaking with a native DRIFT server over a
// WebSocket.
//
// This runs under Node rather than a browser. The drift-wasm
// crate imports `web_sys::WebSocket`, which calls `new
// WebSocket(url)` on the global — so we polyfill that global
// with the `ws` npm package. Same wire bytes either way; only
// the runtime differs.
//
// Usage:
//   node test-wasm.mjs <ws-url> <server-pub-hex>
// Example:
//   node test-wasm.mjs ws://127.0.0.1:9202 6b0b616d...

import { WebSocket as NodeWs } from 'ws';
import { createRequire } from 'node:module';

class BrowserLikeWS extends NodeWs {
    constructor(url, protocols) {
        super(url, protocols);
        this.binaryType = 'arraybuffer';
    }
}

globalThis.WebSocket = BrowserLikeWS;

// wasm-pack --target nodejs emits CommonJS; load with createRequire.
const require = createRequire(import.meta.url);
const { DriftIdentity, DriftClient } = require('../drift-wasm/pkg-node/drift_wasm.js');

const args = process.argv.slice(2);
const url = args[0] || 'ws://127.0.0.1:9202';
const serverPubHex = args[1];

if (!serverPubHex) {
    console.error('Usage: node test-wasm.mjs <ws-url> <server-pub-hex>');
    process.exit(2);
}

console.log(`[wasm-test] target: ${url}`);
console.log(`[wasm-test] server pub: ${serverPubHex.slice(0, 16)}...`);

// Generate a fresh identity inside the WASM.
const id = DriftIdentity.generate();
console.log(`[wasm-test] our peer_id: ${id.peerIdHex()}`);
console.log(`[wasm-test] our pub:     ${id.publicKeyHex().slice(0, 16)}...`);

try {
    console.log('[wasm-test] connecting + handshaking...');
    const client = await DriftClient.connect(url, id, serverPubHex);
    console.log(`[wasm-test] handshake OK (server peer_id=${client.serverPeerIdHex()})`);

    client.onMessage((data) => {
        console.log(`[wasm-test] recv: ${new TextDecoder().decode(data)}`);
    });

    const payload = new TextEncoder().encode('hello from wasm!');
    await client.send(payload);
    console.log('[wasm-test] sent: "hello from wasm!"');

    // Give the server time to decrypt + log our DATA.
    await new Promise((r) => setTimeout(r, 2500));

    client.close();
    console.log('[wasm-test] done.');
    process.exit(0);
} catch (err) {
    console.error(`[wasm-test] FAILED: ${err}`);
    process.exit(1);
}

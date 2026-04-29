// End-to-end test: drift-wasm client connecting to a native
// DRIFT server over plain HTTP/SSE.
//
// SSE is the downstream half (server → client) and per-packet
// fetch() POST is the uplink. Same drift-wasm bytes either way;
// the wire just changes from `ws://` to `http://`.
//
// Node 24 ships fetch() globally but not EventSource — polyfill
// it with the `eventsource` npm package.
//
// Usage:
//   node test-http.mjs <http-url> <server-pub-hex>
// Example:
//   node test-http.mjs http://127.0.0.1:9205 6b0b616d...

import { EventSource as NodeES } from 'eventsource';
import { createRequire } from 'node:module';

globalThis.EventSource = NodeES;

const require = createRequire(import.meta.url);
const { DriftIdentity, DriftClient } = require('../drift-wasm/pkg-node/drift_wasm.js');

const args = process.argv.slice(2);
const url = args[0] || 'http://127.0.0.1:9205';
const serverPubHex = args[1];

if (!serverPubHex) {
    console.error('Usage: node test-http.mjs <http-url> <server-pub-hex>');
    process.exit(2);
}

console.log(`[http-test] target: ${url}`);
console.log(`[http-test] server pub: ${serverPubHex.slice(0, 16)}...`);

const id = DriftIdentity.generate();
console.log(`[http-test] our peer_id: ${id.peerIdHex()}`);

try {
    console.log('[http-test] connecting + handshaking...');
    const client = await DriftClient.connectHttp(url, id, serverPubHex);
    console.log(`[http-test] handshake OK (server peer_id=${client.serverPeerIdHex()})`);

    const payload = new TextEncoder().encode('hello from wasm over http!');
    await client.send(payload);
    console.log('[http-test] sent: "hello from wasm over http!"');

    // Give the server time to decrypt + log.
    await new Promise((r) => setTimeout(r, 2500));

    client.close();
    console.log('[http-test] done.');
    process.exit(0);
} catch (err) {
    console.error(`[http-test] FAILED: ${err}`);
    process.exit(1);
}

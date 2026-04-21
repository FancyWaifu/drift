// End-to-end mesh test: WASM client → WebSocket → bridge → UDP peer.
//
// Proves that a browser-equivalent client can reach a native
// UDP DRIFT peer without speaking UDP itself. The bridge accepts
// all four mediums simultaneously and mesh-forwards by peer_id.
//
// Topology at runtime:
//
//   WASM (this process, WS)  ──┐
//                              │
//   UDP chat peer @127.0.0.1 ──┴── drift-chat bridge (native relay)
//
// The WASM client:
//   1. connects to the bridge over WebSocket
//   2. registers the UDP peer by pubkey (addPeer)
//   3. handshakes with the UDP peer through the bridge (mesh)
//   4. sends an AEAD-encrypted DATA packet to the UDP peer
//
// The UDP peer (a native `drift-chat 127.0.0.1` running in auto
// mode) will log the incoming message in its output: that's the
// proof the bridge did a WS→UDP medium translation with
// end-to-end DRIFT crypto intact.
//
// Usage:
//   node test-mesh.mjs <bridge-ws-url> <bridge-pub-hex> <udp-peer-pub-hex>

import { WebSocket as NodeWs } from 'ws';
import { createRequire } from 'node:module';

class BrowserLikeWS extends NodeWs {
    constructor(url, protocols) {
        super(url, protocols);
        this.binaryType = 'arraybuffer';
    }
}

globalThis.WebSocket = BrowserLikeWS;

const require = createRequire(import.meta.url);
const { DriftIdentity, DriftClient, derivePeerId } = require('../drift-wasm/pkg-node/drift_wasm.js');

const [bridgeUrl, bridgePubHex] = process.argv.slice(2);
if (!bridgeUrl || !bridgePubHex) {
    console.error('Usage: node test-mesh.mjs <bridge-ws-url> <bridge-pub-hex>');
    process.exit(2);
}

// drift-chat's native peer at 127.0.0.1 derives its identity from
// role=0xCC + "127.0.0.1" bytes. Recompute the same secret here
// so we can derive the peer's pubkey without any extra out-of-band
// step. This is demo-only — a real deployment would exchange
// pubkeys via a directory or signaling channel.
function chatSecretForIp(ip) {
    const seed = new Uint8Array(32);
    seed[0] = 0xCC;
    const bytes = new TextEncoder().encode(ip);
    for (let i = 0; i < Math.min(bytes.length, 30); i++) {
        seed[i + 1] = bytes[i];
    }
    return Array.from(seed).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const UDP_PEER_IP = '127.0.0.1';
const udpPeerIdentity = DriftIdentity.fromSecretHex(chatSecretForIp(UDP_PEER_IP));
const udpPeerPubHex = udpPeerIdentity.publicKeyHex();
const udpPeerIdHex = derivePeerId(udpPeerPubHex);

console.log(`[mesh-test] bridge: ${bridgeUrl}`);
console.log(`[mesh-test] bridge pub:   ${bridgePubHex.slice(0, 16)}...`);
console.log(`[mesh-test] UDP peer pub: ${udpPeerPubHex.slice(0, 16)}...`);
console.log(`[mesh-test] UDP peer pid: ${udpPeerIdHex}`);

const id = DriftIdentity.generate();
console.log(`[mesh-test] our peer_id:  ${id.peerIdHex()}`);

try {
    console.log('[mesh-test] connecting to bridge + handshaking...');
    const client = await DriftClient.connect(bridgeUrl, id, bridgePubHex);
    console.log(`[mesh-test] bridge session OK (bridge_pid=${client.serverPeerIdHex()})`);

    client.onMessage((srcHex, data) => {
        console.log(`[mesh-test] recv from ${srcHex}: ${new TextDecoder().decode(data)}`);
    });

    console.log('[mesh-test] adding UDP peer + handshaking through bridge...');
    const addedPid = await client.addPeer(udpPeerPubHex);
    console.log(`[mesh-test] UDP peer session OK (pid=${addedPid})`);

    const msg = `hello-from-wasm-through-bridge-to-udp-peer`;
    const payload = new TextEncoder().encode(msg);
    await client.sendToPeer(udpPeerIdHex, payload);
    console.log(`[mesh-test] sent to UDP peer: "${msg}"`);

    // Give the bridge + UDP peer time to forward/receive/log.
    await new Promise((r) => setTimeout(r, 2500));

    client.close();
    console.log('[mesh-test] done.');
    process.exit(0);
} catch (err) {
    console.error(`[mesh-test] FAILED: ${err}`);
    process.exit(1);
}

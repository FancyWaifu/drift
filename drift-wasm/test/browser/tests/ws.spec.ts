// First-light browser test: WASM `ws://` adapter end-to-end
// against the native `wire_ws` listener inside the harness's
// drift bridge subprocess.
//
// What we prove:
//   1. The pkg-web bundle loads inside the browser and the
//      WASM init succeeds.
//   2. `DriftIdentity.generate()` returns a usable identity
//      (no init order bugs).
//   3. `DriftClient.connectWebSocket(...)` completes the DRIFT
//      handshake (HELLO/SERVER_HELLO + key derivation) over a
//      live WebSocket to the native bridge.
//   4. `client.close()` is idempotent and doesn't throw.
//
// Coverage: chromium + firefox + webkit (all expose `WebSocket`).

import { test, expect } from "@playwright/test";
import { loadHarness } from "../fixtures/harness.js";

test.describe("ws:// WASM adapter ↔ native bridge", () => {
  test("handshake completes and close is idempotent", async ({ page }) => {
    const harness = loadHarness();

    // Surface page-side console output to test stdout for debugging.
    page.on("console", (msg) => {
      console.log(`[page:${msg.type()}] ${msg.text()}`);
    });
    page.on("pageerror", (err) => {
      console.log(`[page:error] ${err.message}`);
    });

    await page.goto("/");
    // Wait for the module-script bootstrap to flip `driftReady`.
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    const result = await page.evaluate(
      async ({ wsUrl, bridgePubHex }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const t0 = performance.now();
        const client = await w.DriftClient.connectWebSocket(
          wsUrl,
          id,
          bridgePubHex,
        );
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        // Idempotent close.
        client.close();
        client.close();
        return {
          ok: true,
          handshakeMs,
          serverPeerIdHex,
          myPubHex: id.publicKeyHex(),
          myPeerIdHex: id.peerIdHex(),
        };
      },
      { wsUrl: harness.bridgeWsUrl, bridgePubHex: harness.bridgePubHex },
    );

    expect(result.ok).toBe(true);
    expect(result.handshakeMs).toBeLessThan(5_000);
    expect(result.serverPeerIdHex).toMatch(/^[0-9a-f]{16}$/);
    expect(result.myPubHex).toMatch(/^[0-9a-f]{64}$/);
    expect(result.myPeerIdHex).toMatch(/^[0-9a-f]{16}$/);
    // Cross-check: the bridge's pubkey hashes to its peer ID,
    // which must match what the client extracts from the live
    // session.
    const expectedPeerIdHex = await page.evaluate(
      (pubHex) => (window as any).derivePeerId(pubHex),
      harness.bridgePubHex,
    );
    expect(result.serverPeerIdHex).toBe(expectedPeerIdHex);
  });
});

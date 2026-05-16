// HTTP/SSE WASM adapter end-to-end against the native `wire_http`
// listener. Same harness, different transport:
//   - downstream: `GET /drift-sse`, one SSE event per DRIFT packet
//   - uplink:     one `POST /drift-send` per packet
//
// Universal-support story: works in any browser with `fetch` +
// `ReadableStream` (so chromium, firefox, webkit all qualify).
// This is the corporate-proxy fallback wire — proves DRIFT will
// get through anything that proxies plain HTTP at all.

import { test, expect } from "@playwright/test";
import { loadHarness } from "../fixtures/harness.js";

test.describe("http:// WASM adapter ↔ native bridge", () => {
  test("SSE downstream + POST uplink complete a handshake", async ({ page }) => {
    const harness = loadHarness();

    page.on("console", (m) => console.log(`[page:${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`[page:error] ${e.message}`));

    await page.goto("/");
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    const result = await page.evaluate(
      async ({ httpUrl, bridgePubHex }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const t0 = performance.now();
        const client = await w.DriftClient.connectHttp(
          httpUrl,
          id,
          bridgePubHex,
        );
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        client.close();
        return { ok: true, handshakeMs, serverPeerIdHex };
      },
      { httpUrl: harness.bridgeHttpUrl, bridgePubHex: harness.bridgePubHex },
    );

    expect(result.ok).toBe(true);
    // HTTP/SSE is slower than ws — bump ceiling but still bound it.
    expect(result.handshakeMs).toBeLessThan(8_000);
    expect(result.serverPeerIdHex).toMatch(/^[0-9a-f]{16}$/);

    const expectedPeerIdHex = await page.evaluate(
      (pubHex) => (window as any).derivePeerId(pubHex),
      harness.bridgePubHex,
    );
    expect(result.serverPeerIdHex).toBe(expectedPeerIdHex);
  });
});

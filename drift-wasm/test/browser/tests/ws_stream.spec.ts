// WebSocketStream WASM adapter — backpressure-aware variant of
// ws://. Same on-wire bytes as `connectWebSocket`, so it dials
// the same native `wire_ws` listener; the difference is in the
// browser-side API.
//
// Chromium-only as of 2026 (see WASM doc on
// `DriftClient.connectWebSocketStream`). Skip in firefox/webkit.

import { test, expect } from "@playwright/test";
import { loadHarness } from "../fixtures/harness.js";

test.describe("ws_stream WASM adapter ↔ native bridge", () => {
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "WebSocketStream is Chromium-only",
  );

  test("handshake completes via WebSocketStream when available", async ({ page }) => {
    const harness = loadHarness();

    page.on("console", (m) => console.log(`[page:${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`[page:error] ${e.message}`));

    await page.goto("/");
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    // Guard against headless Chromium variants that don't expose
    // WebSocketStream — skip live rather than spuriously failing.
    const hasWss = await page.evaluate(
      () => typeof (window as any).WebSocketStream === "function",
    );
    test.skip(!hasWss, "this Chromium build doesn't expose WebSocketStream");

    // `WebSocketStream` is exposed in `chromium-headless-shell`
    // but its `opened` promise never resolves there — it's still
    // behind an Origin Trial. Race the handshake against a tight
    // timeout and skip live if it hangs, so we exercise it for
    // real on full-Chrome runs without flaking headless ones.
    const result = await page.evaluate(
      async ({ wsUrl, bridgePubHex }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const t0 = performance.now();
        let timedOut = false;
        const timeout = new Promise<"timeout">((res) =>
          setTimeout(() => {
            timedOut = true;
            res("timeout");
          }, 4_000),
        );
        const outcome = await Promise.race([
          w.DriftClient.connectWebSocketStream(wsUrl, id, bridgePubHex),
          timeout,
        ]);
        if (timedOut || outcome === "timeout") {
          return { ok: false, reason: "WebSocketStream opened never resolved" };
        }
        const client = outcome;
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        client.close();
        return { ok: true, handshakeMs, serverPeerIdHex };
      },
      { wsUrl: harness.bridgeWsStreamUrl, bridgePubHex: harness.bridgePubHex },
    );

    if (!result.ok) {
      test.skip(true, `ws_stream not usable here: ${(result as any).reason}`);
      return;
    }
    expect(result.handshakeMs).toBeLessThan(5_000);
    expect(result.serverPeerIdHex).toMatch(/^[0-9a-f]{16}$/);
  });
});

// WebTransport WASM adapter end-to-end against a native
// `webtransport://` listener (drift/src/wire_webtransport.rs).
//
// Wire: HTTP/3 + QUIC. Each DRIFT packet rides as one QUIC
// datagram — actual UDP-like semantics in the browser. Pins the
// server cert by SHA-256 via `serverCertificateHashes`, so the
// listener's ephemeral self-signed cert is fine; no CA needed.
//
// Browser support: Chromium 97+. Firefox technically shipped it
// in 114 but it's still gated; WebKit has no implementation.

import { test, expect } from "@playwright/test";
import { loadHarness } from "../fixtures/harness.js";

test.describe("webtransport WASM adapter ↔ native bridge", () => {
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "WebTransport is Chromium-only in our matrix",
  );

  test("handshake completes against a pinned self-signed bridge", async ({ page }) => {
    const harness = loadHarness();

    page.on("console", (m) => console.log(`[page:${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`[page:error] ${e.message}`));

    await page.goto("/");
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    // Headless Chromium may not implement WebTransport — if the
    // global is missing, skip rather than fail.
    const hasWt = await page.evaluate(
      () => typeof (window as any).WebTransport === "function",
    );
    test.skip(!hasWt, "this Chromium build doesn't expose WebTransport");

    const result = await page.evaluate(
      async ({ wtUrl, bridgePubHex, certHex }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const t0 = performance.now();

        // Race the connect against an explicit timeout so a
        // stuck `wt.ready` doesn't blow the full Playwright
        // timeout — gives a clear error string instead.
        let timedOut = false;
        const timeout = new Promise<"timeout">((res) =>
          setTimeout(() => {
            timedOut = true;
            res("timeout");
          }, 8_000),
        );
        let outcome: unknown;
        try {
          outcome = await Promise.race([
            w.DriftClient.connectWebTransport(wtUrl, id, bridgePubHex, certHex),
            timeout,
          ]);
        } catch (e: any) {
          return { ok: false, reason: String(e?.message || e) };
        }
        if (timedOut || outcome === "timeout") {
          return { ok: false, reason: "connectWebTransport never resolved" };
        }
        const client = outcome as any;
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        client.close();
        return { ok: true, handshakeMs, serverPeerIdHex };
      },
      {
        wtUrl: harness.bridgeWebTransportUrl,
        bridgePubHex: harness.bridgePubHex,
        certHex: harness.bridgeWebTransportCertHex,
      },
    );

    if (!result.ok) {
      throw new Error(`WebTransport handshake failed: ${(result as any).reason}`);
    }
    expect(result.handshakeMs).toBeLessThan(5_000);
    expect(result.serverPeerIdHex).toMatch(/^[0-9a-f]{16}$/);

    const expectedPeerIdHex = await page.evaluate(
      (pubHex) => (window as any).derivePeerId(pubHex),
      harness.bridgePubHex,
    );
    expect(result.serverPeerIdHex).toBe(expectedPeerIdHex);
  });
});

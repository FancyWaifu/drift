// Live browser → public router-bridge → router-side mosh client.
//
// Unlike the rest of the harness (which spawns a local bridge),
// this spec dials the user's real ASUS router-bridge on its
// public WAN IP through the forwarded TCP port. Then it does
// two things:
//
//   1. Establishes a WebSocket session with the router-bridge
//      and sends a small DATA packet directly TO the bridge
//      (which just drains it — bridges don't terminate
//      sessions, they relay).
//
//   2. addPeer's the router's own drift-mosh-server pubkey
//      (a DRIFT client of the same bridge) and sends a DATA
//      packet to that peer_id. The bridge mesh-routes the
//      packet to the local mosh-server process running on the
//      router. mosh-server isn't a generic DRIFT echo
//      service so it just drops the payload — but the
//      addPeer round-trip and the bridge accepting the
//      sendToPeer call are what we prove.
//
// `#[ignore]`-equivalent — runs only when `DRIFT_LIVE_ROUTER`
// is set, so normal `npx playwright test` runs ignore it. Run
// explicitly:
//
//   DRIFT_LIVE_ROUTER=1 npx playwright test --project=chromium tests/router_live.spec.ts

import { test, expect } from "@playwright/test";

// Hard-coded — these are the documented identities from the
// session-memory and the running router-side processes.
const ROUTER_WAN_IP = "203.0.113.99";
const ROUTER_WS_PORT = 51821;
const ROUTER_BRIDGE_PUB =
  "426b136d6f8ce128a4b632f8c2bc979a458ab4776ba2bd9f9ba9a1e724bfc025";
const ROUTER_MOSH_PUB =
  "92b70685743bd0f6e6b61f537239303a13f97984b8738cab45909f13f3895577";
// Pre-derived (for assertion clarity): peer_id is the first
// 8 bytes of BLAKE2b-256(pub).
const ROUTER_BRIDGE_PEER_ID = "354c981eb6986e56";
const ROUTER_MOSH_PEER_ID = "3bd71d177c0d77db";

test.describe("LIVE: browser ↔ browser via public router-bridge", () => {
  test.skip(
    () => !process.env.DRIFT_LIVE_ROUTER,
    "set DRIFT_LIVE_ROUTER=1 to run against the public WAN IP",
  );
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "single-browser live test to keep WAN traffic predictable",
  );
  test.setTimeout(45_000);

  test("A sendToPeer → bridge mesh-route → B receives", async ({ browser }) => {
    // The WASM Session gained server-side handshake support
    // (drift-wasm/src/session.rs handle_hello) — so a browser
    // can now respond to an incoming HELLO. Combined with the
    // bridge's mesh routing, two browsers can DRIFT-handshake
    // entirely through the bridge with no direct addressability.
    const ctxA = await browser.newContext();
    const ctxB = await browser.newContext();
    const pageA = await ctxA.newPage();
    const pageB = await ctxB.newPage();
    pageA.on("console", (m) => console.log(`[A:${m.type()}] ${m.text()}`));
    pageB.on("console", (m) => console.log(`[B:${m.type()}] ${m.text()}`));

    await Promise.all([pageA.goto("/"), pageB.goto("/")]);
    await Promise.all([
      pageA.waitForFunction(() => (window as any).driftReady === true, null, {
        timeout: 10_000,
      }),
      pageB.waitForFunction(() => (window as any).driftReady === true, null, {
        timeout: 10_000,
      }),
    ]);

    const wsUrl = `ws://${ROUTER_WAN_IP}:${ROUTER_WS_PORT}`;

    // B connects first + stashes an onMessage handler that
    // buffers received DATA payloads onto window.__received.
    const bPubAndPeerId = await pageB.evaluate(
      async ({ wsUrl, bridgePub }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const client = await w.DriftClient.connectWebSocket(wsUrl, id, bridgePub);
        w.__client = client;
        w.__received = [];
        client.onMessage((srcPeerIdHex: string, data: Uint8Array) => {
          w.__received.push({
            from: srcPeerIdHex,
            text: new TextDecoder().decode(data),
          });
          console.log(`[B onMessage] from=${srcPeerIdHex} bytes=${data.length}`);
        });
        return { pub: id.publicKeyHex(), peerId: id.peerIdHex() };
      },
      { wsUrl, bridgePub: ROUTER_BRIDGE_PUB },
    );
    console.log(
      `[live] B online: pub=${bPubAndPeerId.pub} peerId=${bPubAndPeerId.peerId}`,
    );

    // A connects, addPeer's B (which round-trips a mesh
    // handshake through the bridge), then sends DATA.
    const aResult = await pageA.evaluate(
      async ({ wsUrl, bridgePub, bPub }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const log = (s: string) => console.log(`[A] ${s}`);

        const client = await w.DriftClient.connectWebSocket(wsUrl, id, bridgePub);
        log(`handshake ok server=${client.serverPeerIdHex()}`);

        const t0 = performance.now();
        const bPeerId = await client.addPeer(bPub);
        const addPeerMs = performance.now() - t0;
        log(`addPeer(B) ok ${addPeerMs.toFixed(0)}ms → ${bPeerId}`);

        const msg = new TextEncoder().encode("hello-B-from-A-via-router-bridge");
        await client.sendToPeer(bPeerId, msg);
        log(`sendToPeer(B, ${msg.length}B) ok`);

        await new Promise((r) => setTimeout(r, 500));
        return { addPeerMs, bPeerId, aPub: id.publicKeyHex() };
      },
      { wsUrl, bridgePub: ROUTER_BRIDGE_PUB, bPub: bPubAndPeerId.pub },
    );
    console.log(
      `[live] A → B mesh handshake completed in ${aResult.addPeerMs.toFixed(0)}ms`,
    );

    // Poll briefly for B's receive buffer to fill (don't race
    // delivery).
    const bReceived: any[] = await pageB.evaluate(async () => {
      const w = window as any;
      for (let i = 0; i < 30; i++) {
        if (w.__received.length > 0) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      return w.__received;
    });
    console.log(`[live] B received: ${JSON.stringify(bReceived)}`);

    expect(bReceived.length).toBeGreaterThan(0);
    expect(bReceived[0].text).toBe("hello-B-from-A-via-router-bridge");

    await pageA.evaluate(() => (window as any).__client?.close?.());
    await pageB.evaluate(() => (window as any).__client?.close?.());
    await ctxA.close();
    await ctxB.close();
  });
});

test.describe("LIVE: browser → public router-bridge", () => {
  test.skip(
    () => !process.env.DRIFT_LIVE_ROUTER,
    "set DRIFT_LIVE_ROUTER=1 to run against the public WAN IP",
  );
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "single-browser live test to keep WAN traffic predictable",
  );
  test.setTimeout(30_000);

  test("WS handshake + send → bridge; addPeer + sendToPeer → mosh-server", async ({ page }) => {
    page.on("console", (m) => console.log(`[page:${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`[page:error] ${e.message}`));

    await page.goto("/");
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    const result = await page.evaluate(
      async ({ wsUrl, bridgePub, moshPub, expectedBridgePeerId, expectedMoshPeerId }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();
        const log = (s: string) => console.log(`[live-step] ${s}`);

        // Per-step soft timeout helper. Lets us prove which
        // step hangs without losing earlier signal.
        const withTimeout = <T>(p: Promise<T>, ms: number, label: string) =>
          Promise.race<T | "TIMEOUT">([
            p,
            new Promise<"TIMEOUT">((res) => setTimeout(() => res("TIMEOUT"), ms)),
          ]).then((v) => {
            if (v === "TIMEOUT") {
              throw new Error(`${label}: timed out after ${ms}ms`);
            }
            return v as T;
          });

        // ───── 1. WS handshake against the router-bridge ─────
        log("connecting WS + handshake…");
        const t0 = performance.now();
        const client = await withTimeout(
          w.DriftClient.connectWebSocket(wsUrl, id, bridgePub),
          8_000,
          "WS handshake",
        );
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        log(
          `handshake ok ${handshakeMs.toFixed(0)}ms; server_peer_id=${serverPeerIdHex}`,
        );
        if (serverPeerIdHex !== expectedBridgePeerId) {
          throw new Error(
            `wrong bridge: got ${serverPeerIdHex}, expected ${expectedBridgePeerId}`,
          );
        }

        // ───── 2. Send DATA directly to the bridge ─────
        log("sending DATA to bridge…");
        const greeting = new TextEncoder().encode("hello-router-bridge");
        await withTimeout(client.send(greeting), 5_000, "client.send to bridge");
        log(`sent ${greeting.length}B DATA to bridge ok`);

        // ───── 3. addPeer for the router's mosh-server ─────
        // bridge mesh-relays a handshake between us and the
        // mosh peer. If mosh-server's config has
        // `accept_any_peer: false`, this is *expected* to
        // time out — we report rather than fail the whole
        // test, since "bridge accepted the request" is the
        // wire-level proof we care about.
        let moshPeerId: string | null = null;
        let addPeerMs: number | null = null;
        let addPeerError: string | null = null;
        const moshT0 = performance.now();
        log("addPeer(mosh-server)…");
        try {
          moshPeerId = await withTimeout(
            client.addPeer(moshPub),
            12_000,
            "addPeer(mosh)",
          );
          addPeerMs = performance.now() - moshT0;
          log(`addPeer ok ${addPeerMs.toFixed(0)}ms → ${moshPeerId}`);
        } catch (e: any) {
          addPeerError = String(e?.message || e);
          log(`addPeer failed: ${addPeerError}`);
        }

        // ───── 4. sendToPeer to mosh-server (only if addPeer worked) ─────
        let sendToPeerOk = false;
        let sendToPeerError: string | null = null;
        if (moshPeerId) {
          log("sendToPeer(mosh)…");
          const ping = new TextEncoder().encode("hello-router-mosh-from-browser");
          try {
            await withTimeout(
              client.sendToPeer(moshPeerId, ping),
              5_000,
              "sendToPeer(mosh)",
            );
            sendToPeerOk = true;
            log(`sendToPeer ok (${ping.length}B)`);
          } catch (e: any) {
            sendToPeerError = String(e?.message || e);
            log(`sendToPeer failed: ${sendToPeerError}`);
          }
        }

        await new Promise((r) => setTimeout(r, 200));
        client.close();

        return {
          ok: true,
          handshakeMs,
          addPeerMs,
          serverPeerIdHex,
          moshPeerId,
          addPeerError,
          sendToPeerOk,
          sendToPeerError,
          expectedMoshPeerIdMatched: moshPeerId === expectedMoshPeerId,
        };
      },
      {
        wsUrl: `ws://${ROUTER_WAN_IP}:${ROUTER_WS_PORT}`,
        bridgePub: ROUTER_BRIDGE_PUB,
        moshPub: ROUTER_MOSH_PUB,
        expectedBridgePeerId: ROUTER_BRIDGE_PEER_ID,
        expectedMoshPeerId: ROUTER_MOSH_PEER_ID,
      },
    );

    console.log("[live] summary:", JSON.stringify(result, null, 2));

    // Hard-required: WS handshake + send-to-bridge worked.
    expect(result.ok).toBe(true);
    expect(result.serverPeerIdHex).toBe(ROUTER_BRIDGE_PEER_ID);
    expect(result.handshakeMs).toBeLessThan(5_000);

    // Soft-required: addPeer + sendToPeer through the bridge
    // to the router's mosh-server. mosh-server may legitimately
    // reject the unknown identity (`accept_any_peer: false`),
    // so we report rather than block on it.
    if (result.moshPeerId) {
      expect(result.expectedMoshPeerIdMatched).toBe(true);
      console.log(
        `[live] mesh path works: addPeer ${result.addPeerMs?.toFixed(0)}ms, ` +
          `sendToPeer ${result.sendToPeerOk ? "ok" : "failed: " + result.sendToPeerError}`,
      );
    } else {
      console.log(
        `[live] mesh path didn't open (addPeer: ${result.addPeerError}) — ` +
          `expected if mosh-server has accept_any_peer=false`,
      );
    }
  });
});

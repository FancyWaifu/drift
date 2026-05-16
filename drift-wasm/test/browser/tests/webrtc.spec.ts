// WebRTC WASM adapter ↔ native `webrtc://` listener.
//
// The browser opens a WebSocket to the signaling URL (the
// listener's bound port), receives an SDP offer, replies with
// an answer, waits for the data channel to fire ondatachannel
// + open, then hands the channel to
// `DriftClient.connectWebRtc` for the DRIFT handshake.
//
// What we prove:
//   1. The native `webrtc://` listener (drift/src/wire_webrtc.rs)
//      can negotiate ICE/DTLS with a real browser.
//   2. The WASM `connectWebRtc` API completes a DRIFT
//      handshake over the resulting data channel.
//   3. The session key derives correctly — i.e. AEAD-protected
//      DATA round-trips would work, but we settle for proving
//      `serverPeerIdHex()` matches `derivePeerId(bridgePub)`.
//
// Chromium-only — Firefox/WebKit RTCDataChannel timing
// behaviors differ enough that gating to one engine keeps the
// failure modes legible. Adapter coverage on those browsers
// remains via ws + http; webrtc is the most-NAT-friendly wire
// of the bunch, so Chrome coverage is the realistic floor.

import { test, expect } from "@playwright/test";
import { loadHarness } from "../fixtures/harness.js";

test.describe("webrtc WASM adapter ↔ native bridge", () => {
  test.skip(
    ({ browserName }) => browserName !== "chromium",
    "WebRTC test uses Chromium for predictable ICE timing",
  );

  // WebRTC handshake involves SDP exchange, ICE gathering,
  // DTLS, then DRIFT HELLO/ACK — meaningfully slower than ws
  // or http. Bump the per-test timeout above the global
  // default (15s in playwright.config.ts).
  test.setTimeout(45_000);

  test("SDP signaling → data channel → DRIFT handshake", async ({ page }) => {
    const harness = loadHarness();

    page.on("console", (m) => console.log(`[page:${m.type()}] ${m.text()}`));
    page.on("pageerror", (e) => console.log(`[page:error] ${e.message}`));

    await page.goto("/");
    await page.waitForFunction(() => (window as any).driftReady === true, null, {
      timeout: 10_000,
    });

    const result = await page.evaluate(
      async ({ signalingUrl, bridgePubHex }) => {
        const w = window as any;
        const id = w.DriftIdentity.generate();

        // Set up the WebRTC peer connection BEFORE opening the
        // signaling WebSocket — ondatachannel must be wired up
        // before setRemoteDescription, which is what causes the
        // server's data channel description to arrive.
        const pc = new RTCPeerConnection({ iceServers: [] });

        // Promise that resolves with the open data channel.
        const dcPromise = new Promise<RTCDataChannel>((resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error("data channel never opened (15s)")),
            15_000,
          );
          pc.ondatachannel = (ev) => {
            const dc = ev.channel;
            dc.binaryType = "arraybuffer";
            if (dc.readyState === "open") {
              clearTimeout(timer);
              resolve(dc);
              return;
            }
            dc.onopen = () => {
              clearTimeout(timer);
              resolve(dc);
            };
          };
        });

        const ws = new WebSocket(signalingUrl);
        await new Promise<void>((res, rej) => {
          ws.onopen = () => res();
          ws.onerror = () => rej(new Error("signaling ws error"));
        });

        // Receive offer.
        const offerMsg: { kind: string; sdp: string } = await new Promise(
          (res, rej) => {
            ws.onmessage = (ev) => {
              try {
                res(JSON.parse(ev.data as string));
              } catch (e) {
                rej(e);
              }
            };
            ws.onerror = () => rej(new Error("ws error before offer"));
          },
        );
        if (offerMsg.kind !== "offer") {
          throw new Error(`expected offer, got ${offerMsg.kind}`);
        }
        await pc.setRemoteDescription({ type: "offer", sdp: offerMsg.sdp });

        // Create + send answer. Wait for ICE gathering to
        // complete so the answer is "final" (no trickle ICE
        // wire protocol on our signaling channel).
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await new Promise<void>((res) => {
          if (pc.iceGatheringState === "complete") {
            res();
            return;
          }
          pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === "complete") res();
          };
        });
        const localDesc = pc.localDescription!;
        ws.send(JSON.stringify({ kind: "answer", sdp: localDesc.sdp }));

        // Wait for the data channel to open.
        const dc = await dcPromise;

        // DRIFT handshake.
        const t0 = performance.now();
        const client = await w.DriftClient.connectWebRtc(
          dc,
          id,
          bridgePubHex,
        );
        const handshakeMs = performance.now() - t0;
        const serverPeerIdHex = client.serverPeerIdHex();
        client.close();
        // Signaling WS is done now too.
        try {
          ws.close();
        } catch {}
        return { ok: true, handshakeMs, serverPeerIdHex };
      },
      {
        signalingUrl: harness.bridgeWebRtcSignalingUrl,
        bridgePubHex: harness.bridgePubHex,
      },
    );

    expect(result.ok).toBe(true);
    // WebRTC handshake (SDP + ICE + DTLS + data channel +
    // DRIFT HELLO/ACK) is slower than ws but should fit
    // well under 10s on loopback.
    expect(result.handshakeMs).toBeLessThan(10_000);
    expect(result.serverPeerIdHex).toMatch(/^[0-9a-f]{16}$/);

    const expectedPeerIdHex = await page.evaluate(
      (pubHex) => (window as any).derivePeerId(pubHex),
      harness.bridgePubHex,
    );
    expect(result.serverPeerIdHex).toBe(expectedPeerIdHex);
  });
});

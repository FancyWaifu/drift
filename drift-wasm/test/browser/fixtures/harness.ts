// Shared harness state — written by global-setup, read by tests.
//
// We can't use Playwright's fixtures for this because the bridge
// pubkey + ports are dynamic and discovered AT SETUP TIME from
// the bridge subprocess's stdout. globalSetup writes a JSON
// file; tests load it via `loadHarness()`.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

export interface HarnessState {
  bridgePubHex: string;       // 64-char hex
  bridgeWsUrl: string;        // ws://127.0.0.1:<port>
  bridgeWsStreamUrl: string;  // ws://127.0.0.1:<port>  — same wire, Chromium-only API
  bridgeHttpUrl: string;      // http://127.0.0.1:<port>
  bridgeUdpAddr: string;      // 127.0.0.1:<port>  — informational; browsers can't dial UDP
  bridgeTlsUrl: string;       // tls://127.0.0.1:<port>
  // WebTransport: the listener's HTTPS URL the browser dials,
  // plus the SHA-256 (hex) of the listener's self-signed cert.
  // The browser pins via `serverCertificateHashes`.
  bridgeWebTransportUrl: string;       // https://127.0.0.1:<port>
  bridgeWebTransportCertHex: string;   // 64 hex chars
  // WebRTC: the WS signaling URL the browser dials. The
  // `webrtc://` scheme is registered native-side
  // (drift/src/wire_webrtc.rs); on the wire the signaling step
  // is plain WebSocket carrying SDP, then the data plane lives
  // on the resulting RTCDataChannel.
  bridgeWebRtcSignalingUrl: string;    // ws://127.0.0.1:<port>
  bridgePid: number;
  staticServerUrl: string;    // http://127.0.0.1:<port>  for index.html
  staticServerPid: number;
  pkgWebDir: string;          // absolute path to the built pkg-web bundle
}

const HARNESS_FILE = join(tmpdir(), "drift-wasm-browser-harness.json");

export function saveHarness(s: HarnessState): void {
  writeFileSync(HARNESS_FILE, JSON.stringify(s, null, 2));
}

export function loadHarness(): HarnessState {
  return JSON.parse(readFileSync(HARNESS_FILE, "utf-8")) as HarnessState;
}

export function harnessFilePath(): string {
  return HARNESS_FILE;
}

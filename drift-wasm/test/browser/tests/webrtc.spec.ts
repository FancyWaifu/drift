// WebRTC WASM adapter — `DriftClient.connectWebRtc` takes an
// already-open `RTCDataChannel` and runs DRIFT on top.
//
// STUB — fixtures alone aren't enough; the underlying WASM and
// native code both have gaps that block end-to-end coverage:
//
//   - The WASM `Session` (drift-wasm/src/session.rs) is strictly
//     client-side: `Session::new` only registers a "server", and
//     `handle_incoming_bytes` only handles `HelloAck` / `Data`.
//     Two browsers both calling `connectWebRtc(channel, id, peer)`
//     would both send HELLO and both ignore each other's HELLO
//     as an unknown packet type — deadlock. To make browser↔
//     browser work, `Session` needs a server-handshake codepath
//     and a tie-breaker convention (e.g. lower pubkey initiates).
//
//   - There's no native WebRTC listener with signaling. Native
//     `WebRTCPacketIO` exists (drift/src/io.rs:459) but it wraps
//     an already-accepted RTCDataChannel — no accept loop, no
//     `scheme: "webrtc"` registration, no SDP/ICE coordination
//     surface. A real `wire_webrtc.rs` listener would need to
//     ride the existing ws bridge for signaling.
//
// Pick one of the two paths above before un-stubbing this spec.

import { test } from "@playwright/test";

test.describe("WebRTC WASM adapter (browser↔browser)", () => {
  test("end-to-end DRIFT over a real RTCDataChannel", async () => {
    test.skip(
      true,
      "TODO: scaffold offerer/answerer fixture; see file header for plan",
    );
  });
});

// Playwright globalTeardown — kills the bridge subprocess
// that globalSetup spawned. The static-file HTTP server runs
// inside the Playwright Node process and dies with it.

import { loadHarness } from "./harness.js";

export default async function globalTeardown(): Promise<void> {
  try {
    const state = loadHarness();
    try {
      process.kill(state.bridgePid, "SIGTERM");
      console.log(`[harness] sent SIGTERM to bridge pid ${state.bridgePid}`);
    } catch (e) {
      // Already dead — fine.
    }
    // Give it 1s to die, then SIGKILL.
    await new Promise((r) => setTimeout(r, 1_000));
    try {
      process.kill(state.bridgePid, "SIGKILL");
    } catch {
      /* ignore */
    }
  } catch (e) {
    console.warn("[harness] teardown: could not load harness state:", e);
  }
}

import { defineConfig, devices } from "@playwright/test";

// drift-wasm browser harness — runs WASM-side adapter tests
// against a native `drift bridge` subprocess.
//
// `globalSetup` (fixtures/global-setup.ts) is responsible for:
//   1. Running `wasm-pack build --target web` if pkg-web is stale.
//   2. Building the native drift binary if missing.
//   3. Spawning a fresh `drift bridge` subprocess on ephemeral
//      ports (one UDP, TCP, WS, TLS, HTTP listener) and writing
//      its identity pubkey to a JSON file that tests read.
//   4. Spawning a tiny static-file HTTP server for index.html +
//      the pkg-web bundle, on its own port.
// `globalTeardown` kills both subprocesses.
//
// Tests are pure browser-side: they `page.goto(harness URL)`,
// `page.evaluate(...)` to invoke the WASM API directly, and
// assert from the returned values.

export default defineConfig({
  testDir: "./tests",
  timeout: 15_000,
  fullyParallel: false,            // bridge subprocess is shared; serialize
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  retries: process.env.CI ? 1 : 0,

  globalSetup: "./fixtures/global-setup.ts",
  globalTeardown: "./fixtures/global-teardown.ts",

  use: {
    baseURL: process.env.HARNESS_URL ?? "http://127.0.0.1:51900",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  // Run every test against Chromium by default. WebKit + Firefox
  // are gated per-test (some adapters are Chromium-only, e.g.
  // `WebSocketStream` and `WebTransport` until Safari catches up).
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
});

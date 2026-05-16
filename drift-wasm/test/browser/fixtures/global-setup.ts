// Playwright globalSetup. Runs ONCE before all tests:
//
//   1. Ensure pkg-web is built (drift-wasm/pkg-web).
//   2. Ensure native drift binary is built
//      (target/release/drift).
//   3. Spawn `drift bridge` on ephemeral ports for UDP, TCP,
//      WS, TLS, HTTP. Capture its READY banner to extract pubkey.
//   4. Spawn a tiny static-file HTTP server to serve index.html
//      + the pkg-web bundle, on an ephemeral port.
//   5. Save state to a JSON file so per-test fixtures can read it.

import { spawn, spawnSync, ChildProcess } from "node:child_process";
import { createServer, AddressInfo } from "node:net";
import { existsSync, mkdirSync, statSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { saveHarness, HarnessState } from "./harness.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROWSER_DIR = resolve(HERE, "..");           // drift-wasm/test/browser
const DRIFT_WASM_DIR = resolve(BROWSER_DIR, "..", ".."); // drift-wasm
const WORKSPACE = resolve(DRIFT_WASM_DIR, "..");        // repo root

/** Find an unused TCP port by binding 0 and reading back. */
async function pickPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

/** Build pkg-web if missing or older than the source. */
function ensurePkgWeb(): string {
  const pkg = join(DRIFT_WASM_DIR, "pkg-web");
  const wasmFile = join(pkg, "drift_wasm_bg.wasm");
  if (existsSync(wasmFile)) {
    // Cheap check: if the source dir was modified after the wasm,
    // rebuild.
    const wasmMtime = statSync(wasmFile).mtimeMs;
    const srcMtime = statSync(join(DRIFT_WASM_DIR, "src", "lib.rs")).mtimeMs;
    if (wasmMtime >= srcMtime) return pkg;
  }
  console.log("[harness] building pkg-web via wasm-pack…");
  const r = spawnSync(
    "wasm-pack",
    ["build", "--release", "--target", "web", "--out-dir", "pkg-web"],
    { cwd: DRIFT_WASM_DIR, stdio: "inherit" }
  );
  if (r.status !== 0) {
    throw new Error("wasm-pack build failed");
  }
  return pkg;
}

/** Build the native drift binary if missing, or stale relative
 *  to the CLI source. Cheap check: if drift/src/cli/bridge.rs is
 *  newer than the binary, rebuild — that's the file most likely
 *  to gate test behavior (the bridge subcommand wasn't always
 *  in `--help`). */
function ensureDriftBinary(): string {
  const bin = join(WORKSPACE, "target", "release", "drift");
  const bridgeSrc = join(WORKSPACE, "drift", "src", "cli", "bridge.rs");
  let needsBuild = !existsSync(bin);
  if (!needsBuild && existsSync(bridgeSrc)) {
    needsBuild = statSync(bridgeSrc).mtimeMs > statSync(bin).mtimeMs;
  }
  if (!needsBuild) return bin;
  console.log("[harness] building target/release/drift…");
  const r = spawnSync(
    "cargo",
    ["build", "--release", "-p", "drift", "--bin", "drift"],
    { cwd: WORKSPACE, stdio: "inherit" }
  );
  if (r.status !== 0) throw new Error("cargo build drift failed");
  return bin;
}

/** Spawn `drift bridge` on the given listener URLs. Waits for
 *  the READY banner and returns (proc, pubkey, wtCertHex). */
async function spawnBridge(
  driftBin: string,
  listeners: string[]
): Promise<{ proc: ChildProcess; pubkey: string; wtCertHex: string }> {
  // Use ephemeral identity dir — fresh keypair each test run.
  const idDir = join(BROWSER_DIR, ".harness-state");
  mkdirSync(idDir, { recursive: true });
  const idPath = join(idDir, "bridge.key");

  // Generate identity if missing.
  if (!existsSync(idPath)) {
    const r = spawnSync(driftBin, ["keygen", "--output", idPath], {
      stdio: "inherit",
    });
    if (r.status !== 0) throw new Error("drift keygen failed");
  }

  const args = ["--identity", idPath, "bridge"];
  for (const l of listeners) {
    args.push("--listen", l);
  }
  // Phase PQ: turn on the hybrid handshake on the test bridge.
  // The WASM client side doesn't speak PQ — this exercises the
  // classical-client → PQ-server interop path, which is the
  // backward-compat guarantee we depend on for browsers.
  args.push("--hybrid-pq");
  const proc = spawn(driftBin, args, {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, RUST_LOG: "error" }, // quiet during tests
  });

  // Wait for both the bridge banner pubkey AND (if a webtransport
  // listener was requested) the cert SHA-256 line. Resolve as
  // soon as both are present.
  const wantWtCert = listeners.some((l) => l.startsWith("webtransport://"));
  const { pubkey, wtCertHex } = await new Promise<{
    pubkey: string;
    wtCertHex: string;
  }>((resolveFn, rejectFn) => {
    const timeout = setTimeout(() => {
      rejectFn(new Error("bridge did not emit expected banner lines within 10s"));
    }, 10_000);
    let buf = "";
    let pubMatch: string | null = null;
    let certMatch: string | null = null;
    // The bridge banner goes to STDERR, not stdout (see
    // drift/src/cli/bridge.rs — every line is `eprintln!`).
    proc.stderr!.on("data", (chunk: Buffer) => {
      const s = chunk.toString();
      buf += s;
      process.stderr.write(`[bridge] ${s}`);
      if (!pubMatch) {
        const m = buf.match(/pubkey:\s*([0-9a-f]{64})/);
        if (m) pubMatch = m[1];
      }
      if (!certMatch) {
        const m = buf.match(/webtransport listener[^\n]*cert SHA-256:\s*([0-9a-f]{64})/);
        if (m) certMatch = m[1];
      }
      const ready = pubMatch && (!wantWtCert || certMatch);
      if (ready) {
        clearTimeout(timeout);
        resolveFn({ pubkey: pubMatch!, wtCertHex: certMatch ?? "" });
      }
    });
    proc.on("error", rejectFn);
    proc.on("exit", (code) => {
      clearTimeout(timeout);
      rejectFn(new Error(`bridge exited prematurely with code ${code}`));
    });
  });

  return { proc, pubkey, wtCertHex };
}

/** Spawn a tiny static-file HTTP server serving index.html +
 *  the pkg-web bundle. The browser tests load
 *  http://127.0.0.1:<port>/ which returns index.html with a
 *  module import for /pkg-web/drift_wasm.js. */
function spawnStaticServer(pkgWebDir: string, port: number): ReturnType<typeof createHttpServer> {
  const server = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "/";
    // CORS for clarity (same-origin in practice).
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (url === "/" || url === "/index.html") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(readFileSync(join(BROWSER_DIR, "index.html")));
      return;
    }
    if (url.startsWith("/pkg-web/")) {
      const file = url.slice("/pkg-web/".length);
      const path = join(pkgWebDir, file);
      try {
        const bytes = readFileSync(path);
        if (file.endsWith(".wasm")) {
          res.setHeader("Content-Type", "application/wasm");
        } else if (file.endsWith(".js")) {
          res.setHeader("Content-Type", "text/javascript");
        }
        res.end(bytes);
      } catch {
        res.statusCode = 404;
        res.end("not found");
      }
      return;
    }
    if (url === "/harness.json") {
      // Tests can fetch this if they want runtime config.
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          ts: Date.now(),
          source: "drift-wasm-browser-harness",
        })
      );
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  server.listen(port, "127.0.0.1");
  return server;
}

export default async function globalSetup(): Promise<void> {
  const pkgWebDir = ensurePkgWeb();
  const driftBin = ensureDriftBinary();

  const udpPort = await pickPort();
  const tcpPort = await pickPort();
  const wsPort = await pickPort();
  const httpPort = await pickPort();
  const wtPort = await pickPort();
  const staticPort = await pickPort();

  // No tls:// listener — would need a self-signed cert we don't
  // have. webtransport:// brings its own ephemeral cert (the
  // listener generates one on bind and prints its SHA-256 to
  // stderr; the browser pins via `serverCertificateHashes`).
  const listeners = [
    `udp://127.0.0.1:${udpPort}`,
    `tcp://127.0.0.1:${tcpPort}`,
    `ws://127.0.0.1:${wsPort}`,
    `http://127.0.0.1:${httpPort}`,
    `webtransport://127.0.0.1:${wtPort}`,
  ];

  console.log(`[harness] starting bridge on UDP=${udpPort} TCP=${tcpPort} WS=${wsPort} HTTP=${httpPort} WT=${wtPort}`);
  const { proc: bridgeProc, pubkey, wtCertHex } = await spawnBridge(driftBin, listeners);
  console.log(`[harness] bridge pubkey: ${pubkey}`);

  const staticServer = spawnStaticServer(pkgWebDir, staticPort);
  console.log(`[harness] static server: http://127.0.0.1:${staticPort}`);

  const state: HarnessState = {
    bridgePubHex: pubkey,
    bridgeWsUrl: `ws://127.0.0.1:${wsPort}`,
    bridgeWsStreamUrl: `ws://127.0.0.1:${wsPort}`,
    bridgeHttpUrl: `http://127.0.0.1:${httpPort}`,
    bridgeUdpAddr: `127.0.0.1:${udpPort}`,
    bridgeTlsUrl: "",
    bridgeWebTransportUrl: `https://127.0.0.1:${wtPort}`,
    bridgeWebTransportCertHex: wtCertHex,
    bridgePid: bridgeProc.pid!,
    staticServerUrl: `http://127.0.0.1:${staticPort}`,
    staticServerPid: process.pid, // not separately spawned; runs in this Node process
    pkgWebDir,
  };
  saveHarness(state);
  process.env.HARNESS_URL = state.staticServerUrl;
}

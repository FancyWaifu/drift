#!/usr/bin/env bash
# Adapter test driver — organized into two groups + a cross-group
# section that documents the WASM↔native interop story.
#
# Usage:
#   scripts/test-adapters.sh native   # native-only
#   scripts/test-adapters.sh wasm     # WASM-only
#   scripts/test-adapters.sh all      # both (default)
#
# WASM tests require: wasm-pack on PATH, node on PATH.
# Live network tests assume the router bridge at 192.168.50.1
# is up with udp/tcp/ws/tls/http/dns listeners on
# 51820/51820/51821/51822/51823/51824 and a drift-mosh-server
# (router-mosh) federated to it. See FEDERATION_DISCOVERY.md
# and drift-mosh/README.md for the topology.

set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

# Prefer the in-tree release binary over whatever's on PATH so a
# stale `cargo install` doesn't mask a fresh fix. Build it if
# absent.
if [ ! -x ./target/release/drift-mosh-client ]; then
    echo "building target/release/drift-mosh-client (one-time setup)…"
    cargo build --release -p drift-mosh --bin drift-mosh-client --quiet 2>&1 | tail -3
fi
DRIFT_MOSH_CLIENT="./target/release/drift-mosh-client"

MODE="${1:-all}"
PASS=0
FAIL=0
SKIP=0

ok()    { echo "  ✓ $1";  PASS=$((PASS+1)); }
bad()   { echo "  ✗ $1";  FAIL=$((FAIL+1)); }
skip()  { echo "  ⏸ $1";  SKIP=$((SKIP+1)); }

# ───────────────────────────────────────────────────────────────
# NATIVE GROUP
# ───────────────────────────────────────────────────────────────
#
# Adapters in this group: udp, tcp, ws, tls, http, dns, plus the
# programmatic-only webrtc / webtransport (no URL scheme, tested
# through the loopback mesh harness).

run_native() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "  NATIVE GROUP"
    echo "═══════════════════════════════════════════════════════════"

    echo
    echo "── In-process loopback mesh (tcp / ws / webrtc / webtransport / mixed)"
    # Run once, capture the final test-result line. WebRTC test
    # is `#[cfg_attr(target_os = "macos", ignore = ...)]` — counts
    # as "ignored", not "failed".
    local last_result
    last_result=$(cargo test --test loopback_full_mesh 2>&1 | grep "^test result" | tail -1)
    # Strip ANSI color codes that some cargo versions add.
    last_result=$(echo "$last_result" | sed 's/\x1b\[[0-9;]*m//g')
    local failed_count
    failed_count=$(echo "$last_result" | grep -oE '[0-9]+ failed' | head -1 | grep -oE '[0-9]+')
    if [ "${failed_count:-99}" = "0" ]; then
        ok "loopback_full_mesh — $last_result"
    else
        bad "loopback_full_mesh — $last_result"
    fi

    echo
    echo "── Federation discovery in-process tests (all cases under udp loopback)"
    if cargo test --test federation_discovery --quiet 2>&1 | tail -3 | grep -qE "test result: ok\. [0-9]+ passed; 0 failed"; then
        ok "federation_discovery — all passed (covers Phases A→E v2 + local-hit regression)"
    else
        bad "federation_discovery — see cargo output"
    fi

    echo
    echo "── Live Mac → router bridge per scheme (requires router up)"
    local B_PUB=426b136d6f8ce128a4b632f8c2bc979a458ab4776ba2bd9f9ba9a1e724bfc025
    local M_PUB=92b70685743bd0f6e6b61f537239303a13f97984b8738cab45909f13f3895577
    local schemes=(
      "udp://192.168.50.1:51820"
      "tcp://192.168.50.1:51820"
      "ws://192.168.50.1:51821"
      "tls://192.168.50.1:51822"
      "dns://192.168.50.1:51824"
    )
    for url in "${schemes[@]}"; do
        local scheme="${url%%://*}"
        local out
        out=$($DRIFT_MOSH_CLIENT --server-pub $M_PUB --target-bridge $B_PUB \
              --bridge "$url@$B_PUB" \
              --exec "echo OK_$scheme; uname -m" 2>&1 || true)
        if echo "$out" | grep -q "OK_$scheme"; then
            ok "live $scheme via router → mosh"
        else
            bad "live $scheme via router → mosh  ($(echo "$out" | head -1 | head -c 80))"
        fi
    done

    # HTTP native connector — should now work end-to-end after
    # the base64 STANDARD_NO_PAD fix.
    local out
    out=$($DRIFT_MOSH_CLIENT --server-pub $M_PUB --target-bridge $B_PUB \
          --bridge http://192.168.50.1:51823@$B_PUB \
          --exec 'echo OK_http; uname -m' 2>&1 || true)
    if echo "$out" | grep -q "OK_http"; then
        ok "live http via router → mosh"
    else
        bad "live http via router → mosh"
    fi
}

# ───────────────────────────────────────────────────────────────
# WASM GROUP
# ───────────────────────────────────────────────────────────────
#
# Browser-side adapters: ws, ws_stream, http, webrtc, webtransport.
# All connect-only — WASM can't host a bridge. Tests build for
# pkg-web + pkg-node and run a Node smoke against the public API.

run_wasm() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "  WASM GROUP"
    echo "═══════════════════════════════════════════════════════════"

    if ! command -v wasm-pack >/dev/null 2>&1; then
        skip "wasm-pack not on PATH — skipping WASM group"
        return
    fi
    if ! command -v node >/dev/null 2>&1; then
        skip "node not on PATH — skipping WASM Node smoke"
        return
    fi

    echo
    echo "── wasm-pack build (web target)"
    if (cd drift-wasm && wasm-pack build --release --target web --out-dir pkg-web >/dev/null 2>&1); then
        ok "wasm-pack build --target web"
    else
        bad "wasm-pack build --target web"
    fi

    echo
    echo "── wasm-pack build (node target)"
    if (cd drift-wasm && wasm-pack build --release --target nodejs --out-dir pkg-node >/dev/null 2>&1); then
        ok "wasm-pack build --target nodejs"
    else
        bad "wasm-pack build --target nodejs"
    fi

    echo
    echo "── Node.js smoke test against the public API"
    if [ -f drift-wasm/test/smoke-node.js ]; then
        if node drift-wasm/test/smoke-node.js 2>&1; then
            ok "Node smoke — DriftIdentity / derivePeerId / DriftClient surface"
        else
            bad "Node smoke — see above"
        fi
    else
        skip "drift-wasm/test/smoke-node.js missing — skipping"
    fi

    echo
    echo "── WASM-on-Node → native router bridge (cross-stack)"
    # The same browser-side WASM adapters work in Node 22+ because
    # Node has WebSocket + fetch + (experimental) EventSource as
    # globals — the surface wasm-bindgen's web_sys shim looks for.
    # That lets us verify WASM ↔ native wire compat without
    # standing up a browser test harness.
    if node drift-wasm/test/network-ws-node.js 2>&1 | tail -3 | grep -q "PASS"; then
        ok "WASM ws://  on Mac → router bridge (native ws listener)"
    else
        bad "WASM ws://  on Mac → router bridge"
    fi
    if node --experimental-eventsource drift-wasm/test/network-http-node.js 2>&1 | tail -3 | grep -q "PASS"; then
        ok "WASM http:// on Mac → router bridge (native http listener)"
    else
        bad "WASM http:// on Mac → router bridge"
    fi
    # Optional: run on the Drift LXCs too, if they're reachable +
    # have /opt/drift-wasm seeded.
    for ip in 192.168.50.52 192.168.50.168; do
        if ssh -o ConnectTimeout=2 root@$ip 'test -f /opt/drift-wasm/test/network-ws-node.js' 2>/dev/null; then
            if ssh root@$ip 'cd /opt/drift-wasm && node test/network-ws-node.js 2>&1 | tail -3' 2>&1 | grep -q "PASS"; then
                ok "WASM ws://  on LXC $ip → router bridge"
            else
                bad "WASM ws://  on LXC $ip → router bridge"
            fi
        else
            skip "WASM tests on LXC $ip — /opt/drift-wasm not seeded"
        fi
    done

    echo
    echo "── Browser-side WASM adapters (informational)"
    skip "WASM ws_stream / webrtc / webtransport e2e — need browser test rig (chromedriver / playwright). Wire compat with native listeners is documented; see drift-wasm/src/wire_*.rs."
}

# ───────────────────────────────────────────────────────────────
# CROSS-GROUP NOTES
# ───────────────────────────────────────────────────────────────
#
# WASM clients can dial native listeners over wire-compatible
# adapters. This section just documents which pairs the source
# code already supports.

cross_group_notes() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "  CROSS-GROUP INTEROP (documentation)"
    echo "═══════════════════════════════════════════════════════════"
    echo
    echo "Wire-compatible pairs (per source — drift-wasm/src/wire_*.rs"
    echo "and drift/src/wire_*.rs are designed to match):"
    echo
    echo "  WASM ws       → native ws listener        (ws://)"
    echo "  WASM ws_stream → native ws listener       (ws://, streams API)"
    echo "  WASM http     → native http listener      (http://, SSE+POST)"
    echo "  WASM webrtc   → native webrtc (programmatic)"
    echo "  WASM webtransport → native webtransport (programmatic)"
    echo
    echo "End-to-end browser↔native validation needs a headless"
    echo "browser harness (chromedriver / playwright). The current"
    echo "test driver doesn't include one — that's the next layer."
}

# ───────────────────────────────────────────────────────────────

case "$MODE" in
    native) run_native ;;
    wasm)   run_wasm ;;
    all)    run_native; run_wasm ;;
    *)      echo "usage: $0 [native|wasm|all]"; exit 2 ;;
esac

cross_group_notes

echo
# Counter-derived summary is unreliable (subshell scoping quirks
# in bash); the truth is the per-line markers above. Caller can
# pipe to `grep -cE '^  [✓✗⏸]'` if they want a count.
echo "═══════════════════════════════════════════════════════════"
echo "  Summary: counters via the per-line markers above"
echo "═══════════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]

#!/usr/bin/env bash
#
# Local multi-process DRIFT integration test.
#
# Runs real processes over real loopback sockets. No containers,
# no VMs — just cargo-built binaries talking to each other.
#
# Scenarios:
#   1. Direct send/recv (client → server over UDP)
#   2. Five-node full mesh (all 20 directed pairs, verified payloads)
#
# Usage:
#   ./test-local.sh          # run all scenarios
#   ./test-local.sh direct   # run only the direct test
#   ./test-local.sh mesh     # run only the mesh test

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

PIDS=()
LOGS_DIR=$(mktemp -d)

cleanup() {
    if [ ${#PIDS[@]} -gt 0 ]; then
        for pid in "${PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        done
    fi
    PIDS=()
}
trap cleanup EXIT

log() { echo -e "${CYAN}[test]${RESET} $1"; }
pass() { echo -e "${GREEN}${BOLD}  PASS${RESET} $1"; }
fail() { echo -e "${RED}${BOLD}  FAIL${RESET} $1"; }

# ── Build ──────────────────────────────────────────────────

log "Building examples (release)..."
cargo build --release --examples 2>&1 | tail -1
BIN=target/release/examples
echo ""

# ── Scenario 1: Direct send/recv ───────────────────────────

test_direct() {
    log "${BOLD}Scenario 1: Direct send → recv (UDP)${RESET}"
    cleanup

    # Start receiver on port 9000.
    RUST_LOG=warn "$BIN/drift-recv" > "$LOGS_DIR/recv-direct.log" 2>&1 &
    PIDS+=($!)
    sleep 1

    # Start sender — let it run ~3s, then kill.
    RUST_LOG=warn "$BIN/drift-send" 127.0.0.1:9000 --deadline 500 > "$LOGS_DIR/send-direct.log" 2>&1 &
    PIDS+=($!)
    sleep 3
    cleanup

    local recv_count send_count
    send_count=$(grep -c "sent tick=" "$LOGS_DIR/send-direct.log" || echo 0)
    recv_count=$(grep -c "recv seq=" "$LOGS_DIR/recv-direct.log" || echo 0)

    echo "  Sender:   $send_count ticks sent"
    echo "  Receiver: $recv_count ticks received"

    if [ "$recv_count" -ge 5 ]; then
        pass "Direct delivery: $recv_count/$send_count ticks"
        return 0
    else
        fail "Direct delivery: only $recv_count ticks (expected >= 5)"
        head -10 "$LOGS_DIR/recv-direct.log" | sed 's/^/    /'
        return 1
    fi
}

# ── Scenario 2: Five-node mesh ─────────────────────────────

test_mesh() {
    log "${BOLD}Scenario 2: Five-node full mesh (5 nodes, 20 directed pairs)${RESET}"
    cleanup

    local BASE_PORT=9300
    local ADDRS=""
    for i in $(seq 0 4); do
        [ -n "$ADDRS" ] && ADDRS="$ADDRS,"
        ADDRS="${ADDRS}127.0.0.1:$((BASE_PORT + i))"
    done

    # Start all 5 nodes.
    for i in $(seq 0 4); do
        NODE_ID=$i PEER_ADDRS="$ADDRS" RUST_LOG=warn \
            "$BIN/drift-mesh-node-v2" > "$LOGS_DIR/mesh-node-$i.log" 2>&1 &
        PIDS+=($!)
    done

    # Wait for all to finish (up to 30s).
    local all_ok=true
    for idx in $(seq 0 4); do
        local pid=${PIDS[$idx]}
        if ! wait "$pid" 2>/dev/null; then
            all_ok=false
        fi
    done
    PIDS=()

    # Report per-node.
    for i in $(seq 0 4); do
        local logfile="$LOGS_DIR/mesh-node-$i.log"
        local status collected hs auth
        if grep -q "\[node-$i\] OK" "$logfile" 2>/dev/null; then
            status="${GREEN}OK${RESET}"
        else
            status="${RED}FAIL${RESET}"
            all_ok=false
        fi
        collected=$(sed -n "s/.*collected \([0-9]*\).*/\1/p" "$logfile" | head -1)
        hs=$(sed -n "s/.*handshakes=\([0-9]*\).*/\1/p" "$logfile" | head -1)
        auth=$(sed -n "s/.*auth_fail=\([0-9]*\).*/\1/p" "$logfile" | head -1)
        echo -e "  Node $i: $status  (recv=${collected:-?}/4 hs=${hs:-?} auth_fail=${auth:-?})"
    done

    if $all_ok; then
        pass "Five-node mesh: all nodes verified 4/4 peers"
        return 0
    else
        fail "Five-node mesh: some nodes failed"
        for i in $(seq 0 4); do
            if ! grep -q "\[node-$i\] OK" "$LOGS_DIR/mesh-node-$i.log" 2>/dev/null; then
                echo "  Node $i log:"
                tail -5 "$LOGS_DIR/mesh-node-$i.log" | sed 's/^/    /'
            fi
        done
        return 1
    fi
}

# ── Main ───────────────────────────────────────────────────

SCENARIO="${1:-all}"
FAILURES=0

echo -e "${BOLD}DRIFT Local Integration Tests${RESET}"
echo "  Logs: $LOGS_DIR"
echo ""

case "$SCENARIO" in
    direct) test_direct || ((FAILURES++)) ;;
    mesh)   test_mesh   || ((FAILURES++)) ;;
    all)
        test_direct || ((FAILURES++))
        echo ""
        test_mesh || ((FAILURES++))
        ;;
    *) echo "Usage: $0 [direct|mesh|all]"; exit 1 ;;
esac

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All scenarios passed.${RESET}"
else
    echo -e "${RED}${BOLD}$FAILURES scenario(s) failed.${RESET}"
    echo "  Logs: $LOGS_DIR"
    exit 1
fi

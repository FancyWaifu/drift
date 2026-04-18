#!/usr/bin/env bash
#
# drift-shell demonstration: identity-first addressing over DRIFT,
# exercised over three loopback IPs on this machine.
#
# Two scenarios:
#   1. sequential rotation — one active server at a time, its IP
#      (and distinct per-IP identity) changing each round. Exercises
#      route re-convergence when a peer moves.
#   2. simultaneous — three servers live at once on three IPs with
#      three distinct identities. Clients fan out to every target
#      and get one response per live server.
#
# Requires loopback aliases on macOS (lo0 is /32 by default):
#   sudo ifconfig lo0 alias 127.0.0.2 up
#   sudo ifconfig lo0 alias 127.0.0.3 up
#
# Cleanup when done:
#   sudo ifconfig lo0 -alias 127.0.0.2
#   sudo ifconfig lo0 -alias 127.0.0.3
#
# Usage:
#   ./demo-shell.sh              # both scenarios
#   ./demo-shell.sh rotation     # only scenario 1
#   ./demo-shell.sh simultaneous # only scenario 2

set -eo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[demo]${RESET} $1"; }
head() { echo -e "${BOLD}== $1 ==${RESET}"; }

PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    PIDS=()
    wait 2>/dev/null || true
}
trap cleanup EXIT

# Build once.
log "Building drift-shell..."
cargo build --example drift-shell 2>&1 | tail -1
BIN=./target/debug/examples/drift-shell
echo ""

# Check aliases.
if ! ifconfig lo0 2>/dev/null | grep -q '127.0.0.2'; then
    echo -e "${RED}Missing loopback alias 127.0.0.2 — add with:${RESET}"
    echo "    sudo ifconfig lo0 alias 127.0.0.2 up"
    exit 1
fi
if ! ifconfig lo0 2>/dev/null | grep -q '127.0.0.3'; then
    echo -e "${RED}Missing loopback alias 127.0.0.3 — add with:${RESET}"
    echo "    sudo ifconfig lo0 alias 127.0.0.3 up"
    exit 1
fi

# ── Scenario 1: sequential rotation ────────────────────────
scenario_rotation() {
    head "Scenario 1: sequential rotation (one active server per round)"
    rm -f /tmp/drift-shell-counter
    $BIN bridge > /tmp/demo-bridge.log 2>&1 &
    PIDS+=($!)
    sleep 0.5

    run_round() {
        local n=$1 active=$2
        echo ""
        echo -e "${BOLD}Round $n: server @ $active${RESET}"
        $BIN server "$active" --rotation $((n - 1)) > "/tmp/demo-server-r$n.log" 2>&1 &
        local sp=$!
        PIDS+=($sp)
        sleep 1.2
        $BIN client 127.0.0.1 --target "$active" time
        $BIN client 127.0.0.2 --target "$active" count
        $BIN client 127.0.0.3 --target "$active" whoami
        kill $sp 2>/dev/null || true
        wait $sp 2>/dev/null || true
        sleep 0.2
    }

    run_round 1 127.0.0.1
    run_round 2 127.0.0.2
    run_round 3 127.0.0.3

    cleanup
}

# ── Scenario 2: simultaneous ───────────────────────────────
scenario_simultaneous() {
    head "Scenario 2: three servers live at once, clients fan out"
    rm -f /tmp/drift-shell-counter
    $BIN bridge > /tmp/demo-bridge.log 2>&1 &
    PIDS+=($!)
    sleep 0.3

    for ip in 127.0.0.1 127.0.0.2 127.0.0.3; do
        $BIN server "$ip" --rotation 0 > "/tmp/demo-server-$ip.log" 2>&1 &
        PIDS+=($!)
    done
    sleep 2

    echo ""
    echo "--- Every client fans to all three server identities ---"
    for ip in 127.0.0.1 127.0.0.2 127.0.0.3; do
        $BIN client "$ip" --any whoami
        echo ""
    done

    echo "--- Each server returns its OWN bind IP ---"
    $BIN client 127.0.0.1 --any ip

    cleanup
}

SCENARIO="${1:-all}"
case "$SCENARIO" in
    rotation)     scenario_rotation ;;
    simultaneous) scenario_simultaneous ;;
    all)
        scenario_rotation
        echo ""
        scenario_simultaneous
        ;;
    *) echo "Usage: $0 [rotation|simultaneous|all]"; exit 1 ;;
esac

echo ""
log "Done."

#!/bin/bash
# Multi-transport test: server listens on UDP + TCP simultaneously,
# clients connect via either, both succeed and return the same bytes.
#
# Proves the principle "tools must run over any DRIFT transport" —
# one binary, one identity, two transports, both work end-to-end.

set -u
BIN=/Users/youruser/drift/target/release/drift-http
LOGDIR=/tmp/drift-http-multitransport
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/site"
SITE="$LOGDIR/site"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    pkill -f "drift-http connect" 2>/dev/null
}
trap cleanup EXIT

# Tiny site.
echo "multi-transport works" > "$SITE/probe.txt"

# Start server bound to BOTH udp and tcp on ephemeral ports.
"$BIN" serve --root "$SITE" \
    --bind udp://127.0.0.1:0 \
    --bind tcp://127.0.0.1:0 \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!

PUB=""; UDP_ADDR=""; TCP_ADDR=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_HTTP_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    UDP_ADDR=$(grep -oE 'DRIFT_HTTP_BIND=udp://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d/ -f3)
    TCP_ADDR=$(grep -oE 'DRIFT_HTTP_BIND=tcp://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d/ -f3)
    [ -n "$PUB" ] && [ -n "$UDP_ADDR" ] && [ -n "$TCP_ADDR" ] && break
done
[ -z "$PUB" ] && { echo "FAIL: server banner missing"; cat "$LOGDIR/server.err"; exit 1; }
[ -z "$UDP_ADDR" ] && { echo "FAIL: UDP bind not in banner"; cat "$LOGDIR/server.out"; exit 1; }
[ -z "$TCP_ADDR" ] && { echo "FAIL: TCP bind not in banner"; cat "$LOGDIR/server.out"; exit 1; }
echo "server: udp=$UDP_ADDR tcp=$TCP_ADDR pub=${PUB:0:16}..."

# Helper: spin up a connect client over the chosen transport,
# fetch /probe.txt through it, kill the client, return content.
fetch_via() {
    local scheme="$1"
    local server_addr="$2"
    local client_log="$LOGDIR/client-$scheme.out"
    local listen_port=$((9400 + RANDOM % 100))
    "$BIN" connect \
        --peer "$PUB@$scheme://$server_addr" \
        --listen "127.0.0.1:$listen_port" \
        > "$client_log" 2>&1 &
    local CPID=$!
    for _ in $(seq 1 30); do
        sleep 0.1
        grep -q DRIFT_HTTP_READY "$client_log" 2>/dev/null && break
    done
    if ! grep -q DRIFT_HTTP_READY "$client_log"; then
        echo "FAIL: $scheme connect never became ready"
        cat "$client_log"
        kill "$CPID" 2>/dev/null
        return 1
    fi
    local got
    got=$(curl -sf "http://127.0.0.1:$listen_port/probe.txt")
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    echo "$got"
}

EXPECTED="multi-transport works"

# Test 1: UDP path.
GOT_UDP=$(fetch_via udp "$UDP_ADDR")
if [ "$GOT_UDP" = "$EXPECTED" ]; then
    echo "PASS: fetch via UDP"
else
    echo "FAIL: UDP fetch (expected '$EXPECTED', got '$GOT_UDP')"
    exit 1
fi

# Test 2: TCP path (same identity, same server, different wire).
GOT_TCP=$(fetch_via tcp "$TCP_ADDR")
if [ "$GOT_TCP" = "$EXPECTED" ]; then
    echo "PASS: fetch via TCP"
else
    echo "FAIL: TCP fetch (expected '$EXPECTED', got '$GOT_TCP')"
    exit 1
fi

echo
echo "RESULT: same identity reachable over both UDP and TCP"

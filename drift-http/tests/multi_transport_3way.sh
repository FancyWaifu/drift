#!/bin/bash
# Three-transport test: drift-http serves the same files behind a
# single pubkey, simultaneously reachable via UDP, TCP, AND WebSocket.
#
# Proves the plug-and-play abstraction. drift-http's own source code
# never mentions WebSocket — the new transport works because we
# added one Listener impl + one URL-dispatcher arm in `drift::io`.

set -u
BIN=/Users/youruser/drift/target/release/drift-http
LOGDIR=/tmp/drift-http-3way
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/site"
SITE="$LOGDIR/site"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    pkill -f "drift-http connect" 2>/dev/null
}
trap cleanup EXIT

echo "three-transport works" > "$SITE/probe.txt"

"$BIN" serve --root "$SITE" \
    --bind udp://127.0.0.1:0 \
    --bind tcp://127.0.0.1:0 \
    --bind ws://127.0.0.1:0 \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!

PUB=""; UDP_ADDR=""; TCP_ADDR=""; WS_ADDR=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_HTTP_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    UDP_ADDR=$(grep -oE 'DRIFT_HTTP_BIND=udp://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d/ -f3)
    TCP_ADDR=$(grep -oE 'DRIFT_HTTP_BIND=tcp://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d/ -f3)
    WS_ADDR=$(grep -oE 'DRIFT_HTTP_BIND=ws://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d/ -f3)
    [ -n "$PUB" ] && [ -n "$UDP_ADDR" ] && [ -n "$TCP_ADDR" ] && [ -n "$WS_ADDR" ] && break
done

[ -z "$PUB" ] && { echo "FAIL: server banner missing"; cat "$LOGDIR/server.err"; exit 1; }
[ -z "$UDP_ADDR" ] && { echo "FAIL: UDP bind missing"; cat "$LOGDIR/server.out"; exit 1; }
[ -z "$TCP_ADDR" ] && { echo "FAIL: TCP bind missing"; cat "$LOGDIR/server.out"; exit 1; }
[ -z "$WS_ADDR" ]  && { echo "FAIL: WS bind missing";  cat "$LOGDIR/server.out"; exit 1; }
echo "server: udp=$UDP_ADDR tcp=$TCP_ADDR ws=$WS_ADDR"
echo "        pub=${PUB:0:16}..."

fetch_via() {
    local scheme="$1"
    local server_addr="$2"
    local listen_port="$3"
    local client_log="$LOGDIR/client-$scheme.out"
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
        echo ""
        return 1
    fi
    local got
    got=$(curl -sf "http://127.0.0.1:$listen_port/probe.txt")
    kill "$CPID" 2>/dev/null
    wait "$CPID" 2>/dev/null
    echo "$got"
}

EXPECTED="three-transport works"
PASS=0; FAIL=0

for spec in "udp $UDP_ADDR 9501" "tcp $TCP_ADDR 9502" "ws $WS_ADDR 9503"; do
    set -- $spec
    scheme=$1; addr=$2; port=$3
    got=$(fetch_via "$scheme" "$addr" "$port")
    if [ "$got" = "$EXPECTED" ]; then
        echo "PASS: fetch via $scheme"
        PASS=$((PASS+1))
    else
        echo "FAIL: $scheme fetch (expected '$EXPECTED', got '$got')"
        FAIL=$((FAIL+1))
    fi
done

echo
echo "RESULT: $PASS pass / $FAIL fail (of 3 transports)"
[ "$FAIL" -eq 0 ]

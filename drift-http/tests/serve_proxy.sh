#!/bin/bash
# End-to-end test for `serve --proxy` mode: spin up Python's
# http.server as the "upstream" Jellyfin-stand-in, then pull a
# file through it via DRIFT and verify byte-identical bytes.

set -u
BIN=/Users/5speeddeasil/drift/target/release/drift-http
LOGDIR=/tmp/drift-http-proxy-e2e
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/upstream"
UPSTREAM_DIR="$LOGDIR/upstream"

cleanup() {
    [ -n "${UPID:-}" ] && kill "$UPID" 2>/dev/null
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null
}
trap cleanup EXIT

# 64 KB binary file as the "video clip" stand-in.
dd if=/dev/urandom of="$UPSTREAM_DIR/clip.bin" bs=1024 count=64 2>/dev/null
SHA_EXPECTED=$(shasum -a 256 "$UPSTREAM_DIR/clip.bin" | awk '{print $1}')

# 1. Upstream HTTP server.
UPSTREAM_PORT=39201
( cd "$UPSTREAM_DIR" && python3 -m http.server $UPSTREAM_PORT > "$LOGDIR/upstream.out" 2>&1 ) &
UPID=$!
for _ in $(seq 1 30); do
    sleep 0.1
    curl -sf "http://127.0.0.1:$UPSTREAM_PORT/clip.bin" -o /dev/null && break
done
curl -sf "http://127.0.0.1:$UPSTREAM_PORT/clip.bin" -o /dev/null \
    || { echo "FAIL: upstream never came up"; exit 1; }

# 2. drift-http in proxy mode.
"$BIN" serve --proxy "127.0.0.1:$UPSTREAM_PORT" --bind 127.0.0.1:0 \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!

PUB=""; ADDR=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_HTTP_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    ADDR=$(grep -oE 'DRIFT_HTTP_ADDR=[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$PUB" ] && [ -n "$ADDR" ] && break
done
[ -z "$PUB" ] && { echo "FAIL: server banner missing"; cat "$LOGDIR/server.err"; exit 1; }
echo "drift-http proxy: $ADDR  pub=${PUB:0:16}..."

# 3. Connect bridge.
LISTEN="127.0.0.1:9301"
"$BIN" connect --peer "$PUB@$ADDR" --listen "$LISTEN" \
    > "$LOGDIR/client.out" 2> "$LOGDIR/client.err" &
CPID=$!
for _ in $(seq 1 30); do
    sleep 0.1
    grep -q DRIFT_HTTP_READY "$LOGDIR/client.out" 2>/dev/null && break
done

# 4. Fetch through the whole stack.
curl -sf "http://$LISTEN/clip.bin" -o "$LOGDIR/clip.dl"
SHA_GOT=$(shasum -a 256 "$LOGDIR/clip.dl" | awk '{print $1}')

if [ "$SHA_EXPECTED" = "$SHA_GOT" ]; then
    echo "PASS: 64 KB tunneled through proxy mode, byte-identical"
    echo "  expected sha: $SHA_EXPECTED"
    echo "  got      sha: $SHA_GOT"
    exit 0
else
    echo "FAIL: byte mismatch"
    echo "  expected sha: $SHA_EXPECTED"
    echo "  got      sha: $SHA_GOT"
    exit 1
fi

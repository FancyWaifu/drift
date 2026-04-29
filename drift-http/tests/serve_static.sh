#!/bin/bash
# End-to-end test:
#   1. drift-http serve --root <site> on the "server" side
#   2. drift-http connect on the "client" side
#   3. curl through the local listener and verify we get the
#      file's bytes back, byte-identical.
#
# Bonus: also fetch a binary blob and a sub-path to confirm
# range requests / index resolution work.

set -u
BIN=/Users/youruser/drift/target/release/drift-http
LOGDIR=/tmp/drift-http-e2e
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/site"
SITE="$LOGDIR/site"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null
}
trap cleanup EXIT

# Build a tiny site.
echo "<h1>hello drift-http</h1>" > "$SITE/index.html"
echo "static page" > "$SITE/page.txt"
mkdir -p "$SITE/sub"
echo "nested file content" > "$SITE/sub/deep.txt"
# A 256 KB binary blob to test ranges + larger transfers.
dd if=/dev/urandom of="$SITE/blob.bin" bs=1024 count=256 2>/dev/null
SHA_EXPECTED=$(shasum -a 256 "$SITE/blob.bin" | awk '{print $1}')

# 1. Server (Apache mode).
"$BIN" serve --root "$SITE" --bind 127.0.0.1:0 \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!

PUB=""; ADDR=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_HTTP_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    ADDR=$(grep -oE 'DRIFT_HTTP_ADDR=[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$PUB" ] && [ -n "$ADDR" ] && break
done
[ -z "$PUB" ] && { echo "FAIL: server didn't print banner"; cat "$LOGDIR/server.err"; exit 1; }
echo "server: $ADDR  pub=${PUB:0:16}..."

# 2. Connect bridge — listens on a local TCP port.
LISTEN="127.0.0.1:9201"
"$BIN" connect --peer "$PUB@$ADDR" --listen "$LISTEN" \
    > "$LOGDIR/client.out" 2> "$LOGDIR/client.err" &
CPID=$!
for _ in $(seq 1 30); do
    sleep 0.1
    grep -q DRIFT_HTTP_READY "$LOGDIR/client.out" 2>/dev/null && break
done
grep -q DRIFT_HTTP_READY "$LOGDIR/client.out" || {
    echo "FAIL: connect side never became ready"; cat "$LOGDIR/client.err"; exit 1
}
echo "bridge listening on $LISTEN"

# 3. Test cases.
PASS=0; FAIL=0
check() {
    local name="$1"; local expected="$2"; local got="$3"
    if [ "$expected" = "$got" ]; then
        echo "  PASS — $name"
        PASS=$((PASS+1))
    else
        echo "  FAIL — $name"
        echo "    expected: $expected"
        echo "    got:      $got"
        FAIL=$((FAIL+1))
    fi
}

echo "tests:"

# (a) GET /index.html
got=$(curl -sf "http://$LISTEN/index.html")
check "GET /index.html" "<h1>hello drift-http</h1>" "$got"

# (b) GET / with default index resolution
got=$(curl -sf "http://$LISTEN/")
check "GET / (index resolution)" "<h1>hello drift-http</h1>" "$got"

# (c) GET nested path
got=$(curl -sf "http://$LISTEN/sub/deep.txt")
check "GET /sub/deep.txt" "nested file content" "$got"

# (d) 404 for missing file
got_status=$(curl -s -o /dev/null -w "%{http_code}" "http://$LISTEN/missing.html")
check "GET /missing.html (404)" "404" "$got_status"

# (e) Binary blob — full byte-for-byte fidelity
curl -sf "http://$LISTEN/blob.bin" -o "$LOGDIR/blob.dl"
SHA_GOT=$(shasum -a 256 "$LOGDIR/blob.dl" | awk '{print $1}')
check "GET /blob.bin (256 KB SHA-256)" "$SHA_EXPECTED" "$SHA_GOT"

# (f) Range request — bytes 100-199 (100 bytes)
curl -sf -H "Range: bytes=100-199" "http://$LISTEN/blob.bin" -o "$LOGDIR/blob.range"
RANGE_GOT_LEN=$(wc -c < "$LOGDIR/blob.range" | tr -d ' ')
check "Range: bytes=100-199 length" "100" "$RANGE_GOT_LEN"

# Compare the actual range content with the original.
dd if="$SITE/blob.bin" bs=1 skip=100 count=100 of="$LOGDIR/blob.expect" 2>/dev/null
SHA_R_EXPECTED=$(shasum -a 256 "$LOGDIR/blob.expect" | awk '{print $1}')
SHA_R_GOT=$(shasum -a 256 "$LOGDIR/blob.range" | awk '{print $1}')
check "Range bytes match expected" "$SHA_R_EXPECTED" "$SHA_R_GOT"

echo
echo "RESULT: $PASS pass / $FAIL fail"
[ "$FAIL" -eq 0 ]

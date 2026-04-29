#!/bin/bash
# Test `drift-http open --no-browse`:
# 1. Start serve --root with a tiny site.
# 2. Call `drift-http open --no-browse drift://...`. It should
#    spawn a background bridge and print the resulting
#    http://127.0.0.1:NNNN/path URL.
# 3. curl that URL — should return the file content.
# 4. Call open again — should reuse the same bridge (same port).

set -u
BIN=/Users/youruser/drift/target/release/drift-http
LOGDIR=/tmp/drift-http-open-e2e
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/site"
SITE="$LOGDIR/site"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    pkill -f "drift-http connect" 2>/dev/null
    # Wipe leftover bridge state so a re-run doesn't reuse a
    # stale port file.
    rm -rf "$HOME/.config/drift/links" 2>/dev/null
    rm -rf "$HOME/Library/Application Support/drift/links" 2>/dev/null
}
trap cleanup EXIT

# Tiny site.
mkdir -p "$SITE/sub"
echo "<title>via drift://</title><h1>open subcommand works</h1>" > "$SITE/index.html"
echo "deeper file" > "$SITE/sub/deep.txt"

# Wipe any leftover state from prior runs.
rm -rf "$HOME/.config/drift/links" 2>/dev/null
rm -rf "$HOME/Library/Application Support/drift/links" 2>/dev/null

# 1. Server.
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
[ -z "$PUB" ] && { echo "FAIL: server banner missing"; cat "$LOGDIR/server.err"; exit 1; }
echo "server: $ADDR  pub=${PUB:0:16}..."

DRIFT_URL="drift://$PUB@$ADDR/"

# 2. drift-http open --no-browse → prints http URL.
HTTP_URL=$("$BIN" open --no-browse "$DRIFT_URL" 2>"$LOGDIR/open1.err")
if [ -z "$HTTP_URL" ]; then
    echo "FAIL: open didn't print a URL"
    cat "$LOGDIR/open1.err"
    exit 1
fi
echo "got url: $HTTP_URL"

# 3. Fetch the index through it.
got=$(curl -sf "$HTTP_URL")
expected="<title>via drift://</title><h1>open subcommand works</h1>"
if [ "$got" = "$expected" ]; then
    echo "PASS: GET / via drift:// open"
else
    echo "FAIL: GET via open"
    echo "  expected: $expected"
    echo "  got:      $got"
    exit 1
fi

# 3b. Path with a sub-resource.
DRIFT_URL_DEEP="drift://$PUB@$ADDR/sub/deep.txt"
HTTP_URL_DEEP=$("$BIN" open --no-browse "$DRIFT_URL_DEEP")
got=$(curl -sf "$HTTP_URL_DEEP")
if [ "$got" = "deeper file" ]; then
    echo "PASS: nested path through open"
else
    echo "FAIL: nested path"
    echo "  expected: deeper file"
    echo "  got:      $got"
    exit 1
fi

# 4. Re-open should reuse the same bridge → same port.
HTTP_URL_2=$("$BIN" open --no-browse "$DRIFT_URL")
PORT_1=$(echo "$HTTP_URL"  | sed -E 's|.*://[^:]*:([0-9]+).*|\1|')
PORT_2=$(echo "$HTTP_URL_2" | sed -E 's|.*://[^:]*:([0-9]+).*|\1|')
if [ "$PORT_1" = "$PORT_2" ]; then
    echo "PASS: re-open reused the same bridge port ($PORT_1)"
else
    echo "FAIL: bridge port changed across calls ($PORT_1 → $PORT_2)"
    exit 1
fi

echo
echo "RESULT: all open subcommand checks passed"

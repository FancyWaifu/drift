#!/bin/bash
# End-to-end petname test for drift-http:
# 1. Start a server with --name "myserver".
# 2. Run `connect --peer PUBHEX@addr` (literal form). This
#    auto-records the server in the client's contacts file.
# 3. Run `drift contacts list` — see the entry.
# 4. Run `connect --peer myserver` — petname resolves, fetches
#    a file successfully.

set -u
BIN_HTTP=/Users/youruser/drift/target/release/drift-http
BIN_DRIFT=/Users/youruser/drift/target/release/drift
LOGDIR=/tmp/drift-http-petname
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/site"
SITE="$LOGDIR/site"

# Isolate per-user config so this test doesn't touch real
# contacts.toml.
export HOME="$LOGDIR/home"
mkdir -p "$HOME"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    pkill -f "drift-http connect" 2>/dev/null
}
trap cleanup EXIT

echo "petname test marker" > "$SITE/probe.txt"

# 1. Server with --name.
"$BIN_HTTP" serve --root "$SITE" --bind 127.0.0.1:0 --name myserver \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!
PUB=""; ADDR=""; NAME=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_HTTP_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    ADDR=$(grep -oE 'DRIFT_HTTP_ADDR=[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    NAME=$(grep -oE 'DRIFT_HTTP_NAME=[A-Za-z0-9_-]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$PUB" ] && [ -n "$ADDR" ] && [ -n "$NAME" ] && break
done
if [ -z "$NAME" ]; then
    echo "FAIL: server didn't advertise DRIFT_HTTP_NAME=myserver"
    cat "$LOGDIR/server.out"
    exit 1
fi
echo "PASS: server advertises name=$NAME"

# 2. First-contact via literal form. This should auto-record
#    the server in the client's contacts file.
LISTEN1="127.0.0.1:9701"
"$BIN_HTTP" connect --peer "$PUB@$ADDR" --listen "$LISTEN1" \
    > "$LOGDIR/c1.out" 2> "$LOGDIR/c1.err" &
CPID1=$!
for _ in $(seq 1 30); do
    sleep 0.1
    grep -q DRIFT_HTTP_READY "$LOGDIR/c1.out" 2>/dev/null && break
done
got=$(curl -sf "http://$LISTEN1/probe.txt")
kill "$CPID1" 2>/dev/null; wait "$CPID1" 2>/dev/null

if [ "$got" != "petname test marker" ]; then
    echo "FAIL: literal-form fetch (got '$got')"
    exit 1
fi
echo "PASS: first-contact (literal form) fetched OK"

# 3. Confirm the contact got auto-saved (will be a
#    `peer-<pubprefix>` placeholder since drift-http is L4
#    and doesn't see the advertised name on the wire — by
#    design, since the wire is opaque). User can rename.
LIST=$("$BIN_DRIFT" contacts list 2>&1)
if ! echo "$LIST" | grep -q "peer-"; then
    echo "FAIL: contact wasn't auto-recorded after literal-form connect"
    echo "$LIST"
    exit 1
fi
echo "PASS: contact auto-recorded after first connect"

# 4. Rename it to the advertised name (myserver) so the
#    petname-form connect works.
PETNAME=$(echo "$LIST" | grep "peer-" | awk '{print $1}' | head -1)
"$BIN_DRIFT" contacts rename "$PETNAME" myserver
echo "renamed $PETNAME → myserver"

# 5. Petname-form connect.
LISTEN2="127.0.0.1:9702"
"$BIN_HTTP" connect --peer myserver --listen "$LISTEN2" \
    > "$LOGDIR/c2.out" 2> "$LOGDIR/c2.err" &
CPID2=$!
for _ in $(seq 1 30); do
    sleep 0.1
    grep -q DRIFT_HTTP_READY "$LOGDIR/c2.out" 2>/dev/null && break
done
if ! grep -q DRIFT_HTTP_READY "$LOGDIR/c2.out"; then
    echo "FAIL: petname connect didn't become ready"
    cat "$LOGDIR/c2.err"
    exit 1
fi
got=$(curl -sf "http://$LISTEN2/probe.txt")
kill "$CPID2" 2>/dev/null; wait "$CPID2" 2>/dev/null
if [ "$got" != "petname test marker" ]; then
    echo "FAIL: petname-form fetch (got '$got')"
    exit 1
fi
echo "PASS: petname-form connect (drift-http connect --peer myserver) fetched OK"

echo
echo "RESULT: petname round-trip works"

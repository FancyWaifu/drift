#!/bin/bash
# Mesh-hop drift-git test: real `git push` routed through an
# intermediate bridge.
#
#   [git push helper] ←ws/udp→ [drift-chat bridge] ←udp→ [drift-git-server]
#
# Server connects OUT to the bridge (--connect mode); helper
# connects to the same bridge but addresses messages to the
# server's pubkey. DRIFT mesh-routes between them.

set -uo pipefail
# Note: deliberately not `-e`. Several wait loops run grep
# against a freshly-created log file before any matches are
# present, and pipefail+e turns the grep-no-match (exit 1)
# into a script-fatal error mid-loop. We check return codes
# explicitly where it matters.

ROOT="/Users/youruser/drift"
BRIDGE_BIN="$ROOT/target/release/examples/drift-chat"
SERVER_BIN="$ROOT/target/release/drift-git-server"
HELPER_BIN="$ROOT/target/release/git-remote-drift"

[ -x "$BRIDGE_BIN" ] || { echo "FAIL: build the workspace first"; exit 1; }
[ -x "$SERVER_BIN" ] || { echo "FAIL: build drift-git first"; exit 1; }

LOGDIR=/tmp/drift-git-meshhop
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/server-root"

HELPER_DIR="$LOGDIR/helper-bin"
mkdir -p "$HELPER_DIR"
cp "$HELPER_BIN" "$HELPER_DIR/git-remote-drift"
export PATH="$HELPER_DIR:$PATH"

cleanup() {
    pkill -f "drift-git-server" 2>/dev/null
    pkill -f "drift-chat" 2>/dev/null
}
trap cleanup EXIT

# 1. Start the bridge.
"$BRIDGE_BIN" bridge > "$LOGDIR/bridge.out" 2>&1 &
BPID=$!
BRIDGE_PUB=""
for _ in $(seq 1 30); do
    sleep 0.2
    BRIDGE_PUB=$(grep -oE 'pubkey=[a-f0-9]+' "$LOGDIR/bridge.out" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$BRIDGE_PUB" ] && break
done
if [ -z "$BRIDGE_PUB" ]; then
    echo "FAIL: bridge didn't print pubkey"
    cat "$LOGDIR/bridge.out"
    exit 1
fi
# drift-chat bridge defaults: UDP 9200, TCP 9201, WS 9202.
BRIDGE_UDP="udp://127.0.0.1:9200"
echo "bridge: pub=${BRIDGE_PUB:0:16}... udp=$BRIDGE_UDP"

# 2. Start drift-git-server in --connect mode.
git init --bare --initial-branch=main "$LOGDIR/server-root/myrepo.git" > /dev/null
"$SERVER_BIN" --connect "$BRIDGE_UDP" --bridge-pub "$BRIDGE_PUB" \
    --root "$LOGDIR/server-root" --allow-any \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!
SERVER_PUB=""
for _ in $(seq 1 30); do
    sleep 0.2
    SERVER_PUB=$(grep -oE 'DRIFT_GIT_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$SERVER_PUB" ] && break
done
if [ -z "$SERVER_PUB" ]; then
    echo "FAIL: server didn't print pubkey"
    cat "$LOGDIR/server.out" "$LOGDIR/server.err"
    exit 1
fi
# Wait a beat so the server's mesh handshake with the bridge
# completes before the client tries to mesh-route to it.
sleep 1
echo "server: pub=${SERVER_PUB:0:16}... (connected to bridge)"

# 3. Real git push, with helper env vars pointing at the bridge.
WORK="$LOGDIR/work"
mkdir -p "$WORK"
cd "$WORK"
git init -q -b main
git -c user.email=a@b -c user.name=a commit --allow-empty -q -m "first via bridge"
COMMIT=$(git rev-parse HEAD)

# URL host:port is the bridge's wire endpoint; the env vars tell
# the helper to mesh-route to SERVER_PUB through the bridge.
URL="drift://$SERVER_PUB@127.0.0.1:9200/myrepo.git"
git remote add origin "$URL"

export DRIFT_GIT_BRIDGE_URL="$BRIDGE_UDP"
export DRIFT_GIT_BRIDGE_PUB="$BRIDGE_PUB"

if git push origin main 2> "$LOGDIR/push.err"; then
    echo "PASS: git push routed through bridge"
else
    echo "FAIL: push via bridge"
    echo "--- push.err ---"
    cat "$LOGDIR/push.err"
    echo "--- server.out (last 10) ---"
    tail -10 "$LOGDIR/server.out"
    echo "--- bridge.out (last 10) ---"
    tail -10 "$LOGDIR/bridge.out"
    exit 1
fi

# 4. Verify the bare repo holds the pushed commit.
SERVER_HEAD=$(git --git-dir="$LOGDIR/server-root/myrepo.git" rev-parse main 2>/dev/null || true)
if [ "$SERVER_HEAD" = "$COMMIT" ]; then
    echo "PASS: bare repo HEAD ($SERVER_HEAD) matches pushed commit"
else
    echo "FAIL: bare repo HEAD ($SERVER_HEAD) != pushed ($COMMIT)"
    exit 1
fi

# 5. Bonus: clone via bridge too.
CLONE="$LOGDIR/clone"
cd "$LOGDIR"
if git clone "$URL" "$CLONE" 2> "$LOGDIR/clone.err"; then
    CLONED=$(cd "$CLONE" && git rev-parse HEAD)
    if [ "$CLONED" = "$COMMIT" ]; then
        echo "PASS: clone routed through bridge, HEAD matches"
    else
        echo "FAIL: clone HEAD mismatch"
        exit 1
    fi
else
    echo "FAIL: clone via bridge"
    cat "$LOGDIR/clone.err"
    exit 1
fi

echo
echo "RESULT: drift-git push + clone work mesh-routed through a bridge"

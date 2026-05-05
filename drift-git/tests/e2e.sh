#!/bin/bash
# End-to-end test: real git push + clone over DRIFT.
#
#   1. Set up a bare repo on the "server" side.
#   2. Start drift-git-server pointing at it.
#   3. Use a real `git` (the user's installed C git) on the
#      "client" side to clone the repo via drift://...
#   4. Make a commit, push it back, fetch into a third clone,
#      verify the commit is visible.
#
# Requires `git`, the workspace's release builds.

set -euo pipefail

ROOT="/Users/youruser/drift"
SERVER_BIN="$ROOT/target/release/drift-git-server"
HELPER_BIN="$ROOT/target/release/git-remote-drift"

if [ ! -x "$SERVER_BIN" ]; then
    echo "FAIL: $SERVER_BIN missing — run 'cargo build --release -p drift-git'"
    exit 1
fi
if [ ! -x "$HELPER_BIN" ]; then
    echo "FAIL: $HELPER_BIN missing"
    exit 1
fi

LOGDIR=/tmp/drift-git-e2e
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"

# --- server-side: bare repo ---
SERVER_ROOT="$LOGDIR/server-root"
mkdir -p "$SERVER_ROOT"
git init --bare --initial-branch=main "$SERVER_ROOT/myrepo.git" > /dev/null

# --- helper visibility: git looks up `git-remote-drift` in PATH ---
HELPER_DIR="$LOGDIR/helper-bin"
mkdir -p "$HELPER_DIR"
cp "$HELPER_BIN" "$HELPER_DIR/git-remote-drift"
export PATH="$HELPER_DIR:$PATH"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
}
trap cleanup EXIT

# --- start server ---
"$SERVER_BIN" --bind "udp://127.0.0.1:0" --root "$SERVER_ROOT" --allow-any \
    > "$LOGDIR/server.out" 2> "$LOGDIR/server.err" &
SPID=$!

PUB=""; ADDR=""
for _ in $(seq 1 30); do
    sleep 0.1
    PUB=$(grep -oE 'DRIFT_GIT_PUB=[a-f0-9]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | cut -d= -f2)
    ADDR=$(grep -oE 'DRIFT_GIT_BIND=udp://[0-9.:]+' "$LOGDIR/server.out" 2>/dev/null | head -1 | sed 's|DRIFT_GIT_BIND=udp://||')
    [ -n "$PUB" ] && [ -n "$ADDR" ] && break
done
if [ -z "$PUB" ] || [ -z "$ADDR" ]; then
    echo "FAIL: server didn't print pub+bind"
    cat "$LOGDIR/server.out" "$LOGDIR/server.err"
    exit 1
fi
echo "server: pub=${PUB:0:16}... addr=$ADDR"

URL="drift://$PUB@$ADDR/myrepo.git"

# --- client side: set up a working repo, push it ---
WORK="$LOGDIR/work"
mkdir -p "$WORK"
cd "$WORK"
git init -q -b main
git -c user.email=a@b -c user.name=a commit --allow-empty -q -m "first commit"
COMMIT_HASH=$(git rev-parse HEAD)
echo "client made commit $COMMIT_HASH"

git remote add origin "$URL"
if git push origin main 2> "$LOGDIR/push.err"; then
    echo "PASS: git push drift://...  succeeded"
else
    echo "FAIL: git push failed"
    cat "$LOGDIR/push.err"
    exit 1
fi

# --- second client: clone the same repo and verify the commit lands ---
CLONE="$LOGDIR/clone"
cd "$LOGDIR"
if git clone "$URL" "$CLONE" 2> "$LOGDIR/clone.err"; then
    echo "PASS: git clone drift://... succeeded"
else
    echo "FAIL: git clone failed"
    cat "$LOGDIR/clone.err"
    exit 1
fi

CLONED_HASH=$(cd "$CLONE" && git rev-parse HEAD)
if [ "$COMMIT_HASH" = "$CLONED_HASH" ]; then
    echo "PASS: clone HEAD matches push HEAD ($CLONED_HASH)"
else
    echo "FAIL: clone HEAD ($CLONED_HASH) != push HEAD ($COMMIT_HASH)"
    exit 1
fi

# --- third: make another commit, push, fetch into clone, verify ---
cd "$WORK"
git -c user.email=a@b -c user.name=a commit --allow-empty -q -m "second commit"
SECOND_HASH=$(git rev-parse HEAD)
git push origin main 2> "$LOGDIR/push2.err" || {
    echo "FAIL: second push failed"
    cat "$LOGDIR/push2.err"
    exit 1
}
echo "PASS: second push succeeded ($SECOND_HASH)"

cd "$CLONE"
git fetch origin main 2> "$LOGDIR/fetch.err" || {
    echo "FAIL: fetch failed"
    cat "$LOGDIR/fetch.err"
    exit 1
}
FETCHED_HASH=$(git rev-parse origin/main)
if [ "$SECOND_HASH" = "$FETCHED_HASH" ]; then
    echo "PASS: fetched HEAD matches second push ($FETCHED_HASH)"
else
    echo "FAIL: fetched HEAD ($FETCHED_HASH) != second push ($SECOND_HASH)"
    exit 1
fi

echo
echo "RESULT: drift-git push/clone/fetch all work end-to-end"

#!/bin/bash
# Multi-scheme drift-git test: runs the same git push/clone/fetch
# scenario against each of UDP, TCP, TLS, WS by varying the URL
# scheme (drift://, drift+tcp://, drift+tls://, drift+ws://). The
# wire format on each is identical from drift-git's perspective —
# only the underlying DRIFT adapter changes.

set -euo pipefail

ROOT="/Users/5speeddeasil/drift"
SERVER_BIN="$ROOT/target/release/drift-git-server"
HELPER_BIN="$ROOT/target/release/git-remote-drift"

[ -x "$SERVER_BIN" ] || { echo "FAIL: build drift-git first"; exit 1; }
[ -x "$HELPER_BIN" ] || { echo "FAIL: build drift-git first"; exit 1; }

LOGDIR=/tmp/drift-git-multi-scheme
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"

HELPER_DIR="$LOGDIR/helper-bin"
mkdir -p "$HELPER_DIR"
cp "$HELPER_BIN" "$HELPER_DIR/git-remote-drift"
# Git looks up git-remote-<scheme> for each URL it sees. A
# single helper binary serves multiple schemes via symlinks
# (the same trick git-remote-http uses for both http:// and
# https://).
for s in "drift+tcp" "drift+tls" "drift+ws" "drift+http" "drift+onion"; do
    ln -sf git-remote-drift "$HELPER_DIR/git-remote-$s"
done
export PATH="$HELPER_DIR:$PATH"

cleanup() {
    pkill -f "drift-git-server" 2>/dev/null
}
trap cleanup EXIT

run_one_scheme() {
    local scheme="$1"
    local url_prefix="$2"
    local bind_url="$3"

    local TAG="$scheme"
    local SERVER_ROOT="$LOGDIR/$TAG/server-root"
    mkdir -p "$SERVER_ROOT"
    git init --bare --initial-branch=main "$SERVER_ROOT/myrepo.git" > /dev/null

    "$SERVER_BIN" --bind "$bind_url" --root "$SERVER_ROOT" --allow-any \
        > "$LOGDIR/$TAG.server.out" 2> "$LOGDIR/$TAG.server.err" &
    local SPID=$!

    local PUB="" ADDR=""
    for _ in $(seq 1 30); do
        sleep 0.1
        PUB=$(grep -oE 'DRIFT_GIT_PUB=[a-f0-9]+' "$LOGDIR/$TAG.server.out" 2>/dev/null | head -1 | cut -d= -f2)
        ADDR=$(grep -oE "DRIFT_GIT_BIND=${scheme}://[0-9.:]+" "$LOGDIR/$TAG.server.out" 2>/dev/null | head -1 | sed "s|DRIFT_GIT_BIND=${scheme}://||")
        [ -n "$PUB" ] && [ -n "$ADDR" ] && break
    done
    if [ -z "$PUB" ] || [ -z "$ADDR" ]; then
        echo "FAIL [$scheme]: server didn't print pub+bind"
        kill "$SPID" 2>/dev/null
        return 1
    fi

    local URL="${url_prefix}://$PUB@$ADDR/myrepo.git"
    local WORK="$LOGDIR/$TAG/work"
    local CLONE="$LOGDIR/$TAG/clone"
    mkdir -p "$WORK"

    cd "$WORK"
    git init -q -b main
    git -c user.email=a@b -c user.name=a commit --allow-empty -q -m "first via $scheme"
    local FIRST_HASH
    FIRST_HASH=$(git rev-parse HEAD)
    git remote add origin "$URL"
    if ! git push origin main 2> "$LOGDIR/$TAG.push.err"; then
        echo "FAIL [$scheme]: push"
        kill "$SPID" 2>/dev/null
        return 1
    fi

    cd "$LOGDIR/$TAG"
    if ! git clone "$URL" "$CLONE" 2> "$LOGDIR/$TAG.clone.err"; then
        echo "FAIL [$scheme]: clone"
        kill "$SPID" 2>/dev/null
        return 1
    fi
    local CLONED_HASH
    CLONED_HASH=$(cd "$CLONE" && git rev-parse HEAD)
    if [ "$FIRST_HASH" != "$CLONED_HASH" ]; then
        echo "FAIL [$scheme]: clone HEAD ≠ push HEAD"
        kill "$SPID" 2>/dev/null
        return 1
    fi

    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    echo "PASS [$scheme]: push + clone over ${url_prefix}://"
    return 0
}

PASS=0; FAIL=0
for spec in \
    "udp drift udp://127.0.0.1:0" \
    "tcp drift+tcp tcp://127.0.0.1:0" \
    "tls drift+tls tls://127.0.0.1:0" \
    "ws  drift+ws  ws://127.0.0.1:0" ; do
    set -- $spec
    if run_one_scheme "$1" "$2" "$3"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
done

echo
echo "RESULT: $PASS pass / $FAIL fail (of 4 schemes)"
[ "$FAIL" -eq 0 ]

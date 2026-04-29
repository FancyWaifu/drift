#!/bin/bash
# End-to-end test: drift-wormhole send + recv on the same
# machine with two distinct identity files. Picks a random
# binary blob, transfers it, verifies SHA-256 byte-fidelity.

set -u
BIN=/Users/5speeddeasil/drift/target/release/drift-wormhole
LOGDIR=/tmp/drift-wormhole-e2e
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR/in" "$LOGDIR/out"

cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
}
trap cleanup EXIT

# 256 KB random blob.
dd if=/dev/urandom of="$LOGDIR/in/blob.bin" bs=1024 count=256 2>/dev/null
EXPECTED_SHA=$(shasum -a 256 "$LOGDIR/in/blob.bin" | awk '{print $1}')

# Distinct identity files so the two ends don't share a pubkey.
SENDER_KEY="$LOGDIR/sender.key"
RECVER_KEY="$LOGDIR/recver.key"
head -c 32 /dev/urandom | xxd -p -c 64 > "$SENDER_KEY"
head -c 32 /dev/urandom | xxd -p -c 64 > "$RECVER_KEY"

# Spawn the sender, parse the recipient command from its stderr.
"$BIN" send "$LOGDIR/in/blob.bin" \
    --bind "udp://127.0.0.1:0" \
    --identity-file "$SENDER_KEY" \
    > "$LOGDIR/sender.out" 2> "$LOGDIR/sender.err" &
SPID=$!

# Wait for the "drift-wormhole recv ..." line.
RECV_CMD=""
for _ in $(seq 1 50); do
    sleep 0.1
    line=$(grep -oE 'drift-wormhole recv [a-f0-9]+@[a-z]+://[0-9.:]+' "$LOGDIR/sender.err" 2>/dev/null | head -1)
    if [ -n "$line" ]; then
        RECV_CMD="$line"
        break
    fi
    line=$(grep -oE 'drift-wormhole recv [a-f0-9]+@[0-9.:]+' "$LOGDIR/sender.err" 2>/dev/null | head -1)
    if [ -n "$line" ]; then
        RECV_CMD="$line"
        break
    fi
done

if [ -z "$RECV_CMD" ]; then
    echo "FAIL: sender never printed a recv command"
    cat "$LOGDIR/sender.err"
    exit 1
fi

PEER=$(echo "$RECV_CMD" | awk '{print $3}')
echo "peer string: $PEER"

# Run the receiver.
"$BIN" recv "$PEER" \
    --out-dir "$LOGDIR/out" \
    --identity-file "$RECVER_KEY" \
    > "$LOGDIR/recver.out" 2> "$LOGDIR/recver.err"

if [ ! -f "$LOGDIR/out/blob.bin" ]; then
    echo "FAIL: file not delivered"
    cat "$LOGDIR/recver.err"
    exit 1
fi

GOT_SHA=$(shasum -a 256 "$LOGDIR/out/blob.bin" | awk '{print $1}')
if [ "$GOT_SHA" = "$EXPECTED_SHA" ]; then
    echo "PASS: 256 KB transferred, SHA-256 matches"
    echo "  expected: $EXPECTED_SHA"
    echo "  got:      $GOT_SHA"
else
    echo "FAIL: SHA-256 mismatch"
    echo "  expected: $EXPECTED_SHA"
    echo "  got:      $GOT_SHA"
    exit 1
fi

# Sender should also have exited 0.
wait "$SPID"
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "FAIL: sender exited with $RC"
    cat "$LOGDIR/sender.err"
    exit 1
fi
echo "PASS: sender exited 0"

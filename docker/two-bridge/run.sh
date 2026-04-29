#!/bin/bash
# Run the two-bridge mesh demo. Brings up bridge-a, bridge-b,
# and 10 clients; waits for the clients to finish (each exits
# after receiving its 9 expected messages, or fails after a
# 60-second timeout); reports per-client PASS/FAIL.

set -u
cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml)

cleanup() {
    "${COMPOSE[@]}" down --remove-orphans 2>/dev/null
}
trap cleanup EXIT

echo "=== building images ==="
"${COMPOSE[@]}" build

echo
echo "=== starting bridges + 10 clients ==="
"${COMPOSE[@]}" up --abort-on-container-exit --no-color 2>&1 | tee /tmp/two-bridge-run.log

echo
echo "=== per-client exit codes ==="
PASS=0
FAIL=0
for i in $(seq 1 10); do
    rc=$(docker inspect "client-$i" --format '{{.State.ExitCode}}' 2>/dev/null || echo "missing")
    if [ "$rc" = "0" ]; then
        echo "  client-$i: PASS"
        PASS=$((PASS+1))
    else
        echo "  client-$i: FAIL (exit=$rc)"
        FAIL=$((FAIL+1))
    fi
done

echo
echo "=== summary ==="
echo "$PASS / 10 clients received all 9 expected messages"
[ "$FAIL" -eq 0 ]

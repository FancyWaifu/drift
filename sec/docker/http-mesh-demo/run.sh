#!/usr/bin/env bash
# Demo: client machine = drift http listener + caddy + federation
# to a remote bridge. Remote peer sends a message addressed to
# the client's pubkey; it routes through the bridge → federation
# → client, and the client-node binary exits 0 on receipt.
#
# Asserts PASS on the client-node container's exit code.
set -euo pipefail

cd "$(dirname "$0")"
DEMO_DIR="$PWD"
KEYS_DIR="$DEMO_DIR/keys"

cleanup() {
    docker compose -f compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Generating ephemeral bridge + client identities"
mkdir -p "$KEYS_DIR"
rm -f "$KEYS_DIR/bridge.key" "$KEYS_DIR/client.key"
for who in bridge client; do
    docker run --rm --platform linux/amd64 \
        -v "$KEYS_DIR:/keys" \
        drift-sec:latest \
        drift --identity "/keys/${who}.key" keygen \
        >/dev/null
done

get_pub() {
    docker run --rm --platform linux/amd64 \
        -v "$KEYS_DIR:/keys" \
        drift-sec:latest \
        drift --identity "/keys/$1.key" info \
        2>/dev/null | awk '/public_key:/ {print $2}'
}

DRIFT_BRIDGE_PUB=$(get_pub bridge)
DRIFT_CLIENT_PUB=$(get_pub client)
if [[ ${#DRIFT_BRIDGE_PUB} -ne 64 || ${#DRIFT_CLIENT_PUB} -ne 64 ]]; then
    echo "FAIL: pubkey extraction broken"
    exit 1
fi
echo "==> bridge pub: ${DRIFT_BRIDGE_PUB:0:16}..."
echo "==> client pub: ${DRIFT_CLIENT_PUB:0:16}..."

export DRIFT_BRIDGE_PUB DRIFT_CLIENT_PUB

echo "==> Bringing up remote-bridge + client-node + caddy"
docker compose -f compose.yml up -d remote-bridge client-node caddy >/dev/null

# Let federation converge before launching sender. The sender's
# own sleep inside the container handles the rest.
sleep 5

echo "==> Running remote-sender + watching client-node for exit"
set +e
docker compose -f compose.yml up remote-sender \
    --abort-on-container-exit \
    --exit-code-from client-node
RC=$?
set -e

echo ""
echo "==> client-node log:"
docker logs http-mesh-demo-client 2>&1 | tail -25 || true
echo ""
echo "==> remote-sender log:"
docker logs http-mesh-demo-sender 2>&1 | tail -15 || true
echo ""
echo "==> remote-bridge log (last 15 lines):"
docker logs http-mesh-demo-bridge 2>&1 | tail -15 || true
echo ""
echo "==> caddy log (last 5 lines):"
docker logs http-mesh-demo-caddy 2>&1 | tail -5 || true

echo ""
if [[ $RC -eq 0 ]]; then
    echo "==> RESULT: PASS — client machine reachable via mesh AND via http+caddy"
else
    echo "==> RESULT: FAIL (client-node exit code $RC)"
fi
exit $RC

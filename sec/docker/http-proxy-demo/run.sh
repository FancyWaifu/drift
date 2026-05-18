#!/usr/bin/env bash
# End-to-end demo: caddy → drift bridge → drift peer probe.
# Returns 0 if the probe sees a fully Established DRIFT session
# through the proxy, non-zero otherwise.
set -euo pipefail

cd "$(dirname "$0")"
DEMO_DIR="$PWD"
KEYS_DIR="$DEMO_DIR/keys"

cleanup() {
    docker compose -f compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Generating ephemeral bridge identity"
mkdir -p "$KEYS_DIR"
rm -f "$KEYS_DIR/bridge.key"
# Use the locally-built drift binary to keygen so we don't need the
# image yet. (The image is needed for the actual bridge.)
docker run --rm \
    --platform linux/amd64 \
    -v "$KEYS_DIR:/keys" \
    drift-sec:latest \
    drift --identity /keys/bridge.key keygen \
    >/dev/null

DRIFT_BRIDGE_PUB=$(
    docker run --rm \
        --platform linux/amd64 \
        -v "$KEYS_DIR:/keys" \
        drift-sec:latest \
        drift --identity /keys/bridge.key info \
        2>/dev/null | awk '/public_key:/ {print $2}'
)

if [[ -z "$DRIFT_BRIDGE_PUB" || ${#DRIFT_BRIDGE_PUB} -ne 64 ]]; then
    echo "FAIL: couldn't extract bridge pubkey from \`drift info\`"
    exit 1
fi
echo "==> bridge pub: ${DRIFT_BRIDGE_PUB:0:16}..."

export DRIFT_BRIDGE_PUB

echo "==> Bringing up caddy + drift-bridge (background)"
docker compose -f compose.yml up -d drift-bridge caddy >/dev/null

# Give caddy + bridge a moment to bind. The probe also sleeps 3s
# before connecting; this is belt-and-suspenders.
sleep 4

echo "==> Running probe (foreground, attached)"
set +e
docker compose -f compose.yml up probe \
    --abort-on-container-exit \
    --exit-code-from probe
RC=$?
set -e

echo ""
echo "==> Bridge log (last 20 lines):"
docker logs http-proxy-demo-bridge 2>&1 | tail -20 || true

echo ""
echo "==> Caddy log (last 10 lines):"
docker logs http-proxy-demo-caddy 2>&1 | tail -10 || true

echo ""
if [[ $RC -eq 0 ]]; then
    echo "==> RESULT: PASS — drift http:// session established through caddy reverse proxy"
else
    echo "==> RESULT: FAIL (probe exit code $RC)"
fi
exit $RC

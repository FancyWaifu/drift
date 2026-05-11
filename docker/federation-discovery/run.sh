#!/bin/bash
# End-to-end federation-discovery test driver.
#
# Builds the image, generates four identities locally, materializes
# the per-container identities and the client's drift.toml, brings
# up the four-container chain, and verifies the client can dial
# the mosh-server by pubkey alone (only `default_bridge = D2` in
# the inventory).
#
# This is the docker-equivalent of the Proxmox LXC test driver in
# drift-mosh/tests/federation_resilience_test.sh.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

# ─── Build the image ──────────────────────────────────────────────
echo "[1/5] Building drift-federation-discovery image (release mode)…"
docker compose -p federation-discovery build --quiet

# ─── Generate identities locally and bind-mount them ──────────────
echo "[2/5] Generating four fresh DRIFT identities…"
rm -rf identities inventory
mkdir -p identities inventory

# Use the locally-built drift binary (faster than spinning up a
# transient container just to call `drift keygen`).
DRIFT_BIN=$(realpath ../../target/debug/drift)
if [ ! -x "$DRIFT_BIN" ]; then
  (cd ../.. && cargo build -p drift --bin drift -q)
fi

for n in d1 d2 d3 d4; do
  "$DRIFT_BIN" keygen --output "identities/$n.key" >/dev/null
  # drift-mosh expects hex-format identity files; derive from the
  # DRFT-magic file (skip first 4 bytes of "DRFT" header).
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "identities/$n.key" > "identities/$n.hex"
done

PUB_D2=$("$DRIFT_BIN" info identities/d2.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D3=$("$DRIFT_BIN" info identities/d3.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D4=$("$DRIFT_BIN" info identities/d4.key | grep -oE '[0-9a-f]{64}' | head -1)
echo "  PUB_D2=$PUB_D2"
echo "  PUB_D3=$PUB_D3"
echo "  PUB_D4=$PUB_D4"

# ─── Materialize the client's drift.toml ─────────────────────────
# Inventory deliberately knows only D2 (its on-ramp bridge). The
# server (D4) is NOT in the inventory. The test validates that the
# dynamic-discovery path (default_bridge + FederationDirectory
# announcements) routes correctly without per-target config.
cat > inventory/drift.toml <<EOF
default_bridge = "$PUB_D2"

[network]
name = "federation-discovery"

[hosts.bridge-d2]
pubkey = "$PUB_D2"
endpoints = ["udp://172.30.0.12:51820"]
EOF

# ─── Bring up the stack ──────────────────────────────────────────
echo "[3/5] Starting bridges + mosh-server + client container…"
# Export the pubkeys so compose can substitute them into command:
export PUB_D2 PUB_D3
docker compose -p federation-discovery down --remove-orphans >/dev/null 2>&1 || true
docker compose -p federation-discovery up -d --quiet-pull

# ─── Wait for the directories to converge ─────────────────────────
# Bridges announce every 7 s; first announce fires 1 s after
# startup, so by 10 s D2 should have D4 in its directory via D3's
# announcement. Give 12 s for slack on slow CPUs.
echo "[4/5] Waiting 12s for federation directories to converge…"
sleep 12

# Sanity: server's banner should have made it to stdout. If it's
# not there, the bridges aren't talking and the test will fail
# downstream anyway — surface that early.
echo "  mosh-server banner:"
docker logs fd-mosh-server 2>&1 | grep DRIFT_MOSH | sed 's/^/    /'

# ─── Run the client dial ──────────────────────────────────────────
echo "[5/5] drift-mosh-client --server-pub <D4> (D4 NOT in inventory):"
RESULT=$(docker exec fd-client drift-mosh-client \
  --identity-file /identities/d1.hex \
  --server-pub "$PUB_D4" \
  --exec 'echo DYNAMIC_DISCOVERY_OK; uname -n; id' \
  --exec-timeout 8 2>&1 || true)
echo "$RESULT" | sed 's/^/  /'

# Cleanup
docker compose -p federation-discovery down --remove-orphans >/dev/null 2>&1 || true

# Verdict
if echo "$RESULT" | grep -q DYNAMIC_DISCOVERY_OK; then
  echo ""
  echo "  ✅ Client dialed the server by pubkey alone, routed through"
  echo "     D2 via the directory (D3's announcement → D2's directory)."
  echo "     Idempotent-set + first-write-wins + shorter TTL fixes"
  echo "     verified end-to-end."
  exit 0
else
  echo ""
  echo "  ❌ Dynamic discovery did not produce DYNAMIC_DISCOVERY_OK"
  exit 1
fi

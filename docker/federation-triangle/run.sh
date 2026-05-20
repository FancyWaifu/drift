#!/bin/bash
# End-to-end federation-triangle test driver.
#
# Three bridges federated in a full triangle (B1↔B2, B2↔B3, B1↔B3).
# At each vertex we attach (server-sN, client-cN) on the same
# bridge. The driver runs every cross-vertex dial — six in total —
# and asserts they all succeed via dynamic directory routing.
# Each client knows ONLY its on-ramp bridge in drift.toml.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

# ─── Build the image ──────────────────────────────────────────────
echo "[1/5] Building drift-federation-discovery image (release mode)…"
docker compose -p federation-triangle build --quiet

# ─── Generate identities locally and bind-mount them ──────────────
echo "[2/5] Generating nine fresh DRIFT identities…"
rm -rf identities inventory-c1 inventory-c2 inventory-c3
mkdir -p identities inventory-c1 inventory-c2 inventory-c3

DRIFT_BIN=$(realpath ../../target/debug/drift)
if [ ! -x "$DRIFT_BIN" ]; then
  (cd ../.. && cargo build -p drift --bin drift -q)
fi

for n in b1 b2 b3 s1 s2 s3 c1 c2 c3; do
  "$DRIFT_BIN" keygen --output "identities/$n.key" >/dev/null
  # drift-mosh expects hex-format identity files; derive from the
  # DRFT-magic file (skip first 4 bytes of "DRFT" header).
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "identities/$n.key" > "identities/$n.hex"
done

read_pub() {
  "$DRIFT_BIN" info "identities/$1.key" | grep -oE '[0-9a-f]{64}' | head -1
}

PUB_B1=$(read_pub b1); PUB_B2=$(read_pub b2); PUB_B3=$(read_pub b3)
PUB_S1=$(read_pub s1); PUB_S2=$(read_pub s2); PUB_S3=$(read_pub s3)

echo "  bridges: B1=${PUB_B1:0:12}…  B2=${PUB_B2:0:12}…  B3=${PUB_B3:0:12}…"
echo "  servers: S1=${PUB_S1:0:12}…  S2=${PUB_S2:0:12}…  S3=${PUB_S3:0:12}…"

# ─── Materialize each client's drift.toml ─────────────────────────
# Inventory deliberately knows only the local on-ramp bridge.
# Discovery handles every other vertex via directory propagation.
write_inventory() {
  local dir=$1 pub=$2 ip=$3
  cat > "$dir/drift.toml" <<EOF
default_bridge = "$pub"

[network]
name = "federation-triangle"

[hosts.local-bridge]
pubkey = "$pub"
endpoints = ["udp://$ip:51820"]
EOF
}

write_inventory inventory-c1 "$PUB_B1" 172.31.0.12
write_inventory inventory-c2 "$PUB_B2" 172.31.0.13
write_inventory inventory-c3 "$PUB_B3" 172.31.0.14

# ─── Bring up the stack ──────────────────────────────────────────
echo "[3/5] Starting 3 bridges + 3 servers + 3 clients (9 containers)…"
export PUB_B1 PUB_B2 PUB_B3
docker compose -p federation-triangle down --remove-orphans >/dev/null 2>&1 || true
docker compose -p federation-triangle up -d --quiet-pull

# ─── Wait for the directories to converge ─────────────────────────
# Bridges announce every 7 s; first announce fires 1 s after
# startup. With three federated peers each, give 14 s of slack on
# slow CPUs.
echo "[4/5] Waiting 45s for triangle directories to converge…"
sleep 45

# Sanity: each server should print its banner. If the bridges
# aren't talking, surface that early.
for s in s1 s2 s3; do
  banner=$(docker logs "tri-server-$s" 2>&1 | grep DRIFT_MOSH | head -1)
  if [ -n "$banner" ]; then
    echo "  $s: ${banner}"
  else
    echo "  $s: NO BANNER (likely bridge-server handshake failed)"
  fi
done

# ─── Run six cross-bridge dials ───────────────────────────────────
echo "[5/5] Six cross-bridge dials (each client → both non-local servers):"
PASS=0
FAIL=0
RESULTS=()

run_dial() {
  local from=$1 to_name=$2 to_pub=$3
  local out
  out=$(docker exec "tri-client-$from" drift-mosh-client \
    --identity-file "/identities/$from.hex" \
    --server-pub "$to_pub" \
    --exec "echo TRIANGLE_OK_${from}_to_${to_name}; hostname; id -un" \
    --exec-timeout 10 2>&1 || true)
  if echo "$out" | grep -q "TRIANGLE_OK_${from}_to_${to_name}"; then
    echo "  PASS  $from -> $to_name"
    RESULTS+=("PASS ${from}->${to_name}")
    PASS=$((PASS+1))
  else
    echo "  FAIL  $from -> $to_name"
    echo "$out" | tail -10 | sed 's/^/        /'
    RESULTS+=("FAIL ${from}->${to_name}")
    FAIL=$((FAIL+1))
  fi
}

run_dial c1 s2 "$PUB_S2"
run_dial c1 s3 "$PUB_S3"
run_dial c2 s1 "$PUB_S1"
run_dial c2 s3 "$PUB_S3"
run_dial c3 s1 "$PUB_S1"
run_dial c3 s2 "$PUB_S2"

echo ""
echo "  Summary: $PASS pass / $FAIL fail (of 6)"
for r in "${RESULTS[@]}"; do echo "    $r"; done

# Cleanup
docker compose -p federation-triangle down --remove-orphans >/dev/null 2>&1 || true

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "  Triangle federation works for every pair. Directory propagation"
  echo "  reached every vertex through every on-ramp."
  exit 0
else
  echo ""
  echo "  One or more cross-bridge dials failed; see output above."
  exit 1
fi

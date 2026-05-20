#!/bin/bash
# Federation topology sweep driver.
#
# Same 5 bridges + 5 servers + 5 clients pattern as pentagon, but
# the federation EDGE SET is determined by the TOPOLOGY env var
# instead of being hardcoded. Combined with FED_WIRE this lets us
# run the full 4-topology × 3-wire matrix from one script.
#
# Usage:
#   TOPOLOGY=ring FED_WIRE=h2s bash run.sh
#   TOPOLOGY=star FED_WIRE=webtransport bash run.sh
#   bash sweep.sh                       # all 4×3 combinations
#
# Topologies:
#   mesh  — K5 (10 edges, 1-hop everywhere)
#   ring  — 5-cycle (5 edges, up to 2 hops)
#   star  — hub-spoke at b1 (4 edges, max 2 hops via hub)
#   chain — b1-b2-b3-b4-b5 (4 edges, up to 4 hops c1↔c5)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

# ─── Topology + wire selection ────────────────────────────────────
TOPOLOGY="${TOPOLOGY:-ring}"
case "${FED_WIRE:-h2s}" in
  h2s)          : "${FED_SCHEME:=h2s}";          : "${FED_PORT:=51827}" ;;
  h2)           : "${FED_SCHEME:=h2}";           : "${FED_PORT:=51826}" ;;
  webtransport) : "${FED_SCHEME:=webtransport}"; : "${FED_PORT:=51828}" ;;
  *)
    echo "FED_WIRE must be one of: h2s | h2 | webtransport (got ${FED_WIRE})" >&2
    exit 2
    ;;
esac
export TOPOLOGY FED_SCHEME FED_PORT

# project name embeds topology so multiple sweeps don't clash
PROJ="topology-${TOPOLOGY}"

echo "[0/5] Topology=${TOPOLOGY}  Wire=${FED_SCHEME}://…:${FED_PORT}"

# ─── Generate the compose YAML from the topology spec ────────────
TOPOLOGY="$TOPOLOGY" FED_SCHEME="$FED_SCHEME" FED_PORT="$FED_PORT" \
  python3 gen-compose.py > docker-compose.yml

# ─── Build the image ──────────────────────────────────────────────
echo "[1/5] Building (cached after first run)…"
docker compose -p "$PROJ" build --quiet

# ─── Generate identities + inventories ────────────────────────────
echo "[2/5] Generating fifteen fresh DRIFT identities…"
rm -rf identities inventory-c1 inventory-c2 inventory-c3 inventory-c4 inventory-c5
mkdir -p identities inventory-c1 inventory-c2 inventory-c3 inventory-c4 inventory-c5

DRIFT_BIN=$(realpath ../../target/debug/drift)
if [ ! -x "$DRIFT_BIN" ]; then
  (cd ../.. && cargo build -p drift --bin drift -q)
fi

VERTICES=(b1 b2 b3 b4 b5 s1 s2 s3 s4 s5 c1 c2 c3 c4 c5)
for n in "${VERTICES[@]}"; do
  "$DRIFT_BIN" keygen --output "identities/$n.key" >/dev/null
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "identities/$n.key" > "identities/$n.hex"
done

read_pub() {
  "$DRIFT_BIN" info "identities/$1.key" | grep -oE '[0-9a-f]{64}' | head -1
}

PUB_B1=$(read_pub b1); PUB_B2=$(read_pub b2); PUB_B3=$(read_pub b3)
PUB_B4=$(read_pub b4); PUB_B5=$(read_pub b5)
PUB_S1=$(read_pub s1); PUB_S2=$(read_pub s2); PUB_S3=$(read_pub s3)
PUB_S4=$(read_pub s4); PUB_S5=$(read_pub s5)

pub_for() {
  case "$1" in
    b1) echo "$PUB_B1" ;; b2) echo "$PUB_B2" ;; b3) echo "$PUB_B3" ;;
    b4) echo "$PUB_B4" ;; b5) echo "$PUB_B5" ;;
    s1) echo "$PUB_S1" ;; s2) echo "$PUB_S2" ;; s3) echo "$PUB_S3" ;;
    s4) echo "$PUB_S4" ;; s5) echo "$PUB_S5" ;;
    *) echo "??" >&2; return 1 ;;
  esac
}

BRIDGE_IDS=(b1 b2 b3 b4 b5)
CLIENT_IDS=(c1 c2 c3 c4 c5)
SERVER_IDS=(s1 s2 s3 s4 s5)
BRIDGE_IPS=(10.56.0.11 10.56.0.12 10.56.0.13 10.56.0.14 10.56.0.15)

write_inventory() {
  local cid=$1 pub=$2 ip=$3
  cat > "inventory-$cid/drift.toml" <<EOF
default_bridge = "$pub"

[network]
name = "federation-topology-${TOPOLOGY}"

[hosts.local-bridge]
pubkey = "$pub"
endpoints = ["udp://$ip:51820"]
EOF
}

for i in 0 1 2 3 4; do
  cid="${CLIENT_IDS[$i]}"
  bid="${BRIDGE_IDS[$i]}"
  bip="${BRIDGE_IPS[$i]}"
  write_inventory "$cid" "$(pub_for "$bid")" "$bip"
done

# ─── Bring up + converge ──────────────────────────────────────────
echo "[3/5] Starting 5 bridges + 5 servers + 5 clients…"
export PUB_B1 PUB_B2 PUB_B3 PUB_B4 PUB_B5
docker compose -p "$PROJ" down --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$PROJ" up -d --quiet-pull

echo "[4/5] Waiting 45s for directory propagation…"
sleep 45

# ─── 20 cross-bridge dials ────────────────────────────────────────
echo "[5/5] 20 cross-bridge dials:"
PASS=0
FAIL=0
RESULTS=()

run_dial() {
  local from=$1 to_name=$2 to_pub=$3
  local out
  out=$(docker exec "top-client-$from" drift-mosh-client \
    --identity-file "/identities/$from.hex" \
    --server-pub "$to_pub" \
    --attach-timeout-secs 20 \
    --exec "echo TOPOLOGY_OK_${from}_to_${to_name}" \
    --exec-timeout 10 2>&1 || true)
  if echo "$out" | grep -q "TOPOLOGY_OK_${from}_to_${to_name}"; then
    printf "  PASS  %s -> %s\n" "$from" "$to_name"
    RESULTS+=("PASS ${from}->${to_name}")
    PASS=$((PASS+1))
  else
    printf "  FAIL  %s -> %s\n" "$from" "$to_name"
    RESULTS+=("FAIL ${from}->${to_name}")
    FAIL=$((FAIL+1))
  fi
}

for i in 0 1 2 3 4; do
  from="${CLIENT_IDS[$i]}"
  for j in 0 1 2 3 4; do
    if [ "$i" -ne "$j" ]; then
      to="${SERVER_IDS[$j]}"
      run_dial "$from" "$to" "$(pub_for "$to")"
    fi
  done
done

echo ""
echo "  Summary: $PASS pass / $FAIL fail (of 20)  topology=${TOPOLOGY}  wire=${FED_SCHEME}"

if [ "${KEEP_UP:-0}" != "1" ]; then
  docker compose -p "$PROJ" down --remove-orphans >/dev/null 2>&1 || true
fi

# Always exit 0 so a sweep loop continues even when individual runs
# fail; the operator reads pass/fail counts to decide what's broken.
exit 0

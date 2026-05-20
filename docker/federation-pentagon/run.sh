#!/bin/bash
# End-to-end federation-pentagon test driver.
#
# 5 bridges in a complete graph (K5): every bridge federates to
# every other. Verifies federation directory propagation scales
# past the 3-bridge triangle case and that bridge fanout doesn't
# introduce delivery bugs at 4-peer-per-bridge density.
#
# Topology:           1
#                 5 ──┼── 2          (every line is a --federate)
#                 │   │   │           10 edges total
#                 │   │   │
#                 4 ──┴── 3
#
# 20 cross-bridge dials (every client → every non-local server).
#
# Differences from federation-triangle/run.sh:
#  • 45 s convergence (was 14 s) — empirically required on Docker
#    Desktop / macOS where containers don't get the full host CPU.
#    Bridges still announce every 7 s; we just give 6× the budget.
#  • Uses `drift info` to derive bridge pubkeys (same as triangle).
#  • Subnet 10.55.0.0/24 so it can coexist with the triangle.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

VERTICES=(b1 b2 b3 b4 b5 s1 s2 s3 s4 s5 c1 c2 c3 c4 c5)
BRIDGE_IDS=(b1 b2 b3 b4 b5)
CLIENT_IDS=(c1 c2 c3 c4 c5)
SERVER_IDS=(s1 s2 s3 s4 s5)
BRIDGE_IPS=(10.55.0.11 10.55.0.12 10.55.0.13 10.55.0.14 10.55.0.15)

# ─── Build the image ──────────────────────────────────────────────
echo "[1/5] Building drift-federation-discovery image (reused)…"
docker compose -p federation-pentagon build --quiet

# ─── Generate identities locally and bind-mount them ──────────────
echo "[2/5] Generating fifteen fresh DRIFT identities…"
rm -rf identities inventory-c1 inventory-c2 inventory-c3 inventory-c4 inventory-c5
mkdir -p identities inventory-c1 inventory-c2 inventory-c3 inventory-c4 inventory-c5

DRIFT_BIN=$(realpath ../../target/debug/drift)
if [ ! -x "$DRIFT_BIN" ]; then
  (cd ../.. && cargo build -p drift --bin drift -q)
fi

for n in "${VERTICES[@]}"; do
  "$DRIFT_BIN" keygen --output "identities/$n.key" >/dev/null
  # drift-mosh expects hex-format identity files; derive from the
  # DRFT-magic file (skip first 4 bytes of "DRFT" header).
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "identities/$n.key" > "identities/$n.hex"
done

read_pub() {
  "$DRIFT_BIN" info "identities/$1.key" | grep -oE '[0-9a-f]{64}' | head -1
}

# macOS still ships bash 3.2 which lacks `declare -A`. Use one
# variable per vertex (15 verts → 15 vars, named `PUB_<UPPER>`).
PUB_B1=$(read_pub b1); PUB_B2=$(read_pub b2); PUB_B3=$(read_pub b3)
PUB_B4=$(read_pub b4); PUB_B5=$(read_pub b5)
PUB_S1=$(read_pub s1); PUB_S2=$(read_pub s2); PUB_S3=$(read_pub s3)
PUB_S4=$(read_pub s4); PUB_S5=$(read_pub s5)
PUB_C1=$(read_pub c1); PUB_C2=$(read_pub c2); PUB_C3=$(read_pub c3)
PUB_C4=$(read_pub c4); PUB_C5=$(read_pub c5)

# Helper that prints the pubkey for a given vertex name. Used in
# loops where we'd otherwise want an associative lookup.
pub_for() {
  case "$1" in
    b1) echo "$PUB_B1" ;; b2) echo "$PUB_B2" ;; b3) echo "$PUB_B3" ;;
    b4) echo "$PUB_B4" ;; b5) echo "$PUB_B5" ;;
    s1) echo "$PUB_S1" ;; s2) echo "$PUB_S2" ;; s3) echo "$PUB_S3" ;;
    s4) echo "$PUB_S4" ;; s5) echo "$PUB_S5" ;;
    c1) echo "$PUB_C1" ;; c2) echo "$PUB_C2" ;; c3) echo "$PUB_C3" ;;
    c4) echo "$PUB_C4" ;; c5) echo "$PUB_C5" ;;
    *) echo "??" >&2; return 1 ;;
  esac
}

echo "  bridges: B1=${PUB_B1:0:10}… B2=${PUB_B2:0:10}… B3=${PUB_B3:0:10}… B4=${PUB_B4:0:10}… B5=${PUB_B5:0:10}…"
echo "  servers: S1=${PUB_S1:0:10}… S2=${PUB_S2:0:10}… S3=${PUB_S3:0:10}… S4=${PUB_S4:0:10}… S5=${PUB_S5:0:10}…"

# ─── Materialize each client's drift.toml ─────────────────────────
# Inventory deliberately knows only the local on-ramp bridge.
# Discovery handles every other vertex via directory propagation.
write_inventory() {
  local cid=$1 pub=$2 ip=$3
  cat > "inventory-$cid/drift.toml" <<EOF
default_bridge = "$pub"

[network]
name = "federation-pentagon"

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

# ─── Bring up the stack ──────────────────────────────────────────
echo "[3/5] Starting 5 bridges + 5 servers + 5 clients (15 containers)…"
export PUB_B1 PUB_B2 PUB_B3 PUB_B4 PUB_B5
docker compose -p federation-pentagon down --remove-orphans >/dev/null 2>&1 || true
docker compose -p federation-pentagon up -d --quiet-pull

# ─── Wait for the K5 directory mesh to converge ───────────────────
# Bridges announce every 7 s; at K5 each bridge has 4 federation
# peers, so directory state is roughly 4× the triangle case. 45 s
# gives ~6 announce intervals — plenty of slack on Docker Desktop.
echo "[4/5] Waiting 45s for K5 federation directories to converge…"
sleep 45

# Sanity: each server should print its banner.
for s in "${SERVER_IDS[@]}"; do
  banner=$(docker logs "pent-server-$s" 2>&1 | grep DRIFT_MOSH | head -1)
  if [ -n "$banner" ]; then
    echo "  $s: ${banner:0:80}…"
  else
    echo "  $s: NO BANNER (likely bridge-server handshake failed)"
  fi
done

# ─── Run 20 cross-bridge dials ────────────────────────────────────
echo "[5/5] 20 cross-bridge dials (each client → every non-local server):"
PASS=0
FAIL=0
RESULTS=()

run_dial() {
  local from=$1 to_name=$2 to_pub=$3
  local out
  # --attach-timeout-secs 20 (was hardcoded 5 s before mosh got
  # the flag): federation cold-start on Docker Desktop / macOS
  # occasionally needs longer than the 5 s default while the
  # cross-bridge directory entries warm up.
  out=$(docker exec "pent-client-$from" drift-mosh-client \
    --identity-file "/identities/$from.hex" \
    --server-pub "$to_pub" \
    --attach-timeout-secs 20 \
    --exec "echo PENTAGON_OK_${from}_to_${to_name}" \
    --exec-timeout 10 2>&1 || true)
  if echo "$out" | grep -q "PENTAGON_OK_${from}_to_${to_name}"; then
    printf "  PASS  %s -> %s\n" "$from" "$to_name"
    RESULTS+=("PASS ${from}->${to_name}")
    PASS=$((PASS+1))
  else
    printf "  FAIL  %s -> %s\n" "$from" "$to_name"
    echo "$out" | tail -3 | sed 's/^/        /'
    RESULTS+=("FAIL ${from}->${to_name}")
    FAIL=$((FAIL+1))
  fi
}

# Each client dials the four remote servers (every (c, s) pair
# where index(c) != index(s)).
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
echo "  Summary: $PASS pass / $FAIL fail (of 20)"

# Show only failures in summary, plus a "all good" if everything passed.
if [ "$FAIL" -gt 0 ]; then
  echo "  Failures:"
  for r in "${RESULTS[@]}"; do
    case "$r" in
      FAIL*) echo "    $r" ;;
    esac
  done
fi

# Optionally keep containers up for log inspection.
if [ "${KEEP_UP:-0}" = "1" ]; then
  echo ""
  echo "  KEEP_UP=1 set — containers left running for inspection:"
  echo "    docker logs pent-bridge-b1  (etc)"
  echo "    docker compose -p federation-pentagon down --remove-orphans"
else
  docker compose -p federation-pentagon down --remove-orphans >/dev/null 2>&1 || true
fi

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "  K5 federation works: directory propagation reached every vertex"
  echo "  through every on-ramp at 4-peer-per-bridge density."
  exit 0
else
  echo ""
  echo "  One or more cross-bridge dials failed; see output above."
  exit 1
fi

#!/bin/bash
# Corporate federation reliability test.
#
# Brings up a 17-bridge tiered corporate topology (DMZ + backbone +
# regional hubs + branches) with a server attached to every bridge
# and 6 clients distributed across branches. Each client dials every
# non-local server (96 cross-bridge dials).
#
# Dial results are categorized by the federation-path hop count
# between the client's bridge and the server's bridge. A reliable
# federation should pass 100 % of dials at every depth up to the
# topology diameter (4 hops for this design).
#
# Usage:
#   bash run.sh                       (default: h2s federation)
#   FED_WIRE=h2 bash run.sh
#   KEEP_UP=1 bash run.sh             (preserve containers for log
#                                       inspection)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

# ─── Wire selection ───────────────────────────────────────────────
case "${FED_WIRE:-h2s}" in
  h2s)          : "${FED_SCHEME:=h2s}";          : "${FED_PORT:=51827}" ;;
  h2)           : "${FED_SCHEME:=h2}";           : "${FED_PORT:=51826}" ;;
  webtransport) : "${FED_SCHEME:=webtransport}"; : "${FED_PORT:=51828}" ;;
  *)
    echo "FED_WIRE must be one of: h2s | h2 | webtransport" >&2
    exit 2
    ;;
esac
export FED_SCHEME FED_PORT

PROJ="federation-corporate"

echo "[0/7] Wire: ${FED_SCHEME}://…:${FED_PORT}"

# ─── Generate the compose YAML ───────────────────────────────────
FED_SCHEME="$FED_SCHEME" FED_PORT="$FED_PORT" \
  python3 gen-compose.py > docker-compose.yml

# ─── Build image ──────────────────────────────────────────────────
echo "[1/7] Building docker image (cached after first run)…"
docker compose -p "$PROJ" build --quiet

# ─── Identities + inventories ────────────────────────────────────
echo "[2/7] Generating identities for 17 bridges + 17 servers + 6 clients…"
rm -rf identities inventory-c-*
mkdir -p identities

DRIFT_BIN=$(realpath ../../target/debug/drift)
if [ ! -x "$DRIFT_BIN" ]; then
  (cd ../.. && cargo build -p drift --bin drift -q)
fi

# Bridges + clients use `<name>.key`; servers use `s-<bridge>.key`
# (so a bridge `be1` has matching `be1.key` and `s-be1.key`).
BRIDGES=(
  edge1 edge2
  dc1 dc2 dc3
  hub-east hub-central hub-west
  be1 be2 be3
  bc1 bc2 bc3
  bw1 bw2 bw3
)
CLIENTS=(c-be1 c-be3 c-bc1 c-bc3 c-bw1 c-bw3)

# macOS still ships bash 3.2 — no `declare -A`. Use case-statement
# lookups instead of associative arrays.
client_home() {
  case "$1" in
    c-be1) echo "be1" ;; c-be3) echo "be3" ;;
    c-bc1) echo "bc1" ;; c-bc3) echo "bc3" ;;
    c-bw1) echo "bw1" ;; c-bw3) echo "bw3" ;;
    *) echo "??" >&2; return 1 ;;
  esac
}

bridge_index() {
  local i=0
  for b in "${BRIDGES[@]}"; do
    if [ "$b" = "$1" ]; then echo "$i"; return; fi
    i=$((i+1))
  done
  echo "-1"
}

# Identity names: 17 + 17 + 6 = 40 keys.
IDENTITIES=( "${BRIDGES[@]}" )
for b in "${BRIDGES[@]}"; do IDENTITIES+=("s-$b"); done
IDENTITIES+=( "${CLIENTS[@]}" )

for n in "${IDENTITIES[@]}"; do
  "$DRIFT_BIN" keygen --output "identities/$n.key" >/dev/null
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "identities/$n.key" > "identities/$n.hex"
done

read_pub() {
  "$DRIFT_BIN" info "identities/$1.key" | grep -oE '[0-9a-f]{64}' | head -1
}

# Bridge + server pubkeys as flat shell vars (PUB_<BRIDGE> /
# SPUB_<BRIDGE>) — the compose file's ${PUB_…} interpolation
# reads PUB_<BRIDGE_NAME_UPPER_UNDERSCORED>.
for b in "${BRIDGES[@]}"; do
  v=$(echo "$b" | tr 'a-z-' 'A-Z_')
  declare -x "PUB_$v=$(read_pub "$b")"
  declare -x "SPUB_$v=$(read_pub "s-$b")"
done

# Bridge pubkey lookup helper (reads from the PUB_<NAME> vars
# we just exported).
pub_for() {
  local v
  v=$(echo "$1" | tr 'a-z-' 'A-Z_')
  eval "echo \$PUB_$v"
}
spub_for() {
  local v
  v=$(echo "$1" | tr 'a-z-' 'A-Z_')
  eval "echo \$SPUB_$v"
}

# Per-client drift.toml: each client knows only its home bridge as
# default_bridge — federation discovery handles the rest.
write_inventory() {
  local client=$1 bridge=$2
  local pub
  pub=$(pub_for "$bridge")
  local idx
  idx=$(bridge_index "$bridge")
  local bridge_ip="10.57.0.$((11 + idx))"
  mkdir -p "inventory-$client"
  cat > "inventory-$client/drift.toml" <<EOF
default_bridge = "$pub"

[network]
name = "federation-corporate"

[hosts.local-bridge]
pubkey = "$pub"
endpoints = ["udp://$bridge_ip:51820"]
EOF
}

for c in "${CLIENTS[@]}"; do
  write_inventory "$c" "$(client_home "$c")"
done

# ─── Bring up the stack ──────────────────────────────────────────
echo "[3/7] Starting 17 bridges + 17 servers + 6 clients (40 containers)…"
docker compose -p "$PROJ" down --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$PROJ" up -d --quiet-pull

# ─── Convergence wait ────────────────────────────────────────────
# Worst-case path is 4 hops. Announce ticker is 7 s. Each
# re-announce adds one hop of propagation, so 4-hop directory
# entries need ~28 s minimum. 60 s gives ~8 announce intervals
# of slack, plenty for the directory to converge end-to-end on
# Docker Desktop.
echo "[4/7] Waiting 60s for the federation directory to converge…"
sleep 60

# ─── Compute shortest-path hop counts via BFS ────────────────────
# So we can categorize dial results by the federation-path
# length and report which depths work.
echo "[5/7] Computing hop-count matrix (BFS over the federation graph)…"
HOPS_FILE=$(mktemp)
python3 <<'PY' > "$HOPS_FILE"
from collections import deque

BRIDGES = [
    "edge1", "edge2",
    "dc1", "dc2", "dc3",
    "hub-east", "hub-central", "hub-west",
    "be1", "be2", "be3",
    "bc1", "bc2", "bc3",
    "bw1", "bw2", "bw3",
]
EDGES = [
    ("dc1", "dc2"), ("dc1", "dc3"), ("dc2", "dc3"),
    ("edge1", "dc1"), ("edge1", "dc2"),
    ("edge2", "dc2"), ("edge2", "dc3"),
    ("hub-east", "dc1"), ("hub-east", "dc2"),
    ("hub-central", "dc2"), ("hub-central", "dc3"),
    ("hub-west", "dc1"), ("hub-west", "dc3"),
    ("be1", "hub-east"), ("be2", "hub-east"), ("be3", "hub-east"),
    ("bc1", "hub-central"), ("bc2", "hub-central"), ("bc3", "hub-central"),
    ("bw1", "hub-west"), ("bw2", "hub-west"), ("bw3", "hub-west"),
]

adj = {b: set() for b in BRIDGES}
for a, b in EDGES:
    adj[a].add(b); adj[b].add(a)

def hops(src, dst):
    if src == dst:
        return 0
    seen = {src}
    q = deque([(src, 0)])
    while q:
        n, d = q.popleft()
        for nb in adj[n]:
            if nb == dst:
                return d + 1
            if nb not in seen:
                seen.add(nb); q.append((nb, d + 1))
    return -1

# Emit `<src> <dst> <hops>` for every bridge pair.
for s in BRIDGES:
    for d in BRIDGES:
        if s != d:
            print(f"{s} {d} {hops(s, d)}")
PY

# ─── Run cross-bridge dials ──────────────────────────────────────
echo "[6/7] Running cross-bridge dials (6 clients × 16 servers = 96 total)…"
TOTAL=0
PASS=0
FAIL=0
# Parallel arrays indexed by hop count 0..6 (no assoc arrays).
HOPS_PASS=(0 0 0 0 0 0 0)
HOPS_FAIL=(0 0 0 0 0 0 0)
HOPS_TOTAL=(0 0 0 0 0 0 0)

for c in "${CLIENTS[@]}"; do
  src_bridge=$(client_home "$c")
  for s in "${BRIDGES[@]}"; do
    if [ "$s" = "$src_bridge" ]; then
      continue   # skip same-bridge dials (no federation involved)
    fi
    hop=$(grep "^$src_bridge $s " "$HOPS_FILE" | awk '{print $3}')
    TOTAL=$((TOTAL+1))
    HOPS_TOTAL[$hop]=$((HOPS_TOTAL[$hop]+1))
    sp=$(spub_for "$s")
    out=$(docker exec "corp-client-$c" drift-mosh-client \
      --identity-file "/identities/$c.hex" \
      --server-pub "$sp" \
      --attach-timeout-secs 20 \
      --exec "echo CORP_OK_${c}_to_${s}" \
      --exec-timeout 8 2>&1 || true)
    if echo "$out" | grep -q "CORP_OK_${c}_to_${s}"; then
      printf "  PASS  %-7s -> %-12s (%d hop)\n" "$c" "$s" "$hop"
      PASS=$((PASS+1))
      HOPS_PASS[$hop]=$((HOPS_PASS[$hop]+1))
    else
      printf "  FAIL  %-7s -> %-12s (%d hop)\n" "$c" "$s" "$hop"
      FAIL=$((FAIL+1))
      HOPS_FAIL[$hop]=$((HOPS_FAIL[$hop]+1))
    fi
  done
done

# ─── Summary ─────────────────────────────────────────────────────
echo ""
echo "[7/7] Results: $PASS / $TOTAL pass ($FAIL fail) — wire=${FED_SCHEME}"
echo ""
echo "  by hop count:"
for hop in 1 2 3 4 5 6; do
  t=${HOPS_TOTAL[$hop]}
  if [ "$t" -gt 0 ]; then
    p=${HOPS_PASS[$hop]}
    printf "    %d hop: %2d / %2d pass\n" "$hop" "$p" "$t"
  fi
done

# Cleanup unless KEEP_UP set.
if [ "${KEEP_UP:-0}" != "1" ]; then
  docker compose -p "$PROJ" down --remove-orphans >/dev/null 2>&1 || true
fi

rm -f "$HOPS_FILE"

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "  Corporate federation works across the full diameter (4 hops)."
  exit 0
else
  exit 1
fi

#!/bin/bash
# Native-process variant of the corporate federation test, designed
# to run on a single Linux host (no Docker).
#
# Each bridge gets its own port range on 127.0.0.1:
#   bridge_index i (0..16) uses:
#     udp listen   on  127.0.0.1: 5{1820 + i*10}
#     h2s listen   on  127.0.0.1: 5{1827 + i*10}
#     (so b0 = 51820/51827, b1 = 51830/51837, …, b16 = 51980/51987)
#
# Servers connect to their local bridge via udp (port from above).
# Clients similarly.
#
# Federation links use h2s://127.0.0.1:<port>@<pubkey>.
#
# Purpose: verify whether the 80-84% reliability ceiling we saw
# with Docker Desktop on macOS is environmental. Running the same
# topology as native processes on real Linux removes the Docker
# Desktop VM as a variable. If pass rate climbs significantly,
# the protocol is fine and the docker numbers are CPU-contention
# noise. If similar, there's a real bug at K=17 worth chasing.
#
# Run as:
#   bash run-native.sh             (default h2s)
#   FED_WIRE=h2 bash run-native.sh

set -eu

# ─── Wire selection ──────────────────────────────────────────────
case "${FED_WIRE:-h2s}" in
  h2s)          : "${FED_SCHEME:=h2s}";          : "${FED_PORT_BASE_OFFSET:=7}" ;;
  h2)           : "${FED_SCHEME:=h2}";           : "${FED_PORT_BASE_OFFSET:=6}" ;;
  webtransport) : "${FED_SCHEME:=webtransport}"; : "${FED_PORT_BASE_OFFSET:=8}" ;;
  iroh)         : "${FED_SCHEME:=iroh}";         : "${FED_PORT_BASE_OFFSET:=8}" ;;
  *) echo "FED_WIRE must be h2s|h2|webtransport|iroh" >&2; exit 2 ;;
esac

# Iroh needs a deterministic SecretKey per bridge so that
# `iroh://<endpoint_id>@<host:port>@<bridge_pub>` URLs survive
# restarts AND so that the test orchestrator can compute / probe
# them once and reuse. Seeds are SHA-256 of "drift-corp-<bridge>".
IROH=0; [ "$FED_SCHEME" = "iroh" ] && IROH=1

HERE=$(cd "$(dirname "$0")" && pwd)

# Working directories. Use /tmp/drift-corp-test so we don't clutter HERE.
WORK="${WORK_DIR:-/tmp/drift-corp-test}"
BIN_DIR="${BIN_DIR:-$WORK/bin}"
IDENT_DIR="$WORK/identities"
LOG_DIR="$WORK/logs"
PID_DIR="$WORK/pids"
mkdir -p "$IDENT_DIR" "$LOG_DIR" "$PID_DIR"

DRIFT_BIN="$BIN_DIR/drift"
MOSH_SERVER="$BIN_DIR/drift-mosh-server"
MOSH_CLIENT="$BIN_DIR/drift-mosh-client"

for b in "$DRIFT_BIN" "$MOSH_SERVER" "$MOSH_CLIENT"; do
  if [ ! -x "$b" ]; then echo "missing binary: $b" >&2; exit 1; fi
done

# ─── Topology ────────────────────────────────────────────────────
BRIDGES=(
  edge1 edge2
  dc1 dc2 dc3
  hub-east hub-central hub-west
  be1 be2 be3
  bc1 bc2 bc3
  bw1 bw2 bw3
)
EDGES_STR="\
dc1-dc2 dc1-dc3 dc2-dc3 \
edge1-dc1 edge1-dc2 edge2-dc2 edge2-dc3 \
hub-east-dc1 hub-east-dc2 hub-central-dc2 hub-central-dc3 hub-west-dc1 hub-west-dc3 \
be1-hub-east be2-hub-east be3-hub-east \
bc1-hub-central bc2-hub-central bc3-hub-central \
bw1-hub-west bw2-hub-west bw3-hub-west"

CLIENTS=(c-be1 c-be3 c-bc1 c-bc3 c-bw1 c-bw3)
client_home() {
  case "$1" in
    c-be1) echo be1 ;; c-be3) echo be3 ;;
    c-bc1) echo bc1 ;; c-bc3) echo bc3 ;;
    c-bw1) echo bw1 ;; c-bw3) echo bw3 ;;
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

# Port plan: bridge i uses udp:5{1820+i*10}, h2s:5{1827+i*10}, etc.
udp_port() {  printf '%d' $((51820 + 10 * $(bridge_index "$1"))); }
fed_port() {  printf '%d' $((51820 + FED_PORT_BASE_OFFSET + 10 * $(bridge_index "$1"))); }

# Bridge ↔ bridge pairs from EDGES_STR (each "a-b" → "a b").
edge_pairs() {
  for e in $EDGES_STR; do
    # The hyphenated bridge names mean we can't just split on -. List each
    # edge explicitly. Names contain hub-east etc, so use a fixed split.
    case "$e" in
      dc1-dc2)     echo "dc1 dc2" ;;
      dc1-dc3)     echo "dc1 dc3" ;;
      dc2-dc3)     echo "dc2 dc3" ;;
      edge1-dc1)   echo "edge1 dc1" ;;
      edge1-dc2)   echo "edge1 dc2" ;;
      edge2-dc2)   echo "edge2 dc2" ;;
      edge2-dc3)   echo "edge2 dc3" ;;
      hub-east-dc1)    echo "hub-east dc1" ;;
      hub-east-dc2)    echo "hub-east dc2" ;;
      hub-central-dc2) echo "hub-central dc2" ;;
      hub-central-dc3) echo "hub-central dc3" ;;
      hub-west-dc1)    echo "hub-west dc1" ;;
      hub-west-dc3)    echo "hub-west dc3" ;;
      be1-hub-east)    echo "be1 hub-east" ;;
      be2-hub-east)    echo "be2 hub-east" ;;
      be3-hub-east)    echo "be3 hub-east" ;;
      bc1-hub-central) echo "bc1 hub-central" ;;
      bc2-hub-central) echo "bc2 hub-central" ;;
      bc3-hub-central) echo "bc3 hub-central" ;;
      bw1-hub-west)    echo "bw1 hub-west" ;;
      bw2-hub-west)    echo "bw2 hub-west" ;;
      bw3-hub-west)    echo "bw3 hub-west" ;;
    esac
  done
}

# Federation peers of a given bridge (both directions of the edge).
peers_of() {
  local b="$1"
  edge_pairs | while read a c; do
    if [ "$a" = "$b" ]; then echo "$c"; fi
    if [ "$c" = "$b" ]; then echo "$a"; fi
  done
}

echo "[0/6] Wire ${FED_SCHEME} | bridges=${#BRIDGES[@]} clients=${#CLIENTS[@]}"

# ─── Identities ──────────────────────────────────────────────────
echo "[1/6] Generating identities…"
IDENTITIES=( "${BRIDGES[@]}" )
for b in "${BRIDGES[@]}"; do IDENTITIES+=("s-$b"); done
IDENTITIES+=( "${CLIENTS[@]}" )

for n in "${IDENTITIES[@]}"; do
  if [ ! -f "$IDENT_DIR/$n.key" ]; then
    "$DRIFT_BIN" keygen --output "$IDENT_DIR/$n.key" >/dev/null
  fi
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    "$IDENT_DIR/$n.key" > "$IDENT_DIR/$n.hex"
done

read_pub() {
  "$DRIFT_BIN" info "$IDENT_DIR/$1.key" | grep -oE '[0-9a-f]{64}' | head -1
}

for b in "${BRIDGES[@]}"; do
  v=$(echo "$b" | tr 'a-z-' 'A-Z_')
  declare -x "PUB_$v=$(read_pub "$b")"
  declare -x "SPUB_$v=$(read_pub "s-$b")"
done
pub_for()  { eval "echo \$PUB_$(echo "$1" | tr 'a-z-' 'A-Z_')"; }
spub_for() { eval "echo \$SPUB_$(echo "$1" | tr 'a-z-' 'A-Z_')"; }

# ─── Iroh seeds + probe-discover endpoint ids ────────────────────
# iroh URLs need <endpoint_id>; we compute it via a short-lived
# probe boot of each bridge's iroh listener, then scrape the
# "iroh listener bound — id=…" line and kill the probe.
iroh_id_for() { eval "echo \$IROH_ID_$(echo "$1" | tr 'a-z-' 'A-Z_')"; }
iroh_seed_for() { eval "echo \$IROH_SEED_$(echo "$1" | tr 'a-z-' 'A-Z_')"; }

if [ "$IROH" = 1 ]; then
  echo "[1b/6] Seeding iroh secret keys + probing endpoint ids…"
  # Deterministic per-bridge seed: sha256("drift-corp-<bridge>")[:32 bytes]
  for b in "${BRIDGES[@]}"; do
    seed=$(printf "drift-corp-%s" "$b" | sha256sum | cut -d' ' -f1)
    v=$(echo "$b" | tr 'a-z-' 'A-Z_')
    declare -x "IROH_SEED_$v=$seed"
  done

  # Spawn each bridge with just an iroh listener, no federation.
  for b in "${BRIDGES[@]}"; do
    fport=$(fed_port "$b")
    seed=$(iroh_seed_for "$b")
    DRIFT_IROH_SECRET_HEX="$seed" \
      "$DRIFT_BIN" --identity "$IDENT_DIR/$b.key" bridge \
      --listen iroh://0.0.0.0:${fport} \
      > "$LOG_DIR/probe-$b.log" 2>&1 &
    echo $! > "$PID_DIR/probe-$b.pid"
  done
  sleep 4

  # Scrape ids
  for b in "${BRIDGES[@]}"; do
    id=$(grep -oE 'id=[0-9a-f]{64}' "$LOG_DIR/probe-$b.log" | head -1 | cut -d= -f2)
    if [ -z "$id" ]; then
      echo "FAILED to scrape iroh id for $b — check $LOG_DIR/probe-$b.log" >&2
      exit 1
    fi
    v=$(echo "$b" | tr 'a-z-' 'A-Z_')
    declare -x "IROH_ID_$v=$id"
  done

  # Kill probe bridges
  for b in "${BRIDGES[@]}"; do
    if [ -f "$PID_DIR/probe-$b.pid" ]; then
      kill "$(cat "$PID_DIR/probe-$b.pid")" 2>/dev/null || true
      rm -f "$PID_DIR/probe-$b.pid"
    fi
  done
  sleep 2
  pkill -f "drift.*--listen iroh" 2>/dev/null || true
  sleep 1
fi

# ─── Start bridges ───────────────────────────────────────────────
echo "[2/6] Spawning 17 bridges as native processes…"
for b in "${BRIDGES[@]}"; do
  uport=$(udp_port "$b")
  fport=$(fed_port "$b")
  # Construct --federate flags for each peer bridge.
  feds=""
  for p in $(peers_of "$b"); do
    pp=$(fed_port "$p")
    if [ "$IROH" = 1 ]; then
      pid=$(iroh_id_for "$p")
      feds="$feds --federate iroh://${pid}@127.0.0.1:${pp}@$(pub_for "$p")"
    else
      feds="$feds --federate ${FED_SCHEME}://127.0.0.1:${pp}@$(pub_for "$p")"
    fi
  done

  if [ "$IROH" = 1 ]; then
    seed=$(iroh_seed_for "$b")
    DRIFT_IROH_SECRET_HEX="$seed" \
      "$DRIFT_BIN" --identity "$IDENT_DIR/$b.key" bridge \
      --listen udp://127.0.0.1:${uport} \
      --listen iroh://0.0.0.0:${fport} \
      $feds \
      > "$LOG_DIR/bridge-$b.log" 2>&1 &
  else
    "$DRIFT_BIN" --identity "$IDENT_DIR/$b.key" bridge \
      --listen udp://127.0.0.1:${uport} \
      --listen ${FED_SCHEME}://127.0.0.1:${fport} \
      $feds \
      > "$LOG_DIR/bridge-$b.log" 2>&1 &
  fi
  echo $! > "$PID_DIR/bridge-$b.pid"
done

# Wait briefly for bridge listeners to come up.
sleep 2

# ─── Start servers ───────────────────────────────────────────────
echo "[3/6] Spawning 17 mosh servers…"
for b in "${BRIDGES[@]}"; do
  uport=$(udp_port "$b")
  "$MOSH_SERVER" \
    --identity-file "$IDENT_DIR/s-$b.hex" \
    --bridge "udp://127.0.0.1:${uport}@$(pub_for "$b")" \
    --shell /bin/sh \
    > "$LOG_DIR/server-$b.log" 2>&1 &
  echo $! > "$PID_DIR/server-$b.pid"
done

# ─── Convergence wait ────────────────────────────────────────────
# 30s default — federation directory propagation needs ~25-30s
# on a 12-core unconstrained host (every bridge's BEACON jitter
# adds a half-interval spread; BFS over 22 federation edges
# takes O(diameter × beacon_interval) to fully populate). On
# constrained hosts (Drift-4: 2 cores) routes don't get faster
# with longer waits — CPU is the bottleneck — but shortening
# doesn't help either, so we keep the 30s default and let
# operators override via env if they have a reason.
CONVERGE_WAIT_SECS="${CONVERGE_WAIT_SECS:-30}"
echo "[4/6] Waiting ${CONVERGE_WAIT_SECS}s for federation directory to converge…"
sleep "$CONVERGE_WAIT_SECS"

# ─── BFS hop-count matrix ────────────────────────────────────────
echo "[5/6] Computing hop-count matrix…"
HOPS_FILE=$(mktemp)
python3 <<'PY' > "$HOPS_FILE"
from collections import deque
BRIDGES = [
  "edge1","edge2","dc1","dc2","dc3",
  "hub-east","hub-central","hub-west",
  "be1","be2","be3","bc1","bc2","bc3","bw1","bw2","bw3"]
EDGES = [
  ("dc1","dc2"),("dc1","dc3"),("dc2","dc3"),
  ("edge1","dc1"),("edge1","dc2"),("edge2","dc2"),("edge2","dc3"),
  ("hub-east","dc1"),("hub-east","dc2"),
  ("hub-central","dc2"),("hub-central","dc3"),
  ("hub-west","dc1"),("hub-west","dc3"),
  ("be1","hub-east"),("be2","hub-east"),("be3","hub-east"),
  ("bc1","hub-central"),("bc2","hub-central"),("bc3","hub-central"),
  ("bw1","hub-west"),("bw2","hub-west"),("bw3","hub-west")]
adj = {b:set() for b in BRIDGES}
for a,b in EDGES: adj[a].add(b); adj[b].add(a)
def hops(s,d):
  if s==d: return 0
  seen={s}; q=deque([(s,0)])
  while q:
    n,k=q.popleft()
    for nb in adj[n]:
      if nb==d: return k+1
      if nb not in seen: seen.add(nb); q.append((nb,k+1))
for s in BRIDGES:
  for d in BRIDGES:
    if s!=d: print(f"{s} {d} {hops(s,d)}")
PY

# ─── Dials ───────────────────────────────────────────────────────
echo "[6/6] Running 96 cross-bridge dials…"
TOTAL=0; PASS=0; FAIL=0
HOPS_PASS=(0 0 0 0 0 0 0); HOPS_TOTAL=(0 0 0 0 0 0 0)

# Skip drift.toml entirely — when running as root the default
# inventory path is /etc/drift/drift.toml which we don't have.
# Instead pass --bridge + --target-bridge directly to mosh-client
# so it has all the routing info it needs without inventory.
# target-bridge = UNKNOWN_BRIDGE_PUB (zero) tells the local bridge
# to resolve via its peer directory (federation discovery).

ZERO_BRIDGE_PUB="0000000000000000000000000000000000000000000000000000000000000000"

for c in "${CLIENTS[@]}"; do
  src=$(client_home "$c")
  src_pub=$(pub_for "$src")
  src_port=$(udp_port "$src")
  for s in "${BRIDGES[@]}"; do
    if [ "$s" = "$src" ]; then continue; fi
    hop=$(grep "^$src $s " "$HOPS_FILE" | awk '{print $3}')
    TOTAL=$((TOTAL+1))
    HOPS_TOTAL[$hop]=$((HOPS_TOTAL[$hop]+1))
    out=$("$MOSH_CLIENT" \
        --identity-file "$IDENT_DIR/$c.hex" \
        --server-pub "$(spub_for "$s")" \
        --bridge "udp://127.0.0.1:${src_port}@${src_pub}" \
        --target-bridge "$ZERO_BRIDGE_PUB" \
        --attach-timeout-secs 20 \
        --exec "echo CORP_NATIVE_OK_${c}_to_${s}" \
        --exec-timeout 8 2>&1 || true)
    if echo "$out" | grep -q "CORP_NATIVE_OK_${c}_to_${s}"; then
      printf "  PASS  %-7s -> %-12s (%d hop)\n" "$c" "$s" "$hop"
      PASS=$((PASS+1))
      HOPS_PASS[$hop]=$((HOPS_PASS[$hop]+1))
    else
      printf "  FAIL  %-7s -> %-12s (%d hop)\n" "$c" "$s" "$hop"
      FAIL=$((FAIL+1))
    fi
  done
done

echo ""
echo "[done] $PASS / $TOTAL pass ($FAIL fail) — wire=$FED_SCHEME"
for hop in 1 2 3 4 5 6; do
  t=${HOPS_TOTAL[$hop]}
  if [ "$t" -gt 0 ]; then
    printf "    %d hop: %2d / %2d pass\n" "$hop" "${HOPS_PASS[$hop]}" "$t"
  fi
done

# ─── Cleanup ─────────────────────────────────────────────────────
if [ "${KEEP_UP:-0}" != "1" ]; then
  echo ""
  echo "Tearing down processes…"
  for p in "$PID_DIR"/*.pid; do
    [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true
  done
  sleep 1
  for p in "$PID_DIR"/*.pid; do
    [ -f "$p" ] && kill -9 "$(cat "$p")" 2>/dev/null || true
  done
  rm -f "$PID_DIR"/*.pid
fi

rm -f "$HOPS_FILE"
exit 0

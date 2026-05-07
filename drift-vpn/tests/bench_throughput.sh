#!/usr/bin/env bash
# v0.7 benchmark harness for drift-vpn tunnel throughput.
#
# Distinct from `throughput.sh` (which is a CI sanity check
# that "throughput is non-zero"). This is the OPTIMIZATION
# benchmark — same numbers each run, designed to be re-run
# before/after each performance change so the delta is clear.
#
# Reports both throughput AND CPU cost. Throughput alone can
# mislead (a CPU-bound bench looks the same regardless of the
# code path); CPU-per-Gbps is the real efficiency number.
#
# Run mode:
#   bash bench_throughput.sh                   # standard 30s run
#   DURATION=60 bash bench_throughput.sh       # longer
#   STREAMS=8 bash bench_throughput.sh         # more parallelism

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-bench-net"
NODE_A="drift-vpn-bench-a"
NODE_B="drift-vpn-bench-b"
WORKDIR="/tmp/drift-vpn-bench-test"
DURATION="${DURATION:-30}"
STREAMS="${STREAMS:-4}"
LABEL="${LABEL:-baseline}"

cleanup() {
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$WORKDIR"
echo "==> Building $IMAGE"
if ! docker build -f Dockerfile -t "$IMAGE" .. >/dev/null 2> "$WORKDIR/build.err"; then
    echo "FAIL: docker build"; tail -30 "$WORKDIR/build.err"; exit 1
fi

cleanup
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet 172.43.0.0/24 "$NETWORK" >/dev/null
A_IP="172.43.0.10"
B_IP="172.43.0.11"

docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/a.key > "$WORKDIR/a.pub"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/b.key > "$WORKDIR/b.pub"
PUB_A=$(cat "$WORKDIR/a.pub")
PUB_B=$(cat "$WORKDIR/b.pub")

cat > "$WORKDIR/a.toml" <<EOF
[interface]
identity_file = "/keys/a.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://${B_IP}:51820"
EOF
cat > "$WORKDIR/b.toml" <<EOF
[interface]
identity_file = "/keys/b.key"
address       = "10.99.0.2/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "$PUB_A"
allowed_ips = ["10.99.0.1/32"]
endpoint    = "udp://${A_IP}:51820"
EOF

start() {
    local name=$1 ip=$2 cfg=$3
    docker run -d \
        --name "$name" --hostname "$name" \
        --network "$NETWORK" --ip "$ip" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
        -e RUST_LOG="drift_vpn=warn,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/$cfg" >/dev/null
}

start "$NODE_A" "$A_IP" "a.toml"
start "$NODE_B" "$B_IP" "b.toml"
sleep 3

# Sanity: tunnel up.
docker exec "$NODE_A" ping -c 1 -W 3 10.99.0.2 >/dev/null || {
    echo "FAIL: tunnel didn't come up"; exit 1; }

echo
echo "================================================================"
echo "  drift-vpn throughput benchmark — label='$LABEL'"
echo "  duration=${DURATION}s streams=$STREAMS"
echo "================================================================"

# CPU baseline: capture both daemon containers' CPU before iperf3
# to compute "cpu used by the bench" rather than includes-startup.
docker_cpu() {
    docker stats --no-stream --format '{{.CPUPerc}}' "$1" | tr -d '%'
}

# Start iperf3 server.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 0.5

# Snapshot CPU just before the run.
A_CPU_BEFORE=$(docker_cpu "$NODE_A")
B_CPU_BEFORE=$(docker_cpu "$NODE_B")

# TCP run, JSON output.
echo "==> TCP iperf3 (${DURATION}s, ${STREAMS} streams)"
docker exec "$NODE_A" iperf3 \
    -c 10.99.0.2 -t "$DURATION" -P "$STREAMS" -J \
    > "$WORKDIR/tcp.json" 2> "$WORKDIR/tcp.err" || {
    echo "FAIL: TCP iperf3"; cat "$WORKDIR/tcp.err"; exit 1; }

# Snapshot CPU just after — averaged over the run.
A_CPU_AFTER=$(docker_cpu "$NODE_A")
B_CPU_AFTER=$(docker_cpu "$NODE_B")

TCP_GBPS=$(python3 -c "
import json
d = json.load(open('$WORKDIR/tcp.json'))
print(f\"{d['end']['sum_received']['bits_per_second']/1e9:.3f}\")
")
TCP_RETX=$(python3 -c "
import json
d = json.load(open('$WORKDIR/tcp.json'))
print(d['end']['sum_sent'].get('retransmits', 0))
")

# UDP run — different question: how much UDP can we push without
# packet loss? Run at 80% of TCP throughput as a target.
TARGET_MBPS=$(python3 -c "print(int(float('$TCP_GBPS')*1000*0.8))")
echo "==> UDP iperf3 (${DURATION}s, target ${TARGET_MBPS}M, 1200B datagrams)"
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 0.5
docker exec "$NODE_A" iperf3 \
    -c 10.99.0.2 -t "$DURATION" -u -b "${TARGET_MBPS}M" -l 1200 -J \
    > "$WORKDIR/udp.json" 2> "$WORKDIR/udp.err" || true

UDP_GBPS=$(python3 -c "
import json
try:
    d = json.load(open('$WORKDIR/udp.json'))
    print(f\"{d['end']['sum']['bits_per_second']/1e9:.3f}\")
except Exception:
    print('n/a')
")
UDP_LOSS=$(python3 -c "
import json
try:
    d = json.load(open('$WORKDIR/udp.json'))
    print(f\"{d['end']['sum'].get('lost_percent', 0):.2f}\")
except Exception:
    print('n/a')
")

echo
echo "================================================================"
echo "  RESULTS — $LABEL"
echo "================================================================"
printf "  TCP:  %s Gbps  (%s retransmits)\n" "$TCP_GBPS" "$TCP_RETX"
printf "  UDP:  %s Gbps  (%s%% loss)\n" "$UDP_GBPS" "$UDP_LOSS"
echo
printf "  CPU during run:\n"
printf "    node-a: %s%% → %s%%\n" "$A_CPU_BEFORE" "$A_CPU_AFTER"
printf "    node-b: %s%% → %s%%\n" "$B_CPU_BEFORE" "$B_CPU_AFTER"
TOTAL_CPU=$(python3 -c "print(round(float('$A_CPU_AFTER') + float('$B_CPU_AFTER'), 1))")
TCP_GBPS_NUM=$(python3 -c "print(float('$TCP_GBPS'))")
if python3 -c "import sys; sys.exit(0 if float('$TCP_GBPS_NUM') > 0.01 else 1)"; then
    CPU_PER_GBPS=$(python3 -c "print(round($TOTAL_CPU/$TCP_GBPS_NUM, 1))")
    printf "    total: %s%%   →  %s%% per Gbps\n" "$TOTAL_CPU" "$CPU_PER_GBPS"
fi
echo "================================================================"
echo

# CSV-ish line for easy paste into a spreadsheet.
echo "BENCH,$LABEL,${DURATION},${STREAMS},$TCP_GBPS,$UDP_GBPS,$UDP_LOSS,$A_CPU_AFTER,$B_CPU_AFTER"

#!/usr/bin/env bash
# Stability test: 60 seconds of continuous ping at 10 Hz
# (~600 packets) plus a parallel 60-second iperf3 TCP stream
# in the background. Verifies:
#
#   1. ≥99% ICMP delivery — no random drops mid-stream.
#   2. Both daemons stay alive (process check at the end).
#   3. No "send_data dropped" or other WARN spam in logs
#      (the kind that would suggest leaks or accumulating
#      state).
#
# This is the simplest "did anything regress over time" check.
# Real stability needs hours, but 60s in CI catches the obvious
# fast-leak / fast-deadlock regressions.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-stab-net"
NODE_A="drift-vpn-stab-a"
NODE_B="drift-vpn-stab-b"
WORKDIR="/tmp/drift-vpn-stab-test"
DURATION="${DURATION:-60}"

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
docker network create --subnet 172.37.0.0/24 "$NETWORK" >/dev/null
A_IP="172.37.0.10"
B_IP="172.37.0.11"

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
        -e RUST_LOG="drift_vpn=info,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/$cfg" >/dev/null
}

start "$NODE_A" "$A_IP" "a.toml"
start "$NODE_B" "$B_IP" "b.toml"
sleep 2

# Sanity check first.
docker exec "$NODE_A" ping -c 1 -W 3 10.99.0.2 >/dev/null || {
    echo "FAIL: tunnel didn't come up"; exit 1; }

PINGS=$((DURATION * 10))
echo "==> Continuous ping for ${DURATION}s ($PINGS pings at 10 Hz) + parallel iperf3"

# Background iperf3 server.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 0.5

# Background iperf3 client (loose; we only care it doesn't
# crash the daemon).
docker exec -d "$NODE_A" sh -c \
    "iperf3 -c 10.99.0.2 -t $DURATION -P 2 -J > /tmp/iperf.out 2>&1"

# Foreground ping. -i 0.1 = 10 packets/s. -W 1 = 1s timeout
# per packet. Capture stats; tolerate ICMP-recoverable drops
# (since a few may be dropped under simultaneous iperf load).
docker exec "$NODE_A" ping -c "$PINGS" -i 0.1 -W 1 10.99.0.2 \
    > "$WORKDIR/ping.out" 2>&1 || true

# Parse result.
SENT=$(grep -oE '[0-9]+ packets transmitted' "$WORKDIR/ping.out" | head -1 | awk '{print $1}')
RECV=$(grep -oE '[0-9]+ received' "$WORKDIR/ping.out" | head -1 | awk '{print $1}')
LOSS_PCT=$(grep -oE '[0-9.]+% packet loss' "$WORKDIR/ping.out" | head -1 | awk '{print $1}' | tr -d '%')
echo "    ping: $RECV / $SENT delivered, $LOSS_PCT% loss"

# Wait for iperf3 to finish, copy its result out, parse on
# the host (the runtime image is Debian slim, no python3).
sleep 5
docker cp "$NODE_A:/tmp/iperf.out" "$WORKDIR/iperf.out" 2>/dev/null || true
IPERF_MBPS=$(python3 -c "
import json
try:
    with open('$WORKDIR/iperf.out') as f: d = json.load(f)
    print(f\"{d['end']['sum_received']['bits_per_second']/1e6:.1f}\")
except Exception:
    print('n/a')
" 2>/dev/null)
echo "    iperf3 over the same ${DURATION}s: $IPERF_MBPS Mbps received"

# Health checks.
fail=0
LOSS_OK=$(python3 -c "print(1 if float('$LOSS_PCT' or 100) <= 1.0 else 0)")
if [ "$LOSS_OK" -eq 0 ]; then
    echo "FAIL: ping loss $LOSS_PCT% > 1% threshold"
    fail=1
fi
for n in "$NODE_A" "$NODE_B"; do
    if [ "$(docker inspect -f '{{.State.Status}}' $n 2>/dev/null)" != "running" ]; then
        echo "FAIL: $n is no longer running"
        fail=1
    fi
done
WARNS_A=$(docker logs "$NODE_A" 2>&1 | grep -c "send_data dropped" || true)
WARNS_B=$(docker logs "$NODE_B" 2>&1 | grep -c "send_data dropped" || true)
if [ "$WARNS_A" -gt 0 ] || [ "$WARNS_B" -gt 0 ]; then
    echo "FAIL: send_data dropped warnings in steady state — A=$WARNS_A, B=$WARNS_B"
    fail=1
fi
[ "$fail" -ne 0 ] && exit 1

echo
echo "PASS: ${DURATION}s continuous load"
echo "RESULT: drift-vpn stable over ${DURATION}s — $RECV/$SENT pings"
echo "        ($LOSS_PCT% loss), iperf3 $IPERF_MBPS Mbps in parallel,"
echo "        no daemon crashes, no send_data drops in steady state."

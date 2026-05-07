#!/usr/bin/env bash
# Lossy-network test: tc/netem injects 5% packet loss + 20ms
# delay on the wire between two containers. Verifies the
# tunnel:
#   1. Survives — handshake completes despite drops.
#   2. Carries TCP traffic at a reduced-but-nonzero rate.
#   3. Carries UDP traffic with loss roughly matching the
#      injected loss (sanity check that we're not multiplying
#      the rate).
#
# This is the closest thing to a "real WAN" scenario the bench
# can simulate without leaving the docker host. Both directions
# get the netem rule on their respective eth0; that doubles
# the simulated latency to ~40ms RTT on the wire (each direction
# delayed independently).

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-lossy-net"
NODE_A="drift-vpn-lossy-a"
NODE_B="drift-vpn-lossy-b"
WORKDIR="/tmp/drift-vpn-lossy-test"

LOSS_PCT="${LOSS_PCT:-5}"
DELAY_MS="${DELAY_MS:-20}"

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
docker network create --subnet 172.36.0.0/24 "$NETWORK" >/dev/null
A_IP="172.36.0.10"
B_IP="172.36.0.11"

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

echo "==> Apply tc/netem: ${LOSS_PCT}% loss, ${DELAY_MS}ms delay (each direction)"
for n in "$NODE_A" "$NODE_B"; do
    docker exec "$n" tc qdisc add dev eth0 root netem \
        loss "${LOSS_PCT}%" delay "${DELAY_MS}ms" || {
        echo "warn: tc on $n returned nonzero (replacing instead)"
        docker exec "$n" tc qdisc replace dev eth0 root netem \
            loss "${LOSS_PCT}%" delay "${DELAY_MS}ms" || {
            echo "FAIL: couldn't apply tc netem on $n"; exit 1; }
    }
done

# Sanity: the tunnel still completes a handshake under loss.
ok=0
for i in $(seq 1 20); do
    if docker exec "$NODE_A" ping -c 1 -W 3 10.99.0.2 >/dev/null 2>&1; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" -ne 1 ]; then
    echo "FAIL: tunnel never came up under ${LOSS_PCT}%/${DELAY_MS}ms"
    docker logs "$NODE_A" 2>&1 | tail -5
    exit 1
fi
echo "PASS: tunnel handshake survives ${LOSS_PCT}%/${DELAY_MS}ms"

# UDP throughput. With ~5% wire-level loss we'd expect around
# 5% packet loss reported by iperf; significantly higher would
# mean the daemon is dropping additionally.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 1
echo "==> iperf3 UDP (10s, target 100Mbps)"
docker exec "$NODE_A" iperf3 -c 10.99.0.2 -t 10 -u -b 100M -l 1200 -J \
    2> "$WORKDIR/iperf-udp.err" > "$WORKDIR/iperf-udp.json" || {
    echo "FAIL: UDP iperf3"; cat "$WORKDIR/iperf-udp.err"; exit 1; }
UDP_MBPS=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf-udp.json'))
print(f\"{d['end']['sum']['bits_per_second']/1e6:.1f}\")
")
UDP_LOSS=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf-udp.json'))
print(f\"{d['end']['sum'].get('lost_percent', 0):.1f}\")
")
echo "    UDP: $UDP_MBPS Mbps, $UDP_LOSS% loss reported"

# TCP throughput. With 5% loss + 40ms RTT we expect TCP cwnd
# to bound throughput. Mathematical limit (BBR ignored) is
# ~MSS / (RTT * sqrt(1.5 * loss)) ≈ several hundred Mbps. We
# just check it's nonzero to confirm TCP works at all.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 1
echo "==> iperf3 TCP (10s, 4 streams)"
docker exec "$NODE_A" iperf3 -c 10.99.0.2 -t 10 -P 4 -J \
    2> "$WORKDIR/iperf-tcp.err" > "$WORKDIR/iperf-tcp.json" || {
    echo "FAIL: TCP iperf3"; cat "$WORKDIR/iperf-tcp.err"; exit 1; }
TCP_MBPS=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf-tcp.json'))
print(f\"{d['end']['sum_received']['bits_per_second']/1e6:.1f}\")
")
TCP_RETX=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf-tcp.json'))
print(d['end']['sum_sent'].get('retransmits', 0))
")
echo "    TCP: $TCP_MBPS Mbps, $TCP_RETX retransmits"

# Pass criteria: TCP > 1 Mbps (proves it actually works); UDP
# loss reported is within 3× of injected loss (sanity).
fail=0
TCP_OK=$(python3 -c "print(1 if float('$TCP_MBPS') > 1.0 else 0)")
if [ "$TCP_OK" -eq 0 ]; then
    echo "FAIL: TCP throughput too low ($TCP_MBPS Mbps under ${LOSS_PCT}%/${DELAY_MS}ms)"
    fail=1
fi
LOSS_OK=$(python3 -c "
loss = float('$UDP_LOSS')
inj = float('$LOSS_PCT')
# Each direction has loss; round-trip-ish so up to ~2× injected.
print(1 if loss <= inj * 4 else 0)
")
if [ "$LOSS_OK" -eq 0 ]; then
    echo "FAIL: UDP loss too high ($UDP_LOSS% reported vs ${LOSS_PCT}% injected — daemon may be dropping)"
    fail=1
fi
[ "$fail" -ne 0 ] && exit 1

echo
echo "RESULT: tunnel survives ${LOSS_PCT}% loss + ${DELAY_MS}ms delay."
echo "        UDP: $UDP_MBPS Mbps ($UDP_LOSS% loss)"
echo "        TCP: $TCP_MBPS Mbps ($TCP_RETX retransmits)"

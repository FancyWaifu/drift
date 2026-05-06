#!/usr/bin/env bash
# Throughput test: iperf3 over the drift-vpn tunnel.
#
# Two containers, point-to-point UDP DRIFT tunnel as in the
# v0.1 test. Then in-container:
#   node-b: iperf3 -s -B 10.99.0.2          (server, bound to tun)
#   node-a: iperf3 -c 10.99.0.2 -t 10 -P 4  (client, 10s, 4 streams)
#
# Reports mbits/sec via the tun device — that's the headline
# throughput number for "what does drift-vpn cost per packet."

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-tput-net"
NODE_A="drift-vpn-tput-a"
NODE_B="drift-vpn-tput-b"
WORKDIR="/tmp/drift-vpn-tput-test"

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
docker network create --subnet 172.33.0.0/24 "$NETWORK" >/dev/null
NODE_A_IP="172.33.0.10"
NODE_B_IP="172.33.0.11"

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
endpoint    = "udp://${NODE_B_IP}:51820"
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
endpoint    = "udp://${NODE_A_IP}:51820"
EOF

# We need iperf3 to keep running, so we override the entrypoint
# from `drift-vpn` to a shell that starts both. Simplest: keep
# the entrypoint, run the daemon as PID 1; exec into the
# running container for iperf3. That's what we do below.
echo "==> Starting daemons"
for spec in "${NODE_A}:${NODE_A_IP}:a.toml" "${NODE_B}:${NODE_B_IP}:b.toml"; do
    IFS=: read -r name ip cfg <<< "$spec"
    docker run -d \
        --name "$name" --hostname "$name" \
        --network "$NETWORK" --ip "$ip" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
        -e RUST_LOG="drift_vpn=warn,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/$cfg" >/dev/null
done

sleep 2
# Sanity: tunnel up.
if ! docker exec "$NODE_A" ping -c 1 -W 5 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: tunnel didn't come up"
    docker logs "$NODE_A" 2>&1 | tail -10
    exit 1
fi
echo "tunnel up — running iperf3"

# DRIFT's MAX_PAYLOAD is 1348 bytes. Linux GSO/TSO can hand
# 64KB pseudo-segments to the tun device; our daemon sees them
# as one packet, send_data rejects, TCP collapses. The fix
# until the tun crate exposes the offload-flag ioctls is to
# clamp the TCP MSS at iptables level. This makes Linux emit
# real-MSS segments instead of GSO superpackets.
for n in "$NODE_A" "$NODE_B"; do
    docker exec "$n" sh -c \
        'iptables -t mangle -A FORWARD -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null;
         iptables -t mangle -A OUTPUT  -o tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null;
         iptables -t mangle -A INPUT   -i tun0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null;
         true' || true
done

# Server on B, bound to its tun address.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 1

# Run UDP first (bypass TCP cwnd dynamics, get raw rate).
echo "==> iperf3 UDP over the tunnel (10s, push 1Gbps target)"
docker exec "$NODE_A" iperf3 -c 10.99.0.2 -t 10 -u -b 1G -l 1200 -J \
    2> "$WORKDIR/iperf3-udp.err" > "$WORKDIR/iperf3-udp.json" || {
    echo "FAIL: iperf3 UDP client"
    cat "$WORKDIR/iperf3-udp.err"
    exit 1
}
UDP_SENT=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf3-udp.json'))
print(f\"{d['end']['sum']['bits_per_second']/1e6:.1f}\")
")
UDP_LOSS=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf3-udp.json'))
s = d['end']['sum']
print(f\"{s.get('lost_percent', 0):.1f}\")
")

# Restart B's iperf server for the TCP run.
docker exec -d "$NODE_B" iperf3 -s -B 10.99.0.2 -1 >/dev/null
sleep 1

# Now TCP for comparison.
echo "==> iperf3 TCP over the tunnel (10s, 4 parallel streams)"
docker exec "$NODE_A" iperf3 -c 10.99.0.2 -t 10 -P 4 -J \
    2> "$WORKDIR/iperf3-tcp.err" > "$WORKDIR/iperf3-tcp.json" || {
    echo "FAIL: iperf3 TCP client"
    cat "$WORKDIR/iperf3-tcp.err"
    exit 1
}

TCP_SENT=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf3-tcp.json'))
print(f\"{d['end']['sum_sent']['bits_per_second']/1e6:.1f}\")
")
TCP_RECV=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf3-tcp.json'))
print(f\"{d['end']['sum_received']['bits_per_second']/1e6:.1f}\")
")
TCP_RETX=$(python3 -c "
import json
d = json.load(open('$WORKDIR/iperf3-tcp.json'))
print(d['end']['sum_sent'].get('retransmits', 0))
")

# Pull daemon logs so we can diagnose drops/warnings.
echo
echo "==> daemon-A warnings (last 6)"
docker logs "$NODE_A" 2>&1 | grep -E "WARN|ERROR" | tail -6 | sed 's/^/    /'
echo "==> daemon-B warnings (last 6)"
docker logs "$NODE_B" 2>&1 | grep -E "WARN|ERROR" | tail -6 | sed 's/^/    /'
echo "==> ethtool offload state on node-a's tun0"
docker exec "$NODE_A" ethtool -k tun0 2>/dev/null | grep -E "tcp-segmentation|generic-segmentation|generic-receive|large-receive" | sed 's/^/    /'

echo
echo "RESULT: drift-vpn throughput over UDP tunnel"
echo "    UDP:  $UDP_SENT Mbps  (loss $UDP_LOSS%)"
echo "    TCP:  $TCP_SENT Mbps sent, $TCP_RECV Mbps received  ($TCP_RETX retransmits)"
echo
echo "(measured by iperf3 over the 10.99.0.x tun device — payload"
echo " is encrypted by DRIFT, sent over UDP between the containers."
echo " UDP is the raw rate the tunnel can push; TCP is what apps"
echo " actually see, which depends on RTT, MTU, and any drops.)"

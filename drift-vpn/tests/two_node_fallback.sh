#!/usr/bin/env bash
# v0.2 test: server-side multi-listen.
#
# Each node binds TWO listeners simultaneously
#   listen = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
#
# This is the ship-able piece of the multi-transport story:
# one daemon offers multiple wires, and each peer's endpoint
# config picks one (or, when v0.3 ships per-endpoint Transports,
# the daemon will pick at runtime). For this test, peers reach
# each other on UDP — but the TCP listener also comes up,
# proving the multi-listen plumbing works.
#
# v0.3 will extend this with runtime fallover (try each
# endpoint, switch transports mid-session if the active wire
# degrades). v0.2 ships the foundations.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-fb-net"
NODE_A="drift-vpn-fb-a"
NODE_B="drift-vpn-fb-b"
WORKDIR="/tmp/drift-vpn-fb-test"

cleanup() {
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$WORKDIR"
echo "==> Building $IMAGE"
if ! docker build -f Dockerfile -t "$IMAGE" .. >/dev/null 2> "$WORKDIR/build.err"; then
    echo "FAIL: docker build"
    tail -30 "$WORKDIR/build.err"
    exit 1
fi

echo "==> Cleaning state"
cleanup
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet 172.31.0.0/24 "$NETWORK" >/dev/null
NODE_A_IP="172.31.0.10"
NODE_B_IP="172.31.0.11"

echo "==> Generating identities"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/a.key > "$WORKDIR/a.pub"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/b.key > "$WORKDIR/b.pub"
PUB_A=$(cat "$WORKDIR/a.pub")
PUB_B=$(cat "$WORKDIR/b.pub")
echo "    a pub: ${PUB_A:0:16}...   b pub: ${PUB_B:0:16}..."

cat > "$WORKDIR/a.toml" <<EOF
[interface]
identity_file = "/keys/a.key"
address       = "10.99.0.1/24"
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1380
name          = "tun0"

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoints   = [
  "udp://${NODE_B_IP}:51820",
  "tcp://${NODE_B_IP}:51821",
]
EOF

cat > "$WORKDIR/b.toml" <<EOF
[interface]
identity_file = "/keys/b.key"
address       = "10.99.0.2/24"
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1380
name          = "tun0"

[[peer]]
public_key  = "$PUB_A"
allowed_ips = ["10.99.0.1/32"]
endpoints   = [
  "udp://${NODE_A_IP}:51820",
  "tcp://${NODE_A_IP}:51821",
]
EOF

echo "==> Starting node-a (static IP $NODE_A_IP)"
docker run -d \
    --name "$NODE_A" --hostname "$NODE_A" \
    --network "$NETWORK" --ip "$NODE_A_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
    -e RUST_LOG="drift_vpn=info,drift=warn" \
    "$IMAGE" up -c /etc/drift-vpn/a.toml >/dev/null

echo "==> Starting node-b (static IP $NODE_B_IP)"
docker run -d \
    --name "$NODE_B" --hostname "$NODE_B" \
    --network "$NETWORK" --ip "$NODE_B_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
    -e RUST_LOG="drift_vpn=info,drift=warn" \
    "$IMAGE" up -c /etc/drift-vpn/b.toml >/dev/null

echo "==> Waiting 3s for both daemons to settle"
sleep 3

echo "==> node-a logs"
docker logs "$NODE_A" 2>&1 | sed 's/^/    /' | tail -10
echo
echo "==> node-b logs"
docker logs "$NODE_B" 2>&1 | sed 's/^/    /' | tail -10

# Verify the multi-listen banner appeared on both sides.
fail=0
for node in "$NODE_A" "$NODE_B"; do
    if ! docker logs "$node" 2>&1 | grep -q "additional listener bound"; then
        echo "FAIL: $node didn't bind a second listener"
        fail=1
    fi
done

# Verify both primary listeners came up.
for node in "$NODE_A" "$NODE_B"; do
    if ! docker logs "$node" 2>&1 | grep -q "DRIFT transport bound"; then
        echo "FAIL: $node didn't bind primary listener"
        fail=1
    fi
done

[ $fail -ne 0 ] && exit 1
echo "PASS: both nodes bound primary UDP + additional TCP listeners"

echo
echo "==> Pinging 10.99.0.2 from node-a"
if docker exec "$NODE_A" ping -c 3 -W 5 10.99.0.2 2>&1 | tail -8; then
    echo "PASS: a → b ping works"
else
    echo "FAIL: ping a → b"
    exit 1
fi

echo
echo "==> Pinging 10.99.0.1 from node-b"
if docker exec "$NODE_B" ping -c 3 -W 5 10.99.0.1 2>&1 | tail -8; then
    echo "PASS: b → a ping works"
else
    echo "FAIL: ping b → a"
    exit 1
fi

echo
echo "RESULT: drift-vpn v0.2 multi-listen works (UDP + TCP listeners up;"
echo "        peers reach each other on UDP; TCP listener idle but live)"

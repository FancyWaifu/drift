#!/usr/bin/env bash
# Two-node drift-vpn test:
#
#   1. Build the image (multi-stage; only drift-vpn bin).
#   2. keygen identities for two nodes.
#   3. Generate matching TOML configs.
#   4. Bring up two containers on a shared bridge.
#   5. ping 10.99.0.2 from node-a; verify packets round-trip
#      through DRIFT-encrypted tunnel.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-test-net"
NODE_A="drift-vpn-node-a"
NODE_B="drift-vpn-node-b"
WORKDIR="/tmp/drift-vpn-test"

cleanup() {
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building $IMAGE"
docker build -f Dockerfile -t "$IMAGE" .. >/dev/null

echo "==> Cleaning state"
cleanup
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
# Recreate the network with a known subnet so we can pin
# static IPs. Docker's embedded DNS works for container-name
# resolution between containers on the same user-defined
# bridge, but it's only reliable AFTER both containers have
# joined — at startup, node-a may try to resolve node-b
# before node-b is registered. Static IPs sidestep that race.
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet 172.30.0.0/24 "$NETWORK" >/dev/null
NODE_A_IP="172.30.0.10"
NODE_B_IP="172.30.0.11"

echo "==> Generating identities"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/a.key > "$WORKDIR/a.pub"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/b.key > "$WORKDIR/b.pub"
PUB_A=$(cat "$WORKDIR/a.pub")
PUB_B=$(cat "$WORKDIR/b.pub")
echo "    node-a pub: ${PUB_A:0:16}..."
echo "    node-b pub: ${PUB_B:0:16}..."

cat > "$WORKDIR/a.toml" <<EOF
[interface]
identity_file = "/keys/a.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1380
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
mtu           = 1380
name          = "tun0"

[[peer]]
public_key  = "$PUB_A"
allowed_ips = ["10.99.0.1/32"]
endpoint    = "udp://${NODE_A_IP}:51820"
EOF

echo "==> Starting node-a (static IP $NODE_A_IP)"
docker run -d \
    --name "$NODE_A" \
    --hostname "$NODE_A" \
    --network "$NETWORK" \
    --ip "$NODE_A_IP" \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    -v "$WORKDIR:/etc/drift-vpn" \
    -v "$WORKDIR:/keys" \
    -e RUST_LOG="drift_vpn=info,drift=warn" \
    "$IMAGE" \
    up -c /etc/drift-vpn/a.toml \
    >/dev/null

echo "==> Starting node-b (static IP $NODE_B_IP)"
docker run -d \
    --name "$NODE_B" \
    --hostname "$NODE_B" \
    --network "$NETWORK" \
    --ip "$NODE_B_IP" \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    -v "$WORKDIR:/etc/drift-vpn" \
    -v "$WORKDIR:/keys" \
    -e RUST_LOG="drift_vpn=info,drift=warn" \
    "$IMAGE" \
    up -c /etc/drift-vpn/b.toml \
    >/dev/null

echo "==> Waiting for both daemons to settle (handshake)"
sleep 3

# Show what each side thinks is happening.
echo "==> node-a logs"
docker logs "$NODE_A" 2>&1 | sed 's/^/     /' | tail -10
echo "==> node-b logs"
docker logs "$NODE_B" 2>&1 | sed 's/^/     /' | tail -10

echo
echo "==> Pinging 10.99.0.2 from node-a"
if docker exec "$NODE_A" ping -c 3 -W 5 10.99.0.2 2>&1 | tee "$WORKDIR/ping-a-to-b.out"; then
    echo "PASS: a → b ping works"
else
    echo "FAIL: ping a → b"
    echo "--- node-a logs ---"
    docker logs --tail=30 "$NODE_A"
    echo "--- node-b logs ---"
    docker logs --tail=30 "$NODE_B"
    exit 1
fi

echo
echo "==> Pinging 10.99.0.1 from node-b"
if docker exec "$NODE_B" ping -c 3 -W 5 10.99.0.1 2>&1 | tee "$WORKDIR/ping-b-to-a.out"; then
    echo "PASS: b → a ping works"
else
    echo "FAIL: ping b → a"
    exit 1
fi

echo
echo "RESULT: drift-vpn two-node tunnel works — packets cross between containers via DRIFT"

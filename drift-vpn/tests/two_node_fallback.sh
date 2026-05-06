#!/usr/bin/env bash
# v0.3 test: real client-side happy-eyeballs across endpoints.
#
# Each node has TWO endpoints for the other:
#   1. udp://172.31.0.99:51820 — DEAD (no host on that IP).
#   2. udp://<real peer IP>:51820 — REAL.
#
# The daemon tries them in priority order. First endpoint times
# out after PROBE_TIMEOUT (1.5s); daemon does
# update_peer_addr + restart_handshake; second endpoint gets a
# fresh HELLO at the new addr; handshake completes; tunnel up.
#
# Also exercises server-side multi-listen: each node binds
# udp://...:51820 + tcp://...:51821. The TCP listener is idle
# but live, demonstrating that v0.2 multi-listen still works
# alongside v0.3 happy-eyeballs.
#
# Same scheme (UDP) on all endpoints. Cross-scheme outbound
# (UDP→TLS) is v0.4 work because it needs per-peer outbound
# interface pinning.

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
DEAD_IP="172.31.0.99"

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
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoints   = [
  "udp://${DEAD_IP}:51820",
  "udp://${NODE_B_IP}:51820",
]
EOF

cat > "$WORKDIR/b.toml" <<EOF
[interface]
identity_file = "/keys/b.key"
address       = "10.99.0.2/24"
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "$PUB_A"
allowed_ips = ["10.99.0.1/32"]
endpoints   = [
  "udp://${DEAD_IP}:51820",
  "udp://${NODE_A_IP}:51820",
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

# Each node tries dead (1.5s timeout), then real. Both nodes
# come up concurrently; once both are at the real endpoint, the
# handshake completes within ~100ms. So 4-5s total.
echo "==> Waiting 6s for happy-eyeballs to fall through"
sleep 6

echo "==> node-a logs (last 12 lines)"
docker logs "$NODE_A" 2>&1 | sed 's/^/    /' | tail -12
echo
echo "==> node-b logs (last 12 lines)"
docker logs "$NODE_B" 2>&1 | sed 's/^/    /' | tail -12

fail=0
# Both nodes should bind multi-listen (UDP primary + TCP fallback).
for node in "$NODE_A" "$NODE_B"; do
    if ! docker logs "$node" 2>&1 | grep -q "additional listener bound"; then
        echo "FAIL: $node didn't bind a second listener"
        fail=1
    fi
done

# Both nodes should report the dead endpoint timed out, then
# log a happy-eyeballs winner at the second endpoint.
for node in "$NODE_A" "$NODE_B"; do
    if ! docker logs "$node" 2>&1 | grep -q "no handshake within timeout"; then
        echo "FAIL: $node didn't log a timeout on the dead endpoint"
        fail=1
    fi
    if ! docker logs "$node" 2>&1 | grep -q "happy-eyeballs winner"; then
        echo "FAIL: $node didn't log a happy-eyeballs winner"
        fail=1
    fi
done

[ $fail -ne 0 ] && exit 1
echo "PASS: dead endpoint timed out, real endpoint won"

echo
echo "==> Pinging 10.99.0.2 from node-a"
if docker exec "$NODE_A" ping -c 3 -W 5 10.99.0.2 2>&1 | tail -8; then
    echo "PASS: a → b ping works after fallback"
else
    echo "FAIL: ping a → b"
    exit 1
fi

echo
echo "==> Pinging 10.99.0.1 from node-b"
if docker exec "$NODE_B" ping -c 3 -W 5 10.99.0.1 2>&1 | tail -8; then
    echo "PASS: b → a ping works after fallback"
else
    echo "FAIL: ping b → a"
    exit 1
fi

echo
echo "RESULT: drift-vpn v0.3 — happy-eyeballs across endpoints works."
echo "        Each daemon tried a dead endpoint first, fell through to"
echo "        the real one via update_peer_addr + restart_handshake,"
echo "        and the tunnel came up cleanly."

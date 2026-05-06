#!/usr/bin/env bash
# Restart resilience: kill node-a's daemon, restart it with the
# same identity + config, verify the tunnel reestablishes.
#
# This is the "what happens when one side dies" case — VPN
# users hit it via systemd restarts, OOM kills, daemon crashes.
# The same identity reconnecting should land cleanly without
# manual intervention on the surviving peer.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-restart-net"
NODE_A="drift-vpn-restart-a"
NODE_B="drift-vpn-restart-b"
WORKDIR="/tmp/drift-vpn-restart-test"

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
docker network create --subnet 172.34.0.0/24 "$NETWORK" >/dev/null
NODE_A_IP="172.34.0.10"
NODE_B_IP="172.34.0.11"

# Identities are persistent so node-a can rejoin with the same
# pubkey after restart.
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

start_node() {
    local name=$1 ip=$2 cfg=$3
    docker run -d \
        --name "$name" --hostname "$name" \
        --network "$NETWORK" --ip "$ip" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
        -e RUST_LOG="drift_vpn=info,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/$cfg" >/dev/null
}

echo "==> Starting both daemons"
start_node "$NODE_A" "$NODE_A_IP" "a.toml"
start_node "$NODE_B" "$NODE_B_IP" "b.toml"
sleep 3

# Sanity: tunnel up.
if ! docker exec "$NODE_A" ping -c 1 -W 5 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: initial tunnel didn't come up"
    docker logs "$NODE_A" 2>&1 | tail -8
    exit 1
fi
echo "PASS: initial tunnel up"

echo
echo "==> Killing node-a"
docker rm -f "$NODE_A" >/dev/null

# Verify the tunnel is broken (B can't ping A any more).
if docker exec "$NODE_B" ping -c 1 -W 2 10.99.0.1 >/dev/null 2>&1; then
    echo "warn: ping B→A succeeded after killing A; B's session may have buffered, retrying"
fi

echo "==> Restarting node-a with same identity + config"
start_node "$NODE_A" "$NODE_A_IP" "a.toml"

# How long does it take for the new A to handshake with the
# still-running B? B's peer table has the old session for A.
# A re-connects with the same pubkey; on the first inbound
# packet B's path-validation logic should accept the new path.
# In practice we expect handshake within a couple of seconds.
echo "==> Probing 10.99.0.2 from new node-a (allow up to 15s for re-establish)"
ok=0
for i in $(seq 1 30); do
    if docker exec "$NODE_A" ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; then
        ok=1
        echo "PASS: ping a → b succeeded after $((i / 2 + 1))s"
        break
    fi
    sleep 0.5
done
if [ "$ok" -ne 1 ]; then
    echo "FAIL: ping a → b never succeeded"
    echo "--- node-a logs (last 12) ---"
    docker logs --tail=12 "$NODE_A" 2>&1 | sed 's/^/  /'
    echo "--- node-b logs (last 12) ---"
    docker logs --tail=12 "$NODE_B" 2>&1 | sed 's/^/  /'
    exit 1
fi

# Reverse direction too (b → a; b had a stale session, has to
# accept the new one).
ok=0
for i in $(seq 1 30); do
    if docker exec "$NODE_B" ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1; then
        ok=1
        echo "PASS: ping b → a succeeded"
        break
    fi
    sleep 0.5
done
if [ "$ok" -ne 1 ]; then
    echo "FAIL: ping b → a never succeeded after restart"
    docker logs --tail=12 "$NODE_B" 2>&1 | sed 's/^/  /'
    exit 1
fi

echo
echo "RESULT: drift-vpn survives a daemon restart — same identity"
echo "        reconnects without operator intervention on the peer."

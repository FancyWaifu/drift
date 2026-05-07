#!/usr/bin/env bash
# Reverse-path filter: a peer tries to send a packet with a
# src IP that's NOT in its allowed_ips. The receiving daemon
# must drop it. (Without this, a compromised or misconfigured
# peer could spoof addresses owned by other peers — same
# threat WireGuard's allowed_ips defends against.)
#
# Topology:
#   server (B) — peer registry:
#     - A: allowed_ips = ["10.99.0.1/32"]
#     - attacker: allowed_ips = ["10.99.0.99/32"]
#
# attacker is misconfigured: their LOCAL tun is at 10.99.0.1
# (impersonating A), so any packet they emit via the tunnel
# carries src=10.99.0.1. When B receives, the daemon checks:
# is 10.99.0.1 in attacker's allowed_ips ["10.99.0.99/32"]?
# No → drop.
#
# Test: attacker pings 10.99.0.2 from src=10.99.0.1. The
# packet is encrypted by attacker's daemon and shipped to B.
# B's drift→tun loop drops it on the reverse-path check.
# We verify (a) ping fails, (b) B's daemon logged the
# rejection.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-spoof-net"
NODE_B="drift-vpn-spoof-server"
NODE_A="drift-vpn-spoof-legit"
NODE_X="drift-vpn-spoof-attacker"
WORKDIR="/tmp/drift-vpn-spoof-test"

cleanup() {
    docker rm -f "$NODE_A" "$NODE_B" "$NODE_X" >/dev/null 2>&1 || true
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
docker network create --subnet 172.35.0.0/24 "$NETWORK" >/dev/null
B_IP="172.35.0.10"
A_IP="172.35.0.11"
X_IP="172.35.0.12"

# Generate three identities.
for n in a b x; do
    docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
        keygen -o "/keys/${n}.key" > "$WORKDIR/${n}.pub"
done
PUB_A=$(cat "$WORKDIR/a.pub")
PUB_B=$(cat "$WORKDIR/b.pub")
PUB_X=$(cat "$WORKDIR/x.pub")

# Server B: knows both A and attacker. attacker's
# allowed_ips is 10.99.0.99/32 — NOT 10.99.0.1.
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

[[peer]]
public_key  = "$PUB_X"
allowed_ips = ["10.99.0.99/32"]
endpoint    = "udp://${X_IP}:51820"
EOF

# Legitimate peer A: tun=10.99.0.1, peers with B.
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

# Attacker X: tun=10.99.0.1 — IMPERSONATING A. Any packet
# emitted by X's daemon will carry src=10.99.0.1 in its IP
# header. attacker's allowed_ips on B's side is 10.99.0.99/32,
# so B should drop the packet on reverse-path check.
cat > "$WORKDIR/x.toml" <<EOF
[interface]
identity_file = "/keys/x.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://${B_IP}:51820"
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

start "$NODE_B" "$B_IP" "b.toml"
start "$NODE_A" "$A_IP" "a.toml"
start "$NODE_X" "$X_IP" "x.toml"
sleep 3

# Sanity: legitimate A ↔ B works.
if ! docker exec "$NODE_A" ping -c 1 -W 3 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: legit tunnel A→B didn't come up"
    docker logs "$NODE_A" 2>&1 | tail -8
    exit 1
fi
echo "PASS: legit A → B works"

# Attacker tries to ping B from src=10.99.0.1 (their tun
# address). The packet goes through their drift-vpn →
# encrypted → arrives at B → B's daemon drops it on
# reverse-path check.
if docker exec "$NODE_X" ping -c 2 -W 2 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: attacker's spoofed ping was DELIVERED — reverse-path filter is broken"
    docker logs "$NODE_B" 2>&1 | tail -10
    exit 1
fi
echo "PASS: attacker's spoofed ping was rejected (no ICMP reply received)"

# Verify B's daemon actually logged the rejection.
if docker logs "$NODE_B" 2>&1 | grep -qE "rpfilter dropped: src not in"; then
    echo "PASS: B's daemon logged the spoof rejection"
else
    echo "FAIL: B's daemon didn't log a reverse-path rejection"
    docker logs "$NODE_B" 2>&1 | tail -15
    exit 1
fi

echo
echo "RESULT: reverse-path filter correctly rejects a peer claiming a"
echo "        src IP outside its allowed_ips."

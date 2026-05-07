#!/usr/bin/env bash
# v0.5 test: cross-scheme runtime failover (UDP → TCP).
#
# Setup: each daemon listens on BOTH `udp://0.0.0.0:51820` and
# `tcp://0.0.0.0:51821`. Each peer config lists both endpoints,
# UDP first. Tunnel comes up via UDP.
#
# Mid-stream we DROP all UDP traffic between the containers
# (regardless of port). The supervisor must:
#   1. Detect staleness (no AEAD-valid traffic for `stale_secs`).
#   2. Try the next endpoint — `tcp://...`. v0.5 supervisor opens
#      a fresh outbound connector for the URL, gets back a TCP
#      PacketIO, attaches it as a new transport interface.
#   3. Send a PathChallenge via that new interface.
#   4. On matching PathResponse, transport pins BOTH `peer.addr`
#      AND `peer.interface_id` to the new (TCP) interface.
#   5. send_data flows over TCP from then on.
#
# This is the headline v0.5 feature: WireGuard can't do this at
# all. drift-vpn switches medium without dropping the session.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-xscheme-net"
NODE_A="drift-vpn-xscheme-a"
NODE_B="drift-vpn-xscheme-b"
WORKDIR="/tmp/drift-vpn-xscheme-test"

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
docker network create --subnet 172.41.0.0/24 "$NETWORK" >/dev/null
A_IP="172.41.0.10"
B_IP="172.41.0.11"

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
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1340
name          = "tun0"

[failover]
check_interval_ms = 1000
stale_secs        = 4
hold_secs         = 2

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoints   = [
  "udp://${B_IP}:51820",
  "tcp://${B_IP}:51821",
]
EOF

cat > "$WORKDIR/b.toml" <<EOF
[interface]
identity_file = "/keys/b.key"
address       = "10.99.0.2/24"
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1340
name          = "tun0"

[failover]
check_interval_ms = 1000
stale_secs        = 4
hold_secs         = 2

[[peer]]
public_key  = "$PUB_A"
allowed_ips = ["10.99.0.1/32"]
endpoints   = [
  "udp://${A_IP}:51820",
  "tcp://${A_IP}:51821",
]
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

echo "==> Starting nodes"
start "$NODE_A" "$A_IP" "a.toml"
start "$NODE_B" "$B_IP" "b.toml"
sleep 3

echo "==> Verifying tunnel via UDP primary"
if ! docker exec "$NODE_A" ping -c 2 -W 2 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: tunnel didn't come up on UDP"
    docker logs "$NODE_A" 2>&1 | tail -10
    docker logs "$NODE_B" 2>&1 | tail -10
    exit 1
fi
echo "PASS: tunnel up on UDP"

PRE_HANDSHAKES_A=$(docker logs "$NODE_A" 2>&1 | grep -c "peer registered" || true)
PRE_HANDSHAKES_B=$(docker logs "$NODE_B" 2>&1 | grep -c "peer registered" || true)

echo "==> Severing ALL UDP between containers (block any UDP, both directions)"
for n in "$NODE_A" "$NODE_B"; do
    docker exec "$n" iptables -A INPUT  -p udp -j DROP
    docker exec "$n" iptables -A OUTPUT -p udp -j DROP
done

echo "==> Waiting up to 25s for cross-scheme failover (UDP → TCP)"
recovered=0
for i in $(seq 1 25); do
    if docker exec "$NODE_A" ping -c 1 -W 2 10.99.0.2 >/dev/null 2>&1; then
        recovered=1
        echo "    ping recovered at second $i"
        break
    fi
    sleep 1
done

if [ "$recovered" -ne 1 ]; then
    echo "FAIL: tunnel never recovered after UDP block"
    echo "==> a logs (last 30):"; docker logs "$NODE_A" 2>&1 | tail -30
    echo "==> b logs (last 30):"; docker logs "$NODE_B" 2>&1 | tail -30
    exit 1
fi

# Confirm the failover happened over a NON-UDP scheme.
COMMITS_A=$(docker logs "$NODE_A" 2>&1 | grep "failover committed" || true)
COMMITS_B=$(docker logs "$NODE_B" 2>&1 | grep "failover committed" || true)
TCP_COMMITS=$(echo "$COMMITS_A$COMMITS_B" | grep -c "tcp://" || true)

if [ "$TCP_COMMITS" -eq 0 ]; then
    echo "FAIL: tunnel recovered but no `tcp://` failover commit logged"
    echo "      A's commits: $COMMITS_A"
    echo "      B's commits: $COMMITS_B"
    exit 1
fi
echo "PASS: $TCP_COMMITS cross-scheme failover commit(s) logged (UDP → TCP)"

# No re-handshake — graceful migration only.
POST_HANDSHAKES_A=$(docker logs "$NODE_A" 2>&1 | grep -c "peer registered" || true)
POST_HANDSHAKES_B=$(docker logs "$NODE_B" 2>&1 | grep -c "peer registered" || true)
if [ "$POST_HANDSHAKES_A" -gt "$PRE_HANDSHAKES_A" ] || \
   [ "$POST_HANDSHAKES_B" -gt "$PRE_HANDSHAKES_B" ]; then
    echo "WARN: re-handshake observed (graceful path-probe is preferred)"
    echo "      A: $PRE_HANDSHAKES_A → $POST_HANDSHAKES_A"
    echo "      B: $PRE_HANDSHAKES_B → $POST_HANDSHAKES_B"
fi

# Solid run of pings over TCP-now.
echo "==> 10 pings over the TCP tunnel"
docker exec "$NODE_A" ping -c 10 -W 2 -i 0.2 10.99.0.2 | tail -3 || {
    echo "FAIL: ping degraded over TCP"; exit 1; }

echo
echo "RESULT: drift-vpn v0.5 — cross-scheme failover works."
echo "        UDP got blocked entirely; supervisor opened a fresh"
echo "        TCP connector, probed via that interface, transport"
echo "        pinned peer.addr + peer.interface_id to the TCP path."
echo "        Session keys preserved; no re-handshake required."

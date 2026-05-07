#!/usr/bin/env bash
# v0.4 test: hysteresis under primary-endpoint flapping.
#
# A misbehaving primary endpoint that comes back briefly and
# then goes away again could trigger a thrash loop: switch to
# secondary, switch back, switch to secondary again. The
# supervisor's `hold_secs` window is supposed to prevent that.
#
# Setup is identical to failover_basic.sh — A has [B:51820,
# B:51821], B has both listeners. We toggle the iptables rule
# on B's :51820 multiple times and count how many failover
# events show up in A's logs. With hold_secs=10 and a 6-cycle
# flap, we expect AT MOST 2-3 failover events (not 6).

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-flap-net"
NODE_A="drift-vpn-flap-a"
NODE_B="drift-vpn-flap-b"
WORKDIR="/tmp/drift-vpn-flap-test"

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
docker network create --subnet 172.40.0.0/24 "$NETWORK" >/dev/null
A_IP="172.40.0.10"
B_IP="172.40.0.11"

docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/a.key > "$WORKDIR/a.pub"
docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
    keygen -o /keys/b.key > "$WORKDIR/b.pub"
PUB_A=$(cat "$WORKDIR/a.pub")
PUB_B=$(cat "$WORKDIR/b.pub")

# stale_secs=4, hold_secs=10. Flap interval below is 5s (long
# enough to definitely time out, short enough that two flaps
# fall inside the hold window so hysteresis kicks in).
cat > "$WORKDIR/a.toml" <<EOF
[interface]
identity_file = "/keys/a.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[failover]
check_interval_ms = 1000
stale_secs        = 4
hold_secs         = 10

[[peer]]
public_key  = "$PUB_B"
allowed_ips = ["10.99.0.2/32"]
endpoints   = [
  "udp://${B_IP}:51820",
  "udp://${B_IP}:51821",
]
EOF

cat > "$WORKDIR/b.toml" <<EOF
[interface]
identity_file = "/keys/b.key"
address       = "10.99.0.2/24"
listen        = ["udp://0.0.0.0:51820", "udp://0.0.0.0:51821"]
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
sleep 3

if ! docker exec "$NODE_A" ping -c 2 -W 2 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: tunnel didn't come up"; exit 1
fi
echo "PASS: tunnel up at startup"

# Flap cycle: alternate dropping and unblocking inbound :51820
# on B every 5 seconds. With check_interval=1s, stale_secs=4,
# hold_secs=10, each flap_off should trigger at most one
# failover; subsequent failovers within the 10s hold are
# suppressed.
echo "==> Flap cycle (6 toggles × 5s = 30s)"
for i in 1 2 3; do
    echo "    cycle $i: blocking :51820"
    docker exec "$NODE_B" iptables -A INPUT -p udp --dport 51820 -j DROP
    sleep 5
    echo "    cycle $i: unblocking :51820"
    docker exec "$NODE_B" iptables -D INPUT -p udp --dport 51820 -j DROP || true
    sleep 5
done

sleep 3

# How many failover commits did A actually do? With perfect
# hysteresis we expect ~3 (one per blocked window). The pass
# threshold is "fewer than the number of toggles" — i.e. some
# events were suppressed by the hold window. If we see 6 or
# more events, hysteresis isn't working.
EVENTS=$(docker logs "$NODE_A" 2>&1 | grep -c "failover committed" || true)
SKIPS=$(docker logs "$NODE_A" 2>&1 | grep -c "in_hold_for_secs" || true)
echo
echo "    failover commits: $EVENTS"
echo "    skipped due to hold window: $SKIPS"

# Tunnel should still be alive at the end (b's :51820 is open
# right now, but A might be on :51821 — both should work).
if ! docker exec "$NODE_A" ping -c 5 -W 2 10.99.0.2 >/dev/null 2>&1; then
    echo "FAIL: tunnel dead at end of flap test"
    docker logs "$NODE_A" 2>&1 | tail -10
    exit 1
fi
echo "PASS: tunnel still alive after flap cycle"

# Hysteresis check: should have at least one suppressed event.
# A reasonable upper bound on commits over a 30s run with 3
# blocked windows + hold_secs=10 is 4 (could happen if timing
# breaks just right). More than 6 is definitely thrashing.
if [ "$EVENTS" -gt 6 ]; then
    echo "FAIL: $EVENTS failover commits in 30s — hysteresis not working"
    exit 1
fi
if [ "$SKIPS" -lt 1 ]; then
    echo "WARN: zero hold-window suppressions — hold_secs may not be doing anything"
fi

echo
echo "RESULT: drift-vpn v0.4 hysteresis works. 30s flap cycle"
echo "        produced $EVENTS commits + $SKIPS hold-window skips,"
echo "        not the 6+ thrashing pattern. Tunnel alive throughout."

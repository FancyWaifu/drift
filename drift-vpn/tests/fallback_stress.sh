#!/usr/bin/env bash
# Symmetric-timing stress test for happy-eyeballs.
#
# The fallback test exercises one race: two daemons start with
# identical configs (dead first, real second), both fall through
# the dead endpoint, both win on the real one. With careful
# timing the wrong endpoint can be falsely attributed as
# "winner" — see commit history for the addr-verification fix
# and probe-timeout jitter.
#
# A single run of fallback won't catch a regression there
# (the race is timing-dependent and fires only sometimes).
# This test loops it 20 times. If any iteration mis-attributes
# the dead endpoint as winner, this test fails.
#
# Wall time: ~2 minutes.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-stress-net"
NODE_A="drift-vpn-stress-a"
NODE_B="drift-vpn-stress-b"
WORKDIR="/tmp/drift-vpn-stress-test"
ITERS="${ITERS:-20}"

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
docker network create --subnet 172.38.0.0/24 "$NETWORK" >/dev/null
A_IP="172.38.0.10"
B_IP="172.38.0.11"
DEAD_IP="172.38.0.99"

# One identity pair reused across iterations — the race
# is about timing, not about identity churn.
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
endpoints   = [
  "udp://${DEAD_IP}:51820",
  "udp://${B_IP}:51820",
]
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
endpoints   = [
  "udp://${DEAD_IP}:51820",
  "udp://${A_IP}:51820",
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

# A "good" iteration:
#   1. Both daemons log `no handshake within timeout` for the
#      dead endpoint at least once.
#   2. Both daemons log `happy-eyeballs winner ... tried=2 of=2`.
#   3. Cross-tunnel ping succeeds.
# A "bad" iteration is anything else — most importantly, a
# `winner ... tried=1 of=2` line on either side, which would
# mean the dead endpoint was falsely attributed as winner.

PASSES=0
FAILS=0
declare -a FAIL_REASONS

for i in $(seq 1 "$ITERS"); do
    cleanup
    sleep 0.3
    start "$NODE_A" "$A_IP" "a.toml"
    start "$NODE_B" "$B_IP" "b.toml"

    # Wait up to 7s for both daemons to either time out or win.
    ok=0
    for _ in $(seq 1 70); do
        a_done=$(docker logs "$NODE_A" 2>&1 | grep -cE "happy-eyeballs winner|no endpoint completed handshake")
        b_done=$(docker logs "$NODE_B" 2>&1 | grep -cE "happy-eyeballs winner|no endpoint completed handshake")
        if [ "$a_done" -ge 1 ] && [ "$b_done" -ge 1 ]; then
            ok=1
            break
        fi
        sleep 0.1
    done
    if [ "$ok" -ne 1 ]; then
        FAILS=$((FAILS+1))
        FAIL_REASONS+=("iter $i: timed out waiting for both daemons to finish probing")
        continue
    fi

    # Check: did either side wrongly attribute tried=1?
    bad_a=$(docker logs "$NODE_A" 2>&1 | grep -c "happy-eyeballs winner.*tried=1")
    bad_b=$(docker logs "$NODE_B" 2>&1 | grep -c "happy-eyeballs winner.*tried=1")
    if [ "$bad_a" -gt 0 ] || [ "$bad_b" -gt 0 ]; then
        FAILS=$((FAILS+1))
        FAIL_REASONS+=("iter $i: tried=1 winner (false attribution): a=$bad_a b=$bad_b")
        continue
    fi

    # Check: did the tunnel actually come up?
    if ! docker exec "$NODE_A" ping -c 1 -W 3 10.99.0.2 >/dev/null 2>&1; then
        FAILS=$((FAILS+1))
        FAIL_REASONS+=("iter $i: ping failed despite both sides probing")
        continue
    fi

    PASSES=$((PASSES+1))
done

echo
echo "Stress: $PASSES / $ITERS iterations passed"
if [ "$FAILS" -gt 0 ]; then
    echo "Failures:"
    for r in "${FAIL_REASONS[@]}"; do
        echo "  - $r"
    done
    exit 1
fi

echo
echo "RESULT: $ITERS iterations of two-node fallback completed"
echo "        without a single false-attribution race. Probe-timeout"
echo "        jitter + addr-verification keep symmetric peers honest."

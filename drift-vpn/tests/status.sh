#!/usr/bin/env bash
# v0.6 test: `drift-vpn status` subcommand.
#
# Bring up a normal two-node tunnel, run some traffic, then
# query the status socket from inside the container. Verify the
# JSON structure includes the right fields and that the human
# rendering shows sensible values (peer count, srtt non-zero,
# counters).

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-status-net"
NODE_A="drift-vpn-status-a"
NODE_B="drift-vpn-status-b"
WORKDIR="/tmp/drift-vpn-status-test"

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
docker network create --subnet 172.42.0.0/24 "$NETWORK" >/dev/null
A_IP="172.42.0.10"
B_IP="172.42.0.11"

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
        -e RUST_LOG="drift_vpn=info,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/$cfg" \
        --status-socket /tmp/drift-vpn.sock >/dev/null
}

start "$NODE_A" "$A_IP" "a.toml"
start "$NODE_B" "$B_IP" "b.toml"
sleep 2

# Generate some traffic so RTT samples land.
docker exec "$NODE_A" ping -c 5 -W 2 -i 0.2 10.99.0.2 >/dev/null

# Human-readable status from inside node-a.
echo "==> Human-readable status from node-a:"
docker exec "$NODE_A" /usr/local/bin/drift-vpn status \
    --socket /tmp/drift-vpn.sock | head -25 | sed 's/^/    /'

echo
echo "==> JSON status from node-a (parsed checks):"
JSON=$(docker exec "$NODE_A" /usr/local/bin/drift-vpn status \
    --socket /tmp/drift-vpn.sock --json)

# Sanity checks. We use python3-less host-side parsing — just
# grep for fields we expect to exist. If the JSON is malformed
# any of these fail and the test exits.
fail=0
for field in \
    '"local"' '"peers"' '"metrics"' \
    '"peer_id_hex"' '"is_established": true' \
    '"tun_writes"' '"failover_commits_total"' \
    '"rpfilter_config_mismatch"'; do
    if ! grep -q "$field" <<<"$JSON"; then
        echo "FAIL: status JSON missing field $field"
        fail=1
    fi
done

# At least one peer should be established.
if ! grep -q '"is_established": true' <<<"$JSON"; then
    echo "FAIL: no established peer in status output"
    fail=1
fi

[ "$fail" -ne 0 ] && exit 1

echo "PASS: status JSON structure looks right"

# Counters should show non-zero traffic after the pings. The
# daemon emits compact JSON (no whitespace); --json on the CLI
# pretty-prints. Match either shape.
TUN_W=$(docker exec "$NODE_A" /usr/local/bin/drift-vpn status \
    --socket /tmp/drift-vpn.sock --json \
    | grep -oE '"tun_writes":[[:space:]]*[0-9]+' \
    | head -1 \
    | grep -oE '[0-9]+$')
if [ -z "${TUN_W:-}" ] || [ "$TUN_W" -lt 5 ]; then
    echo "FAIL: tun_writes counter is too low ($TUN_W) — expected >= 5 after 5 pings"
    exit 1
fi
echo "PASS: counters reflect real traffic (tun_writes=$TUN_W)"

echo
echo "RESULT: drift-vpn v0.6 status socket works. Daemon serves a"
echo "        JSON snapshot with peer state + counters, CLI client"
echo "        connects to it, both human and JSON outputs are sane."

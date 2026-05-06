#!/usr/bin/env bash
# Three-node mesh test: full mesh of N=3 peers.
#
# Topology:
#   node-a 10.99.0.1   ←→   node-b 10.99.0.2
#       │                       │
#       └───────────────────────┴── node-c 10.99.0.3
#
# Each container's drift-vpn has TWO peers configured (the
# other two nodes). Verifies:
#
# - Routing table works with > 1 peer (the AllowedIPs scan
#   has to pick the right one for each destination).
# - Multiple concurrent DRIFT sessions on one daemon.
# - Reverse-path filter accepts each peer's traffic
#   independently.
#
# Tests the 6 directed pings (3 * 2): a→b, a→c, b→a, b→c,
# c→a, c→b. All must succeed.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-mesh-net"
NODES=("drift-vpn-mesh-a" "drift-vpn-mesh-b" "drift-vpn-mesh-c")
WORKDIR="/tmp/drift-vpn-mesh-test"

cleanup() {
    for n in "${NODES[@]}"; do
        docker rm -f "$n" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

mkdir -p "$WORKDIR"
echo "==> Building $IMAGE"
if ! docker build -f Dockerfile -t "$IMAGE" .. >/dev/null 2> "$WORKDIR/build.err"; then
    echo "FAIL: docker build"; tail -30 "$WORKDIR/build.err"; exit 1
fi

echo "==> Cleaning state"
cleanup
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet 172.32.0.0/24 "$NETWORK" >/dev/null

# Wire IPs and tun-overlay IPs, deterministic.
WIRE_IPS=(172.32.0.10 172.32.0.11 172.32.0.12)
TUN_IPS=(10.99.0.1 10.99.0.2 10.99.0.3)

echo "==> Generating identities"
for i in 0 1 2; do
    docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
        keygen -o "/keys/${NODES[$i]}.key" > "$WORKDIR/${NODES[$i]}.pub"
done
PUBS=()
for i in 0 1 2; do
    PUBS+=("$(cat "$WORKDIR/${NODES[$i]}.pub")")
    echo "    ${NODES[$i]} pub: ${PUBS[$i]:0:16}..."
done

# Generate per-node configs. Node i's peers are nodes j ≠ i.
for i in 0 1 2; do
    cfg="$WORKDIR/${NODES[$i]}.toml"
    cat > "$cfg" <<EOF
[interface]
identity_file = "/keys/${NODES[$i]}.key"
address       = "${TUN_IPS[$i]}/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"
EOF
    for j in 0 1 2; do
        [ "$i" = "$j" ] && continue
        cat >> "$cfg" <<EOF

[[peer]]
public_key  = "${PUBS[$j]}"
allowed_ips = ["${TUN_IPS[$j]}/32"]
endpoint    = "udp://${WIRE_IPS[$j]}:51820"
EOF
    done
done

for i in 0 1 2; do
    echo "==> Starting ${NODES[$i]} (wire ${WIRE_IPS[$i]} tun ${TUN_IPS[$i]})"
    docker run -d \
        --name "${NODES[$i]}" --hostname "${NODES[$i]}" \
        --network "$NETWORK" --ip "${WIRE_IPS[$i]}" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
        -e RUST_LOG="drift_vpn=info,drift=warn" \
        "$IMAGE" up -c "/etc/drift-vpn/${NODES[$i]}.toml" >/dev/null
done

echo "==> Waiting 4s for the 3-way mesh to settle"
sleep 4

echo "==> Last log line per node (sanity)"
for i in 0 1 2; do
    docker logs "${NODES[$i]}" 2>&1 | grep "peer registered" | head -2 | sed "s/^/    [${NODES[$i]}] /"
done

# Run all 6 directed pings.
fail=0
for src in 0 1 2; do
    for dst in 0 1 2; do
        [ "$src" = "$dst" ] && continue
        if docker exec "${NODES[$src]}" ping -c 2 -W 5 "${TUN_IPS[$dst]}" >/dev/null 2>&1; then
            echo "PASS: ${NODES[$src]} → ${TUN_IPS[$dst]}"
        else
            echo "FAIL: ${NODES[$src]} → ${TUN_IPS[$dst]}"
            fail=1
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo
    echo "Diagnostics:"
    for n in "${NODES[@]}"; do
        echo "--- $n logs (last 8) ---"
        docker logs --tail=8 "$n" 2>&1 | sed 's/^/  /'
    done
    exit 1
fi

echo
echo "RESULT: 3-node full mesh works (6/6 directed pings via DRIFT-encrypted tunnels)"

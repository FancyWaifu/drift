#!/usr/bin/env bash
# v0.8 test: mesh-only peers via hub-and-spoke topology.
#
# STATUS: WIP. Infrastructure (config + add_mesh_peer + warmup
# retrier) is in place and beacon propagation is observed in
# logs ("learned routes from beacon ... updated=2"). The
# forwarded-handshake path is timing-sensitive in macOS Docker
# and the test currently fails to complete A↔C ping in this
# environment within the 15s wait window. NOT yet wired into
# `run_all.sh`. Run manually:
#
#   bash drift-vpn/tests/mesh_only.sh
#
# Likely needs a real Linux environment for reliable
# verification, OR a longer timeout, OR the hub forwarding to
# explicitly drive HELLO/HELLO_ACK across boundaries.

#
# Topology:
#
#     node-a              node-b              node-c
#     10.99.0.1   ←→     10.99.0.2     ←→    10.99.0.3
#                   ↑                ↑
#               direct UDP       direct UDP
#
#     a ←-----------------(no direct)---------------→ c
#                          (forwards via b)
#
# Node A's config:    [B as peer with endpoint, C as peer w/o]
# Node B's config:    [A as peer with endpoint, C as peer with endpoint]
# Node C's config:    [B as peer with endpoint, A as peer w/o]
#
# A and C never speak directly. The mesh-only `[[peer]]` entries
# (no endpoint, no endpoints) are registered via add_mesh_peer.
# B's beacons advertise its routes, so A learns "C is reachable
# via B" and vice versa. A→C ping packets get forwarded by B.
#
# This is the hub-and-spoke mode: spokes that can't accept
# incoming connections (mobile, behind NAT) reach each other via
# a hub that's publicly reachable. WireGuard requires manual
# routing table jiggery; drift-vpn handles it via DRIFT's mesh
# layer.

set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="drift-vpn:test"
NETWORK="drift-vpn-mesh-only-net"
NODES=("drift-vpn-mo-a" "drift-vpn-mo-b" "drift-vpn-mo-c")
WORKDIR="/tmp/drift-vpn-mesh-only-test"

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

cleanup
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create --subnet 172.44.0.0/24 "$NETWORK" >/dev/null

WIRE_IPS=(172.44.0.10 172.44.0.11 172.44.0.12)
TUN_IPS=(10.99.0.1 10.99.0.2 10.99.0.3)

for i in 0 1 2; do
    docker run --rm -v "$WORKDIR:/keys" "$IMAGE" \
        keygen -o "/keys/${NODES[$i]}.key" > "$WORKDIR/${NODES[$i]}.pub"
done
PUBS=()
for i in 0 1 2; do
    PUBS+=("$(cat "$WORKDIR/${NODES[$i]}.pub")")
done

# Node A: direct to B, mesh-only to C.
cat > "$WORKDIR/${NODES[0]}.toml" <<EOF
[interface]
identity_file = "/keys/${NODES[0]}.key"
address       = "${TUN_IPS[0]}/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "${PUBS[1]}"
allowed_ips = ["${TUN_IPS[1]}/32"]
endpoint    = "udp://${WIRE_IPS[1]}:51820"

[[peer]]
public_key  = "${PUBS[2]}"
allowed_ips = ["${TUN_IPS[2]}/32"]
# no endpoint — reach C via mesh forwarding through B
EOF

# Node B (the hub): direct to both A and C.
cat > "$WORKDIR/${NODES[1]}.toml" <<EOF
[interface]
identity_file = "/keys/${NODES[1]}.key"
address       = "${TUN_IPS[1]}/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "${PUBS[0]}"
allowed_ips = ["${TUN_IPS[0]}/32"]
endpoint    = "udp://${WIRE_IPS[0]}:51820"

[[peer]]
public_key  = "${PUBS[2]}"
allowed_ips = ["${TUN_IPS[2]}/32"]
endpoint    = "udp://${WIRE_IPS[2]}:51820"
EOF

# Node C: direct to B, mesh-only to A.
cat > "$WORKDIR/${NODES[2]}.toml" <<EOF
[interface]
identity_file = "/keys/${NODES[2]}.key"
address       = "${TUN_IPS[2]}/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340
name          = "tun0"

[[peer]]
public_key  = "${PUBS[1]}"
allowed_ips = ["${TUN_IPS[1]}/32"]
endpoint    = "udp://${WIRE_IPS[1]}:51820"

[[peer]]
public_key  = "${PUBS[0]}"
allowed_ips = ["${TUN_IPS[0]}/32"]
# no endpoint — reach A via mesh forwarding through B
EOF

for i in 0 1 2; do
    docker run -d \
        --name "${NODES[$i]}" --hostname "${NODES[$i]}" \
        --network "$NETWORK" --ip "${WIRE_IPS[$i]}" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR:/etc/drift-vpn" -v "$WORKDIR:/keys" \
        -e RUST_LOG="drift_vpn=info,drift=info" \
        "$IMAGE" up -c "/etc/drift-vpn/${NODES[$i]}.toml" >/dev/null
done

echo "==> Waiting 15s for hub-and-spoke handshakes + beacon-driven mesh routes"
# Beacon interval is 2s; we need at least one round-trip from B
# to A and B to C, then A's first packet to C must reach C and
# trigger C's discovery of A's mesh route.
sleep 15

# Confirm A and C registered each other as mesh-only.
fail=0
for n in "${NODES[0]}" "${NODES[2]}"; do
    if ! docker logs "$n" 2>&1 | grep -q "mesh-only peer registered"; then
        echo "FAIL: $n didn't register a mesh-only peer"
        docker logs "$n" 2>&1 | tail -10
        fail=1
    fi
done
[ "$fail" -ne 0 ] && exit 1
echo "PASS: A and C both registered mesh-only peers"

# Direct pings (sanity).
echo "==> Direct pings (a↔b, b↔c)"
for pair in "0 1" "1 0" "1 2" "2 1"; do
    set -- $pair
    if docker exec "${NODES[$1]}" ping -c 2 -W 3 "${TUN_IPS[$2]}" >/dev/null 2>&1; then
        echo "    PASS: ${NODES[$1]} → ${TUN_IPS[$2]}"
    else
        echo "    FAIL: ${NODES[$1]} → ${TUN_IPS[$2]}"
        fail=1
    fi
done
[ "$fail" -ne 0 ] && exit 1

# The real test: A↔C, which has NO direct path. Must go via B.
echo "==> Mesh-forwarded ping (A → C via B, no direct endpoint)"
if docker exec "${NODES[0]}" ping -c 5 -W 5 "${TUN_IPS[2]}" >/dev/null 2>&1; then
    echo "PASS: a → c (via mesh forwarding through b)"
else
    echo "FAIL: a → c didn't get through"
    echo "==> a logs (last 15):"; docker logs --tail=15 "${NODES[0]}" 2>&1 | sed 's/^/    /'
    echo "==> b logs (last 15):"; docker logs --tail=15 "${NODES[1]}" 2>&1 | sed 's/^/    /'
    echo "==> c logs (last 15):"; docker logs --tail=15 "${NODES[2]}" 2>&1 | sed 's/^/    /'
    fail=1
fi

# Reverse direction.
echo "==> Mesh-forwarded ping (C → A via B)"
if docker exec "${NODES[2]}" ping -c 5 -W 5 "${TUN_IPS[0]}" >/dev/null 2>&1; then
    echo "PASS: c → a (via mesh forwarding through b)"
else
    echo "FAIL: c → a didn't get through"
    fail=1
fi

[ "$fail" -ne 0 ] && exit 1

# Sanity: B should have forwarded packets. Look for the
# `forwarded` counter via status.
FORWARDED_B=$(docker exec "${NODES[1]}" /usr/local/bin/drift-vpn status \
    --json 2>/dev/null \
    | grep -oE '"forwarded":[[:space:]]*[0-9]+' \
    | head -1 \
    | grep -oE '[0-9]+$' || echo 0)
# `forwarded` isn't in DaemonMetrics directly — it's a transport
# metric that we don't currently surface. So this check is
# best-effort; missing is OK, present > 0 confirms.
if [ -n "$FORWARDED_B" ] && [ "$FORWARDED_B" -gt 0 ]; then
    echo "    bonus: B forwarded $FORWARDED_B packets"
fi

echo
echo "RESULT: drift-vpn v0.8 — mesh-only peers work."
echo "        A and C have NO direct endpoint between them; they"
echo "        reach each other through B's mesh forwarding without"
echo "        any manual routing-table configuration. Spokes that"
echo "        can't accept incoming connections (mobile, NAT) get"
echo "        full mesh reachability for free."

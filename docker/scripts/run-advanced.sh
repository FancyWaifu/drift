#!/usr/bin/env bash
# Runs every advanced Docker scenario from this session.
set -u
cd "$(dirname "$0")/.."

scenarios=(
    "chaos-link:compose/chaos-link.yml:15"
    "satellite:compose/satellite.yml:15"
    "extreme-loss-50:compose/extreme-loss.yml:20"
    "asymmetric:compose/asymmetric.yml:15"
    "multi-client-nat:compose/multi-client-nat.yml:15"
    "memory-soak:compose/memory-soak.yml:10"
    "packet-capture:compose/packet-capture.yml:15"
    "cross-arch:compose/cross-arch.yml:15"
)

results=()
for entry in "${scenarios[@]}"; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    file="${rest%%:*}"
    wait_time="${rest#*:}"

    echo
    echo "=== $name ==="
    docker compose -f "$file" up -d >/dev/null 2>&1
    sleep "$wait_time"

    delivered=0
    for cid in $(docker compose -f "$file" ps -q); do
        n=$(docker logs "$cid" 2>&1 | grep -c "recv seq\|clients=10" || true)
        if [ "$n" -gt 0 ]; then
            delivered=$((delivered + n))
        fi
    done

    docker compose -f "$file" down >/dev/null 2>&1

    if [ "$delivered" -gt 0 ]; then
        results+=("PASS  $name ($delivered)")
    else
        results+=("NODATA $name")
    fi
done

echo
echo "=== summary ==="
for r in "${results[@]}"; do
    echo "$r"
done

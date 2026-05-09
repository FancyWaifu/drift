#!/usr/bin/env bash
# Run every NAT scenario and report results.
set -u
cd "$(dirname "$0")/.."

scenarios=(
    "single:compose/nat-single.yml:WORKS"
    "dual-direct:compose/nat-dual-direct.yml:FAILS_BY_DESIGN"
    "port-forward:compose/nat-port-forward.yml:DOCKER_LIMITATION"
    "keepalive:compose/nat-keepalive.yml:WORKS"
)

echo "=== NAT test battery ==="
results=()
for entry in "${scenarios[@]}"; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    file="${rest%%:*}"
    expected="${rest#*:}"

    echo
    echo "--- $name (expected: $expected) ---"
    docker compose -f "$file" up -d >/dev/null 2>&1

    # Hold steady briefly then observe delivered packets on any "recv seq"
    # line in the receiver container logs.
    sleep 8
    delivered=0
    for cid in $(docker compose -f "$file" ps -q); do
        n=$(docker logs "$cid" 2>&1 | grep -c "recv seq" || true)
        if [ "$n" -gt 0 ]; then
            delivered=$((delivered + n))
        fi
    done

    # Safety: verify containers cannot reach real internet.
    safety="sealed"
    for cid in $(docker compose -f "$file" ps -q); do
        if docker exec "$cid" sh -c "ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1" 2>/dev/null; then
            safety="LEAKED"
        fi
    done

    docker compose -f "$file" down >/dev/null 2>&1

    case "$expected" in
        WORKS)
            if [ "$delivered" -ge 5 ]; then
                result="PASS"
            else
                result="FAIL (expected delivery, got $delivered)"
            fi
            ;;
        FAILS_BY_DESIGN)
            if [ "$delivered" -eq 0 ]; then
                result="PASS (correctly failed, 0 packets)"
            else
                result="FAIL (unexpected delivery, $delivered)"
            fi
            ;;
        DOCKER_LIMITATION)
            result="DOCS (docker bridge SNAT quirk, not drift)"
            ;;
    esac

    results+=("$name: $result  safety=$safety  delivered=$delivered")
done

echo
echo "=== summary ==="
for r in "${results[@]}"; do
    echo "$r"
done

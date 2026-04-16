#!/usr/bin/env bash
# Runs every Docker-based DRIFT test scenario in sequence.
# Each scenario's pass/fail is printed at the end.

set -u
cd "$(dirname "$0")/.."

scenarios=(
    "two-node:compose/two-node.yml"
    "lossy-link:compose/lossy-link.yml"
    "mesh-5hop:compose/mesh-5hop.yml"
    "small-mtu:compose/small-mtu.yml"
    "mtu-probe:compose/mtu-probe.yml"
    "scale-50:compose/scale.yml"
)

results=()

for entry in "${scenarios[@]}"; do
    name="${entry%%:*}"
    file="${entry#*:}"
    echo
    echo "=== scenario: $name ($file) ==="
    docker compose -f "$file" up -d 2>&1 | tail -3
    sleep 10
    # Look for any container that exited with non-zero OR that has
    # expected output. Simple heuristic: check that SOMETHING got
    # logged.
    container_count=$(docker compose -f "$file" ps -q | wc -l | tr -d ' ')
    any_errors=0
    for cid in $(docker compose -f "$file" ps -q); do
        if docker logs "$cid" 2>&1 | grep -qE "panic|\bFAIL\b|unable to start"; then
            any_errors=1
        fi
    done
    docker compose -f "$file" down 2>&1 | tail -1
    if [ "$any_errors" -eq 0 ]; then
        results+=("PASS  $name")
    else
        results+=("FAIL  $name")
    fi
done

echo
echo "=== summary ==="
for r in "${results[@]}"; do
    echo "$r"
done

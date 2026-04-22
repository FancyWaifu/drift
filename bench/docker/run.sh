#!/usr/bin/env bash
# Orchestrate the DRIFT vs QUIC vs WireGuard comparison.
#
# Flow per (protocol, workload) pair:
#   1. `docker compose run` the server detached.
#   2. Give it ~1 s to bind.
#   3. Run the client; capture its JSON report.
#   4. Tear down.
#
# Aggregate results go into results/<timestamp>.json and get
# formatted into a Markdown table at the end.
#
# Optional netem: set NETEM_DELAY=20ms NETEM_LOSS=1% to shape
# the bridge inside the server container before each run.

set -euo pipefail

cd "$(dirname "$0")"

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_FILE="$RESULTS_DIR/$STAMP.json"
: > "$RESULTS_FILE"

PROTOCOLS=(drift quic wireguard)
WORKLOADS=(handshake rtt throughput)

PAYLOAD_BYTES="${PAYLOAD_BYTES:-1024}"
RTT_ITERS="${RTT_ITERS:-1000}"
DURATION_SECS="${DURATION_SECS:-10}"

echo "==> Building drift-bench:latest"
docker compose build --quiet

run_one() {
    local proto="$1"
    local workload="$2"
    echo "==> $proto / $workload"

    local server_cmd=(
        "--protocol" "$proto"
        "--mode" "server"
        "--workload" "$workload"
        "--listen" "0.0.0.0:9000"
        "--payload-bytes" "$PAYLOAD_BYTES"
        "--rtt-iters" "$RTT_ITERS"
        "--duration-secs" "$DURATION_SECS"
        "--server-idle-secs" "60"
    )
    local client_cmd=(
        "--protocol" "$proto"
        "--mode" "client"
        "--workload" "$workload"
        "--target" "server:9000"
        "--payload-bytes" "$PAYLOAD_BYTES"
        "--rtt-iters" "$RTT_ITERS"
        "--duration-secs" "$DURATION_SECS"
    )

    # Clean stale state between runs: the cert volume holds a
    # QUIC cert from a previous run, and stale boringtun
    # sessions will reject handshakes.
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true

    # Start server detached.
    docker compose run -d --name bench-server server "${server_cmd[@]}" \
        >/dev/null

    # Optional netem shaping.
    if [[ -n "${NETEM_DELAY:-}${NETEM_LOSS:-}" ]]; then
        local shape=""
        [[ -n "${NETEM_DELAY:-}" ]] && shape="$shape delay $NETEM_DELAY"
        [[ -n "${NETEM_LOSS:-}" ]] && shape="$shape loss $NETEM_LOSS"
        docker exec bench-server sh -c \
            "tc qdisc add dev eth0 root netem $shape" || true
        echo "   netem:$shape"
    fi

    # Give the server a moment to bind.
    sleep 1

    # Run client. `run --rm` autocleans when it exits.
    local result
    if ! result=$(docker compose run --rm client "${client_cmd[@]}" 2>/dev/null); then
        echo "   CLIENT FAILED"
        docker compose logs --tail=20 bench-server || true
        docker rm -f bench-server >/dev/null 2>&1 || true
        return
    fi

    echo "   $result"
    echo "$result" >> "$RESULTS_FILE"

    docker rm -f bench-server >/dev/null 2>&1 || true
}

for proto in "${PROTOCOLS[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
        run_one "$proto" "$workload"
    done
done

docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true

echo
echo "==> Results"
echo
python3 format_results.py "$RESULTS_FILE" || cat "$RESULTS_FILE"

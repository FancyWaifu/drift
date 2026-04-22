#!/usr/bin/env bash
# Orchestrate the DRIFT vs QUIC vs WireGuard comparison.
#
# Uses raw `docker run` with an explicit bridge network and
# network-alias rather than `docker compose run`, which gets
# confused mixing `run -d` (detached server) with a follow-up
# `run --rm` (foreground client) in the same session.
#
# Flow per (protocol, workload) pair:
#   1. `docker run -d` starts the server with alias `server`
#      on the shared bridge network.
#   2. Optional tc/netem shaping on the server's eth0.
#   3. `docker run --rm` runs the client; captures JSON output.
#   4. Remove the server container.
#
# Optional: set NETEM_DELAY=20ms NETEM_LOSS=1% to shape the
# server's link.

set -euo pipefail

cd "$(dirname "$0")"

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_FILE="$RESULTS_DIR/$STAMP.json"
: > "$RESULTS_FILE"

IMAGE="drift-bench:latest"
NETWORK="drift-bench-net"
SERVER_NAME="drift-bench-server"
CLIENT_NAME="drift-bench-client"
CERT_VOLUME="drift-bench-certs"

PROTOCOLS=(drift quic wireguard)
WORKLOADS=(handshake rtt throughput)

PAYLOAD_BYTES="${PAYLOAD_BYTES:-1024}"
RTT_ITERS="${RTT_ITERS:-1000}"
HANDSHAKE_ITERS="${HANDSHAKE_ITERS:-30}"
DURATION_SECS="${DURATION_SECS:-10}"

cleanup() {
    docker rm -f "$SERVER_NAME" "$CLIENT_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building $IMAGE"
docker build -f Dockerfile -t "$IMAGE" ../.. >/dev/null

echo "==> Provisioning network + volume"
docker network create "$NETWORK" >/dev/null 2>&1 || true
docker volume create "$CERT_VOLUME" >/dev/null 2>&1 || true
# QUIC server writes a fresh cert per run; wipe the volume
# between run.sh invocations so a stale cert can't fool the
# client into trusting the wrong key.
docker run --rm -v "$CERT_VOLUME:/tmp" alpine:latest sh -c "rm -f /tmp/quic-cert.der" >/dev/null 2>&1 || true

run_one() {
    local proto="$1"
    local workload="$2"
    echo "==> $proto / $workload"

    cleanup

    # Start server detached. `--network-alias server` is what
    # gives the client `server:9000` as a DNS target — the
    # alias is stable across container names.
    docker run -d \
        --name "$SERVER_NAME" \
        --network "$NETWORK" \
        --network-alias server \
        -v "$CERT_VOLUME:/tmp" \
        --cap-add NET_ADMIN \
        "$IMAGE" \
        --protocol "$proto" \
        --mode server \
        --workload "$workload" \
        --listen "0.0.0.0:9000" \
        --payload-bytes "$PAYLOAD_BYTES" \
        --rtt-iters "$RTT_ITERS" \
        --handshake-iters "$HANDSHAKE_ITERS" \
        --duration-secs "$DURATION_SECS" \
        --server-idle-secs 60 \
        >/dev/null

    # Optional netem shaping on the server's eth0. Requires
    # NET_ADMIN (granted above).
    if [[ -n "${NETEM_DELAY:-}${NETEM_LOSS:-}" ]]; then
        local shape=""
        [[ -n "${NETEM_DELAY:-}" ]] && shape="$shape delay $NETEM_DELAY"
        [[ -n "${NETEM_LOSS:-}" ]] && shape="$shape loss $NETEM_LOSS"
        docker exec "$SERVER_NAME" sh -c \
            "tc qdisc add dev eth0 root netem $shape" || true
        echo "   netem:$shape"
    fi

    # Give the server a moment to bind the socket.
    sleep 1

    # Run client. Capture stdout (JSON); stderr goes to a
    # scratch file so failures show the actual error plus
    # whatever the server logged.
    local client_err="/tmp/drift-bench-client.err"
    local result
    if ! result=$(docker run --rm \
            --name "$CLIENT_NAME" \
            --network "$NETWORK" \
            -v "$CERT_VOLUME:/tmp" \
            "$IMAGE" \
            --protocol "$proto" \
            --mode client \
            --workload "$workload" \
            --target "server:9000" \
            --payload-bytes "$PAYLOAD_BYTES" \
            --rtt-iters "$RTT_ITERS" \
            --duration-secs "$DURATION_SECS" \
            2>"$client_err"); then
        echo "   CLIENT FAILED"
        echo "   --- client stderr ---"
        sed 's/^/     /' "$client_err"
        echo "   --- server logs ---"
        docker logs --tail=20 "$SERVER_NAME" 2>&1 | sed 's/^/     /'
        docker rm -f "$SERVER_NAME" >/dev/null 2>&1 || true
        return
    fi

    echo "   $result"
    echo "$result" >> "$RESULTS_FILE"

    docker rm -f "$SERVER_NAME" >/dev/null 2>&1 || true
}

for proto in "${PROTOCOLS[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
        run_one "$proto" "$workload"
    done
done

echo
echo "==> Results"
echo
python3 format_results.py "$RESULTS_FILE" || cat "$RESULTS_FILE"

# Network + volume persist so subsequent runs reuse them.
# `cleanup` trap removes the containers.

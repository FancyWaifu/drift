#!/bin/bash
# Run the docker DRIFT-over-Iroh bench: 3-node mesh + orchestrator.
# Runs handshake / rtt / throughput across N (server, client)
# combinations, plus optional LXC↔docker cross-environment tests
# if LXC_IPS is set.

set -u
cd "$(dirname "$0")"

LXC_IPS="${LXC_IPS:-}"  # optional space-separated list of LXC IPs to also include
TRIALS="${TRIALS:-2}"

echo "==== building images ===="
docker compose build 2>&1 | tail -3

echo "==== starting containers ===="
docker compose up -d

# Wait briefly for containers to be ready
sleep 2

OUT=/tmp/drift-iroh-docker-$(date +%Y%m%d-%H%M%S).tsv
echo -e "topology\tsrv_node\tcli_node\tworkload\ttrial\tp50_us\tp95_us\tp99_us\tgoodput_mbps" > "$OUT"

# Run one (server, client) pair: server inside one container,
# client inside another, both via `docker exec`.
run_pair() {
    local srv="$1" srv_ip="$2" cli="$3" workload="$4" trial="$5"
    local extra=""
    case "$workload" in
        handshake)  extra="--handshake-iters 10" ;;
        rtt)        extra="--rtt-iters 300 --payload-bytes 1024" ;;
        throughput) extra="--duration-secs 7 --payload-bytes 1024" ;;
    esac
    # Start server in background inside srv container
    docker exec -d "$srv" bash -c "rm -f /tmp/srv.log; drift-bench --protocol drift --mode server --workload $workload --listen iroh://0.0.0.0:0 $extra --server-idle-secs 30 > /tmp/srv.log 2>&1"
    sleep 4
    # Scrape endpoint id + port from inside the container
    local id port
    id=$(docker exec "$srv" bash -c "grep -oE 'id=[a-f0-9]{64}' /tmp/srv.log | head -1 | cut -d= -f2")
    port=$(docker exec "$srv" bash -c "grep -oE '0\.0\.0\.0:[0-9]+' /tmp/srv.log | head -1 | cut -d: -f2")
    if [ -z "$id" ] || [ -z "$port" ]; then
        echo "  [$srv → $cli $workload trial=$trial] FAILED to scrape iroh id"
        docker exec "$srv" pkill -f drift-bench 2>/dev/null || true
        echo -e "docker\t${srv}\t${cli}\t${workload}\t${trial}\t\t\t\t" >> "$OUT"
        return
    fi
    local target="iroh://${id}@${srv_ip}:${port}"
    echo "  [$srv → $cli $workload trial=$trial] target=$target"
    local client_out
    client_out=$(docker exec "$cli" drift-bench --protocol drift --mode client --workload "$workload" --target "$target" $extra 2>/dev/null | grep '^{')
    if [ "$workload" = "throughput" ]; then sleep 4; fi
    # Parse client JSON + server BENCH markers
    local samples="" p50="" p95="" p99="" good=""
    if [ -n "$client_out" ]; then
        local parsed
        parsed=$(echo "$client_out" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
sm = d.get('handshake_samples') or d.get('rtt_samples') or ''
p50 = d.get('handshake_p50_us') or d.get('rtt_p50_us') or ''
p95 = d.get('handshake_p95_us') or d.get('rtt_p95_us') or ''
p99 = d.get('handshake_p99_us') or d.get('rtt_p99_us') or ''
print(f'{sm}|{p50}|{p95}|{p99}')
")
        IFS='|' read -r samples p50 p95 p99 <<< "$parsed"
    fi
    local brec dur
    brec=$(docker exec "$srv" bash -c "grep -oE 'BENCH_BYTES_RECEIVED=[0-9]+' /tmp/srv.log | tail -1 | cut -d= -f2")
    dur=$(docker exec "$srv" bash -c "grep -oE 'BENCH_DURATION_S=[0-9.]+' /tmp/srv.log | tail -1 | cut -d= -f2")
    if [ -n "$brec" ] && [ -n "$dur" ]; then
        good=$(python3 -c "print(f'{($brec*8.0)/($dur*1_000_000):.1f}')" 2>/dev/null || echo "")
    fi
    echo -e "docker\t${srv}\t${cli}\t${workload}\t${trial}\t${p50}\t${p95}\t${p99}\t${good}" >> "$OUT"
    docker exec "$srv" pkill -f drift-bench 2>/dev/null || true
    sleep 1
}

echo "==== docker ↔ docker bench ===="
# Three combinations: a→b, b→c, a→c (server → client)
for trial in $(seq 1 $TRIALS); do
    for combo in "iroh-node-a:172.30.0.10:iroh-node-b" \
                 "iroh-node-b:172.30.0.11:iroh-node-c" \
                 "iroh-node-a:172.30.0.10:iroh-node-c"; do
        IFS=: read -r srv srv_ip cli <<< "$combo"
        for workload in handshake rtt throughput; do
            run_pair "$srv" "$srv_ip" "$cli" "$workload" "$trial"
        done
    done
done

echo ""
echo "==== results ===="
column -t -s $'\t' "$OUT"
echo ""
echo "==== leaving containers running for inspection ===="
echo "tear down: docker compose down"
echo "results: $OUT"

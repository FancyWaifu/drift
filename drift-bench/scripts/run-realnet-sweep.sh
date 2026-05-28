#!/bin/bash
# Real-network DRIFT wire sweep with proper goodput accounting.
#
# The DRIFT server emits BENCH_BYTES_RECEIVED / BENCH_DURATION_S
# markers on stderr; that's the canonical throughput (bytes that
# actually arrived). Client-side pump-rate is also reported for
# context — h2's send buffer can overstate the client-side
# number by orders of magnitude on a slow wire.

set -u
SRV_IP="${1:?server ip}"
SRV_USER="${2:?server ssh user or 'local'}"
SRV_BIN="${3:?server binary path}"
CLI_IP="${4:?client ip}"
CLI_USER="${5:?client ssh user or 'local'}"
CLI_BIN="${6:?client binary path}"
LABEL="${7:?label for output}"

OUT=/tmp/drift-realnet-${LABEL}-goodput-$(date +%Y%m%d-%H%M%S).tsv
echo "writing $OUT"
echo -e "wire\tpump_mbps\tgoodput_mbps\tbytes_received\tduration_s" > "$OUT"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# Server log path on the server host
SRV_LOG=/tmp/srv-${LABEL}.log

run_remote_bg() {
    # background server with stderr captured to SRV_LOG ON THE SERVER HOST
    local user="$1" ip="$2" cmd="$3"
    if [ "$user" = "local" ]; then
        rm -f "$SRV_LOG"
        bash -c "$cmd" > "$SRV_LOG" 2>&1 &
        echo $!
    else
        ssh $SSH_OPTS "${user}@${ip}" "rm -f $SRV_LOG; nohup $cmd > $SRV_LOG 2>&1 < /dev/null & echo \$!" 2>/dev/null | tail -1
    fi
}

fetch_server_log() {
    local user="$1" ip="$2"
    if [ "$user" = "local" ]; then
        cat "$SRV_LOG" 2>/dev/null
    else
        ssh $SSH_OPTS "${user}@${ip}" "cat $SRV_LOG 2>/dev/null"
    fi
}

run_remote() {
    local user="$1" ip="$2" cmd="$3"
    if [ "$user" = "local" ]; then
        bash -c "$cmd"
    else
        ssh $SSH_OPTS "${user}@${ip}" "$cmd"
    fi
}

kill_remote() {
    local user="$1" ip="$2" pid="$3"
    if [ "$user" = "local" ]; then
        kill "$pid" 2>/dev/null
        pkill -f drift-bench 2>/dev/null
    else
        ssh $SSH_OPTS "${user}@${ip}" "kill $pid 2>/dev/null; pkill -f drift-bench 2>/dev/null; true" > /dev/null 2>&1
    fi
}

WIRES=(
    "udp:9701"
    "tcp:9702"
    "tls:9703"
    "ws:9704"
    "h2:9706"
    "h2s:9707"
    "webtransport:9708"
)

for entry in "${WIRES[@]}"; do
    label="${entry%%:*}"
    port="${entry##*:}"
    echo "==== ${LABEL}: DRIFT over ${label} (port ${port}) ===="
    server_cmd="${SRV_BIN} --protocol drift --mode server --workload throughput --listen ${label}://0.0.0.0:${port} --duration-secs 10 --payload-bytes 1024 --server-idle-secs 60"
    pid=$(run_remote_bg "$SRV_USER" "$SRV_IP" "$server_cmd")
    if [ -z "$pid" ]; then
        echo "FAILED to start server"
        echo -e "${label}\t-\t-\t-\t-" >> "$OUT"
        continue
    fi
    sleep 3
    client_cmd="${CLI_BIN} --protocol drift --mode client --workload throughput --target ${label}://${SRV_IP}:${port} --duration-secs 10 --payload-bytes 1024"
    result=$(run_remote "$CLI_USER" "$CLI_IP" "$client_cmd" 2>/tmp/cli-err.log)
    rc=$?
    pump_mbps=$(echo "$result" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('throughput_mbps','-'))" 2>/dev/null || echo "-")
    sleep 6  # let server's recv-with-timeout finish and emit markers
    # Fetch server log
    srv_log=$(fetch_server_log "$SRV_USER" "$SRV_IP")
    bytes_recv=$(echo "$srv_log" | grep -oE "BENCH_BYTES_RECEIVED=[0-9]+" | tail -1 | cut -d= -f2)
    dur=$(echo "$srv_log" | grep -oE "BENCH_DURATION_S=[0-9.]+" | tail -1 | cut -d= -f2)
    goodput_mbps="-"
    if [ -n "$bytes_recv" ] && [ -n "$dur" ]; then
        goodput_mbps=$(python3 -c "print(f'{($bytes_recv*8.0)/($dur*1_000_000):.1f}')" 2>/dev/null || echo "-")
    fi
    echo "  pump=${pump_mbps} Mbps  goodput=${goodput_mbps} Mbps  bytes=${bytes_recv}  dur=${dur}"
    echo -e "${label}\t${pump_mbps}\t${goodput_mbps}\t${bytes_recv}\t${dur}" >> "$OUT"
    kill_remote "$SRV_USER" "$SRV_IP" "$pid"
    sleep 1
done

echo ""
echo "==== ${LABEL} summary (goodput is canonical) ===="
column -t -s $'\t' "$OUT"

#!/bin/bash
# DRIFT-over-Iroh wire bench. Iroh URLs have a different shape
# than other DRIFT wires (`iroh://<endpoint_id>@<sockaddr>`),
# so it needs a separate orchestrator that scrapes the server's
# endpoint id from stderr before the client can connect.
#
# Usage:
#   run-iroh-bench.sh <srv_ip> <srv_user> <srv_bin> <cli_ip> <cli_user> <cli_bin> <label> [trials]

set -u
SRV_IP="${1:?server ip}"
SRV_USER="${2:?server user or 'local'}"
SRV_BIN="${3:?server binary}"
CLI_IP="${4:?client ip}"
CLI_USER="${5:?client user or 'local'}"
CLI_BIN="${6:?client binary}"
LABEL="${7:?label}"
TRIALS="${8:-3}"

OUT=/tmp/drift-iroh-${LABEL}-$(date +%Y%m%d-%H%M%S).tsv
echo "writing $OUT"
echo -e "context\tworkload\ttrial\tsamples\tp50_us\tp95_us\tp99_us\tgoodput_mbps\tpump_mbps\tbytes" > "$OUT"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SRV_LOG=/tmp/srv-iroh-${LABEL}.log
CLI_OUT=/tmp/cli-iroh-${LABEL}.out

run_remote() {
    if [ "$1" = "local" ]; then bash -c "$3"
    else ssh $SSH_OPTS "${1}@${2}" "$3"
    fi
}
run_remote_bg() {
    if [ "$1" = "local" ]; then
        rm -f "$SRV_LOG"; bash -c "$3" > "$SRV_LOG" 2>&1 &
        echo $!
    else
        ssh $SSH_OPTS "${1}@${2}" "rm -f $SRV_LOG; nohup $3 > $SRV_LOG 2>&1 < /dev/null & echo \$!" 2>/dev/null | tail -1
    fi
}
fetch_log() {
    if [ "$1" = "local" ]; then cat "$SRV_LOG" 2>/dev/null
    else ssh $SSH_OPTS "${1}@${2}" "cat $SRV_LOG 2>/dev/null"
    fi
}
kill_remote() {
    if [ "$1" = "local" ]; then kill "$3" 2>/dev/null; pkill -f drift-bench 2>/dev/null; true
    else ssh $SSH_OPTS "${1}@${2}" "kill $3 2>/dev/null; pkill -f drift-bench 2>/dev/null; true" > /dev/null 2>&1
    fi
}

run_one() {
    local workload="$1" trial="$2"
    local extra=""
    case $workload in
        handshake)  extra="--handshake-iters 20" ;;
        rtt)        extra="--rtt-iters 500 --payload-bytes 1024" ;;
        throughput) extra="--duration-secs 10 --payload-bytes 1024" ;;
    esac
    local server_cmd="${SRV_BIN} --protocol drift --mode server --workload ${workload} --listen iroh://0.0.0.0:0 ${extra} --server-idle-secs 60"
    local pid
    pid=$(run_remote_bg "$SRV_USER" "$SRV_IP" "$server_cmd")
    if [ -z "$pid" ]; then
        echo -e "${LABEL}\t${workload}\t${trial}\t\t\t\t\t\t\t" >> "$OUT"
        return
    fi
    sleep 4

    # Scrape endpoint id + bound port from server stderr
    local srv_log
    srv_log=$(fetch_log "$SRV_USER" "$SRV_IP")
    local iroh_id iroh_port
    iroh_id=$(echo "$srv_log" | grep -oE 'id=[a-f0-9]{64}' | head -1 | cut -d= -f2)
    iroh_port=$(echo "$srv_log" | grep -oE '0\.0\.0\.0:[0-9]+' | head -1 | cut -d: -f2)
    if [ -z "$iroh_id" ] || [ -z "$iroh_port" ]; then
        echo "FAILED to scrape iroh endpoint id from server"
        kill_remote "$SRV_USER" "$SRV_IP" "$pid"
        echo -e "${LABEL}\t${workload}\t${trial}\t\t\t\t\t\t\t" >> "$OUT"
        return
    fi
    local target="iroh://${iroh_id}@${SRV_IP}:${iroh_port}"
    echo "  [$LABEL $workload trial=$trial] target=$target"

    local client_cmd="${CLI_BIN} --protocol drift --mode client --workload ${workload} --target ${target} ${extra}"
    if [ "$CLI_USER" = "local" ]; then
        bash -c "$client_cmd" > "$CLI_OUT" 2>/tmp/cli-iroh-err.log
    else
        ssh $SSH_OPTS "${CLI_USER}@${CLI_IP}" "$client_cmd" > "$CLI_OUT" 2>/tmp/cli-iroh-err.log
    fi
    if [ "$workload" = "throughput" ]; then sleep 6; fi

    # Parse client JSON from temp file
    local samples="" p50="" p95="" p99="" pump=""
    if [ -s "$CLI_OUT" ]; then
        parsed=$(python3 - <<PYEOF
import json
with open('$CLI_OUT') as f:
    lines = [l for l in f if l.startswith('{')]
if lines:
    d = json.loads(lines[0])
    sm = d.get('handshake_samples') or d.get('rtt_samples') or ''
    p50 = d.get('handshake_p50_us') or d.get('rtt_p50_us') or ''
    p95 = d.get('handshake_p95_us') or d.get('rtt_p95_us') or ''
    p99 = d.get('handshake_p99_us') or d.get('rtt_p99_us') or ''
    pump = d.get('throughput_mbps') or ''
    print(f'{sm}|{p50}|{p95}|{p99}|{pump}')
else:
    print('||||')
PYEOF
)
        IFS='|' read -r samples p50 p95 p99 pump <<< "$parsed"
    fi

    # Fetch server log for BENCH markers
    local good="" brec=""
    srv_log=$(fetch_log "$SRV_USER" "$SRV_IP")
    brec=$(echo "$srv_log" | grep -oE 'BENCH_BYTES_RECEIVED=[0-9]+' | tail -1 | cut -d= -f2)
    dur=$(echo "$srv_log" | grep -oE 'BENCH_DURATION_S=[0-9.]+' | tail -1 | cut -d= -f2)
    if [ -n "$brec" ] && [ -n "$dur" ]; then
        good=$(python3 -c "print(f'{($brec*8.0)/($dur*1_000_000):.1f}')" 2>/dev/null || echo "")
    fi

    echo -e "${LABEL}\t${workload}\t${trial}\t${samples}\t${p50}\t${p95}\t${p99}\t${good}\t${pump}\t${brec}" >> "$OUT"
    kill_remote "$SRV_USER" "$SRV_IP" "$pid"
    sleep 1
}

START=$(date +%s)
for trial in $(seq 1 $TRIALS); do
    for workload in handshake rtt throughput; do
        run_one "$workload" "$trial"
    done
done
END=$(date +%s)
echo "==== $LABEL done in $((END-START))s; results in $OUT ===="
column -t -s $'\t' "$OUT"

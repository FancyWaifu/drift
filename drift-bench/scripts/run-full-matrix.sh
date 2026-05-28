#!/bin/bash
# Full DRIFT bench matrix: wires × workloads × trials, one
# server/client topology per invocation. Output is a TSV
# aggregable across contexts.
#
# Usage:
#   run-full-matrix.sh <srv_ip> <srv_user> <srv_bin> <cli_ip> <cli_user> <cli_bin> <label> [trials]
#
#   srv_user / cli_user can be "local" to mean "no ssh, just bash".
#   trials defaults to 3.

set -u
SRV_IP="${1:?server ip}"
SRV_USER="${2:?server user or 'local'}"
SRV_BIN="${3:?server binary}"
CLI_IP="${4:?client ip}"
CLI_USER="${5:?client user or 'local'}"
CLI_BIN="${6:?client binary}"
LABEL="${7:?label}"
TRIALS="${8:-3}"

OUT=/tmp/drift-matrix-${LABEL}-$(date +%Y%m%d-%H%M%S).tsv
echo "writing $OUT"
echo -e "context\twire\tworkload\ttrial\tsamples\tp50_us\tp95_us\tp99_us\tgoodput_mbps\tpump_mbps\tbytes" > "$OUT"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SRV_LOG=/tmp/srv-mx-${LABEL}.log

run_remote() {
    local user="$1" ip="$2" cmd="$3"
    if [ "$user" = "local" ]; then
        bash -c "$cmd"
    else
        ssh $SSH_OPTS "${user}@${ip}" "$cmd"
    fi
}

run_remote_bg() {
    local user="$1" ip="$2" cmd="$3"
    if [ "$user" = "local" ]; then
        rm -f "$SRV_LOG"
        bash -c "$cmd" > "$SRV_LOG" 2>&1 &
        echo $!
    else
        ssh $SSH_OPTS "${user}@${ip}" "rm -f $SRV_LOG; nohup $cmd > $SRV_LOG 2>&1 < /dev/null & echo \$!" 2>/dev/null | tail -1
    fi
}

fetch_log() {
    local user="$1" ip="$2"
    if [ "$user" = "local" ]; then
        cat "$SRV_LOG" 2>/dev/null
    else
        ssh $SSH_OPTS "${user}@${ip}" "cat $SRV_LOG 2>/dev/null"
    fi
}

kill_remote() {
    local user="$1" ip="$2" pid="$3"
    if [ "$user" = "local" ]; then
        kill "$pid" 2>/dev/null; pkill -f drift-bench 2>/dev/null; true
    else
        ssh $SSH_OPTS "${user}@${ip}" "kill $pid 2>/dev/null; pkill -f drift-bench 2>/dev/null; true" > /dev/null 2>&1
    fi
}

# Wires + ports (each wire gets its own port to avoid port reuse races)
WIRES=(
    "udp:9701"
    "tcp:9702"
    "tls:9703"
    "ws:9704"
    "h2:9706"
    "h2s:9707"
    "webtransport:9708"
)

# Parses JSON output and writes a TSV row
emit_row() {
    local wire="$1" workload="$2" trial="$3" json="$4"
    python3 - <<PYEOF
import sys, json, os
try:
    d = json.loads("""$json""" if """$json""" else "{}")
except Exception:
    d = {}
def g(k):
    v = d.get(k)
    return "" if v is None else (f"{v}" if isinstance(v, (int, float)) else str(v))
context = os.environ.get('CONTEXT', '$LABEL')
print(f"{context}\t$wire\t$workload\t$trial\t{g('handshake_samples') or g('rtt_samples') or ''}\t{g('handshake_p50_us') or g('rtt_p50_us') or ''}\t{g('handshake_p95_us') or g('rtt_p95_us') or ''}\t{g('handshake_p99_us') or g('rtt_p99_us') or ''}\t\t{g('throughput_mbps')}\t{g('bytes_moved')}")
PYEOF
}

run_one_workload() {
    local wire="$1" port="$2" workload="$3" trial="$4"
    local extra=""
    case $workload in
        handshake)  extra="--handshake-iters 20" ;;
        rtt)        extra="--rtt-iters 500 --payload-bytes 1024" ;;
        throughput) extra="--duration-secs 10 --payload-bytes 1024" ;;
    esac

    local server_cmd="${SRV_BIN} --protocol drift --mode server --workload ${workload} --listen ${wire}://0.0.0.0:${port} ${extra} --server-idle-secs 60"
    local pid
    pid=$(run_remote_bg "$SRV_USER" "$SRV_IP" "$server_cmd")
    if [ -z "$pid" ]; then
        echo -e "$LABEL\t$wire\t$workload\t$trial\t\t\t\t\t\t\t" >> "$OUT"
        return
    fi
    sleep 3

    local client_cmd="${CLI_BIN} --protocol drift --mode client --workload ${workload} --target ${wire}://${SRV_IP}:${port} ${extra}"
    local result
    result=$(run_remote "$CLI_USER" "$CLI_IP" "$client_cmd" 2>/tmp/cli-err.log)
    local rc=$?

    if [ $workload = "throughput" ]; then
        sleep 6  # let server emit BENCH markers
    fi

    local good="" pump="" brec=""
    local p50="" p95="" p99="" samples=""

    if [ $rc -eq 0 ] && [ -n "$result" ]; then
        # parse client-side JSON
        local parsed
        parsed=$(python3 -c "
import sys, json
try:
    d = json.loads('''$result''')
    sm = d.get('handshake_samples') or d.get('rtt_samples') or ''
    p50 = d.get('handshake_p50_us') or d.get('rtt_p50_us') or ''
    p95 = d.get('handshake_p95_us') or d.get('rtt_p95_us') or ''
    p99 = d.get('handshake_p99_us') or d.get('rtt_p99_us') or ''
    pump = d.get('throughput_mbps') or ''
    print(f'{sm}|{p50}|{p95}|{p99}|{pump}')
except Exception as e:
    print('||||')
" 2>/dev/null)
        IFS='|' read -r samples p50 p95 p99 pump <<< "$parsed"

        # If throughput, fetch goodput from server log
        if [ $workload = "throughput" ]; then
            local srv_log
            srv_log=$(fetch_log "$SRV_USER" "$SRV_IP")
            brec=$(echo "$srv_log" | grep -oE "BENCH_BYTES_RECEIVED=[0-9]+" | tail -1 | cut -d= -f2)
            local dur
            dur=$(echo "$srv_log" | grep -oE "BENCH_DURATION_S=[0-9.]+" | tail -1 | cut -d= -f2)
            if [ -n "$brec" ] && [ -n "$dur" ]; then
                good=$(python3 -c "print(f'{($brec*8.0)/($dur*1_000_000):.1f}')" 2>/dev/null || echo "")
            fi
        fi
    fi
    echo -e "$LABEL\t$wire\t$workload\t$trial\t$samples\t$p50\t$p95\t$p99\t$good\t$pump\t$brec" >> "$OUT"
    kill_remote "$SRV_USER" "$SRV_IP" "$pid"
    sleep 1
}

START=$(date +%s)
for trial in $(seq 1 $TRIALS); do
    for entry in "${WIRES[@]}"; do
        wire="${entry%%:*}"
        port="${entry##*:}"
        for workload in handshake rtt throughput; do
            echo "  [$LABEL trial=$trial wire=$wire workload=$workload]"
            run_one_workload "$wire" "$port" "$workload" "$trial"
        done
    done
done
END=$(date +%s)
echo "==== $LABEL done in $((END-START))s; results in $OUT ===="
column -t -s $'\t' "$OUT" | head -50

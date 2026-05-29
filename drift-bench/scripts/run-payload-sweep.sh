#!/bin/bash
# Throughput-only DRIFT wire sweep with configurable payload
# size. Companion to run-full-matrix.sh (which is 1 KB only).
# Goodput, 3 trials per cell.
#
# Usage:
#   run-payload-sweep.sh <srv_ip> <srv_user> <srv_bin> <cli_ip> <cli_user> <cli_bin> <label> <payload_bytes> [trials]

set -u
SRV_IP="${1:?server ip}"
SRV_USER="${2:?server user or 'local'}"
SRV_BIN="${3:?server binary}"
CLI_IP="${4:?client ip}"
CLI_USER="${5:?client user or 'local'}"
CLI_BIN="${6:?client binary}"
LABEL="${7:?label}"
PAYLOAD="${8:?payload bytes}"
TRIALS="${9:-3}"

OUT=/tmp/drift-payload-${LABEL}-${PAYLOAD}-$(date +%Y%m%d-%H%M%S).tsv
echo "writing $OUT"
echo -e "context\tpayload_bytes\twire\ttrial\tgoodput_mbps\tpump_mbps\tbytes_received\tduration_s" > "$OUT"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SRV_LOG=/tmp/srv-pl-${LABEL}-${PAYLOAD}.log

run_remote() {
    if [ "$1" = "local" ]; then
        bash -c "$3"
    else
        ssh $SSH_OPTS "${1}@${2}" "$3"
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

WIRES=(
    "udp:9701"
    "tcp:9702"
    "tls:9703"
    "ws:9704"
    "h2:9706"
    "h2s:9707"
    "webtransport:9708"
)

START=$(date +%s)
for trial in $(seq 1 $TRIALS); do
    for entry in "${WIRES[@]}"; do
        wire="${entry%%:*}"
        port="${entry##*:}"
        echo "  [$LABEL payload=$PAYLOAD trial=$trial wire=$wire]"
        server_cmd="${SRV_BIN} --protocol drift --mode server --workload throughput --listen ${wire}://0.0.0.0:${port} --duration-secs 10 --payload-bytes ${PAYLOAD} --server-idle-secs 60"
        pid=$(run_remote_bg "$SRV_USER" "$SRV_IP" "$server_cmd")
        if [ -z "$pid" ]; then
            echo -e "${LABEL}\t${PAYLOAD}\t${wire}\t${trial}\t\t\t\t" >> "$OUT"
            continue
        fi
        sleep 3
        client_cmd="${CLI_BIN} --protocol drift --mode client --workload throughput --target ${wire}://${SRV_IP}:${port} --duration-secs 10 --payload-bytes ${PAYLOAD}"
        result=$(run_remote "$CLI_USER" "$CLI_IP" "$client_cmd" 2>/tmp/cli-err.log)
        rc=$?
        sleep 6
        pump=""
        if [ $rc -eq 0 ] && [ -n "$result" ]; then
            pump=$(python3 -c "import sys,json; d=json.loads('''$result'''); print(d.get('throughput_mbps',''))" 2>/dev/null || echo "")
        fi
        srv_log=$(fetch_log "$SRV_USER" "$SRV_IP")
        brec=$(echo "$srv_log" | grep -oE "BENCH_BYTES_RECEIVED=[0-9]+" | tail -1 | cut -d= -f2)
        dur=$(echo "$srv_log" | grep -oE "BENCH_DURATION_S=[0-9.]+" | tail -1 | cut -d= -f2)
        good=""
        if [ -n "$brec" ] && [ -n "$dur" ]; then
            good=$(python3 -c "print(f'{($brec*8.0)/($dur*1_000_000):.1f}')" 2>/dev/null || echo "")
        fi
        echo -e "${LABEL}\t${PAYLOAD}\t${wire}\t${trial}\t${good}\t${pump}\t${brec}\t${dur}" >> "$OUT"
        kill_remote "$SRV_USER" "$SRV_IP" "$pid"
        sleep 1
    done
done
END=$(date +%s)
echo "==== ${LABEL} payload=${PAYLOAD} done in $((END-START))s; results in $OUT ===="

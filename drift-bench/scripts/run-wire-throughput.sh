#!/bin/bash
# DRIFT throughput across wires, loopback inside one host.
# Output: TSV with (wire, trial, pump_mbps, goodput_mbps).
#
# Usage: run-wire-throughput.sh [trials]

set -u
TRIALS="${1:-3}"
# Binary path is env-overridable so a baseline-vs-current comparison
# can point at each build in place (avoids copying, which can
# invalidate an ad-hoc code signature on arm64 macOS).
BIN="${BIN:-/tmp/drift-bench}"
PAYLOAD=1024
DUR=10

OUT="/tmp/wire-throughput-$(date +%Y%m%d-%H%M%S).tsv"
echo "writing $OUT"
echo -e "wire\ttrial\tpump_mbps\tgoodput_mbps\tbytes_received" > "$OUT"

cleanup() {
    pkill -9 drift-bench 2>/dev/null
    sleep 1
}

run_wire() {
    local wire="$1" port="$2" trial="$3"
    cleanup

    local srv_log=/tmp/srv-${wire}-${trial}.log
    local cli_out=/tmp/cli-${wire}-${trial}.out
    rm -f "$srv_log" "$cli_out"

    local target_url
    if [ "$wire" = "iroh" ]; then
        # Server: deterministic secret so endpoint id is stable
        # and probeable from its stderr.
        DRIFT_IROH_SECRET_HEX=aa00000000000000000000000000000000000000000000000000000000000000 \
        $BIN --protocol drift --mode server --workload throughput \
             --listen iroh://0.0.0.0:${port} \
             --duration-secs $DUR --payload-bytes $PAYLOAD --server-idle-secs 30 \
             > "$srv_log" 2>&1 &
        sleep 3
        local iroh_id
        iroh_id=$(grep -oE 'id=[0-9a-f]{64}' "$srv_log" | head -1 | cut -d= -f2)
        if [ -z "$iroh_id" ]; then
            echo "  $wire trial=$trial: failed to scrape iroh id"
            echo -e "${wire}\t${trial}\tFAIL_PROBE\t\t" >> "$OUT"
            cleanup
            return
        fi
        target_url="iroh://${iroh_id}@127.0.0.1:${port}"
        # Client: explicitly NO DRIFT_IROH_SECRET_HEX. Without it,
        # iroh generates a fresh random key → distinct endpoint
        # id from the server → no "connecting to ourself" refusal.
        unset DRIFT_IROH_SECRET_HEX
    else
        $BIN --protocol drift --mode server --workload throughput \
             --listen ${wire}://0.0.0.0:${port} \
             --duration-secs $DUR --payload-bytes $PAYLOAD --server-idle-secs 30 \
             > "$srv_log" 2>&1 &
        sleep 3
        target_url="${wire}://127.0.0.1:${port}"
    fi

    # Run client. It runs for $DUR seconds then exits.
    $BIN --protocol drift --mode client --workload throughput \
         --target "$target_url" \
         --duration-secs $DUR --payload-bytes $PAYLOAD \
         > "$cli_out" 2>&1

    # Wait for server's recv loop to time out (5s idle) and flush
    # the BENCH_BYTES_RECEIVED / BENCH_DURATION_S markers, THEN
    # parse, THEN kill. The Drift server stays alive on
    # --server-idle-secs 30, but its workload loop is the thing
    # that exits and writes markers.
    sleep 8

    local pump
    pump=$(python3 -c "
import json
for line in open('$cli_out'):
    line=line.strip()
    if line.startswith('{'):
        try:
            d=json.loads(line)
            v=d.get('throughput_mbps')
            if v is not None: print(f'{v:.1f}'); break
        except: pass
else:
    print('-')
" 2>/dev/null)

    local goodput bytes_received
    goodput=$(python3 -c "
import re
log = open('$srv_log').read()
b = re.search(r'BENCH_BYTES_RECEIVED=(\d+)', log)
d = re.search(r'BENCH_DURATION_S=([\d.]+)', log)
if b and d and float(d.group(1)) > 0:
    print(f'{(int(b.group(1))*8.0)/(float(d.group(1))*1_000_000):.1f}')
else:
    print('-')
" 2>/dev/null)
    bytes_received=$(grep -oE 'BENCH_BYTES_RECEIVED=[0-9]+' "$srv_log" | head -1 | cut -d= -f2)

    cleanup

    echo "  $wire trial=$trial: pump=${pump} Mbps  goodput=${goodput} Mbps  bytes=${bytes_received:-0}"
    echo -e "${wire}\t${trial}\t${pump}\t${goodput}\t${bytes_received:-0}" >> "$OUT"
}

echo "===== DRIFT throughput sweep: $TRIALS trials, 1KB × ${DUR}s, loopback ====="
for trial in $(seq 1 $TRIALS); do
    echo "  ─── trial $trial ───"
    run_wire udp  9701 $trial
    run_wire h2s  9707 $trial
    run_wire iroh 9709 $trial
done

echo ""
echo "===== summary (median across $TRIALS trials) ====="
python3 - <<PY
import csv
from statistics import median
rows = [r for r in csv.DictReader(open('$OUT'), delimiter='\t')]
wires = sorted(set(r['wire'] for r in rows))
print(f"{'wire':10}  {'pump_mbps':>15}  {'goodput_mbps':>15}")
for w in wires:
    pumps = [float(r['pump_mbps']) for r in rows if r['wire']==w and r['pump_mbps'] not in ('','-','FAIL_PROBE')]
    goods = [float(r['goodput_mbps']) for r in rows if r['wire']==w and r['goodput_mbps'] not in ('','-')]
    p = f"{median(pumps):>15.1f}" if pumps else f"{'-':>15}"
    g = f"{median(goods):>15.1f}" if goods else f"{'-':>15}"
    print(f"{w:10}  {p}  {g}")
PY

echo ""
echo "Full results in $OUT"

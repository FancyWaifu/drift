#!/bin/sh
# drift-vpn vs WireGuard reproducer. Expects:
#   - both tunnels already up
#   - iperf3 server on the remote side
#   - DRIFT_TARGET, WG_TARGET, BASELINE_TARGET set OR
#     defaults below
# Prints a small markdown table to stdout.

set -eu

DUR=${DUR:-20}
BASELINE_TARGET=${BASELINE_TARGET:-192.0.2.168}
DRIFT_TARGET=${DRIFT_TARGET:-10.50.0.2}
WG_TARGET=${WG_TARGET:-10.60.0.2}

sample_cpu() {
  before=$(awk '/^cpu / {idle=$5; total=$2+$3+$4+$5+$6+$7+$8; print idle, total}' /proc/stat)
  idle_b=$(echo $before | awk '{print $1}')
  total_b=$(echo $before | awk '{print $2}')
  sleep $1
  after=$(awk '/^cpu / {idle=$5; total=$2+$3+$4+$5+$6+$7+$8; print idle, total}' /proc/stat)
  idle_a=$(echo $after | awk '{print $1}')
  total_a=$(echo $after | awk '{print $2}')
  python3 -c "idle_d=$idle_a-$idle_b; total_d=$total_a-$total_b; print(round(100*(1-idle_d/total_d), 1))"
}

run_one() {
  label=$1
  target=$2
  echo "== $label ($target) ==" >&2
  iperf3 -c $target -t $DUR -J > /tmp/iperf-$label.json 2>/dev/null &
  IPID=$!
  sleep 2
  busy=$(sample_cpu 10)
  wait $IPID
  tput=$(python3 -c "import json; d=json.load(open('/tmp/iperf-$label.json')); print(round(d['end']['sum_received']['bits_per_second']/1e6,1))")
  echo "$label,$tput,$busy"
}

echo "scenario,throughput_mbps,cpu_pct"
run_one "baseline" $BASELINE_TARGET
run_one "drift-vpn" $DRIFT_TARGET
run_one "wireguard" $WG_TARGET

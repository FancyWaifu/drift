#!/bin/bash
# bench-matrix.sh — wire-agnostic throughput matrix for drift-vpn
#
# For each working drift scheme (udp/tcp/ws/tls/http/dns), brings up
# a direct D1↔D2 drift-vpn tunnel, runs a 15s iperf3, and records
# throughput + system-wide CPU. Skips schemes with no native
# connector (doh/webtransport/webrtc).
#
# Usage:
#   ssh keys must reach root@192.0.2.{52,168}.
#   drift-vpn binary should already be deployed to /usr/local/bin/drift-vpn
#   on both LXCs (run scp first if you just rebuilt).
#
# Output: markdown table to stdout, also saved to
#   bench/bench-matrix-$(date +%Y%m%d-%H%M%S).md
#
# This script is intentionally re-run-friendly: it cleans up between
# schemes so consecutive invocations measure the same fresh state.

set +e

D1=192.0.2.52
D2=192.0.2.168
IDENTITY=/tmp/bench-drift/d-bench.key
D1_PUB=2c0c82fd6d5d49135a42091c82f7170cad648eaf7e3776a12488e96ab7bcc762
D2_PUB=f910bce8c3ad800c149a597c8747d2de3faee6dd2937b6bed2eb6e723638db32

DUR=${DUR:-15}

# Each entry: "scheme port_d1 port_d2 mtu"
# MTU 1200 keeps headers under the typical Internet path MTU even
# through encapsulating wires; same MTU per scheme for apples-to-apples.
SCHEMES=(
  "udp  52001 52002 1200"
  "tcp  52003 52004 1200"
  "ws   52005 52006 1200"
  "tls  52007 52008 1200"
  "http 52009 52010 1200"
  "dns  52011 52012 1200"
)

OUTFILE=${OUTFILE:-bench/bench-matrix-$(date +%Y%m%d-%H%M%S).md}
mkdir -p "$(dirname "$OUTFILE")"

write_config() {
  local host=$1 role=$2 scheme=$3 my_port=$4 peer_port=$5 peer_ip=$6 mtu=$7
  local my_addr peer_allowed peer_pub
  if [ "$role" = "d1" ]; then
    my_addr="10.50.0.1/24"; peer_allowed="10.50.0.2/32"; peer_pub=$D2_PUB
  else
    my_addr="10.50.0.2/24"; peer_allowed="10.50.0.1/32"; peer_pub=$D1_PUB
  fi
  ssh root@$host "cat > /tmp/cov-test/config.toml" <<EOF
[interface]
identity_file = "$IDENTITY"
address       = "$my_addr"
listen        = "$scheme://0.0.0.0:$my_port"
mtu           = $mtu

[[peer]]
name        = "peer"
public_key  = "$peer_pub"
allowed_ips = ["$peer_allowed"]
endpoint    = "$scheme://$peer_ip:$peer_port"
keepalive   = 0
EOF
}

cleanup_both() {
  ssh root@$D1 'pkill -9 -f cov-test/config.toml 2>/dev/null; sleep 1' >/dev/null 2>&1 &
  ssh root@$D2 'pkill -9 -f cov-test/config.toml 2>/dev/null; sleep 1' >/dev/null 2>&1 &
  wait
}

bring_up_pair() {
  local scheme=$1 p1=$2 p2=$3 mtu=$4
  ssh root@$D1 'mkdir -p /tmp/cov-test'
  ssh root@$D2 'mkdir -p /tmp/cov-test'
  write_config $D1 d1 $scheme $p1 $p2 $D2 $mtu
  write_config $D2 d2 $scheme $p2 $p1 $D1 $mtu
  # Parallel bringup so PERF.4 retrier handles the stream-wire
  # symmetric-race case correctly.
  ( ssh root@$D1 'setsid nohup drift-vpn up --config /tmp/cov-test/config.toml > /tmp/cov-test/d1.log 2>&1 < /dev/null &' ) &
  ( ssh root@$D2 'setsid nohup drift-vpn up --config /tmp/cov-test/config.toml > /tmp/cov-test/d2.log 2>&1 < /dev/null &' ) &
  wait
  # Stream wires need longer warmup for the connect-retrier to land
  # the handshake. UDP/DNS handshake instantly.
  case "$scheme" in
    udp|dns) sleep 3 ;;
    *)       sleep 6 ;;
  esac
}

bench_one() {
  local scheme=$1
  # Verify ping first; if no handshake, skip iperf3.
  local ping_out
  ping_out=$(ssh root@$D1 'ping -c 2 -W 2 10.50.0.2 2>&1 | tail -1')
  if ! echo "$ping_out" | grep -q "min/avg"; then
    echo "$scheme  -  -  no handshake  -"
    return
  fi
  ssh root@$D2 'pkill iperf3 2>/dev/null; sleep 1; setsid nohup iperf3 -s > /tmp/iperf-server.log 2>&1 < /dev/null &'
  sleep 1
  # System-wide CPU sample during the run (matches the methodology
  # we used for the WG comparison — apples-to-apples).
  local result
  result=$(ssh root@$D1 bash -s <<EOF
before=\$(awk '/^cpu / {idle=\$5; total=\$2+\$3+\$4+\$5+\$6+\$7+\$8; print idle, total}' /proc/stat)
iperf3 -c 10.50.0.2 -t $DUR -J > /tmp/iperf-$scheme.json 2>/dev/null
after=\$(awk '/^cpu / {idle=\$5; total=\$2+\$3+\$4+\$5+\$6+\$7+\$8; print idle, total}' /proc/stat)
python3 -c "
b='\$before'.split(); a='\$after'.split()
idle_d=int(a[0])-int(b[0]); total_d=int(a[1])-int(b[1])
busy=100*(1-idle_d/total_d) if total_d > 0 else 0
import json
try:
    d=json.load(open('/tmp/iperf-$scheme.json'))
    gbps=d['end']['sum_received']['bits_per_second']/1e9
    print(f'{gbps:.2f} {busy:.1f}')
except Exception as e:
    print(f'0.00 {busy:.1f}')
"
EOF
)
  local gbps cpu
  gbps=$(echo "$result" | awk '{print $1}')
  cpu=$(echo "$result" | awk '{print $2}')
  local rtt
  rtt=$(echo "$ping_out" | grep -oE 'min/avg[^=]*= [0-9./]+' | sed 's|.*= ||' | cut -d/ -f2)
  echo "$scheme  $gbps  $cpu  ok  ${rtt}ms"
}

# ─── main ──────────────────────────────────────────────────────────

{
  echo "# drift-vpn cross-wire bench"
  echo ""
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Duration: ${DUR}s per scheme"
  echo "Fabric: D1 ($D1) ↔ D2 ($D2), Proxmox LXC"
  echo "Methodology: iperf3 TCP through drift-vpn tunnel, system-wide CPU sampled during run"
  echo ""
  echo "| scheme | Throughput (Gbps) | System CPU (%) | Status | Ping RTT |"
  echo "|--------|-------------------|----------------|--------|----------|"
} | tee "$OUTFILE"

for entry in "${SCHEMES[@]}"; do
  read scheme p1 p2 mtu <<< "$entry"
  cleanup_both
  sleep 1
  bring_up_pair $scheme $p1 $p2 $mtu
  result=$(bench_one $scheme)
  read sname gbps cpu status rtt <<< "$result"
  printf "| %-6s | %-17s | %-14s | %-6s | %-8s |\n" "$sname" "$gbps" "$cpu" "$status" "$rtt" | tee -a "$OUTFILE"
done

cleanup_both
echo "" | tee -a "$OUTFILE"
echo "Saved to: $OUTFILE"

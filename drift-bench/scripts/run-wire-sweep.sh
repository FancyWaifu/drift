#!/bin/bash
# Sweep DRIFT throughput across its available wire adapters.
# Answers the "how much does the chosen wire cost vs the
# protocol's UDP baseline?" question — each row shows the same
# DRIFT protocol layer riding a different transport.
#
# Loopback (127.0.0.1) on a single host. Numbers will scale
# differently on real LAN / WAN.

set -u
BIN=/Users/5speeddeasil/drift/target/release/drift-bench
OUT=/tmp/drift-wire-sweep-$(date +%Y%m%d-%H%M%S).jsonl
echo "writing results to $OUT"
> "$OUT"

run_throughput_for_wire() {
    local label="$1" scheme="$2" port="$3"
    echo "==== DRIFT over $label ($scheme://) ===="
    local listen="${scheme}://127.0.0.1:${port}"
    local target="${scheme}://127.0.0.1:${port}"

    $BIN --protocol drift --mode server --workload throughput \
        --listen "$listen" --duration-secs 10 --payload-bytes 1024 \
        --server-idle-secs 30 > /tmp/srv.log 2>&1 &
    local SPID=$!
    sleep 2
    local result
    result=$($BIN --protocol drift --mode client --workload throughput \
        --target "$target" --duration-secs 10 --payload-bytes 1024 2>/tmp/cli.err)
    local rc=$?
    if [ $rc -eq 0 ] && [ -n "$result" ]; then
        # tag with wire label
        echo "$result" | sed "s/\"throughput\"/\"throughput[$label]\"/" | tee -a "$OUT"
    else
        echo "FAILED rc=$rc wire=$label"
        echo "client err:"
        tail -5 /tmp/cli.err
        echo "server log:"
        tail -10 /tmp/srv.log
    fi
    kill $SPID 2>/dev/null
    wait $SPID 2>/dev/null
    sleep 1
}

# Wire | scheme | port
# Skipping: dns/doh (need external infra), onion (Tor, slow),
# webrtc (no URL scheme), in-memory (no addr).
run_throughput_for_wire "udp"          udp          9701
run_throughput_for_wire "tcp"          tcp          9702
run_throughput_for_wire "tls"          tls          9703
run_throughput_for_wire "ws"           ws           9704
run_throughput_for_wire "wss"          wss          9705
run_throughput_for_wire "h2"           h2           9706
run_throughput_for_wire "h2s"          h2s          9707
run_throughput_for_wire "webtransport" webtransport 9708

echo ""
echo "==== summary ===="
cat "$OUT"

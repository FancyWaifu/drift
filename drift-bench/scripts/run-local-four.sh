#!/bin/bash
# Run a comparative bench across DRIFT, QUIC, WireGuard, Iroh
# on loopback (single Mac). Each (proto, workload) pair runs as
# a server + client subprocess pair. JSON results captured.
#
# Skip WireGuard for now if rcgen/boringtun on macOS need root
# for TUN device creation — keep it tractable in one session.

set -u
BIN=/Users/5speeddeasil/drift/target/release/drift-bench
OUT=/tmp/bench-results-$(date +%Y%m%d-%H%M%S).jsonl
echo "writing results to $OUT"
> "$OUT"

run_pair() {
    local proto="$1" workload="$2" extra="${3:-}"
    echo "==== $proto $workload $extra ===="
    rm -f /tmp/iroh-nodeaddr.json /tmp/quic-cert.der /tmp/wg-server-pub.txt 2>/dev/null
    local listen="127.0.0.1:0"
    case $proto in
        wireguard) listen="127.0.0.1:51820" ;;
        *)         listen="127.0.0.1:9700" ;;
    esac
    $BIN --protocol "$proto" --mode server --workload "$workload" --listen "$listen" --server-idle-secs 60 $extra > /tmp/srv.log 2>&1 &
    local SPID=$!
    sleep 2
    local target="127.0.0.1:9700"
    [ "$proto" = "wireguard" ] && target="127.0.0.1:51820"
    local result
    result=$($BIN --protocol "$proto" --mode client --workload "$workload" --target "$target" $extra 2>/tmp/cli.err)
    local rc=$?
    if [ $rc -eq 0 ] && [ -n "$result" ]; then
        echo "$result" | tee -a "$OUT"
    else
        echo "FAILED rc=$rc workload=$workload proto=$proto"
        tail -5 /tmp/cli.err
        tail -5 /tmp/srv.log
    fi
    kill $SPID 2>/dev/null
    wait $SPID 2>/dev/null
    sleep 1
}

for proto in drift quic iroh; do
    run_pair $proto handshake "--handshake-iters 30"
    run_pair $proto rtt "--rtt-iters 1000 --payload-bytes 1024"
    run_pair $proto throughput "--duration-secs 10 --payload-bytes 1024"
done

echo "==== done ===="
echo "Results in $OUT"
echo ""
echo "=== quick table ==="
cat "$OUT"

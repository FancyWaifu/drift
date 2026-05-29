#!/bin/bash
# K=3 federation triangle: 3 bridges all federating to each other.
# 6 directed federation edges. Compare iroh vs h2s.

set -u

# Bridge keys + iroh seeds + iroh endpoint ids
B1_PUB=a4210d1387ae2837fd5446925e4432d0c0c2eb9f6a095c83113f55b869b9257d
B2_PUB=c9ec3be425857fc0b78f30c00b7076abf00934b3e645dd7e8bd957d4c52ad53b
B3_PUB=2554ce7a1c7fedd81bc4274d4f5ed12cbac30a9b7dec9ba73e7350cb26a98012
B1_SEED=4555cabd0ece40500f06758288c1430029d559c091f3b7be1942d415d5f81ed9
B2_SEED=fb42cffab7c550d0f93f5797ef257cd037b1f99d08516bf2acf9166ba0926a3c
B3_SEED=d9f6330b010aa8768aeaa1b708d12e5701faf8c73a7b222c8a589916b4d2a03a
B1_IROH=2e60b147502c8759db3fd2bb78fecca853df402347743e8de78f65618cf19e59
B2_IROH=ec2612ebf5191231000dfb821b173b54d9847c1d910c6a27a89d62a1f700a00c
B3_IROH=ba4e0b194b5c4080286ee2d09394ae782cf39d75c1b6f1ebd8b0a0890e1f0571

DURATION=45

cleanup_all() {
    for ip in 192.168.50.52 192.168.50.168 192.168.50.253; do
        ssh -A admin@104.166.196.243 "ssh -y root@${ip} 'pkill -f \"drift bridge\" 2>/dev/null; true'" >/dev/null 2>&1 &
    done
    wait
}

run_k3() {
    local wire="$1"
    local prefix="$2"

    local b1_listen b2_listen b3_listen
    local b1_f2 b1_f3 b2_f1 b2_f3 b3_f1 b3_f2
    local b1_env b2_env b3_env

    case "$wire" in
        iroh)
            b1_listen="iroh://0.0.0.0:51800"; b2_listen="iroh://0.0.0.0:51800"; b3_listen="iroh://0.0.0.0:51800"
            b1_f2="iroh://${B2_IROH}@192.168.50.168:51800@${B2_PUB}"
            b1_f3="iroh://${B3_IROH}@192.168.50.253:51800@${B3_PUB}"
            b2_f1="iroh://${B1_IROH}@192.168.50.52:51800@${B1_PUB}"
            b2_f3="iroh://${B3_IROH}@192.168.50.253:51800@${B3_PUB}"
            b3_f1="iroh://${B1_IROH}@192.168.50.52:51800@${B1_PUB}"
            b3_f2="iroh://${B2_IROH}@192.168.50.168:51800@${B2_PUB}"
            b1_env="DRIFT_IROH_SECRET_HEX=${B1_SEED}"
            b2_env="DRIFT_IROH_SECRET_HEX=${B2_SEED}"
            b3_env="DRIFT_IROH_SECRET_HEX=${B3_SEED}"
            ;;
        h2s)
            b1_listen="h2s://0.0.0.0:51900"; b2_listen="h2s://0.0.0.0:51900"; b3_listen="h2s://0.0.0.0:51900"
            b1_f2="h2s://192.168.50.168:51900@${B2_PUB}"
            b1_f3="h2s://192.168.50.253:51900@${B3_PUB}"
            b2_f1="h2s://192.168.50.52:51900@${B1_PUB}"
            b2_f3="h2s://192.168.50.253:51900@${B3_PUB}"
            b3_f1="h2s://192.168.50.52:51900@${B1_PUB}"
            b3_f2="h2s://192.168.50.168:51900@${B2_PUB}"
            b1_env=""; b2_env=""; b3_env=""
            ;;
    esac

    cleanup_all
    sleep 3

    echo "==== $wire (K=3 triangle, $DURATION s window) ===="

    ssh -A admin@104.166.196.243 \
        "ssh -y root@192.168.50.52 \"$b1_env RUST_LOG=info,drift::transport=debug /tmp/drift bridge --identity /tmp/bridge1.key --listen $b1_listen --federate '$b1_f2' --federate '$b1_f3'\"" \
        > /tmp/${prefix}-b1.log 2>&1 &
    local BR1=$!
    ssh -A admin@104.166.196.243 \
        "ssh -y root@192.168.50.168 \"$b2_env RUST_LOG=info,drift::transport=debug /tmp/drift bridge --identity /tmp/bridge2.key --listen $b2_listen --federate '$b2_f1' --federate '$b2_f3'\"" \
        > /tmp/${prefix}-b2.log 2>&1 &
    local BR2=$!
    ssh -A admin@104.166.196.243 \
        "ssh -y root@192.168.50.253 \"$b3_env RUST_LOG=info,drift::transport=debug /tmp/drift bridge --identity /tmp/bridge3.key --listen $b3_listen --federate '$b3_f1' --federate '$b3_f2'\"" \
        > /tmp/${prefix}-b3.log 2>&1 &
    local BR3=$!

    sleep $DURATION

    cleanup_all
    kill $BR1 $BR2 $BR3 2>/dev/null
    wait 2>/dev/null

    python3 - <<PYEOF
import re

def stats(path):
    handshakes = 0
    beacons = 0
    auth_fails = 0
    invalids = 0
    rtts = []
    dual_inits = 0
    try:
        with open(path) as f:
            for line in f:
                if 'handshake complete' in line: handshakes += 1
                if 'sent BEACON' in line: beacons += 1
                if 'authentication failed' in line: auth_fails += 1
                if 'dropped invalid' in line: invalids += 1
                if 'dual-init' in line: dual_inits += 1
                m = re.search(r'rtt_us=(\d+)', line)
                if m: rtts.append(int(m.group(1)))
    except FileNotFoundError: return None
    return dict(handshakes=handshakes, beacons=beacons, auth_fails=auth_fails,
                invalids=invalids, dual_inits=dual_inits, rtts=rtts)

import statistics
print(f"  bridge | handshakes | BEACONs | auth_fails | dual_inits | RTT samples (med µs)")
total_hs = total_bc = total_af = total_di = 0
all_rtts = []
for n in (1, 2, 3):
    s = stats(f"/tmp/${prefix}-b{n}.log")
    if not s:
        print(f"  b{n} | NO LOG"); continue
    med = int(statistics.median(s['rtts'])) if s['rtts'] else 0
    print(f"  b{n}     | {s['handshakes']:>10} | {s['beacons']:>7} | {s['auth_fails']:>10} | {s['dual_inits']:>10} | {len(s['rtts']):>6} ({med} µs)")
    total_hs += s['handshakes']; total_bc += s['beacons']
    total_af += s['auth_fails']; total_di += s['dual_inits']
    all_rtts.extend(s['rtts'])

print(f"  TOTAL | {total_hs:>10} | {total_bc:>7} | {total_af:>10} | {total_di:>10} | {len(all_rtts):>6}")
if all_rtts:
    print(f"  Combined RTT: min {min(all_rtts)} µs / median {int(statistics.median(all_rtts))} µs / max {max(all_rtts)} µs")
print()
PYEOF
}

run_k3 iroh iroh-k3
sleep 5
run_k3 h2s h2s-k3

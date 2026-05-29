#!/bin/bash
# DRIFT federation: iroh vs h2s comparison, takes timestamps from
# log lines and measures BEACON exchange + auth-fail rate.

set -u

BRIDGE1_PUB=a4210d1387ae2837fd5446925e4432d0c0c2eb9f6a095c83113f55b869b9257d
BRIDGE2_PUB=c9ec3be425857fc0b78f30c00b7076abf00934b3e645dd7e8bd957d4c52ad53b
B1_SEED=4555cabd0ece40500f06758288c1430029d559c091f3b7be1942d415d5f81ed9
B2_SEED=fb42cffab7c550d0f93f5797ef257cd037b1f99d08516bf2acf9166ba0926a3c
B1_IROH=2e60b147502c8759db3fd2bb78fecca853df402347743e8de78f65618cf19e59
B2_IROH=ec2612ebf5191231000dfb821b173b54d9847c1d910c6a27a89d62a1f700a00c

DURATION=45  # seconds to let federation run

cleanup_bridges() {
    ssh -A admin@104.166.196.243 "ssh -y root@192.168.50.52 'pkill -f \"drift bridge\" 2>/dev/null; true'" >/dev/null 2>&1
    ssh -A admin@104.166.196.243 "ssh -y root@192.168.50.168 'pkill -f \"drift bridge\" 2>/dev/null; true'" >/dev/null 2>&1
}

run_fed() {
    local wire="$1"
    local prefix="$2"
    local b1_listen b2_listen b1_fed b2_fed b1_env b2_env

    case "$wire" in
        iroh)
            b1_listen="iroh://0.0.0.0:51800"
            b2_listen="iroh://0.0.0.0:51800"
            b1_fed="iroh://${B2_IROH}@192.168.50.168:51800@${BRIDGE2_PUB}"
            b2_fed="iroh://${B1_IROH}@192.168.50.52:51800@${BRIDGE1_PUB}"
            b1_env="DRIFT_IROH_SECRET_HEX=${B1_SEED}"
            b2_env="DRIFT_IROH_SECRET_HEX=${B2_SEED}"
            ;;
        h2s)
            b1_listen="h2s://0.0.0.0:51900"
            b2_listen="h2s://0.0.0.0:51900"
            b1_fed="h2s://192.168.50.168:51900@${BRIDGE2_PUB}"
            b2_fed="h2s://192.168.50.52:51900@${BRIDGE1_PUB}"
            b1_env=""
            b2_env=""
            ;;
    esac

    cleanup_bridges
    sleep 3

    echo "===== $wire ====="
    ssh -A admin@104.166.196.243 \
        "ssh -y root@192.168.50.52 \"$b1_env RUST_LOG=info,drift::transport=debug /tmp/drift bridge --identity /tmp/bridge1.key --listen $b1_listen --federate '$b1_fed'\"" \
        > /tmp/${prefix}-b1.log 2>&1 &
    local BR1=$!
    ssh -A admin@104.166.196.243 \
        "ssh -y root@192.168.50.168 \"$b2_env RUST_LOG=info,drift::transport=debug /tmp/drift bridge --identity /tmp/bridge2.key --listen $b2_listen --federate '$b2_fed'\"" \
        > /tmp/${prefix}-b2.log 2>&1 &
    local BR2=$!

    sleep $DURATION

    cleanup_bridges
    kill $BR1 $BR2 2>/dev/null
    wait 2>/dev/null

    # Analyze
    python3 - <<PYEOF
import re

def parse_log(path):
    events = []
    try:
        with open(path) as f:
            for line in f:
                # Extract ISO timestamp from tracing output
                m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)', line)
                if not m:
                    continue
                ts = m.group(1)
                # Categorize event
                if 'iroh listener bound' in line or 'h2s listener' in line or 'h2 listener' in line:
                    events.append((ts, 'listener_bound'))
                elif 'sent HELLO ' in line and 'HELLO_ACK' not in line:
                    events.append((ts, 'sent_hello'))
                elif 'sent HELLO_ACK' in line:
                    events.append((ts, 'sent_hello_ack'))
                elif 'handshake complete' in line:
                    events.append((ts, 'handshake_complete'))
                elif 'dual-init: accepting' in line:
                    events.append((ts, 'dual_init_accept'))
                elif 'dual-init: dropping' in line:
                    events.append((ts, 'dual_init_drop'))
                elif 'sent BEACON' in line:
                    events.append((ts, 'beacon'))
                elif 'rtt_us=' in line:
                    rtt = int(re.search(r'rtt_us=(\d+)', line).group(1))
                    events.append((ts, 'rtt', rtt))
                elif 'authentication failed' in line:
                    events.append((ts, 'auth_fail'))
                elif 'dropped invalid' in line:
                    events.append((ts, 'invalid_packet'))
    except FileNotFoundError:
        pass
    return events

def summarize(label, path):
    events = parse_log(path)
    if not events:
        print(f"  {label}: no events")
        return
    listener_ts = next((t for t, k, *_ in events if k == 'listener_bound'), None)
    handshake_ts = next((t for t, k, *_ in events if k == 'handshake_complete'), None)
    if listener_ts and handshake_ts:
        from datetime import datetime
        t0 = datetime.fromisoformat(listener_ts.replace('Z', '+00:00'))
        t1 = datetime.fromisoformat(handshake_ts.replace('Z', '+00:00'))
        elapsed_ms = int((t1 - t0).total_seconds() * 1000)
        print(f"  {label}: handshake complete in {elapsed_ms} ms after listener bind")
    elif handshake_ts:
        print(f"  {label}: handshake complete at {handshake_ts}")
    else:
        print(f"  {label}: no handshake_complete event")
    beacons = sum(1 for _, k, *_ in events if k == 'beacon')
    auths = sum(1 for _, k, *_ in events if k == 'auth_fail')
    invalids = sum(1 for _, k, *_ in events if k == 'invalid_packet')
    rtts = [r[2] for r in events if r[1] == 'rtt']
    print(f"    BEACONs sent: {beacons}")
    print(f"    RTT samples: {len(rtts)}")
    if rtts:
        import statistics
        print(f"      min/med/max/stdev: {min(rtts)}/{int(statistics.median(rtts))}/{max(rtts)}/{int(statistics.stdev(rtts)) if len(rtts) > 1 else 0} µs")
    print(f"    auth-fails: {auths}, invalid-packets: {invalids}")

print("bridge1:")
summarize("bridge1", "/tmp/${prefix}-b1.log")
print("bridge2:")
summarize("bridge2", "/tmp/${prefix}-b2.log")
PYEOF
}

run_fed iroh iroh
echo ""
sleep 5
run_fed h2s h2s

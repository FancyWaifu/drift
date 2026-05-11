#!/bin/bash
# Federation resilience under bridge churn.
#
# Topology: D1 (client) → D2 (bridge) → D3 (bridge) → D4 (server)
# Federation link: symmetric --federate udp:// on both bridges.
#
# All four scenarios should pass. Scenarios 1-3 cover the bridge
# and federation layer's own restart resilience; scenario 4 covers
# drift-mosh-server's bridge watchdog (a 2 s ticker that checks
# peer_metrics().last_seen and force-rehandshakes when the link
# goes silent >5 s).

set -u
D1=192.0.2.52
D2=192.0.2.168
D3=192.0.2.253
D4=192.0.2.33
DRIFT=/root/drift_bin/drift
MS=/root/drift_bin/drift-mosh-server
MC=/root/drift_bin/drift-mosh-client
LOCAL_DRIFT=/Users/youruser/drift/target/debug/drift

cleanup_all() {
  for ip in $D1 $D2 $D3 $D4; do
    ssh -o BatchMode=yes root@$ip 'pkill -9 -f drift_bin 2>/dev/null; true' >/dev/null 2>&1
  done
  sleep 0.5
}
cleanup_all

WORKDIR=/tmp/resilience-test
mkdir -p $WORKDIR
for n in d1 d2 d3 d4; do
  $LOCAL_DRIFT keygen --output $WORKDIR/$n.key >/dev/null 2>&1
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" $WORKDIR/$n.key > $WORKDIR/$n.hex
done
PUB_D2=$($LOCAL_DRIFT info $WORKDIR/d2.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D3=$($LOCAL_DRIFT info $WORKDIR/d3.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D4=$($LOCAL_DRIFT info $WORKDIR/d4.key | grep -oE '[0-9a-f]{64}' | head -1)

scp -o BatchMode=yes $WORKDIR/d2.key root@$D2:/tmp/id.key >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d3.key root@$D3:/tmp/id.key >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d1.hex root@$D1:/tmp/id.hex >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d4.hex root@$D4:/tmp/id.hex >/dev/null 2>&1

start_d2_bridge() {
  ssh -o BatchMode=yes root@$D2 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/id.key bridge \
    --listen udp://0.0.0.0:51820 \
    --federate udp://$D3:51820@$PUB_D3 \
    > /tmp/bridge.log 2>&1 &"
}
start_d3_bridge() {
  # Symmetric --federate: D3 also points back at D2 so the
  # source-authentication check in handle_federated accepts
  # envelopes relayed by D2.
  ssh -o BatchMode=yes root@$D3 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/id.key bridge \
    --listen udp://0.0.0.0:51820 \
    --federate udp://$D2:51820@$PUB_D2 \
    > /tmp/bridge.log 2>&1 &"
}
kill_d2() { ssh -o BatchMode=yes root@$D2 'pkill -9 -f drift_bin/drift 2>/dev/null'; }
kill_d3() { ssh -o BatchMode=yes root@$D3 'pkill -9 -f drift_bin/drift 2>/dev/null'; }
kill_d4() { ssh -o BatchMode=yes root@$D4 'pkill -9 -f drift_bin/drift 2>/dev/null'; }
start_d4_server() {
  ssh -o BatchMode=yes root@$D4 "rm -f /tmp/mosh-server.log; nohup $MS \
    --identity-file /tmp/id.hex \
    --bridge udp://$D3:51820@$PUB_D3 \
    --shell /bin/sh > /tmp/mosh-server.log 2>&1 &"
}
run_client_exec() {
  local marker="$1"
  ssh -o BatchMode=yes root@$D1 "$MC \
    --identity-file /tmp/id.hex \
    --server-pub $PUB_D4 \
    --server-addr 'udp://0.0.0.0:0' \
    --bridge udp://$D2:51820@$PUB_D2 \
    --target-bridge $PUB_D3 \
    --exec 'echo $marker; uname -n' \
    --exec-timeout 6 > /tmp/mosh-client.log 2>&1; echo exit=\$?"
  ssh -o BatchMode=yes root@$D1 'cat /tmp/mosh-client.log' | sed 's/^/      /'
  ssh -o BatchMode=yes root@$D1 "grep -c '$marker' /tmp/mosh-client.log" | tr -d ' \n'
}

# ─────────────────────────────────────────────────────────────────
# SCENARIO 1 — baseline (sanity check)
echo "═══ Scenario 1: baseline federation works"
start_d3_bridge
sleep 1
start_d2_bridge
sleep 2
start_d4_server
sleep 3
echo "  --- client --exec round-trip:"
got1=$(run_client_exec "BASELINE_OK" | tail -1)
echo "  marker hit count: $got1"
if [ "$got1" -ge 1 ]; then echo "  ✅ baseline works"; else echo "  ❌ baseline broken — abort"; cleanup_all; exit 1; fi

# ─────────────────────────────────────────────────────────────────
# SCENARIO 2 — kill+restart D2 (client-side bridge)
echo ""
echo "═══ Scenario 2: kill+restart D2 (client-side bridge), then retry"
echo "  killing D2..."
kill_d2
sleep 2
echo "  restarting D2 (same identity, same port)..."
start_d2_bridge
sleep 3
echo "  --- client --exec round-trip after D2 restart:"
got2=$(run_client_exec "POST_D2_RESTART" | tail -1)
echo "  marker hit count: $got2"
if [ "$got2" -ge 1 ]; then
  echo "  ✅ session recovered after D2 (client-side bridge) restart"
else
  echo "  ❌ session did NOT recover after D2 restart"
fi

# ─────────────────────────────────────────────────────────────────
# SCENARIO 3 — kill+restart D3 (server-side bridge)
echo ""
echo "═══ Scenario 3: kill+restart D3 (server-side bridge), then retry"
echo "  killing D3..."
kill_d3
sleep 2
echo "  restarting D3 (same identity, same port)..."
start_d3_bridge
sleep 2
echo "  NOTE: D4 server's --bridge link to D3 died with D3 — re-bootstrap?"
echo "  killing+restarting D4 server (its bridge handle is stale)..."
kill_d4
sleep 1
start_d4_server
sleep 3
echo "  --- client --exec round-trip after D3+D4 restart:"
got3=$(run_client_exec "POST_D3_RESTART" | tail -1)
echo "  marker hit count: $got3"
if [ "$got3" -ge 1 ]; then
  echo "  ✅ session recovered after D3 (server-side bridge) restart"
else
  echo "  ❌ session did NOT recover after D3 restart"
fi

# ─────────────────────────────────────────────────────────────────
# SCENARIO 4 — kill D3 WITHOUT restarting D4 server
echo ""
echo "═══ Scenario 4: kill D3 alone (server's bridge handle goes stale)"
echo "  killing D3..."
kill_d3
sleep 2
echo "  restarting D3 (same identity) but NOT touching D4..."
start_d3_bridge
# drift-mosh-server's bridge watchdog checks every 2s and resets
# the handshake if the link has been silent >5s. Total recovery
# budget: ~7s from D3 restart. Give the test 8s headroom.
echo "  waiting 8s for the server's bridge watchdog to detect + re-handshake"
sleep 8
echo "  --- client --exec round-trip after D3-only restart:"
got4=$(run_client_exec "POST_D3_ONLY" | tail -1)
echo "  marker hit count: $got4"
if [ "$got4" -ge 1 ]; then
  echo "  ✅ D4's bridge handle re-established automatically"
else
  echo "  ❌ D4 server cannot recover without explicit reconnect logic"
fi

cleanup_all

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Summary:"
printf "    1. baseline                                 %s\n" "$([ "$got1" -ge 1 ] && echo OK || echo FAIL)"
printf "    2. D2 (client-side bridge) restart          %s\n" "$([ "$got2" -ge 1 ] && echo OK || echo FAIL)"
printf "    3. D3+D4 full restart                       %s\n" "$([ "$got3" -ge 1 ] && echo OK || echo FAIL)"
printf "    4. D3 alone (D4 keeps stale fed link)       %s\n" "$([ "$got4" -ge 1 ] && echo OK || echo FAIL)"

#!/bin/bash
# Cross-transport federation:
#
#   D1 (mosh client) ──UDP──▶ D2 (bridge) ◀──TCP──▶ D3 (bridge) ◀──WS── D4 (mosh server)
#
# Three distinct DRIFT transports in one end-to-end chain.
# Each bridge multi-listens on the schemes it needs to serve.
# The federation envelope is identical regardless of the wire
# under it — that's the point of the design.

set -u
D1=192.168.50.52
D2=192.168.50.168
D3=192.168.50.253
D4=192.168.50.33
DRIFT=/root/drift_bin/drift
MS=/root/drift_bin/drift-mosh-server
MC=/root/drift_bin/drift-mosh-client
LOCAL_DRIFT=/Users/5speeddeasil/drift/target/debug/drift

# Cleanup
for ip in $D1 $D2 $D3 $D4; do
  ssh -o BatchMode=yes root@$ip 'pkill -9 -f drift_bin 2>/dev/null; true' >/dev/null
done
sleep 1

# Generate identities (DRFT-magic for drift bridge, hex for drift-mosh)
WORKDIR=$(mktemp -d)
for n in d1 d2 d3 d4; do
  $LOCAL_DRIFT keygen --output $WORKDIR/$n.key >/dev/null 2>&1
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" $WORKDIR/$n.key > $WORKDIR/$n.hex
done
PUB_D1=$($LOCAL_DRIFT info $WORKDIR/d1.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D2=$($LOCAL_DRIFT info $WORKDIR/d2.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D3=$($LOCAL_DRIFT info $WORKDIR/d3.key | grep -oE '[0-9a-f]{64}' | head -1)
PUB_D4=$($LOCAL_DRIFT info $WORKDIR/d4.key | grep -oE '[0-9a-f]{64}' | head -1)
echo "  D1 (mosh client, UDP): ${PUB_D1:0:16}..."
echo "  D2 (bridge UDP→TCP):   ${PUB_D2:0:16}..."
echo "  D3 (bridge TCP+WS):    ${PUB_D3:0:16}..."
echo "  D4 (mosh server, WS):  ${PUB_D4:0:16}..."

scp -o BatchMode=yes $WORKDIR/d2.key root@$D2:/tmp/id.key >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d3.key root@$D3:/tmp/id.key >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d1.hex root@$D1:/tmp/id.hex >/dev/null 2>&1
scp -o BatchMode=yes $WORKDIR/d4.hex root@$D4:/tmp/id.hex >/dev/null 2>&1

# Federation is symmetric: BOTH bridges --federate to each other.
# This matches Matrix / XMPP server-to-server trust — the only
# model that survives the source-authentication check in
# handle_federated (a forged envelope from an unrelated client
# wouldn't pass).  The startup race (each side trying to connect
# to the other's TCP listener before it's bound) is handled by
# bridge.rs: an initial connect_federate failure spawns a
# background retry task with exponential backoff, so the order
# of bridge starts doesn't matter.
echo ""
echo "=== D3 bridge: listens TCP:51821 + WS:51822, federates TCP→D2"
ssh -o BatchMode=yes root@$D3 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/id.key bridge \
  --listen tcp://0.0.0.0:51821 \
  --listen ws://0.0.0.0:51822 \
  --federate tcp://$D2:51821@$PUB_D2 \
  > /tmp/bridge.log 2>&1 &"
sleep 2
ssh -o BatchMode=yes root@$D3 'cat /tmp/bridge.log' | sed 's/^/  /'

# ─── D2 bridge: UDP for D1, TCP listener AND federate for D3 ────
echo ""
echo "=== D2 bridge: listens UDP:51820 + TCP:51821, federates TCP→D3"
ssh -o BatchMode=yes root@$D2 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/id.key bridge \
  --listen udp://0.0.0.0:51820 \
  --listen tcp://0.0.0.0:51821 \
  --federate tcp://$D3:51821@$PUB_D3 \
  > /tmp/bridge.log 2>&1 &"
sleep 2
ssh -o BatchMode=yes root@$D2 'cat /tmp/bridge.log' | sed 's/^/  /'

# ─── Wait for bridge↔bridge handshakes to settle ────────────────
echo ""
echo "=== waiting 6s for bridge↔bridge handshakes (both sides retry)"
sleep 6

# ─── D4 drift-mosh-server, federated to D3 over WS ──────────────
echo ""
echo "=== D4 drift-mosh-server: federated to D3 over WS"
ssh -o BatchMode=yes root@$D4 "rm -f /tmp/mosh-server.log; nohup $MS \
  --identity-file /tmp/id.hex \
  --bridge ws://$D3:51822@$PUB_D3 \
  --shell /bin/sh \
  > /tmp/mosh-server.log 2>&1 &"
sleep 3
ssh -o BatchMode=yes root@$D4 'cat /tmp/mosh-server.log' | sed 's/^/  /'

# ─── D1 drift-mosh-client --exec, federated to D2 over UDP ───────
echo ""
echo "=== D1 drift-mosh-client --exec via UDP→D2→TCP→D3→WS→D4"
ssh -o BatchMode=yes root@$D1 "$MC \
  --identity-file /tmp/id.hex \
  --server-pub $PUB_D4 \
  --server-addr 'udp://0.0.0.0:0' \
  --bridge udp://$D2:51820@$PUB_D2 \
  --target-bridge $PUB_D3 \
  --exec 'echo MIXED_TRANSPORT_OK; uname -a; id; pwd' \
  --exec-timeout 5 \
  > /tmp/mosh-client.log 2>&1; echo exit=\$?"

echo ""
echo "=== drift-mosh-client output:"
ssh -o BatchMode=yes root@$D1 'cat /tmp/mosh-client.log' | sed 's/^/  /'
echo ""
echo "=== drift-mosh-server log:"
ssh -o BatchMode=yes root@$D4 'tail -20 /tmp/mosh-server.log' | sed 's/^/  /'

# Cleanup
for ip in $D1 $D2 $D3 $D4; do
  ssh -o BatchMode=yes root@$ip 'pkill -9 -f drift_bin 2>/dev/null; true' >/dev/null
done

# ─── Verdict ──────────────────────────────────────────────────────
GOT_MARKER=$(ssh -o BatchMode=yes root@$D1 'grep -c MIXED_TRANSPORT_OK /tmp/mosh-client.log 2>/dev/null' | tr -d ' \n')
GOT_LINUX=$(ssh -o BatchMode=yes root@$D1 'grep -c "Linux" /tmp/mosh-client.log 2>/dev/null' | tr -d ' \n')
GOT_ROOT=$(ssh -o BatchMode=yes root@$D1 'grep -c "uid=0" /tmp/mosh-client.log 2>/dev/null' | tr -d ' \n')
GOT_STREAM=$(ssh -o BatchMode=yes root@$D4 'grep -c "new stream pair" /tmp/mosh-server.log 2>/dev/null' | tr -d ' \n')
echo ""
echo "═══════════════════════════════════════════════════════"
echo "    D1 → D2:    UDP"
echo "    D2 ↔ D3:    TCP"
echo "    D3 → D4:    WS"
echo ""
echo "  'MIXED_TRANSPORT_OK' in client output:  ${GOT_MARKER:-0}"
echo "  'Linux ...' (uname -a) in output:        ${GOT_LINUX:-0}"
echo "  'uid=0' (id) in output:                  ${GOT_ROOT:-0}"
echo "  server new-stream-pair logged:           ${GOT_STREAM:-0}"
echo ""
if [ "${GOT_MARKER:-0}" -ge 1 ] && [ "${GOT_LINUX:-0}" -ge 1 ] && [ "${GOT_ROOT:-0}" -ge 1 ]; then
  echo "  ✅ drift-mosh shell session worked across THREE different DRIFT transports."
  rm -rf $WORKDIR
  exit 0
else
  echo "  ❌ cross-transport federation did not produce expected output"
  rm -rf $WORKDIR
  exit 1
fi

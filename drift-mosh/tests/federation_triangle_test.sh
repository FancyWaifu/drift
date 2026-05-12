#!/bin/bash
# LXC triangle federation test (drift-mosh, real network).
#
#                          bridge-B1 (D1) ── bridge-B2 (D2)
#                                \\           //
#                                 \\         //
#                                   bridge-B3 (D3)
#
# Each bridge federates with the other two (every pair). A
# drift-mosh-server sits behind each bridge (S1 co-located on D1,
# S2 on D2, S3 on D3) with its own identity. D4 hosts the client
# driver: it dials each non-local server through each bridge in
# turn — 6 cross-bridge dials total.
#
# Each dial uses explicit --bridge + --target-bridge (no drift.toml,
# no dynamic discovery) so this test is independent of the
# directory propagation path. The Docker federation-triangle test
# already validates dynamic discovery; this one focuses on the
# triangle topology + AEAD across real-network bridges.

set -u

D1=192.168.50.52   # bridge B1 + server S1
D2=192.168.50.168  # bridge B2 + server S2
D3=192.168.50.253  # bridge B3 + server S3
D4=192.168.50.33   # client driver

DRIFT=/root/drift_bin/drift
MS=/root/drift_bin/drift-mosh-server
MC=/root/drift_bin/drift-mosh-client
LOCAL_DRIFT=/Users/5speeddeasil/drift/target/debug/drift

cleanup_all() {
  for ip in $D1 $D2 $D3 $D4; do
    ssh -o BatchMode=yes root@$ip 'pkill -9 -f drift_bin 2>/dev/null; true' >/dev/null 2>&1
  done
  sleep 0.5
}
cleanup_all

WORKDIR=/tmp/triangle-test
rm -rf $WORKDIR && mkdir -p $WORKDIR

# Identities: b1/b2/b3 (bridges), s1/s2/s3 (servers), c (client).
for n in b1 b2 b3 s1 s2 s3 c; do
  $LOCAL_DRIFT keygen --output $WORKDIR/$n.key >/dev/null 2>&1
  python3 -c "import sys; d=open(sys.argv[1],'rb').read(); print(d[4:].hex())" \
    $WORKDIR/$n.key > $WORKDIR/$n.hex
done

read_pub() { $LOCAL_DRIFT info $WORKDIR/$1.key | grep -oE '[0-9a-f]{64}' | head -1; }

PUB_B1=$(read_pub b1); PUB_B2=$(read_pub b2); PUB_B3=$(read_pub b3)
PUB_S1=$(read_pub s1); PUB_S2=$(read_pub s2); PUB_S3=$(read_pub s3)

echo "bridges: B1=${PUB_B1:0:12}…  B2=${PUB_B2:0:12}…  B3=${PUB_B3:0:12}…"
echo "servers: S1=${PUB_S1:0:12}…  S2=${PUB_S2:0:12}…  S3=${PUB_S3:0:12}…"

# Push identity files to their LXCs.
scp -o BatchMode=yes $WORKDIR/b1.key root@$D1:/tmp/b.key >/dev/null
scp -o BatchMode=yes $WORKDIR/s1.hex root@$D1:/tmp/s.hex >/dev/null
scp -o BatchMode=yes $WORKDIR/b2.key root@$D2:/tmp/b.key >/dev/null
scp -o BatchMode=yes $WORKDIR/s2.hex root@$D2:/tmp/s.hex >/dev/null
scp -o BatchMode=yes $WORKDIR/b3.key root@$D3:/tmp/b.key >/dev/null
scp -o BatchMode=yes $WORKDIR/s3.hex root@$D3:/tmp/s.hex >/dev/null
scp -o BatchMode=yes $WORKDIR/c.hex  root@$D4:/tmp/c.hex  >/dev/null

# ─── Start the three bridges (full triangle: each --federate with both others) ───
start_b1() {
  ssh -o BatchMode=yes root@$D1 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/b.key bridge \
    --listen udp://0.0.0.0:51820 \
    --federate udp://$D2:51820@$PUB_B2 \
    --federate udp://$D3:51820@$PUB_B3 \
    > /tmp/bridge.log 2>&1 &"
}
start_b2() {
  ssh -o BatchMode=yes root@$D2 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/b.key bridge \
    --listen udp://0.0.0.0:51820 \
    --federate udp://$D1:51820@$PUB_B1 \
    --federate udp://$D3:51820@$PUB_B3 \
    > /tmp/bridge.log 2>&1 &"
}
start_b3() {
  ssh -o BatchMode=yes root@$D3 "rm -f /tmp/bridge.log; nohup $DRIFT --identity /tmp/b.key bridge \
    --listen udp://0.0.0.0:51820 \
    --federate udp://$D1:51820@$PUB_B1 \
    --federate udp://$D2:51820@$PUB_B2 \
    > /tmp/bridge.log 2>&1 &"
}

# ─── Start the three co-located servers ───
start_s1() {
  ssh -o BatchMode=yes root@$D1 "rm -f /tmp/mosh-server.log; nohup $MS \
    --identity-file /tmp/s.hex --bridge udp://$D1:51820@$PUB_B1 \
    --shell /bin/sh > /tmp/mosh-server.log 2>&1 &"
}
start_s2() {
  ssh -o BatchMode=yes root@$D2 "rm -f /tmp/mosh-server.log; nohup $MS \
    --identity-file /tmp/s.hex --bridge udp://$D2:51820@$PUB_B2 \
    --shell /bin/sh > /tmp/mosh-server.log 2>&1 &"
}
start_s3() {
  ssh -o BatchMode=yes root@$D3 "rm -f /tmp/mosh-server.log; nohup $MS \
    --identity-file /tmp/s.hex --bridge udp://$D3:51820@$PUB_B3 \
    --shell /bin/sh > /tmp/mosh-server.log 2>&1 &"
}

echo "starting B1, B2, B3 (federated triangle)…"
start_b1; start_b2; start_b3
# Triangle federation: each bridge has 2 federation peers. Worst-
# case startup is when a bridge's --federate target isn't listening
# yet on first attempt and the retry backoff (500ms → 1s → 2s …)
# pushes establishment a few seconds out. 6s gives ample headroom
# for all 6 bridge-to-bridge handshakes to settle before dials fire
# — observed 4/6 failures (specifically the B1↔B3 pair) at 3s.
sleep 6
echo "starting S1, S2, S3 (one server per bridge)…"
start_s1; start_s2; start_s3
sleep 4

# ─── Sanity: each server should have logged its DRIFT_MOSH_PUB banner ───
echo ""
echo "server banners:"
for ip in $D1 $D2 $D3; do
  banner=$(ssh -o BatchMode=yes root@$ip 'grep -E "DRIFT_MOSH_PUB|DRIFT_MOSH_READY" /tmp/mosh-server.log | head -2' 2>/dev/null)
  echo "  $ip:"
  echo "$banner" | sed 's/^/    /'
done

# ─── 6 cross-bridge dials ───
# Each dial: client attaches to one bridge (via $D4 → bridge IP) and
# targets a remote server that lives behind a different bridge.
# `--target-bridge <PUB_B*>` tells the bridge which federation peer
# should forward to the server.
run_dial() {
  local label=$1 bridge_ip=$2 bridge_pub=$3 target_bridge=$4 server_pub=$5
  local marker="TRIANGLE_OK_${label}"
  ssh -o BatchMode=yes root@$D4 "$MC \
    --identity-file /tmp/c.hex \
    --server-pub $server_pub \
    --server-addr 'udp://0.0.0.0:0' \
    --bridge udp://$bridge_ip:51820@$bridge_pub \
    --target-bridge $target_bridge \
    --exec 'echo $marker; hostname' \
    --exec-timeout 8 > /tmp/triangle-$label.log 2>&1; echo exit=\$?" >/dev/null
  local out
  out=$(ssh -o BatchMode=yes root@$D4 "cat /tmp/triangle-$label.log")
  if echo "$out" | grep -q "$marker"; then
    local host
    host=$(echo "$out" | grep -E '^drift-' | head -1)
    echo "  PASS  $label  (server hostname: $host)"
    return 0
  else
    echo "  FAIL  $label"
    echo "$out" | tail -6 | sed 's/^/        /'
    return 1
  fi
}

echo ""
echo "Six cross-bridge dials (client D4 -> bridge -> target_bridge -> server):"

PASS=0
FAIL=0
for spec in \
  "c1_b1_to_s2:$D1:$PUB_B1:$PUB_B2:$PUB_S2" \
  "c1_b1_to_s3:$D1:$PUB_B1:$PUB_B3:$PUB_S3" \
  "c2_b2_to_s1:$D2:$PUB_B2:$PUB_B1:$PUB_S1" \
  "c2_b2_to_s3:$D2:$PUB_B2:$PUB_B3:$PUB_S3" \
  "c3_b3_to_s1:$D3:$PUB_B3:$PUB_B1:$PUB_S1" \
  "c3_b3_to_s2:$D3:$PUB_B3:$PUB_B2:$PUB_S2" ; do
  IFS=':' read -r label bip bpub tbpub spub <<<"$spec"
  if run_dial "$label" "$bip" "$bpub" "$tbpub" "$spub"; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Triangle: $PASS pass / $FAIL fail (of 6)"

cleanup_all

if [ "$FAIL" -eq 0 ]; then
  echo "  Federation triangle works end-to-end on real LXCs."
  exit 0
else
  exit 1
fi

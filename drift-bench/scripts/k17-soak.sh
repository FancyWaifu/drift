#!/bin/bash
# K=17 long-soak monitor for DRIFT federation — Tier 3 maturity work
# that earns the iroh-default flip.
#
# What it catches (over a 5-minute K=17 sweep):
#   * slow memory leaks in bridge processes (RSS growth over hours)
#   * file-descriptor leaks (FD count creep)
#   * AEAD auth-failure accumulation under sustained BEACON load
#   * federation-mesh divergence (bridges dying mid-soak)
#
# What it does NOT catch (v1 scope):
#   * data-plane regressions under user-traffic load (no traffic-gen)
#   * dial-pass-rate drift over time (no periodic dial sweeps)
#
# Separation of concerns: this script does NOT start or stop the
# federation. The operator brings it up first via launch-iroh.sh
# (or run-native.sh with KEEP_UP=1), waits for the [done] dial
# sweep line, then runs this soak. At the end the soak leaves the
# federation alive — operator tears it down with pkill drift.
#
# Usage:
#   k17-soak.sh [HOURS] [WIRE]
#     HOURS — soak duration; default 24, smoke-tests use 1.
#     WIRE  — wire label for the output dir (default iroh).
#
# Env knobs:
#   SNAPSHOT_INTERVAL_SECS — metrics cadence (default 300 = 5 min).
#   DURATION_SECS          — overrides HOURS*3600. For smoke tests
#                            (e.g. DURATION_SECS=180 for 3 minutes).
#   WORK                   — harness root (default /tmp/drift-corp-test).
#
# Output layout under $WORK/soak-<wire>-<timestamp>/:
#   metrics.tsv  — per-snapshot row, columns documented below.
#   summary.txt  — end-of-soak verdict (PASS/WARN/FAIL).

set -u

HOURS="${1:-24}"
WIRE="${2:-iroh}"
SNAPSHOT_INTERVAL_SECS="${SNAPSHOT_INTERVAL_SECS:-300}"
WORK="${WORK:-/tmp/drift-corp-test}"
DURATION_SECS="${DURATION_SECS:-$((HOURS * 3600))}"
# Minimum pid-file count expected under $WORK/pids before the
# soak agrees to start. Default 17 matches the K=17 corporate
# harness. Lower for single-bridge soaks (e.g. router bridge:
# MIN_PIDS=2 covers the bridge + its mosh-server).
MIN_PIDS="${MIN_PIDS:-17}"

if [ ! -d "$WORK/pids" ]; then
    echo "no $WORK/pids — bring federation up first \
(e.g. bash launch-iroh.sh, wait for [done] line)" >&2
    exit 2
fi
# For-loop with -f filter, not `find -maxdepth`, so busybox shells
# (e.g. stock ASUSWRT on the router-bridge) can run this script.
# The -f check silently skips the literal `*.pid` non-match case.
PID_COUNT=0
for _f in "$WORK"/pids/*.pid; do
    [ -f "$_f" ] && PID_COUNT=$((PID_COUNT + 1))
done
unset _f
if [ "$PID_COUNT" -lt "$MIN_PIDS" ]; then
    echo "expected ≥$MIN_PIDS pid files under $WORK/pids, found $PID_COUNT — \
federation not fully up? (override the minimum with MIN_PIDS env)" >&2
    exit 2
fi

TS=$(date +%Y%m%d-%H%M%S)
OUT_DIR="$WORK/soak-${WIRE}-${TS}"
mkdir -p "$OUT_DIR"
METRICS="$OUT_DIR/metrics.tsv"
SUMMARY="$OUT_DIR/summary.txt"

echo "K=17 soak: wire=$WIRE duration=${DURATION_SECS}s interval=${SNAPSHOT_INTERVAL_SECS}s"
echo "out_dir=$OUT_DIR"
echo "monitoring $PID_COUNT pid files under $WORK/pids/"

# ─── Metrics snapshot helper ──────────────────────────────────────
# Columns:
#   ts_unix         — seconds since epoch
#   wallclock       — ISO timestamp (sortable, human-readable)
#   alive_bridges   — out of 17 expected bridge processes
#   alive_servers   — out of 17 expected mosh-server processes
#   total_rss_kb    — sum of VmRSS across all drift processes
#   total_fds       — sum of /proc/<pid>/fd entries
#   lo_rx_bytes     — cumulative loopback rx bytes (host-wide, but
#                     this VM only runs DRIFT processes so it's a
#                     clean proxy for total federation traffic)
#   lo_tx_bytes     — cumulative loopback tx bytes
#   auth_failures   — count of "dropped invalid" log lines
snapshot_metrics() {
    local t
    t=$(date +%s)
    local wallclock
    wallclock=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local total_rss=0 total_fds=0 alive_b=0 alive_s=0
    for pidfile in "$WORK"/pids/*.pid; do
        [ -f "$pidfile" ] || continue
        local pid
        pid=$(cat "$pidfile")
        kill -0 "$pid" 2>/dev/null || continue
        case "$(basename "$pidfile")" in
            bridge-*) alive_b=$((alive_b + 1)) ;;
            server-*) alive_s=$((alive_s + 1)) ;;
        esac
        local rss
        rss=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo 0)
        total_rss=$((total_rss + rss))
        local fds
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
        total_fds=$((total_fds + fds))
    done

    # Loopback rx/tx from /proc/net/dev — measures actual network
    # I/O between bridge processes, unlike /proc/<pid>/io which
    # only counts disk writes. The lo row format is:
    #   lo: rx_bytes packets … tx_bytes packets …
    local lo_rx=0 lo_tx=0
    if [ -r /proc/net/dev ]; then
        # Parameter-expansion split rather than `read < <(...)` so
        # busybox bash (router) accepts this; process substitution
        # is bash-only and busybox doesn't ship it.
        local _lo
        _lo=$(awk '/^[[:space:]]*lo:/ {print $2 " " $10; exit}' /proc/net/dev)
        lo_rx="${_lo% *}"
        lo_tx="${_lo#* }"
        : "${lo_rx:=0}" "${lo_tx:=0}"
    fi

    local auth_fails
    auth_fails=$(grep -ch "dropped invalid" "$WORK"/logs/bridge-*.log 2>/dev/null \
        | awk '{s+=$1} END {print s+0}')
    printf "%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n" \
        "$t" "$wallclock" "$alive_b" "$alive_s" "$total_rss" "$total_fds" \
        "$lo_rx" "$lo_tx" "$auth_fails" \
        >> "$METRICS"
}

# ─── Soak loop ────────────────────────────────────────────────────
printf "ts_unix\twallclock\talive_bridges\talive_servers\ttotal_rss_kb\ttotal_fds\tlo_rx_bytes\tlo_tx_bytes\tauth_failures\n" > "$METRICS"
snapshot_metrics
echo "soak start: $(tail -1 "$METRICS")"

END_TS=$(($(date +%s) + DURATION_SECS))
echo "soaking for ${DURATION_SECS}s, snapshot every ${SNAPSHOT_INTERVAL_SECS}s…"
while [ "$(date +%s)" -lt "$END_TS" ]; do
    sleep "$SNAPSHOT_INTERVAL_SECS"
    snapshot_metrics
    tail -1 "$METRICS"
done

# ─── Summary ──────────────────────────────────────────────────────
echo "generating summary…"
python3 - "$METRICS" "$WIRE" "$DURATION_SECS" > "$SUMMARY" <<'PY'
import csv, sys
path, wire, secs = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path) as f:
    rows = list(csv.DictReader(f, delimiter='\t'))
hours = secs / 3600.0
print(f"=== K=17 soak: wire={wire} duration={hours:.2f}h ({secs}s) ===")
print(f"snapshots taken: {len(rows)}")
if len(rows) < 2:
    print("FAIL: too few snapshots to draw conclusions"); raise SystemExit
first, last = rows[0], rows[-1]
def i(k): return int(last[k]) - int(first[k])
def pct(k): return 100.0 * i(k) / max(1, int(first[k]))
print(f"")
print(f"alive_bridges:  start={first['alive_bridges']:>10} end={last['alive_bridges']:>10}  delta={i('alive_bridges'):+d}  (17 expected)")
print(f"alive_servers:  start={first['alive_servers']:>10} end={last['alive_servers']:>10}  delta={i('alive_servers'):+d}  (17 expected)")
print(f"total_rss_kb:   start={first['total_rss_kb']:>10} end={last['total_rss_kb']:>10}  delta={i('total_rss_kb'):+d} kB ({pct('total_rss_kb'):+.1f}%)")
print(f"total_fds:      start={first['total_fds']:>10} end={last['total_fds']:>10}  delta={i('total_fds'):+d}")
# Auth failures, in absolute and per-hour rate. The rate matters more
# than the absolute — a small constant accrual during startup is
# expected (BEACONs to peers that haven't bound listen sockets yet),
# but if the rate stays the same after the first quarter of the soak,
# there's a real auth drift bug.
auth_delta = i('auth_failures')
rate_per_hour = auth_delta / max(0.001, hours)
print(f"auth_failures:  start={first['auth_failures']:>10} end={last['auth_failures']:>10}  delta={auth_delta:+d}  rate={rate_per_hour:.1f}/h")
# Loopback bytes — actual network I/O for this VM (the VM runs
# only drift processes, so lo traffic ≈ federation + dial traffic).
lo_tx_delta = i('lo_tx_bytes')
lo_rx_delta = i('lo_rx_bytes')
print(f"lo_tx_bytes:    start={first['lo_tx_bytes']:>10} end={last['lo_tx_bytes']:>10}  delta={lo_tx_delta:+d}")
print(f"lo_rx_bytes:    start={first['lo_rx_bytes']:>10} end={last['lo_rx_bytes']:>10}  delta={lo_rx_delta:+d}")
print(f"")
print(f"=== verdict ===")
verdict = "PASS"
issues = []
bridge_loss = i('alive_bridges')
server_loss = i('alive_servers')
if bridge_loss < 0:
    verdict = "FAIL"; issues.append(f"{-bridge_loss} bridges died mid-soak")
if server_loss < 0:
    verdict = "FAIL"; issues.append(f"{-server_loss} mosh-servers died mid-soak")
# Auth-failures verdict: a few per hour during convergence churn is
# fine; sustained >60/h is a real bug. Calibrate against the
# OrbStack baseline (~4/min during the first minute of K=17 startup,
# tapering to near-0 once federation settles).
if rate_per_hour > 60:
    verdict = "FAIL"
    issues.append(f"auth_failures rate {rate_per_hour:.1f}/h exceeds 60/h threshold — investigate")
elif rate_per_hour > 20:
    issues.append(f"auth_failures rate {rate_per_hour:.1f}/h is high — watch for steady-state drift")
    if verdict == "PASS": verdict = "WARN"
rg = pct('total_rss_kb')
if rg > 100:
    verdict = "FAIL"; issues.append(f"RSS more than doubled ({rg:+.0f}%) — leak suspected")
elif rg > 50:
    issues.append(f"RSS grew {rg:+.0f}% — watch for leak")
    if verdict == "PASS": verdict = "WARN"
if lo_tx_delta == 0 and len(rows) > 6:
    issues.append("no loopback tx during soak — bridges hung?")
    if verdict == "PASS": verdict = "WARN"
print(f"verdict: {verdict}")
for it in issues:
    print(f"  • {it}")
PY
cat "$SUMMARY"

echo ""
echo "done — results in $OUT_DIR"
echo "federation is still alive; tear down with: pkill -9 -f $WORK/bin/drift"

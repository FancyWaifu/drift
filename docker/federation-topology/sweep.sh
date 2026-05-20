#!/bin/bash
# Run every (topology × wire) combination and emit a compact matrix.
# Each individual run is ~3 min, so the full 4×3 sweep is ~36 min.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

TOPOLOGIES=(mesh ring star chain)
WIRES=(h2s h2 webtransport)

declare LOG="sweep-$(date +%s).log"
echo "Logging individual runs to $LOG" >&2

# Two-pass: collect, then print matrix.
declare -a RESULTS
for topo in "${TOPOLOGIES[@]}"; do
  for wire in "${WIRES[@]}"; do
    echo "" >&2
    echo "=== $topo × $wire ===" >&2
    out=$(TOPOLOGY="$topo" FED_WIRE="$wire" bash run.sh 2>&1)
    echo "$out" >> "$LOG"
    summary=$(echo "$out" | grep '^  Summary:' | tail -1)
    pf=$(echo "$summary" | grep -oE '[0-9]+ pass / [0-9]+ fail' | head -1)
    echo "  → $pf" >&2
    RESULTS+=("$topo $wire $pf")
  done
done

# ─── Render the matrix ───────────────────────────────────────────
echo "" >&2
echo "─── Federation topology × wire matrix ───────────────────────────" >&2
printf "%-8s | %-15s | %-15s | %-15s\n" "" "${WIRES[0]}" "${WIRES[1]}" "${WIRES[2]}" >&2
echo "---------+-----------------+-----------------+----------------" >&2
for topo in "${TOPOLOGIES[@]}"; do
  row="$topo"
  for wire in "${WIRES[@]}"; do
    cell=""
    for r in "${RESULTS[@]}"; do
      set -- $r
      if [ "$1" = "$topo" ] && [ "$2" = "$wire" ]; then
        cell="$3 $4 $5 $6"
        break
      fi
    done
    row="$row | $cell"
  done
  echo "$row" >&2
done

echo "" >&2
echo "Full run logs: $LOG" >&2

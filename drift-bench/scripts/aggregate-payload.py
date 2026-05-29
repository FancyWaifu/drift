#!/usr/bin/env python3
"""Aggregate the per-payload TSV outputs of run-payload-sweep.sh into
a single context × wire × payload-size goodput table.

Usage:
  aggregate-payload.py <out.md> <payload_tsv...>
"""

from __future__ import annotations
import sys
import csv
import statistics
from collections import defaultdict
from typing import Dict, List, Optional


def parse_float(s: str) -> Optional[float]:
    if s in ("", "None", None):
        return None
    try:
        return float(s)
    except ValueError:
        return None


def fmt(v: Optional[float], digits: int = 0) -> str:
    if v is None:
        return "—"
    return f"{v:.{digits}f}"


WIRES = ["udp", "tcp", "tls", "ws", "h2", "h2s", "webtransport"]


def median(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else None


def collect(paths: List[str]):
    """{context: {payload_bytes: {wire: [goodput, ...]}}}"""
    data: Dict[str, Dict[int, Dict[str, List[float]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list)))
    for path in paths:
        with open(path) as fp:
            reader = csv.DictReader(fp, delimiter="\t")
            for row in reader:
                ctx = row["context"]
                pl = int(row["payload_bytes"])
                wire = row["wire"]
                g = parse_float(row["goodput_mbps"])
                if g is not None:
                    data[ctx][pl][wire].append(g)
    return data


def main():
    if len(sys.argv) < 3:
        print("usage: aggregate-payload.py <out.md> <payload_tsv...>", file=sys.stderr)
        sys.exit(1)
    out_path = sys.argv[1]
    tsvs = sys.argv[2:]
    data = collect(tsvs)

    with open(out_path, "w") as out:
        out.write("# DRIFT — payload-size sweep (throughput)\n\n")
        out.write("Median goodput Mbps over 3 trials per cell. DRIFT's datagram\n")
        out.write("API caps at `MAX_PAYLOAD` ≈ 1348 B (MAX_PACKET 1400 − header\n")
        out.write("− AEAD tag). Sweep covers 64 / 256 / 1024 / 1300 byte payloads,\n")
        out.write("which spans the per-packet-overhead-dominated regime through\n")
        out.write("near-cap. Larger application-level messages require DRIFT's\n")
        out.write("reliable-streams API, which fragments transparently into\n")
        out.write("≤MAX_PAYLOAD chunks on the wire — so the wire-level numbers\n")
        out.write("converge to the 1300-byte row regardless of app-level size.\n\n")

        for ctx in ["loopback", "lxc_lan", "cross_arch"]:
            if ctx not in data:
                continue
            out.write(f"## {ctx}\n\n")
            sizes = sorted(data[ctx].keys())
            headers = ["wire"] + [f"{s} B" for s in sizes]
            out.write("| " + " | ".join(headers) + " |\n")
            out.write("|" + "|".join(["---"] * len(headers)) + "|\n")
            for wire in WIRES:
                row = [f"`{wire}`"]
                row_vals = []
                for sz in sizes:
                    vals = data[ctx][sz].get(wire, [])
                    m = median(vals)
                    row_vals.append(m)
                # bold highest in row (for visual scan)
                hi = max((v for v in row_vals if v is not None), default=None)
                for v in row_vals:
                    if v is None:
                        row.append("—")
                    elif hi is not None and abs(v - hi) < 0.5:
                        row.append(f"**{fmt(v)}**")
                    else:
                        row.append(fmt(v))
                out.write("| " + " | ".join(row) + " |\n")
            out.write("\n")

        out.write("## Notes\n\n")
        out.write("- 64 B payload: per-packet overhead (header + AEAD seal + syscall)\n")
        out.write("  dominates. Wires with batching (h2, ws) win because they\n")
        out.write("  amortize.\n")
        out.write("- 1300 B payload: near cap. The wire's framing efficiency at\n")
        out.write("  full-packet-size is what's measured.\n")
        out.write("- Per-wire ranking shifts with payload size — wires with\n")
        out.write("  stream batching benefit disproportionately at small payloads.\n")


if __name__ == "__main__":
    main()

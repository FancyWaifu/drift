#!/usr/bin/env python3
"""Render a drift-bench results JSONL file as a Markdown table.

Each line of the input file is one JSON report from one
(protocol, workload) run. We pivot protocol → workload and emit
three sub-tables (one per workload).

Usage: format_results.py results/<stamp>.json
"""

import json
import sys
from collections import defaultdict

PROTOCOLS = ["drift", "quic", "wireguard"]


def load(path):
    by = defaultdict(dict)  # workload -> protocol -> row
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            by[r["workload"]][r["protocol"]] = r
    return by


def fmt_us(v):
    if v is None:
        return "-"
    return f"{v:,} µs"


def fmt_mbps(v):
    if v is None:
        return "-"
    return f"{v:.1f} Mbps"


def render(by):
    lines = []
    if "handshake" in by:
        lines.append("### Cold handshake (connect → first byte ack)")
        lines.append("")
        lines.append("| Protocol | Handshake |")
        lines.append("|---|---|")
        for p in PROTOCOLS:
            r = by["handshake"].get(p)
            hs = fmt_us(r and r.get("handshake_us"))
            lines.append(f"| {p} | {hs} |")
        lines.append("")

    if "rtt" in by:
        lines.append("### RTT distribution (ping-pong, 1 KB payload)")
        lines.append("")
        lines.append("| Protocol | min | p50 | p95 | p99 | max |")
        lines.append("|---|---|---|---|---|---|")
        for p in PROTOCOLS:
            r = by["rtt"].get(p)
            if r is None:
                lines.append(f"| {p} | - | - | - | - | - |")
                continue
            lines.append(
                "| {p} | {mn} | {p50} | {p95} | {p99} | {mx} |".format(
                    p=p,
                    mn=fmt_us(r.get("rtt_min_us")),
                    p50=fmt_us(r.get("rtt_p50_us")),
                    p95=fmt_us(r.get("rtt_p95_us")),
                    p99=fmt_us(r.get("rtt_p99_us")),
                    mx=fmt_us(r.get("rtt_max_us")),
                )
            )
        lines.append("")

    if "throughput" in by:
        lines.append("### Throughput (sustained send, 1 KB payload)")
        lines.append("")
        lines.append("| Protocol | Throughput |")
        lines.append("|---|---|")
        for p in PROTOCOLS:
            r = by["throughput"].get(p)
            thr = fmt_mbps(r and r.get("throughput_mbps"))
            lines.append(f"| {p} | {thr} |")
        lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    by = load(sys.argv[1])
    print(render(by))


if __name__ == "__main__":
    main()

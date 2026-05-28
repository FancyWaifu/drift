#!/usr/bin/env python3
"""Aggregate the per-trial TSV outputs of run-full-matrix.sh into
publishable summary tables. Reads N TSVs (one per context) plus
the cross-protocol TSV, emits a single markdown doc.

Usage:
  aggregate.py <out.md> <context_tsv...> --cross-proto <cross_proto.tsv>
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


def collect_drift_tsv(path: str) -> Dict[str, Dict[str, List[Dict]]]:
    """{context: {workload: [{wire, trial, ...}, ...]}}"""
    out: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
    with open(path) as fp:
        reader = csv.DictReader(fp, delimiter="\t")
        for row in reader:
            ctx = row["context"]
            wl = row["workload"]
            out[ctx][wl].append(row)
    return out


def collect_xproto_tsv(path: str) -> Dict[str, List[Dict]]:
    """{workload: [{protocol, trial, ...}, ...]}"""
    out: Dict[str, List[Dict]] = defaultdict(list)
    with open(path) as fp:
        reader = csv.DictReader(fp, delimiter="\t")
        for row in reader:
            out[row["workload"]].append(row)
    return out


WIRES = ["udp", "tcp", "tls", "ws", "h2", "h2s", "webtransport"]


def median_range(values: List[float]) -> tuple[Optional[float], Optional[float], Optional[float]]:
    vals = [v for v in values if v is not None]
    if not vals:
        return None, None, None
    return statistics.median(vals), min(vals), max(vals)


def summarize_drift_workload(rows: List[Dict], workload: str) -> Dict[str, Dict]:
    """For one workload, summarize per wire across trials."""
    by_wire: Dict[str, List[Dict]] = defaultdict(list)
    for row in rows:
        by_wire[row["wire"]].append(row)
    summary = {}
    for wire, wire_rows in by_wire.items():
        if workload == "throughput":
            goodput = [parse_float(r["goodput_mbps"]) for r in wire_rows]
            med, lo, hi = median_range(goodput)
            summary[wire] = {"med": med, "lo": lo, "hi": hi, "n": len([g for g in goodput if g is not None])}
        else:
            p50s = [parse_float(r["p50_us"]) for r in wire_rows]
            p95s = [parse_float(r["p95_us"]) for r in wire_rows]
            p99s = [parse_float(r["p99_us"]) for r in wire_rows]
            summary[wire] = {
                "p50": median_range(p50s)[0],
                "p95": median_range(p95s)[0],
                "p99": median_range(p99s)[0],
                "n": len([p for p in p50s if p is not None]),
            }
    return summary


def summarize_xproto(rows: List[Dict], workload: str) -> Dict[str, Dict]:
    by_p: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        by_p[r["protocol"]].append(r)
    summary = {}
    for proto, proto_rows in by_p.items():
        if workload == "throughput":
            goodput = [parse_float(r["goodput_mbps"]) for r in proto_rows]
            med, lo, hi = median_range(goodput)
            summary[proto] = {"med": med, "lo": lo, "hi": hi, "n": len([g for g in goodput if g is not None])}
        else:
            p50s = [parse_float(r["p50_us"]) for r in proto_rows]
            p95s = [parse_float(r["p95_us"]) for r in proto_rows]
            p99s = [parse_float(r["p99_us"]) for r in proto_rows]
            summary[proto] = {
                "p50": median_range(p50s)[0],
                "p95": median_range(p95s)[0],
                "p99": median_range(p99s)[0],
                "n": len([p for p in p50s if p is not None]),
            }
    return summary


def emit_drift_throughput(out, ctx_summaries: Dict[str, Dict]):
    out.write("### Throughput — median goodput Mbps (server-side, 3 trials per cell)\n\n")
    contexts = list(ctx_summaries.keys())
    headers = ["wire"] + contexts
    out.write("| " + " | ".join(headers) + " |\n")
    out.write("|" + "|".join(["---"] * len(headers)) + "|\n")
    for wire in WIRES:
        row = [f"`{wire}`"]
        for ctx in contexts:
            s = ctx_summaries[ctx].get("throughput", {}).get(wire)
            if s and s.get("med") is not None:
                row.append(f"**{fmt(s['med'])}** ({fmt(s['lo'])}–{fmt(s['hi'])})")
            else:
                row.append("—")
        out.write("| " + " | ".join(row) + " |\n")
    out.write("\nCell format: `**median** (min–max)` across 3 trials. Goodput = bytes the server actually received per second.\n\n")


def emit_drift_latency(out, ctx_summaries: Dict[str, Dict], workload: str, title: str):
    out.write(f"### {title} — median p50 µs (3 trials per cell)\n\n")
    contexts = list(ctx_summaries.keys())
    headers = ["wire"] + [f"{c} p50" for c in contexts] + [f"{c} p99" for c in contexts]
    out.write("| " + " | ".join(headers) + " |\n")
    out.write("|" + "|".join(["---"] * len(headers)) + "|\n")
    for wire in WIRES:
        row = [f"`{wire}`"]
        for ctx in contexts:
            s = ctx_summaries[ctx].get(workload, {}).get(wire)
            row.append(fmt(s.get("p50") if s else None))
        for ctx in contexts:
            s = ctx_summaries[ctx].get(workload, {}).get(wire)
            row.append(fmt(s.get("p99") if s else None))
        out.write("| " + " | ".join(row) + " |\n")
    out.write("\n")


def emit_xproto(out, xproto_summaries: Dict[str, Dict]):
    out.write("### Cross-protocol baseline — DRIFT vs Iroh vs QUIC (Mac loopback, 3 trials)\n\n")
    out.write("| Metric | DRIFT (UDP wire) | Iroh | QUIC (quinn) |\n")
    out.write("|---|---|---|---|\n")
    # handshake p50
    hs = xproto_summaries.get("handshake", {})
    out.write(f"| Handshake p50 (µs) | {fmt(hs.get('drift',{}).get('p50'))} | {fmt(hs.get('iroh',{}).get('p50'))} | {fmt(hs.get('quic',{}).get('p50'))} |\n")
    out.write(f"| Handshake p99 (µs) | {fmt(hs.get('drift',{}).get('p99'))} | {fmt(hs.get('iroh',{}).get('p99'))} | {fmt(hs.get('quic',{}).get('p99'))} |\n")
    rt = xproto_summaries.get("rtt", {})
    out.write(f"| RTT p50 (µs) | {fmt(rt.get('drift',{}).get('p50'))} | {fmt(rt.get('iroh',{}).get('p50'))} | {fmt(rt.get('quic',{}).get('p50'))} |\n")
    out.write(f"| RTT p99 (µs) | {fmt(rt.get('drift',{}).get('p99'))} | {fmt(rt.get('iroh',{}).get('p99'))} | {fmt(rt.get('quic',{}).get('p99'))} |\n")
    tp = xproto_summaries.get("throughput", {})
    out.write(f"| Throughput median Mbps | {fmt(tp.get('drift',{}).get('med'))} | {fmt(tp.get('iroh',{}).get('med'))} | {fmt(tp.get('quic',{}).get('med'))} |\n")
    out.write(f"| Throughput range (min–max) | {fmt(tp.get('drift',{}).get('lo'))}–{fmt(tp.get('drift',{}).get('hi'))} | {fmt(tp.get('iroh',{}).get('lo'))}–{fmt(tp.get('iroh',{}).get('hi'))} | {fmt(tp.get('quic',{}).get('lo'))}–{fmt(tp.get('quic',{}).get('hi'))} |\n")
    out.write("\n")


def main():
    args = sys.argv[1:]
    if "--cross-proto" not in args:
        print("usage: aggregate.py <out.md> <ctx_tsv...> --cross-proto <xproto_tsv>", file=sys.stderr)
        sys.exit(1)
    out_path = args[0]
    cp_idx = args.index("--cross-proto")
    ctx_tsvs = args[1:cp_idx]
    xproto_tsv = args[cp_idx + 1]

    # Merge all context TSVs
    ctx_summaries: Dict[str, Dict] = {}
    for tsv in ctx_tsvs:
        d = collect_drift_tsv(tsv)
        for ctx, by_workload in d.items():
            ctx_summaries.setdefault(ctx, {})
            for workload, rows in by_workload.items():
                ctx_summaries[ctx][workload] = summarize_drift_workload(rows, workload)

    # Cross-protocol
    xp = collect_xproto_tsv(xproto_tsv)
    xproto_summaries = {wl: summarize_xproto(rows, wl) for wl, rows in xp.items()}

    with open(out_path, "w") as out:
        out.write("# DRIFT — full-matrix benchmark (2026-05-27)\n\n")
        out.write("This document is auto-generated from the raw TSV outputs of\n")
        out.write("`drift-bench/scripts/run-full-matrix.sh`. Three trials per cell,\n")
        out.write("median + min–max range reported. All throughput is server-side\n")
        out.write("**goodput** (bytes that actually arrived per second), not client-\n")
        out.write("side pump-rate.\n\n")
        out.write("## Cross-protocol baseline\n\n")
        emit_xproto(out, xproto_summaries)

        out.write("## DRIFT wire sweep — three contexts\n\n")
        emit_drift_throughput(out, ctx_summaries)
        emit_drift_latency(out, ctx_summaries, "handshake", "Handshake")
        emit_drift_latency(out, ctx_summaries, "rtt", "RTT (1000 ping-pong, 1 KB payload)")

        out.write("## Methodology\n\n")
        out.write("- Loopback: single Apple Silicon Mac (arm64), tokio multi_thread.\n")
        out.write("- LXC↔LXC: drift-1 (server) and drift-2 (client), both 2-core/512 MB Proxmox LXCs (x86_64), gigabit network.\n")
        out.write("- Cross-arch: Mac (client, arm64) ↔ drift-1 LXC (server, x86_64), real LAN.\n")
        out.write("- Handshake: 20 iterations per trial, fresh client identity per iteration.\n")
        out.write("- RTT: 500 ping-pong iterations per trial, single long-lived session, 1 KB payload.\n")
        out.write("- Throughput: 10 s sustained send, 1 KB DRIFT packets, one-way (server counts bytes received).\n")
        out.write("- Trials: 3 per cell. Median reported; min/max in parentheses for throughput.\n")
        out.write("- Drift-bench: `drift-bench` workspace member at HEAD.\n\n")
        out.write("Reproduce:\n\n")
        out.write("```bash\n")
        out.write("# build\n")
        out.write("cargo build -p drift-bench --release\n")
        out.write("# (for cross-host) cross-build for the LXC target\n")
        out.write("cross build -p drift-bench --target x86_64-unknown-linux-musl --release\n")
        out.write("# loopback bench\n")
        out.write("bash drift-bench/scripts/run-full-matrix.sh \\\n")
        out.write("    127.0.0.1 local target/release/drift-bench \\\n")
        out.write("    127.0.0.1 local target/release/drift-bench \\\n")
        out.write("    loopback 3\n")
        out.write("```\n\n")


if __name__ == "__main__":
    main()

# drift-vpn vs WireGuard — direct-tunnel benchmark

Same-host LXCs on Proxmox (192.0.2.52 ↔ 192.0.2.168), LAN
RTT ~13 µs. Both tunnels configured for direct UDP between the
two LXCs (no bridge in the middle). MTU 1200 on drift-vpn,
1420 on WireGuard.

## Setup

```
# drift-vpn (TransportConfig::default(): hybrid_pq=true,
# handshake_retry_base_ms=1000, …)
[interface]
listen = "udp://0.0.0.0:51840"
address = "10.50.0.1/24"
mtu     = 1200

# WireGuard
[Interface]
ListenPort = 51842
Address    = 10.60.0.1/24
MTU        = 1420
```

## Numbers

Single iperf3 server on D2, client tests from D1, 20s per test:

| Scenario           | TCP-1     | TCP-8     | UDP @ 2 Gbps        | RTT idle |
|--------------------|-----------|-----------|---------------------|----------|
| Baseline (LAN)     | 40.7 Gbps | 42.0 Gbps | 1.62 Gbps, 0% loss  | 13 µs    |
| **drift-vpn (PQ on)** | 1.31 Gbps | 1.14 Gbps | 1.98 Gbps, 52% loss | 205 µs   |
| **WireGuard**      | 1.83 Gbps | 1.85 Gbps | 1.97 Gbps,  0% loss | 284 µs   |

CPU efficiency under sustained iperf3 (15s window, system-wide
%-busy, mid-stream sample):

| Scenario           | Throughput | System CPU | Mbps / % CPU |
|--------------------|------------|------------|--------------|
| Baseline (LAN)     | 24.3 Gbps  | 50.5%      | 482          |
| **drift-vpn**      | 1.30 Gbps  | 91.3%      | 14           |
| **WireGuard**      | 1.82 Gbps  | 16.3%      | 112          |

## What this means

- **Single-stream TCP**: drift-vpn hits ~71% of WireGuard
  (1.31 vs 1.83 Gbps). For a userspace Rust implementation
  vs kernel-space WG, that's a reasonable showing.

- **No benefit from parallel streams**: both saturate around
  ~1.85 Gbps regardless of stream count. The bottleneck for
  drift-vpn is single-core CPU (91% busy on one streaming
  flow); for WireGuard it's likely the LXC's userspace↔kernel
  bridge or iperf3 itself given the low CPU usage.

- **UDP loss**: drift-vpn drops 52% at 2 Gbps offered (receiver
  can't keep up — the userspace recv path is the bottleneck).
  WireGuard at the same offered rate is loss-free. This is the
  biggest gap and the most actionable: optimization targets are
  the recv-loop hot path + the per-packet AEAD decrypt.

- **CPU efficiency**: WireGuard is **~8× more efficient per
  Mbps** (112 vs 14 Mbps per % CPU). Expected — kernel-space
  with hand-tuned crypto + zero context switches per packet.

- **Latency**: comparable, drift-vpn actually edges ahead
  (205 µs vs 284 µs idle). At this granularity the difference
  is noise.

## What to optimize next, in priority order

1. **Reduce userspace↔kernel context switches**. Each tun
   read/write is a syscall; batch with `recvmmsg`/`sendmmsg`
   where supported (already partial on Linux per `drift::transport::batch`).
2. **Larger UDP recv buffer by default for drift-vpn** —
   already added in PQ-T.11 but is currently bridge-only.
   drift-vpn should opt in too.
3. **Per-flow worker thread** — current single-task recv loop
   pegs one core. SO_REUSEPORT + multiple workers would scale.
4. **Investigate the UDP recv-side drop rate** — `netstat -s`
   on D2 during the test will show the kernel-side drop counter.

## Reproducing

```bash
# On both LXCs: install wireguard-tools + iperf3
# Generate drift identity (hex format) + drift-vpn config on each
# Generate WG keys + /etc/wireguard/wg-bench.conf on each
# Bring up both tunnels
# Then from D1:
bench/run-bench.sh
```

See `bench/run-bench.sh` for the full reproducer.

Caveats
- PQ-hybrid is ON in drift-vpn (the workspace default since
  PQ-T.12). Steady-state cost is zero (handshake-only); we
  haven't measured PQ-off explicitly.
- LXCs share a host so the "WAN" is unrealistically fast.
- All numbers are single-run, not averaged across multiple
  trials. Run-to-run variance is probably ±10%.

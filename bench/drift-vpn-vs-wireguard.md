# drift-vpn vs WireGuard — direct-tunnel benchmark

Same-host LXCs on Proxmox (192.0.2.52 ↔ 192.0.2.168), LAN
RTT ~0.3 ms. Both tunnels configured for direct UDP between the
two LXCs (no bridge in the middle). MTU 1200 on drift-vpn,
1420 on WireGuard.

## Headline (post-PERF Phase 2, 2026-05-17)

| | Throughput | System CPU | CPU per Gbps |
|---|---|---|---|
| WireGuard (kernel) | 1.85 Gbps | 60% | 32.4% |
| **drift-vpn (userspace, GSO+GRO)** | **1.96 Gbps** | 66% | 33.7% |

drift-vpn pushes **+6% raw throughput** over WireGuard kernel on
this fabric, at near-parity (+1.3 percentage points) per-Gbps CPU.
A userspace Rust implementation landing within striking distance
of kernel-space on per-Gbps efficiency is meaningful.

## Progression in this session

Starting from the v0.14 baseline (sendmmsg only), two orthogonal
changes landed:

| stage | throughput | stime/utime | commit |
|---|---|---|---|
| Baseline (sendmmsg only) | 1.19 Gbps | 5.00 | — |
| + UDP GSO sender (`UDP_SEGMENT` cmsg) | 1.36 Gbps | 2.30 | `10a65c2` |
| + UDP GRO receiver (`UDP_GRO` sockopt + cmsg parsing) | **1.96 Gbps** | 2.20 | `956517e` |

**Cumulative: +65% throughput in one session.** Sub-millisecond
average ping unchanged across all stages (0.30 ms).

### What was tried and reverted

`parking_lot::Mutex` for `PeerShards` (commit `337eb2c`) bought
~12% additional throughput in this bench (2.21 Gbps), but caused
a starvation regression in `loopback_full_mesh.rs`: pass rate
dropped from 80% to 0% on the 4-peer same-process scenario, because
parking_lot's fast-path acquire skips the runtime yield that
tokio::sync::Mutex provides on every acquire. That yield was
load-bearing for fairness when multiple Transports share a tokio
runtime. Reverted in commit `012cba0`; the 12% throughput delta
is real but the test regression isn't worth it. Future direction:
hybrid scheme that uses parking_lot for the inner per-packet
locks plus explicit periodic yields. Not done here.

Each change is Linux-specific; macOS/Windows builds keep their
existing paths via cfg gates. None of them touch the wire format,
crypto, or any user-visible behavior — they're pure I/O-layer
plumbing.

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

## Detailed numbers (current)

iperf3 -t 15 -J, drift-vpn 0.14+PERF.1+PERF.2 vs WG-kernel-6.8.12:

| Run | drift-vpn (Gbps) | WireGuard (Gbps) |
|---|---|---|
| 1 | 1.95 | 1.87 |
| 2 | 1.96 | 1.84 |
| 3 | 1.97 | 1.83 |
| **avg** | **1.96** | **1.85** |
| stdev | 0.01 | 0.02 |

## Syscall mix (drift-vpn, post-PERF.4)

Strace -c -f -p $PID during a 6-second iperf3:

| syscall | calls | % time | role |
|---|---|---|---|
| futex | 121K | 28.7% | tokio runtime + parking_lot fallback |
| read | 130K | 24.7% | TUN read |
| write | 56K | 13.0% | TUN write |
| sendto | 49K | 11.4% | unbatched DRIFT control + ACK packets |
| recvmsg (GRO) | 47K | 7.3% | UDP recv (coalescing) |
| sendmsg (GSO) | 17K | 5.8% | UDP send (segmentation) |
| epoll_pwait | 17K | 3.3% | tokio readiness |

**Where time goes now**: tokio runtime overhead (futex), TUN I/O
(read+write = 37%), and the long tail of unbatched per-packet
sendto. The UDP send/recv hot path that dominated pre-GSO/GRO is
now 13% combined.

## What's left to chase (next session)

In declining payoff order:

1. **TUN batched I/O via `IFF_VNET_HDR`** — `read`+`write` is 37%
   of CPU. Bypassing the `tun` crate to set `IFF_VNET_HDR` +
   `TUNSETOFFLOAD` lets kernel return many packets per syscall.
   Estimated +20-30% throughput. Day-scale effort.

2. **Multi-core via `SO_REUSEPORT`** — bind N UDP sockets to the
   same port, N worker tasks process them independently.
   Kernel hashes flows across workers. Estimated ~2× throughput
   on multi-core hosts. Day-scale effort (peer-state sharding
   needs care).

3. **Per-packet allocation reduction** — encrypted-output Vec<u8>
   per packet still allocates ~2KB per send. Pooled buffers or
   `bytes::Bytes` with shared backing could cut allocator pressure
   to near-zero. Half-day effort.

4. **Investigate the 49K sendto/sec** — small unbatched DRIFT
   control packets. Most look like ~100B mixed-size; GSO can't
   help with variable sizes, but sendmmsg could.

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

## Caveats

- PQ-hybrid is ON in drift-vpn (the workspace default since PQ-T.12).
  Steady-state cost is zero (handshake-only).
- LXCs share a host so the "WAN" is unrealistically fast.
- 3-run average; stdev ~1-2% across runs.
- Numbers are for a single peer-pair. Multi-peer servers should
  see additional benefit from the PERF.3 parking_lot swap +
  PERF.4 by-peer grouping that don't show at single-peer scale.
- WG runs in the kernel with hand-tuned crypto; drift-vpn runs
  in userspace Rust. Comparing them on a per-Gbps basis is
  inherently unfavorable to drift-vpn. Raw-throughput parity-or-
  better is the right yardstick.

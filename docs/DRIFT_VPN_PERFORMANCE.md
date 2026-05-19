# drift-vpn performance — optimization plan

> **Current numbers:** drift-vpn post-GSO/GRO reaches **1.96 Gbps**
> vs WireGuard kernel's **1.85 Gbps** on the same Proxmox-LXC fabric
> (+6% raw, near-parity per-Gbps CPU). See
> [`bench/drift-vpn-vs-wireguard.md`](../bench/drift-vpn-vs-wireguard.md).
> The 1.31 Gbps figure below is the pre-optimization baseline that
> motivated the plan; it is not the current state.

## Design constraint up front

**drift-vpn is wire-agnostic by design.** It uses
`Transport::bind_url(...)` so any DRIFT scheme works as the
tunnel transport: `udp://`, `tcp://`, `ws://`, `tls://`,
`http://`, `dns://`, `webtransport://`, `webrtc://`. The
killer feature over WireGuard isn't just identity-routing —
it's that the tunnel works through whatever network path is
available (corporate proxies that only allow HTTPS, captive
portals that only allow DNS, browsers that only have
WebRTC).

That principle reshapes the optimization plan: **anything
labeled "wire-specific" only helps when that scheme is
chosen.** "Wire-agnostic" wins help every deployment.

The BENCH.3 baseline (drift-vpn 1.31 Gbps @ 91% CPU vs
WireGuard 1.82 Gbps @ 16% CPU) was UDP-only. **A wire-matrix
bench needs to land first** before we can confidently say
"drift-vpn is at X% of WireGuard" for any path.

---

## Tier 0 — Re-bench across every wire (before optimizing)

The current bench is UDP-only. Run iperf3 through each:

| Wire | Expected vs UDP | Bottleneck likely to be |
|---|---|---|
| `udp://` | 100% (baseline) | recv-syscall rate |
| `tcp://` | 60-80%? | TCP framing + double-stack (TCP-over-TCP) |
| `ws://` | 50-70%? | WebSocket framing + tokio-tungstenite overhead |
| `tls://` | 50-70%? | TLS record layer over TCP |
| `http://` | 5-15%? | base64 + SSE event framing + per-packet POST |
| `webtransport://` | 90-110% | QUIC datagrams; might EDGE UDP via GSO already in wtransport |
| `webrtc://` | 60-80%? | DTLS overhead + ICE keepalive |
| `dns://` | <1% | DNS msg framing; not designed for throughput |

Whatever the actual numbers, **each wire has a different
ceiling**. Optimizations stack differently per wire. Drop the
wire-matrix bench script into `bench/wire-matrix.sh` and run
it before each optimization round.

---

## Tier 1 — Wire-agnostic optimizations (help every adapter)

### A. Increase default UDP recv buffer for drift-vpn
*(Wire-specific to UDP, but covers the most common path)*

We added `udp_recv_buffer_bytes` in PQ-T.11.1 but only
`drift bridge` defaults to 4 MiB; drift-vpn still uses the
OS default (~200 KB). Under sustained iperf3, that's the
likely cause of the 52% UDP drops we observed.

[Red Hat tuning guide][redhat-udp]:
> "If a UDP packet is too large and exceeds the buffer size
> or packets are sent or received at a too fast rate, the
> kernel drops any new incoming UDP packet."

**Lift:** eliminates the 52% UDP loss + ~10% TCP throughput
from reduced retransmits.
**Effort:** 2 lines (only affects UDP wire; the bigger
analogue for TCP/WS/TLS is `SO_RCVBUF` on the accepted
streams).

### B. Diagnose: `netstat -s` during the bench *(free)*

```sh
ssh d2 'netstat -su | grep -E "receive errors|RcvbufErrors|packet"'
```

`RcvbufErrors` → recv buffer too small (item A fixes).
`packet receive errors` → userspace not draining fast enough
(items C/D fix). [LinuxVox analysis][linuxvox-udp] explains
the difference. Do this BEFORE the rest.

### C. Multi-core scaling via `SO_REUSEPORT` (UDP) or
### accept-loop sharding (TCP/WS/TLS)

drift-vpn currently pegs ONE core at 91% to push 1.3 Gbps.
This is wire-agnostic in spirit: every wire has a
single-threaded recv loop today. The mechanism differs:

- **UDP:** `SO_REUSEPORT` lets N sockets bind the same port;
  kernel hashes flows across them. Per-peer state needs
  sharing or sharding by peer_id.
- **TCP/TLS/WS:** the accept loop is single-threaded today;
  spawn one worker per accepted connection (already mostly
  the case with `add_listener` + per-connection tasks; just
  needs verification).
- **HTTP/SSE:** sessions are HTTP-request-level; should
  already parallelize naturally.

**Wire-agnostic abstraction to add:** `TransportConfig`
gets `worker_threads: usize` that the daemon honors via
`tokio::runtime::Builder::worker_threads(n)`. Each wire's
listener factory decides how to actually exploit the
parallelism.

**Lift:** linear with cores up to NIC saturation. On a 4-core
LXC: ~4-5 Gbps for UDP, similar gains for TCP/WS/TLS.
**Effort:** 1 week — the per-peer state sharing is the hard
part and is shared across wires.

### D. Audit `transport::batch` coverage for every wire

drift has a `transport::batch` module (Linux-only) for
batched sends. Audit each adapter's send AND recv path:

| Adapter | Batched recv | Batched send | Notes |
|---|---|---|---|
| UdpPacketIO | recvmmsg? | sendmmsg? | drift::batch likely covers this |
| TcpPacketIO | streaming, no batch needed | vectored writes? | check write_all_vectored |
| WsPacketIO | per-frame; could batch sends | per-frame | tokio-tungstenite limits |
| TlsPacketIO | streaming | streaming | rustls record batching |
| HttpPacketIO | SSE one event at a time | per POST | request pipelining? |
| WebTransportPacketIO | per datagram | per datagram | wtransport's API |

For every wire, the question is "are we paying one syscall
per packet, or one syscall per batch?" [recvmmsg(2)][recvmmsg-man]
and the [HPNPL BatchConn analysis][hpnpl] are the
canonical references for the syscall-cost dominance.

**Lift:** +20-40% on whichever wire was syscall-bound.
**Effort:** 1 day of audit, several days of plumbing per
wire that's not yet batched.

---

## Tier 2 — Wire-specific (chosen because they fit each medium)

### UDP — UDP_GSO + UDP_GRO on Linux

WireGuard-go's own commit ([zx2c4][wg-go-gso]) measured:
> Single-stream TCP went from **8.46 Gbps → 10.6 Gbps
> (+25%)** just from turning on UDP GSO + GRO on Linux.

How: instead of `sendmmsg()`-ing N small UDP packets, hand
the kernel ONE big buffer with a `UDP_SEGMENT` cmsg saying
"split into N segments of K bytes." Kernel does
segmentation in one pass via NIC offload. On receive,
`UDP_GRO` lets the kernel coalesce N incoming packets into
one batched read. Net: 10× fewer userspace↔kernel switches.

Reference impl: [wireguard-go offload mechanisms][deepwiki-gro].

**Lift:** +25% throughput, ~30% CPU drop. **Only for UDP wire.**
**Effort:** 1-2 days.

### TCP / TLS / WS — TCP_NODELAY + congestion-control choice

Three wins specific to stream wires:

1. **`TCP_NODELAY`** on every accepted/connected socket —
   disables Nagle's algorithm. Without this, TCP buffers up
   small writes for 40ms before flushing. For a tunnel
   carrying packetized DRIFT data inside TCP, this is
   catastrophic for latency.
2. **TCP `BBR` or `CUBIC` choice** — `sysctl net.ipv4.tcp_congestion_control=bbr`
   on the host can dramatically improve throughput over
   long-RTT or lossy paths. Document as an ops knob, not a
   code change.
3. **`SO_SNDBUF` / `SO_RCVBUF` on accepted streams** — same
   buffer-tuning story as UDP, applied per-connection.

**Lift:** TCP-tunnel-mode latency 40ms → sub-1ms (the Nagle
fix alone); throughput +10-30% on bandwidth-delay-product
paths.
**Effort:** 1 day total for code; sysctl knobs are docs.

### HTTP/SSE — HTTP/2 multiplexing + connection pooling

The current `http://` wire opens one GET-SSE + one
POST-per-packet. Per-packet POST is the bottleneck (TCP
handshake + HTTP headers per packet). Three improvements:

1. **HTTP keep-alive** — reuse a single TCP connection for
   all POSTs. The hyper/reqwest stack does this by default
   if we use a `Client` pool instead of one-shot requests.
2. **HTTP/2** — frame multiplexing means many "POSTs" share
   one TCP connection without head-of-line blocking. Big
   win for the per-packet pattern.
3. **Batched event frames in the SSE downlink** — instead
   of one `data:` event per DRIFT packet, batch N packets
   into one event with base64-joined bytes.

**Lift:** http-tunnel throughput from "barely usable" to
"acceptable for control-plane traffic" — probably 10-100×
on this wire alone.
**Effort:** 2-3 days. Won't change the verdict that udp/tcp
are still faster, but makes http:// viable when nothing else
is.

### WebRTC — already efficient, but check ICE keepalive

WebRTC datagrams ride DTLS over UDP. Once a session is
established, the steady-state cost is similar to direct UDP
plus DTLS framing (~16 bytes). Check that the ICE
keepalive interval isn't too aggressive (default 2s is
fine). No major optimizations here — the win is that
WebRTC works through NATs without explicit port forwarding,
which is its own form of "performance" in real deployments.

### DNS — accept it's slow

The `dns://` wire trades throughput for stealth (DRIFT
packets ride inside DNS TXT records). Throughput is
fundamentally capped at ~1 Mbps because of DNS message
sizes and per-query overhead. **Don't optimize.** Document
as "control-plane only, not for bulk data."

---

## Tier 3 — Big architectural bets (Linux-UDP only)

These ONLY help the UDP wire. Worth it if UDP is the
expected production wire; not worth it for the wire-flexible
killer-tool story.

### AF_XDP / io_uring (kernel bypass)

[techbytes][techbytes-iouring]:
> "Achieve 10M+ RPS in Rust by bypassing the Linux kernel.
> io_uring and AF_XDP eliminate syscall overhead for
> high-throughput services."

AF_XDP for UDP-direct ring access. io_uring for async-syscall
batching that works for sockets AND tun. Rust bindings:
[xsk-rs][xsk-rs], [io-uring][io-uring-rs].

**Tradeoff:** complete rewrite of the I/O layer for one wire.
Linux-only. Operationally complex (CAP_NET_RAW, hugepages).
**Lift:** 3-5× over current on UDP wire.
**Effort:** 2-4 weeks of focused work.

### TUN device batched I/O + virtio_net header

`IFF_MULTI_QUEUE` (multiple fds per tun) + `IFF_VNET_HDR`
(virtio-net header with GSO info) — same techniques as
UDP GSO/GRO but applied to the tun side. Pairs naturally
with item D + UDP GSO.

**Lift:** +10-20% on top of UDP GSO.
**Effort:** 2-3 days.

---

## Recommended sequence

```
Day 1:   Tier 0 — wire-matrix bench (see bench/wire-matrix.sh below)
Day 1:   Item B — netstat -s diagnosis
Day 2:   Item A — recv-buffer default
Day 2:   Re-bench, expect UDP wire ~+10% from recv buffer
Day 3-4: UDP-specific item — UDP GSO/GRO        (UDP-only +25%)
Day 4:   Re-bench UDP wire, expect ~2.5 Gbps
Day 5-7: Item D + TCP/TLS/WS item — batching + TCP_NODELAY
Day 8:   Re-bench all wires
Day 9-15: Item C — multi-core scaling           (wire-agnostic)
Day 16:  Re-bench all wires
Day 17:  HTTP item — pooling + HTTP/2           (makes http:// viable)
```

Stop and re-bench between each — the matrix data tells you
which wire to optimize next.

---

## Wire-matrix bench script (to add)

```bash
# bench/wire-matrix.sh — same iperf3 method as bench/run-bench.sh,
# but cycles through every DRIFT scheme. Brings up a tunnel per
# scheme, runs the test, tears down, moves on.

for scheme in udp tcp ws tls http webtransport webrtc; do
  bring_up_tunnel "$scheme://"
  run_iperf3_over_tunnel "$scheme"
  tear_down_tunnel
done
```

Each scheme also reports CPU% and a `netstat -s` delta so
the bottleneck per wire is visible.

---

## References

- [`zx2c4`: WireGuard performance roadmap][wg-perf]
- [WireGuard-go commit: UDP GSO/GRO][wg-go-gso] (the +25% data point)
- [WireGuard-go offload mechanisms — DeepWiki][deepwiki-gro]
- [Red Hat — Tuning UDP connections][redhat-udp]
- [LinuxVox — UDP packet drops: INErrors vs RcvbufErrors][linuxvox-udp]
- [Troubleshooting UDP loss with QUIC][udp-loss-blog]
- [`recvmmsg(2)` man page][recvmmsg-man]
- [HPNPL — BatchConn `sendmmsg`/`recvmmsg`][hpnpl]
- [Tokio UDP throughput thread][tokio-udp]
- [`xsk-rs` AF_XDP for Rust][xsk-rs]
- [`io-uring` crate][io-uring-rs]
- [Kernel bypass with io_uring + AF_XDP][techbytes-iouring]
- [Segmentation offloads (kernel docs)][kernel-seg]

[wg-perf]: https://www.wireguard.com/performance/
[wg-go-gso]: https://git.zx2c4.com/wireguard-go/commit/?id=6a84778f2ca810f5fb5cb078e001494f08d9085f
[deepwiki-gro]: https://deepwiki.com/WireGuard/wireguard-go/4.4-offload-mechanisms
[redhat-udp]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/network_troubleshooting_and_performance_tuning/tuning-udp-connections
[linuxvox-udp]: https://linuxvox.com/blog/udp-packet-drop-inerrors-vs-rcvbuferrors/
[udp-loss-blog]: https://ralphbupt.github.io/2024/07/07/Troubleshooting-a-UDP-Packet-Loss-Issue-on-Linux/
[recvmmsg-man]: https://www.man7.org/linux/man-pages/man2/recvmmsg.2.html
[hpnpl]: https://hpnpl.net/
[tokio-udp]: https://users.rust-lang.org/t/tokio-how-do-i-improve-throughput-using-udpsocket/123105
[xsk-rs]: https://github.com/douglasgray/xsk-rs
[io-uring-rs]: https://docs.rs/io-uring/latest/io_uring/
[techbytes-iouring]: https://techbytes.app/posts/rust-performance-io-uring-af-xdp-kernel-bypass/
[kernel-seg]: https://docs.kernel.org/networking/segmentation-offloads.html

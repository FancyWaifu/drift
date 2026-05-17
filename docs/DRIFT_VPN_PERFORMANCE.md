# drift-vpn performance — optimization plan

Based on the BENCH.3 numbers (drift-vpn 1.31 Gbps @ 91% CPU vs
WireGuard 1.82 Gbps @ 16% CPU) the bottleneck is clearly
**userspace packet-processing efficiency**, not the AEAD crypto
itself (the `ring` crate already uses AVX/SSE on x86 and NEON
on ARM, same as the kernel WG uses).

Ranking by **expected throughput-per-CPU lift** vs **implementation
cost**.

---

## Tier 1 — Should-do-now (biggest gains, low complexity)

### 1. UDP GSO/GRO on Linux (segmentation/coalescing offload)

The single biggest win other userspace VPNs have measured.
WireGuard-go's own commit message ([zx2c4][wg-go-gso]) shows:

> Single-stream TCP went from **8.46 Gbps → 10.6 Gbps (+25%)**
> just from turning on UDP GSO + GRO on Linux. Same hardware,
> same code, same CPU budget.

How it works: instead of `sendmmsg()`-ing N small UDP packets
through the kernel, the userspace app hands the kernel ONE
big packet with a `UDP_SEGMENT` cmsg saying "split this into
N segments of 1200 bytes each." The kernel does the
segmentation in one pass through the NIC offload path. On
receive, `UDP_GRO` lets the kernel coalesce N incoming
packets into one batched read. Net effect: 10× fewer
userspace↔kernel context switches.

drift-vpn already builds for x86_64 Linux. Wiring up
`setsockopt(SOL_UDP, UDP_SEGMENT, …)` on send and
`UDP_GRO` on recv is ~200 lines of unsafe-libc plus careful
buffer management. Reference: [wireguard-go conn/gso_linux.go][wg-gso-source].

**Expected lift: +25% throughput, ~30% CPU reduction.**
**Effort: 1–2 days.**

### 2. Increase default UDP recv buffer for drift-vpn

We added `udp_recv_buffer_bytes` in PQ-T.11.1 but only
`drift bridge` defaults to 4 MiB; drift-vpn still uses the
OS default (~200 KB). Under sustained iperf3, that's the
likely cause of the 52% UDP drops we observed.

Linux's defaults (per [Red Hat tuning guide][redhat-udp]):
> "If a UDP packet is too large and exceeds the buffer size
> or packets are sent or received at a too fast rate, the
> kernel drops any new incoming UDP packet."

[LinuxVox's analysis][linuxvox-udp] confirms `RcvbufErrors`
in `netstat -s` means the application can't keep up — exactly
our case.

**Expected lift: eliminates the 52% UDP loss; ~10% TCP
throughput from reduced retransmits.**
**Effort: 2 lines (set `udp_recv_buffer_bytes: Some(4MB)`
in drift-vpn's default config).**

### 3. Diagnose: `netstat -s` during the bench

Before more invasive work, confirm WHERE the drops are
happening:

```sh
# On the receiver during a 30s iperf3 run
ssh d2 'netstat -su | grep -E "receive errors|RcvbufErrors|packet"'
```

If `RcvbufErrors` is the dominant counter → recv buffer
sizing (item 2 above) fixes it. If `packet receive errors`
dominates → the bottleneck is userspace not draining the
socket fast enough → batched recv (item 4 below) is what's
needed.

**Expected lift: clarifies which of items 1 & 2 actually
matters most. Cost: free.**

---

## Tier 2 — Real engineering work, real gains

### 4. Verify + extend `recvmmsg`/`sendmmsg` batching

drift's codebase already has a `transport::batch` module
(Linux-only). Need to check whether drift-vpn's send AND
recv hot paths actually use it. The
[Linux man page][recvmmsg-man]:

> The `recvmmsg()` system call is an extension of `recvmsg(2)`
> that allows the caller to receive multiple messages from a
> socket using a single system call. This has performance
> benefits for some applications.

The [HPNPL BatchConn analysis][hpnpl] (Go but mechanics match
Rust) measured the syscall cost dominating UDP throughput.
For drift-vpn at 1.3 Gbps that means ~110k packets/sec at
1400 B each — every saved syscall counts.

**Expected lift: +20-40% if batching isn't already on both
sides of every wire.**
**Effort: 1 day of audit + plumbing.**

### 5. SO_REUSEPORT + worker pool

drift-vpn pegs one core at 91% CPU at 1.3 Gbps. With
`SO_REUSEPORT`, multiple sockets can bind the same port,
and the kernel distributes incoming packets across them via
hash. Each socket gets its own worker task on a different
core.

Pattern from the Rust users forum ([Tokio UDP throughput][tokio-udp]):
> "After completing a handshake, I instantiate a Connection;
> this instantiates n receive threads via spawn calls. Each
> receive thread gets a copy of a UDPSocket with SO_REUSEPORT
> set, binded and connected."

The QUIC proxy lost-packets case study from
[Link's blog][udp-loss-blog] makes the case concretely:
their single-threaded epoll proxy hit a 20-50 µs per packet
processing wall, capping it at 50k pps. Same fix applies here.

**Caveats:**
- Per-peer ordering across workers requires care
  (the same flow always hashes to the same worker, but
  ordering between workers is independent)
- DRIFT's per-peer session state needs to be shareable
  across workers or sharded by peer_id
- The `tokio::net::UdpSocket` wrapper doesn't expose
  `SO_REUSEPORT` directly; need to use `socket2::Socket` and
  `from_std`

**Expected lift: scales linearly with cores up to NIC
saturation. From 1.3 Gbps single-core → 4-5 Gbps on a 4-core
LXC.**
**Effort: 3-5 days (the per-peer state sharing is the hard
part).**

### 6. TUN device batched I/O

Each `read()` from the tun device returns ONE packet. At
1.3 Gbps that's ~110k syscalls per second on the tun side
alone, doubled if you count writes. wireguard-go also did
[GRO on TUN][deepwiki-gro]:

> "TCP GRO maintains flow state... coalesces multiple
> related packets into larger packets to reduce per-packet
> processing overhead."

The Linux tun device supports `IFF_MULTI_QUEUE` (multiple
fds per tun, kernel distributes) and `IFF_VNET_HDR`
(virtio-net header with GSO info). wireguard-go uses both
in tandem with #1 above.

**Expected lift: another 10-20% on top of UDP GSO.**
**Effort: 2-3 days, complex platform-specific code.**

---

## Tier 3 — Big architectural bets

### 7. AF_XDP / io_uring (kernel bypass)

[techbytes article][techbytes-iouring]:
> "Achieve 10M+ RPS in Rust by bypassing the Linux kernel.
> io_uring and AF_XDP eliminate syscall overhead for
> high-throughput services."

AF_XDP (XDP socket) gives userspace direct access to NIC RX
rings, bypassing the kernel networking stack entirely. Used
by Cloudflare and Tailscale's research forks.
[xsk-rs crate][xsk-rs] provides Rust bindings.

io_uring is the more general approach — async syscall
batching that works for sockets AND files AND tun devices.
The [io-uring crate][io-uring-rs] is mature.

**Tradeoff:** complete rewrite of the I/O layer.
Platform-specific (Linux only). Operationally complex
(CAP_NET_RAW, hugepages for AF_XDP).

**Expected lift: 3-5× over current.**
**Effort: 2-4 weeks of focused work.**

### 8. AVX-512 ChaCha20 (verify ring already uses it)

The `ring` crate auto-detects CPU features and uses AVX/SSE
ChaCha20 on x86 and NEON on aarch64. No action needed unless
profiling shows AEAD as the bottleneck (it shouldn't be at
1.3 Gbps single-stream — that's ~110 MB/s of plaintext,
well under ring's ~1.5 GB/s ChaCha20-Poly1305 throughput on
a modern CPU).

**Action: confirm via flamegraph that AEAD isn't a hotspot.**

---

## Recommended order of attack

```
Day 1:    Item 3 (diagnose with netstat -s)   ← do first
Day 1:    Item 2 (recv-buffer default bump)    ← cheap win
Day 2-3:  Item 1 (UDP GSO/GRO)                 ← big win
Day 4:    Re-bench, expect drift-vpn ~2.5 Gbps
Day 5-6:  Item 4 (audit recvmmsg/sendmmsg coverage)
Day 7-10: Item 5 (SO_REUSEPORT + workers)
Day 11:   Re-bench, expect drift-vpn ~4-5 Gbps on 4-core
```

Stop and re-bench between each item — the data tells you
which to do next.

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
[wg-gso-source]: https://git.zx2c4.com/wireguard-go/tree/conn/gso_linux.go
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

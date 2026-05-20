# Bridge optimization research

Following the corporate-federation reliability test (K=17 bridges,
4-hop diameter) showing 4-hop tail failures both on Docker Desktop
and on a 2-core / 512 MB Proxmox LXC, the failure mode looks
resource-bound (per-bridge packet-processing capacity under
contention) rather than protocol. This doc collects the standard
optimization techniques for relay / proxy servers, ranked by
expected impact for drift's specific case, with concrete pointers
to where the changes would land.

Sources are real-world systems with the same shape (high-fan-in
UDP / TLS relay): the
[Realm](https://deepwiki.com/zhboner/realm/4.1-linux-optimizations)
proxy's Linux optimizations, Matrix
[Synapse federation workers](https://docs.element.io/latest/element-server-suite-classic/advanced-configuration/synapse-section-workers/),
Cloudflare's
[BPF-based UDP load-balancing](https://blog.apnic.net/2023/10/19/rocky-road-towards-ultimate-udp-server-with-bpf-based-load-balancing-on-linux-part-2/),
RHEL's
[listen-queue contention guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/network_troubleshooting_and_performance_tuning/avoiding-listen-queue-lock-contention),
ByteDance's
[monoio thread-per-core runtime](https://github.com/bytedance/monoio),
and Apache Iggy's
[migration to thread-per-core + io_uring](https://iggy.apache.org/blogs/2026/02/27/thread-per-core-io_uring/).

## TL;DR — what to do first

| Rank | Optimization | Effort | Expected impact at K=17 |
| ---- | ------------ | ------ | ----------------------- |
| 1 | `recvmmsg(2)` on the UDP receive path | medium (1-2 days, contained) | **3-10× UDP packet throughput** per bridge |
| 2 | Sysctl tuning on bridge hosts (`net.core.rmem_max=128M`, `wmem_max=128M`, `netdev_max_backlog=50000`) | trivial (one-time) | Bridge actually gets the 4 MB recv buffer it requests today (currently kernel-clamped to ~425 KB) |
| 3 | `tokio::main` → explicit runtime tuning | small | Reduce thread-stealing overhead on 2-core hosts |
| 4 | Replace `Arc<StdMutex<HashMap>>` peer table with shard-or-rcu pattern | medium | Eliminate 146 lock sites' tail latency under contention |
| 5 | Process-per-federation-peer ("Synapse worker" style) | large | Decouples per-peer queues; one slow peer doesn't stall the others |
| 6 | Migrate to `monoio` or `tokio-uring` for io_uring batched async I/O | large | Better envelope at high concurrency; not a fit if we want cross-platform |

The first three are cheap and could realistically be done in a
single focused session. Items 4-6 are bigger architectural
choices worth discussing before committing.

## Detailed: each optimization, why, and where

### 1. Add `recvmmsg(2)` to mirror the existing `sendmmsg` batching

**Status today:** `drift/src/transport/batch.rs` already implements
batched UDP send via raw `libc::sendmmsg`. The receive side is
still one packet per `recv_from` syscall. Asymmetric.

**Why this matters:** A bridge under load receives orders of
magnitude more packets than it originates (one per forwarded
peer-to-peer DATA frame, plus federation announces, plus client
HELLOs). Each `recv_from` is a syscall round-trip; under
contention syscall context switches dominate the per-packet cost.
`recvmmsg(2)` accepts a vector of packets in a single syscall,
shifting the per-packet cost from "syscall" to "memcpy."

**Concrete benchmarks elsewhere:**
- Cloudflare quiche moved to `recvmmsg` and saw substantial CPU
  reduction on their edge.
- Realm's docs claim 3-10× throughput improvement for both
  send and receive paths versus per-packet syscalls.

**Where it lands in drift:**
- Mirror `drift/src/transport/batch.rs` structure: new
  `recv_batch` function that wraps `libc::recvmmsg` with
  `tokio::net::UdpSocket::async_io`.
- The UDP wire's recv loop (`drift/src/wire_udp.rs` or wherever
  `recv_from` is called per packet) becomes
  `recv_batch(MAX_BATCH).await` and dispatches each received
  packet through the existing per-packet pipeline.
- Cross-platform: non-Linux fallback loops `recv_from` (just like
  `sendmmsg`'s sequential fallback).

**Risk:** Receive batching changes ordering slightly (packets
within a batch are processed before next syscall fires) — but
drift's transport already handles out-of-order packets, so this
should be transparent.

### 2. Sysctl tuning on bridge hosts (the "free" optimization)

**Status today:** when drift bridge starts, it logs:

    SO_RCVBUF clamped by kernel; raise sysctl rmem_max for full size
    requested=4194304 granted=425984

So the bridge ASKS the kernel for 4 MiB of UDP receive buffer per
socket, but the kernel grants ~425 KB. Under burst load, the
buffer fills and packets drop at the kernel — invisible to the
bridge.

**The fix is sysadmin-level, not code:**

```bash
cat >> /etc/sysctl.d/99-drift.conf << 'EOF'
net.core.rmem_max         = 134217728   # 128 MiB max receive
net.core.wmem_max         = 134217728   # 128 MiB max send
net.core.rmem_default     = 8388608     # 8 MiB default
net.core.wmem_default     = 8388608     # 8 MiB default
net.core.netdev_max_backlog = 50000     # packets queued per CPU
EOF
sysctl -p /etc/sysctl.d/99-drift.conf
```

After this, the bridge's 4 MiB `SO_RCVBUF` request actually gets
granted. On a host receiving sub-Mbps federation traffic this is
plenty; on a relay seeing real load, the difference between
"packets queued for the application" and "packets dropped silently
at the kernel" is the difference between 80% and 100% reliability.

**Where it lands in drift:**
- Document in `docs/DEPLOYMENT.md` or `drift/README.md`: "before
  running `drift bridge` in production, tune these sysctls."
- Optionally add a startup check that warns when `rmem_max <
  configured SO_RCVBUF`.

### 3. Explicit tokio runtime configuration

**Status today:** `drift/src/main.rs` uses `#[tokio::main]` with
default settings. That gives multi_thread runtime with one worker
per CPU. On a 2-core LXC running 17 drift bridge processes, that's
34 worker threads competing for 2 cores — almost pure scheduler
churn.

**The fix:**

```rust
fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get().clamp(2, 4))
        .thread_name("drift-rt")
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}
```

OR — for relay use cases specifically — single-threaded per
process:

```rust
fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}
```

`current_thread` eliminates work-stealing entirely. Each bridge
process is single-threaded; if you need parallelism, run multiple
processes (Synapse-style). This is what monoio / glommio advocate.

**Where it lands in drift:**
- `drift/src/main.rs::main` — change the `#[tokio::main]` macro
  to an explicit builder pattern.
- Optionally add `--runtime-threads <N>` CLI flag for ops control.

### 4. Reduce lock contention on the peer table

**Status today:** `drift/src/transport/` has 146 sites calling
`peers.lock_for(...)`, `peers.lock_all()`, etc. The peer table is
sharded (`PeerShards`) so it's not a single global lock, but
under burst load — many federation announces arriving, many
forwarded packets — multiple threads can contend on the same
shard.

**Standard fixes, in order of mechanical sympathy:**

1. **DashMap** as a drop-in for sharded `HashMap` with built-in
   sharded locking. **Caveat**: DashMap has well-known async
   deadlock risks (see
   [Beware of the DashMap deadlock](http://gnunicorn.org/writings/beware-of-the-dashmap-deadlock/))
   when guards are held across `.await` points. Drift's lock
   usage would need an audit before switching.

2. **Lock-free linked-list / RCU**: read paths see a snapshot
   (no lock); writers swap the whole pointer atomically. Hot
   path (forward decision) goes from "acquire lock, lookup, drop
   lock" to "load atomic pointer, lookup." Tradeoff: writers
   become more expensive (allocate new snapshot).

3. **Per-task local cache** of the federation_table: each
   forwarding task keeps a snapshot of `(bridge_pub →
   peer_id)`, refreshed every N forwards. Eliminates lock
   acquisition on the hot path entirely; trades stale-route
   tolerance against contention.

**Where it lands in drift:**
- Profile first to confirm the bottleneck. `tokio-console` shows
  per-task wait time; `perf` or `flamegraph` shows
  mutex contention vs syscall vs userspace cost.
- Most likely candidates: `federation_table`, `peer_directory`,
  `presence_tickets` — the three structures touched on every
  forwarded packet.

### 5. Process-per-federation-peer (Synapse-worker pattern)

**What Synapse does:** instead of one homeserver process handling
all federation traffic, it splits into specialized worker
processes:

- `federation_sender` workers — each handles a slice of outgoing
  federation traffic (e.g. by hash of destination domain).
- `federation_reader` workers — handle incoming federation.

**Mapping to drift:** instead of one `drift bridge` process
handling all federation peers, run one bridge-shard process per
federation peer (or per N peers). Each shard has its own peer
table, announce ticker, and forwarding loop — no cross-shard
locks. The kernel's UDP stack handles delivery to the right
shard based on SO_REUSEPORT BPF routing.

**Tradeoffs:**
- (+) Eliminates inter-peer lock contention entirely. One slow
  federation link doesn't stall the others.
- (+) Naturally maps to multi-host deployment — each shard can
  run on its own VM with dedicated CPU.
- (–) Adds operational complexity (process supervision, shard
  routing, identity coordination).
- (–) For homelab / small federation use, almost certainly
  overkill.

**Where it lands in drift:** this is an architectural change,
not a focused fix. Would need a new `drift bridge --shard
<i-of-n>` CLI mode plus per-shard config. Probably not worth it
unless the project actually targets datacenter-scale federation.

### 6. Migrate to io_uring (monoio / tokio-uring)

**What this is:** Linux kernel 5.10+ has `io_uring`, a
shared-ring-buffer interface for async I/O. The Rust ecosystem
has two relevant runtimes built on it:

- **`tokio-uring`** — a tokio-compatible runtime that uses
  io_uring for I/O while keeping tokio's API surface.
- **`monoio`** (ByteDance) and **`glommio`** (Datadog) — pure
  thread-per-core runtimes designed around io_uring from the
  start. Faster than tokio-uring but break tokio API compat.

**Why bridges care:** io_uring eliminates per-I/O syscalls
entirely. The kernel and userspace share a ring buffer; userspace
posts SQEs (submission queue entries), the kernel drains them,
posts CQEs (completion queue entries), userspace reads them. For
a relay seeing 10K+ packets/sec, this dominates everything else.

**For drift specifically:** probably overkill. Drift's target use
case is sub-Mbps federation traffic, not edge-of-CDN throughput.
The win at K=17 might be real but is smaller than items 1-2 above.

**If we did this**, the migration would be:
- Replace `#[tokio::main]` with `monoio::main` or
  `tokio_uring::start`.
- Touch `Send`/`Sync` constraints throughout (monoio doesn't
  require these).
- Rewrite `drift::io` to use the new runtime's I/O primitives.

Big change, not a fit unless drift is committing to Linux-only
production targets.

## What I'd do this week (if I were prioritizing)

1. **Sysctl doc + startup-check warning** (1 hour). Free win;
   gets the bridge its already-requested 4 MiB buffer.
2. **`recvmmsg` recv-side batching** (1-2 days). Mirrors the
   existing `sendmmsg` send-side. Contained change. Likely
   3-10× UDP packet throughput per bridge. Re-run the
   corporate-federation test after — bet is 80% → 95%+.
3. **Re-run corporate test on a beefier Linux host** (an hour,
   maybe rented EC2 instance) to confirm the resource hypothesis
   independent of any code change. Worth doing before chasing
   any of the bigger items.

Items 4-6 only become worth tackling if the corporate test STILL
shows degradation after #1-3 land.

## What I'd defer / not do

- **DashMap** without an audit (deadlock risk under `.await`
  guards).
- **monoio migration** (overkill for the project's scale; would
  cost Windows / macOS as build targets).
- **Per-peer worker processes** (operational complexity not
  justified by current scale).

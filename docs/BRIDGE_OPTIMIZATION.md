# Bridge optimization research

Following the corporate-federation reliability test (K=17 bridges,
4-hop diameter) showing 4-hop tail failures both on Docker Desktop
and on a 2-core / 512 MB Proxmox LXC, the failure mode looks
resource-bound (per-bridge packet-processing capacity under
contention) rather than protocol. This doc collects the standard
optimization techniques for relay / proxy servers, ranked by
expected impact for drift specifically, with concrete pointers to
where the changes would land.

**Important framing**: drift bridge federation is exclusively
**h2 / h2s / webtransport** (HTTP/2 over TCP or TLS, or HTTP/3
over QUIC) per HTTP.FED.STRICT (commit `aafa4b2`). UDP-specific
optimizations like `recvmmsg`/`sendmmsg` are irrelevant to the
federation hot path — they only matter for client-to-bridge
traffic. The optimization research is therefore about HTTP/2
stream throughput, TLS / TCP buffer behavior, and tokio task
scheduling, not UDP packet batching.

## What drift's h2 wire actually does (hot path)

`drift/src/wire_h2.rs` for each federation peer:

**Send-side per packet:**
1. `H2StreamPacketIO::send_to(buf, _dest)` allocates a fresh
   `BytesMut::with_capacity(2 + len)` (line 115).
2. Frames with 2-byte length prefix.
3. Pushes through a `mpsc::Sender<Bytes>` with **`SEND_QUEUE_DEPTH = 256`**
   capacity (line 65). Producer blocks once full.
4. A separate `body_pump` task drains the channel.
5. hyper writes it as an HTTP/2 DATA frame.
6. rustls encrypts (h2s only). ChaCha20-Poly1305 — per-frame work.
7. TCP write. `TCP_NODELAY` is already on (line 216, 258).

**Recv-side per packet:**
1. HTTP/2 incoming body frame.
2. `drain_h2_body_into_packets` accumulates bytes, splits on length-prefix.
3. Pushes each whole drift packet through `mpsc::Sender<Bytes>` with
   **`RECV_QUEUE_DEPTH = 256`** capacity.
4. `H2StreamPacketIO::recv_from` locks `Mutex<mpsc::Receiver<Bytes>>`,
   awaits one item.

**hyper HTTP/2 connection setup** (lines 312, 422): uses
`Builder::new(TokioExecutor)` with **no explicit configuration** —
default flow-control windows (64 KB per stream, 64 KB per
connection per HTTP/2 spec), default max frame size (16 KB), no
adaptive window.

## TL;DR — what to do first

| Rank | Optimization | Effort | Status (2026-05-20) |
| ---- | ------------ | ------ | ------------------- |
| 1 | **Tune hyper HTTP/2 flow control**: `adaptive_window(true)`, bump `initial_stream_window_size` and `initial_connection_window_size` to 2-4 MiB | 1 hour | **Shipped `5182375`**: 66/96 → 73-82/96. Single biggest measured fix. |
| 2 | Bump `SEND_QUEUE_DEPTH` / `RECV_QUEUE_DEPTH` from 256 → 4096 | 1 line each | **Shipped `5182375`** (paired with item 1). |
| 3 | Buffer pool for outgoing `BytesMut` framing | half a day | **Shipped `5182375`**: amortizing arena, 64 KiB chunk backs ~600 frames. |
| 4 | Coalesce multiple drift packets into a single h2 DATA frame on the send side | 1-2 days | **Deferred** (post-research re-rank: 0.6% wire savings + adds latency, gRPC doesn't recommend). |
| 5 | TLS session resumption + 0-RTT (rustls session tickets) | 1 day | **Shipped `9c4ba24`** (forward-compatible 0-RTT plumbing). |
| 5b | HTTP/2 PING keepalive for fast dead-peer detection | 1 hour | **Shipped `9c4ba24`** (30s/20s, gRPC-shaped defaults). |
| 6 | Tokio runtime config — operator lever, not default | 1 hour | **Shipped `9c4ba24`** as `DRIFT_TOKIO_WORKER_THREADS` env var; "cap to 1" default was attempted and reverted (regression). |
| 7 | Reduce peer-table lock contention (146 lock sites in `transport/`) | medium-large | **Deferred** (premature without profiling; arc-swap on `peer_directory` is the textbook target if it becomes a hotspot). |
| 8 | Drop-on-full + stale-drop at h2 send queue (IP-router style) | half a day | **Shipped `3fcfab8`** (correct under overload; bench-neutral on dial loop). |
| 9 | ECN-style backpressure, ECMP multi-path, per-source fair queue | days each | **Deferred** (research showed weak fit for DRIFT's current bottleneck). |

The first three were the high-leverage initial wins. Items 5,
5b, 6, 8 are smaller wins that also went in; their value shows
mostly in failure modes the corporate dial bench doesn't
exercise (reconnects, dead-link detection, overload bursts).
Items 4, 7, 9 are deferred with reasons in their sections.

For the deep post-research re-ranking that landed items 5/5b/6,
see [`docker/federation-corporate/RESULTS.md`](../docker/federation-corporate/RESULTS.md)
sections "third follow-up" and "fourth follow-up."

## Detailed: each optimization

### 1. Hyper HTTP/2 flow control tuning (the single biggest lever)

**What's wrong today**: HTTP/2's per-stream flow control means the
receiver advertises a "window" of bytes the sender can ship before
needing a WINDOW_UPDATE frame back. Default window = **64 KB**.
That covers maybe 50-150 drift packets at typical sizes (~100-500
bytes each, plus framing). After that, the sender stalls until the
receiver processes its read and sends a WINDOW_UPDATE.

For a 4-hop federation chain, each forwarded packet potentially
hits 4 of these windows. Under burst load (many announces +
forwarded dials simultaneously), windows close, packets queue,
tail latency explodes.

**Fix** (line 312, 422 of `drift/src/wire_h2.rs`):

```rust
let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
    .timer(TokioTimer::new())
    // Tune flow control for relay traffic. Default 64 KB
    // windows force a WINDOW_UPDATE round-trip every ~100-150
    // drift packets, which is the wrong tradeoff for a bridge
    // that sees sustained federated traffic. Adaptive window
    // sizes the window from the bandwidth-delay product, much
    // better for long-lived high-rate streams.
    .adaptive_window(true)
    // Larger initial windows reduce stalls until adaptive
    // window catches up. 2 MiB is comfortable for federated
    // relay; bridges with high-throughput downstream peers may
    // bump higher.
    .initial_stream_window_size(2 * 1024 * 1024)
    .initial_connection_window_size(2 * 1024 * 1024)
    // Default max frame size is 16 KB; raising lets us coalesce
    // more drift packets per h2 frame when item 4 lands.
    .max_frame_size(64 * 1024)
    .serve_connection(io, svc);
```

Same builder pattern on the client side around line 422. Both
sides should advertise the larger windows.

**Why this is rank 1**: the symptom (non-deterministic tail
failures at 4-hop diameter that don't improve with more timeout)
is the *exact* signature of flow-control stalls. Each hop adds
one window-update round-trip; under load they compound.
WINDOW_UPDATE frames themselves are cheap, but the producer-side
stalls aren't — and they don't appear as "timeout" because the
producer is doing the right thing (waiting for window credit).

### 2. Bigger channel depths

```rust
const SEND_QUEUE_DEPTH: usize = 4096;  // was 256
const RECV_QUEUE_DEPTH: usize = 4096;  // was 256
```

At 256 capacity × ~200 bytes/packet = 50 KB of buffered traffic.
With 4096 capacity, ~800 KB. The channels are already bounded so
backpressure still works; just at a level that matches the
bigger HTTP/2 window from item 1.

### 3. Buffer pool for outgoing frames

Today (line 115 of `drift/src/wire_h2.rs`):

```rust
let mut framed = BytesMut::with_capacity(FRAME_LEN_PREFIX + buf.len());
framed.extend_from_slice(&(buf.len() as u16).to_be_bytes());
framed.extend_from_slice(buf);
```

Every `send_to` allocates fresh. For a bridge moving thousands of
small packets per second, this is sustained allocator pressure
plus L1-cache thrash on the freshly-allocated buffer.

Fix: maintain a small pool of `BytesMut` of fixed size, leased via
a `thread_local!` or `parking_lot::Mutex<Vec<BytesMut>>`. After the
h2 layer is done with a buffer, return it to the pool. `Bytes` (the
immutable view that h2 actually consumes) handles refcounting
automatically — when the last `Bytes` referring to a buffer is
dropped, the buffer is returned to the pool.

The `bytes` crate's `BytesMut` already does some of this via
shared inner buffers, but explicit pooling gives more control
over the working set size.

### 4. Coalesce multiple drift packets per h2 DATA frame

Today each `send_to` call produces one channel item, and the
`body_pump` task ships each as a separate h2 frame. h2 frames
have a 9-byte header. For a 100-byte drift control packet, h2
overhead is 9% — non-trivial.

Better: the `body_pump` task can drain multiple items from the
channel before flushing. Something like:

```rust
loop {
    let first = match rx.recv().await {
        Some(b) => b,
        None => break,
    };
    let mut batch = vec![first];
    // Opportunistic batching: drain anything else already
    // queued (try_recv doesn't await; we only wait once at
    // the top of the loop).
    while batch_size(&batch) < MAX_BATCH_BYTES {
        match rx.try_recv() {
            Ok(b) => batch.push(b),
            Err(_) => break,
        }
    }
    // Write all framed packets as one h2 DATA frame. Receiver's
    // length-prefix splitter is already chunk-agnostic.
    write_batch_as_one_frame(batch).await?;
}
```

This is the same logical pattern as UDP `sendmmsg`, applied at
the application framing level instead of the kernel syscall
level. Receivers don't need to change.

### 5. TLS session resumption + 0-RTT (h2s only)

> **Status (2026-05-20):** Shipped in commit `9c4ba24`. Server-side
> ticketer (`rustls::crypto::ring::Ticketer`) is enabled,
> `max_early_data_size = 16 KiB` advertises 0-RTT capacity, and
> client-side `enable_early_data = true` opts in. The hyper h2
> client doesn't yet issue an EarlyData write before the handshake
> completes, so this is forward-compatible plumbing — when the
> application opts in, the TLS layer is ready.

rustls supports TLS 1.3 session resumption via session tickets
or PSK. **Key correction from the original write-up:** TLS 1.3
*fresh* handshakes are already 1-RTT, so plain resumption saves
only the CPU cost of cert chain verification + key derivation,
not round trips. The real RTT win is 0-RTT data — normally
dangerous because of replay attacks, but **uniquely safe for
DRIFT** because the inner AEAD already carries a sequence number
+ replay window. A replayed federation packet at the TLS layer
is rejected by the inner transport before any side effect.

For drift, federation sessions are long-lived (no reason to
reconnect under normal operation), so this is only relevant for
recovery after a TCP teardown.

`rustls::ServerConfig` has `ticketer` + `max_early_data_size`;
`rustls::ClientConfig` has `enable_early_data`. Client-side
resumption storage is already on by default (rustls
`Resumption` defaults to 256 server names × 8 tickets).

### 5b. HTTP/2 PING keepalive for fast dead-peer detection

> **Status (2026-05-20):** Shipped in commit `9c4ba24`. Both
> server and client h2 builders configured with
> `keep_alive_interval(30s)` + `keep_alive_timeout(20s)`; client
> also sets `keep_alive_while_idle(true)`.

Linux's default TCP keepalive needs ~2h 11min to detect a dead
peer (`tcp_keepalive_time=7200s` idle + 9 × 75s probes), and
most apps don't even enable `SO_KEEPALIVE`. With h2 PING at
30s/20s, a dead peer is detected in ≤ 50s. PING frames are
17 bytes; at the default cadence that's ~0.6 B/sec/connection
— invisible overhead.

The 30s/20s setting matches gRPC's well-trodden production
defaults and stays above gRPC's 5-minute minimum-receive-ping
interval, so this won't trip the "ENHANCE_YOUR_CALM" / ping-
strike failure mode in heterogeneous federations.

Negligible bench impact (the corporate dial test doesn't drop
connections), but the real-world payoff on flaky WAN /
mobile / corporate-firewall federation is the difference
between "30-second blip" and "2-hour silent outage."

### 6. Explicit tokio runtime configuration

> **Status (2026-05-20):** Partially shipped in commit `9c4ba24`.
> The `DRIFT_TOKIO_WORKER_THREADS` env var is now an operator
> lever (0 → `current_thread`; N → `multi_thread` workers=N).
> **Default is unchanged** — tokio's native `num_cpus`. The
> "cap workers to 1 by default" experiment was attempted and
> measurably regressed the K=17 LXC bench (see below).

Today `drift/src/main.rs::main` uses an explicit runtime builder
that reads the env var; with no env var set, it falls through
to `Builder::new_multi_thread().enable_all().build()`, which
matches the prior `#[tokio::main]` behavior (workers = `num_cpus`).

#### The "cap to 1" regression

The "thread-per-core via N processes" pattern has well-cited
benchmarks showing 1.5-2× wins for shard-per-core / lock-free
workloads. We tried setting the worker_threads default to 1 on
the assumption that DRIFT's bridge workload was a fit (lots of
single-core processes, oversubscription elsewhere). It wasn't:

| Drift-4 (2-core LXC), K=17 bench | total | 4 hop |
| -------------------------------- | ----- | ----- |
| workers=1 default (FAILED)       | 62/96 | 6/36  |
| workers=2 explicit               | 77/96 | 18/36 |
| native default (`num_cpus`)      | 75/96 | 19/36 |

Why it regressed: hyper's h2 connection task, the per-stream
body-drain task, and the request handler all need to run
concurrently within a single bridge process. With one worker,
those tasks serialize on the single thread — the h2 connection
task can't drain frames while a handler is busy, and vice
versa. Transit hops starved, and 4-hop pass rate collapsed.

The lever stays for operators who measurably want the pattern
on their workload (e.g., very high process counts on small
hosts) — but the safe default is letting tokio use `num_cpus`.

#### When to actually reach for `current_thread`

Set `DRIFT_TOKIO_WORKER_THREADS=0` if your workload genuinely
has zero useful intra-process parallelism (single peer,
single stream, no fan-out). For multi-peer federation
bridges, leave it alone.

For relay-shaped workloads specifically (which drift is), the
single-process `current_thread` runtime would only be the
right answer if hyper's h2 internals didn't depend on
concurrent task scheduling — which they do. monoio / glommio
embrace per-core-with-no-work-stealing because their h2
equivalents are co-designed for it.

### 7. Reduce peer-table lock contention

Drift's `drift/src/transport/` has 146 sites calling
`peers.lock_for(...)` or `peers.lock_all()`. The peer table is
already sharded (`PeerShards`), but under high concurrency
contention on individual shards is real.

Standard mitigations:
- **DashMap** — has deadlock pitfalls when guards held across
  `.await` ([reference](http://gnunicorn.org/writings/beware-of-the-dashmap-deadlock/)).
- **Per-task local cache** of `federation_table` — read-mostly
  data, refresh every N ms. Hot forwarding path goes from
  "acquire shard lock, read, release" to "atomic load."
- **RCU / arc-swap** for the directory tables — readers see a
  snapshot pointer; writers swap atomically.

Profile-first. Won't matter if items 1-4 close the gap.

## What's left after the 2026-05-20 round

Items 1-3, 5, 5b, 6, 8 all shipped. The K=17 bench on a 2-core /
512 MB LXC is now in the 73-82/96 band, with the 4-hop tail (50-
67% pass rate) bounded by **CPU scheduler contention across 17
concurrent bridge processes**, not by the federation protocol or
the h2 transport layer.

The remaining levers are diagnostic, not optimization:

1. **Profile a hot bridge under load** — `tokio-console` for task
   scheduling visibility, `perf record / flamegraph` for hot
   allocation sites and lock contention. If item 7's lock
   contention shows up in the top 3, do the arc-swap rewrite of
   `peer_directory`. If allocator pressure does, hunt the
   remaining allocation sites (the BytesMut arena from item 3
   was the obvious one).
2. **Bench on a host that isn't resource-starved** — the K=17
   topology on an 8-core / 8 GB box should hit ~100% pass rate;
   that experiment would confirm the "now CPU-bound" diagnosis
   and tell us whether there's anything left at the protocol
   layer.
3. **Real-world federation logs** — items 5 / 5b / 6 target
   reconnect cost, dead-link detection, and operator-tunability.
   Their value shows on flaky WAN federation, not on the corporate
   dial bench. Collect data from a deployment that actually
   experiences blips, then iterate.

Items 4, 9 (h2 frame coalescing, ECN/ECMP/fair-queue) are well-
understood but research-confirmed low-value-per-effort for DRIFT
specifically. Skip until a future bench exposes them as the
actual bottleneck.

## What I'd defer / not do (yet)

- **DashMap** without an audit — deadlock risk in async code.
- **monoio / glommio migration** — overkill for the project's
  scale, costs Windows / macOS as build targets.
- **Per-peer worker processes** — operational complexity not
  justified by current scale, and doesn't address the per-bridge
  HTTP/2 window throughput issue anyway.
- **`recvmmsg` UDP batching** — irrelevant to federation
  (h2/h2s/webtransport), would only help client-to-bridge UDP.
  Useful eventually for that path, but not the current
  bottleneck.

## Sources

- [hyper Builder docs (HTTP/2)](https://docs.rs/hyper/latest/hyper/server/conn/http2/struct.Builder.html) — official knobs
- [Realm relay's Linux optimizations](https://deepwiki.com/zhboner/realm/4.1-linux-optimizations) — UDP-specific but the design pattern (zero-copy, batching at the kernel boundary) is informative
- [Matrix Synapse federation workers](https://docs.element.io/latest/element-server-suite-classic/advanced-configuration/synapse-section-workers/) — process-per-role architecture
- [Apache Iggy's thread-per-core migration](https://iggy.apache.org/blogs/2026/02/27/thread-per-core-io_uring/) — io_uring migration writeup
- [Beware of the DashMap deadlock](http://gnunicorn.org/writings/beware-of-the-dashmap-deadlock/) — caution flag if going down that path
- [tokio-rs/tokio-uring](https://github.com/tokio-rs/tokio-uring) — tokio + io_uring runtime, if that route ever becomes attractive

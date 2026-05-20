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

| Rank | Optimization | Effort | Expected impact at K=17 |
| ---- | ------------ | ------ | ----------------------- |
| 1 | **Tune hyper HTTP/2 flow control**: `adaptive_window(true)`, bump `initial_stream_window_size` and `initial_connection_window_size` to 2-4 MiB | 1 hour | **Likely the single biggest fix**. Default 64 KB window means every 64 KB of relayed traffic stalls for a WINDOW_UPDATE round-trip. 4-hop chain hits ≥ 4 of these. Tail latency degradation matches the symptom exactly. |
| 2 | Bump `SEND_QUEUE_DEPTH` / `RECV_QUEUE_DEPTH` from 256 → 4096 | 1 line each | Reduces back-pressure stalls under burst. Cheap. |
| 3 | Buffer pool for outgoing `BytesMut` framing | half a day | Eliminates per-packet allocator pressure on the send path. |
| 4 | Coalesce multiple drift packets into a single h2 DATA frame on the send side | 1-2 days | Reduces h2 frame header overhead (9 bytes per frame) and rustls per-encryption setup cost. Receiver already handles arbitrary chunking (length-prefix splitter is independent of frame boundaries). |
| 5 | TLS session resumption (rustls session ticket cache) | 1 day | First TLS handshake is expensive; reconnects today do full handshakes. Session resumption is one round-trip. |
| 6 | Explicit tokio runtime config (cap worker_threads on small hosts) | 1 hour | On 2-core hosts running 17 bridges, default tokio multi_thread creates 34 worker threads competing — pure scheduler churn. |
| 7 | Reduce peer-table lock contention (146 lock sites in `transport/`) | medium-large | Real if profiling shows it, but second-order vs items 1-4. |

The first three are all small, contained changes. Items 4-7 are
larger but well-understood. None requires architectural changes
to the federation protocol.

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

### 5. TLS session resumption (h2s only)

rustls supports TLS 1.3 session resumption via session tickets
or PSK. With it, a reconnecting peer can skip the certificate /
key-exchange round-trip and resume in 1-RTT.

For drift, federation sessions are long-lived (no reason to
reconnect under normal operation), so this is only relevant for
recovery after a TCP teardown. But under K=17 load with
occasional sessions getting reset (e.g. by `recv_from failed;
evicting interface` we saw in the corporate test logs), faster
reconnect = less window during which a federation peer is
unreachable.

`rustls::ServerConfig` has `session_storage`; `rustls::ClientConfig`
has `resumption`. Both off by default in drift currently.

### 6. Explicit tokio runtime configuration

Today `drift/src/main.rs::main` uses `#[tokio::main]` with the
default `multi_thread` runtime. That spawns one worker per CPU.
On a 2-core host running 17 bridge processes, that's 34 worker
threads competing — pure scheduler churn.

Fix: in `main.rs`, replace `#[tokio::main]` with an explicit
builder:

```rust
fn main() -> anyhow::Result<()> {
    let workers = std::env::var("DRIFT_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| num_cpus::get().clamp(1, 4));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("drift-rt")
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}
```

The `clamp(1, 4)` cap matters on small hosts. On a 2-core host
where we want to run many bridges, capping at 2 workers per
bridge process gives each process 2 threads × 17 processes = 34
threads, same as default. Capping at 1 gives 17 — better. The
ideal is environment-specific.

For relay-shaped workloads specifically (which drift is), the
`current_thread` runtime is often the right answer — eliminates
work-stealing overhead entirely, at the cost of no
intra-process parallelism. monoio / glommio embrace this.

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

## What I'd do this week

1. **Tune hyper HTTP/2 flow control** (item 1) — 1 hour. Bump
   initial windows + enable adaptive. Single biggest expected
   win.
2. **Bump channel depths to 4096** (item 2) — 1 line.
3. **Re-run corporate federation test**. Bet: 81/96 → 95%+ with
   just items 1+2. If yes, ship those changes and move on.
4. If still tail-degrades: profile with `tokio-console` and
   `perf record / flamegraph` on a hot bridge to see whether
   the remaining bottleneck is allocation churn, lock contention,
   or rustls cost. Then pick item 3, 5, or 7 accordingly.

Items 5-7 should wait on data from item 1+2 before committing.
Premature optimization without measurement is how protocols
become Frankenstein.

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

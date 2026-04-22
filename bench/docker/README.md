# Docker comparison harness

Run the same handshake / RTT / throughput workload against
DRIFT, QUIC (quinn), and WireGuard (boringtun) across two
networked containers.

Not a substitute for cloud-VM / WAN testing — you're still on
one host, through a Docker bridge + veth pair. But it does
cross real network namespaces, real kernel routing, and lets
you shape the link with netem for loss/latency.

## Quick start

```bash
cd bench/docker
./run.sh
```

First run builds the `drift-bench:latest` image from the
workspace (~5 min). Subsequent runs reuse it.

Output is a Markdown table summarising each workload and raw
JSON lines in `results/<timestamp>.json` if you want to chart.

## Knobs

```bash
PAYLOAD_BYTES=256 RTT_ITERS=500 DURATION_SECS=5 ./run.sh
```

- `PAYLOAD_BYTES` (default 1024): per-packet size for RTT +
  throughput. Must stay under DRIFT's MAX_PAYLOAD of 1348 B.
- `RTT_ITERS` (default 1000): ping-pong samples.
- `DURATION_SECS` (default 10): throughput test length.

## Network shaping

Add latency or loss with netem:

```bash
NETEM_DELAY=20ms NETEM_LOSS=1% ./run.sh
```

`run.sh` injects `tc qdisc netem` on the server container's
`eth0` before each workload. Requires `NET_ADMIN` cap, which
`docker-compose.yml` already grants.

## What each number means

- **handshake** — `--workload handshake` times one cold
  connect plus one data-packet acked by the server. For DRIFT
  this is HELLO + HELLO_ACK + first DATA. For QUIC it's TLS
  1.3 + transport params + first bidi stream frame. For WG
  it's HandshakeInit + HandshakeResponse + first data frame.

- **rtt** — `--workload rtt` runs `RTT_ITERS` ping-pong
  iterations at `PAYLOAD_BYTES` size. The client sends,
  waits for the server's echo, records the elapsed time.
  Reported as min / p50 / p95 / p99 / max.

- **throughput** — `--workload throughput` sends a single
  packet stream at `PAYLOAD_BYTES` size for `DURATION_SECS`,
  with no reads in the loop. Measures raw encode + send + kernel
  drain rate. QUIC uses DATAGRAM frames (unreliable, same
  shape as DRIFT/WG) rather than streams — stream throughput
  is a different benchmark.

## Known limits

- Docker bridge on one host is faster and less jittery than
  any real NIC. Absolute numbers are upper bounds.
- No CPU pinning — noisy neighbors on your workstation will
  move the mean around. Close browsers + IDE indexing before
  serious runs.
- The server containers exit after each workload and are
  rebuilt. Cold-start overhead per run is ~1 s — that's
  outside the timed region, but it keeps the total bench
  time to a few minutes.

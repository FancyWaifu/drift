# DRIFT-over-Iroh docker testbed

Three drift-bench containers + one orchestrator, all on a single
docker bridge network. Tests the `iroh://` wire adapter between
container pairs. The orchestrator and node containers share the
same image (`drift-bench-iroh:latest`) so any container can
launch a server or client.

## Build + run

```bash
# 1. Cross-build drift-bench with iroh feature for musl
(cd ../.. && cross build -p drift-bench --target x86_64-unknown-linux-musl --release)

# 2. Stage the binary in this directory (the Dockerfile COPYs from here)
cp ../../target/x86_64-unknown-linux-musl/release/drift-bench ./drift-bench

# 3. Run the bench
bash run.sh
```

The script:
- Builds the image (debian:bookworm-slim + musl binary, ~80 MB)
- Brings up 4 containers on `drift-iroh-driftnet` (172.30.0.0/24)
- Iterates 3 (server, client) pairs × 3 workloads × N trials
- Scrapes iroh endpoint id from server stderr, hands it to the client
- Writes results to `/tmp/drift-iroh-docker-<ts>.tsv`

Tear down with `docker compose down`.

## Findings

**Handshake works reliably** — 1231–1493 µs p50 across all
3 container pairs, all trials. Tail (~22 ms p99) is higher
than LXC, suggesting Mac Docker Desktop scheduler jitter, but
the protocol succeeds.

**RTT and throughput are throttled by Mac Docker Desktop's
UDP performance**, not the iroh adapter:

- Same problem reproduces with plain `udp://` (not iroh): client
  pumps 1 GB, server receives ~86 KB. ~99.99% data drop.
- The Docker Desktop LinuxKit VM's bridge networking has known
  UDP throughput issues on macOS hosts.
- LXC↔LXC (real Linux veth) shows DRIFT-over-iroh hits
  1432 Mbps with no such loss.

The point of the docker test stands: **DRIFT-over-iroh
successfully establishes connections and exchanges packets
between multiple containers**. Quantitative throughput numbers
should be taken from the LXC bench (real Linux veth) or
loopback (same Mac, no docker VM hop), not from docker.

## Caveats

- Mac Docker Desktop's network stack adds a LinuxKit VM hop
  that throttles UDP-based protocols (DRIFT-UDP, QUIC, iroh).
  Use Linux Docker for accurate throughput numbers.
- Docker container → external LAN (e.g., to a Proxmox LXC) is
  blocked by default Mac Docker Desktop bridge isolation. A
  cross-environment docker↔LXC test requires either Linux
  Docker or explicit port mapping.
- The bench's outer 60s timeout means workloads that get
  stuck on slow QUIC handshake hit the wall and produce
  empty RTT/throughput rows. Increase `--server-idle-secs`
  to extend the bench's outer timeout.

# drift-vpn

**An identity-based VPN that doesn't care what your network blocks.**

drift-vpn looks like WireGuard from the outside — TOML config, peers identified by an X25519 pubkey, `allowed_ips`-style routing — but the wire underneath is [DRIFT](../), and that gives it features WireGuard structurally cannot have:

- **Multi-transport.** UDP, TCP, TLS, WebSocket, HTTP, and Tor onion services in the same daemon.
- **Cross-scheme runtime failover.** UDP gets blocked mid-session? The tunnel migrates to TCP without dropping. WireGuard can't do this.
- **Hub-and-spoke mesh routing.** Spokes that can't accept incoming connections (mobile, behind NAT) reach each other via a hub. No manual routing-table config.
- **Operations built in.** `drift-vpn status` for one-shot ops, `/metrics` HTTP endpoint for Prometheus scrape.

If you already have a working WireGuard deployment, you don't need this. If your network is *hostile* — corporate firewall, censored country, asymmetric NAT, mobile clients behind carrier-grade NAT — drift-vpn is what works when WireGuard doesn't.

## Status: v0.10, production-ready for "tinker and homelab"

15 versions of features, validated on real Linux LXCs:

| Version | What shipped |
|---|---|
| v0.1 | basic two-node tunnel |
| v0.2 | server-side multi-listen (one daemon, many wire schemes) |
| v0.3 | happy-eyeballs across endpoints, race fixes, hardening pass |
| v0.4 | runtime auto-failover during a live session |
| v0.5 | **cross-scheme failover** (UDP → TCP/TLS/WS/HTTP/Onion) |
| v0.6 | production hardening: per-peer metrics, status subcommand, app-aware QoS |
| v0.7 | sendmmsg batching + opportunistic batcher in tun→drift loop |
| v0.8 | mesh-only peers (hub-and-spoke without manual routes) |
| v0.9 | Prometheus `/metrics` HTTP endpoint |
| v0.10 | real-Linux verification + mesh-routed-DATA hop_ttl bug fix |

What's NOT yet there:

- **macOS / Windows clients.** The daemon code is Linux-only via `#![cfg(target_os = "linux")]`. The `tun` crate supports utun and Wintun; the gate is what we haven't lifted yet.
- **No coordination service.** Peers find each other via static config — no Tailscale-style coordinator.
- **No NAT hole-punching.** Both sides need a reachable endpoint somewhere in their `endpoints` list.
- **No identity rotation.** "Lost laptop" story is the same as WireGuard's: update every peer's config.
- **Userspace, not kernel.** ~1.5 Gbps single-stream TCP on a Ryzen 7 6800H — fine for almost any workload, but ~5× slower than WireGuard's Linux kernel module.

## How it differs from WireGuard

| | **WireGuard** | **drift-vpn** |
|---|---|---|
| Crypto | Curve25519 + ChaCha20-Poly1305 | X25519 + ChaCha20-Poly1305 |
| Setup | Static peer config + `AllowedIPs` | Same |
| Wire | **UDP only** | UDP, TCP, TLS, WS, HTTP, Onion |
| If UDP gets blocked | Tunnel dies | **Live migration to TCP/TLS, session preserved** |
| Mesh (no direct path) | Manual routing tables | **Native, beacon-driven** |
| Health monitoring | None | Per-peer SRTT, last-seen, failover counters |
| Operator UI | `wg show` | `drift-vpn status` + Prometheus `/metrics` |
| Throughput (1-stream Linux) | ~5–10 Gbps (kernel) | ~1.5 Gbps (userspace) |
| Platforms | Linux/Windows kernel; userspace on Mac/iOS/Android | Linux-only daemon today |
| Maturity | Years of audits + production use | New project, 14-test suite |

**One-line summary**: WireGuard works great until your network blocks UDP. drift-vpn doesn't care what your network blocks — it switches protocols mid-session.

## Quick start (5 minutes, two Linux hosts)

Install Rust (any recent stable), then:

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo build --release -p drift-vpn
sudo cp target/release/drift-vpn /usr/local/bin/
```

On each host:

```bash
sudo mkdir -p /etc/drift-vpn
sudo drift-vpn keygen -o /etc/drift-vpn/identity.key
# prints the public key hex — share with your peer
```

**Host A** (`/etc/drift-vpn/config.toml`):

```toml
[interface]
identity_file = "/etc/drift-vpn/identity.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340

[[peer]]
public_key  = "<host-B's pubkey hex>"
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://<host-B's IP>:51820"
```

**Host B** (mirror image):

```toml
[interface]
identity_file = "/etc/drift-vpn/identity.key"
address       = "10.99.0.2/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340

[[peer]]
public_key  = "<host-A's pubkey hex>"
allowed_ips = ["10.99.0.1/32"]
endpoint    = "udp://<host-A's IP>:51820"
```

Run:

```bash
sudo drift-vpn up -c /etc/drift-vpn/config.toml
```

Verify from host A:

```bash
ping 10.99.0.2
drift-vpn status
```

That's it. Same five-minute path as WireGuard.

## Configuration reference

### `[interface]`

| Field | Required | Default | What it does |
|---|---|---|---|
| `identity_file` | yes | — | Path to the X25519 secret (`drift-vpn keygen` output) |
| `address` | yes | — | Tun device address as CIDR (e.g., `10.99.0.1/24`) |
| `listen` | yes | — | DRIFT URL or array of URLs to bind. One daemon binds all of them. Examples: `"udp://0.0.0.0:51820"` or `["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]` |
| `mtu` | no | 1340 | Tun MTU. 1340 leaves room under DRIFT's 1348-byte payload limit. |
| `name` | no | kernel-assigned | Tun device name (`tun0`, `tun1`, …). |
| `prom_listen` | no | disabled | `host:port` to serve Prometheus `/metrics`. |

### `[failover]`

Per-daemon failover policy, applied to every peer with two or more endpoints. Optional — defaults work for "WAN that mostly works."

| Field | Default | What it does |
|---|---|---|
| `enabled` | true | Master switch. |
| `check_interval_ms` | 2000 | How often the supervisor checks peer health. |
| `stale_secs` | 10 | Peer is unhealthy if no AEAD-valid traffic in this window. |
| `hold_secs` | 30 | Hysteresis: don't switch again for this long after a commit. |
| `rtt_multiplier` | 0 (off) | Switch when SRTT > `multiplier × baseline` for several samples. |

### `[[peer]]`

| Field | Required | What it does |
|---|---|---|
| `public_key` | yes | 64 hex chars = 32-byte X25519 pubkey. |
| `allowed_ips` | yes | CIDR ranges this peer "owns" — outbound IPs in these ranges route to this peer. Reverse-path filtering enforces the same on inbound. |
| `endpoint` | no | Single-URL form (`"udp://1.2.3.4:51820"`). |
| `endpoints` | no | Priority-ordered list. UDP first, fall through to TCP / TLS / WS / HTTP / Onion. Empty = mesh-only peer. |
| `keepalive` | no | Periodic NAT-keepalive interval in seconds. |

A peer with no `endpoint`/`endpoints` is a **mesh-only peer**: reachable only via forwarding through another peer that has a direct path. See "Hub-and-spoke" below.

## Deployment scenarios

### Point-to-point (laptop ↔ home VPN)

Simplest case. One peer per side, one endpoint, UDP. The 5-minute quickstart above is exactly this.

### Multi-transport fallback (hostile network)

Server has both UDP and TCP listeners. Client lists both endpoints; UDP first.

**Server**:
```toml
[interface]
listen = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:443"]
```

**Client**:
```toml
[[peer]]
public_key  = "..."
allowed_ips = ["10.99.0.0/24"]
endpoints   = [
  "udp://server.example.com:51820",
  "tcp://server.example.com:443",
]
```

If the client's network blocks UDP at any time — corporate firewall, hotel Wi-Fi, captive portal — drift-vpn's runtime supervisor probes the TCP endpoint, commits the migration, **and the session keeps running**. No reconnect, no app-visible disruption.

### Hub-and-spoke (mobile clients behind NAT)

A central hub has direct paths to both spokes; spokes can't reach each other directly but can reach each other through the hub. WireGuard requires manual `iptables` + routing-table config for this; drift-vpn does it natively.

**Hub** (`drift-hub`):
```toml
[interface]
address = "10.99.0.2/24"
listen  = "udp://0.0.0.0:51820"

[[peer]]  # spoke A
public_key  = "..."
allowed_ips = ["10.99.0.1/32"]
endpoint    = "udp://<spoke-A-public-IP>:51820"

[[peer]]  # spoke C
public_key  = "..."
allowed_ips = ["10.99.0.3/32"]
endpoint    = "udp://<spoke-C-public-IP>:51820"
```

**Spoke A**:
```toml
[[peer]]  # hub: direct
public_key  = "<hub-pubkey>"
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://hub.example.com:51820"

[[peer]]  # spoke C: mesh-only — reach via hub
public_key  = "<spoke-C-pubkey>"
allowed_ips = ["10.99.0.3/32"]
# no endpoint — daemon learns the route from hub's beacons
```

**Spoke C**: mirror of Spoke A.

A pings 10.99.0.3 → packet routes to peer C → since C is via_mesh, daemon sends to hub's address with `hop_ttl=8` → hub forwards to C → C responds, packet returns the same way. Zero manual routing.

## Operations

### `drift-vpn status`

Live picture of the daemon's peer table:

```
$ drift-vpn status
local: peer=2676b1d3441c3828 iface=tun0 addr=10.99.0.1/24 uptime=600s
  pubkey: 9e404d432a8ec40cff1f8494f5eebe50582f4701c8ef3463ac2bc8f2cbe3ea72

peers: 2
  9f76ea7164c11021  192.168.50.168:51820  state=established srtt=0.3ms stale=0s
    allowed_ips=["10.99.0.2/32"]  tx=85234 rx=12053
  21b17698b78592e1  192.168.50.168:51820  state=established srtt=0.5ms stale=0s
    allowed_ips=["10.99.0.3/32"]  tx=124  rx=98

counters:
  tun:      writes=12053  bytes=14_362_541  errs=0
  egress:   sent=85234    errs=0  no-route=4
  rpfilter: config-mismatch=0  unknown-peer=0  parse-fail=0
  failover: total=0  udp=0  tcp=0  other=0  restart=0  hold-skipped=0
```

Pass `--json` for machine-readable output.

Note for the second peer above: `192.168.50.168` is the *hub's* IP — that's what mesh-only peers display as their `peer.addr`. The next-hop, not the destination's real address.

### Prometheus

Set `prom_listen = "0.0.0.0:9091"` in `[interface]`. Then point Prometheus at the daemon:

```yaml
scrape_configs:
  - job_name: drift-vpn
    static_configs:
      - targets: [vpn-host:9091]
```

Exposed metrics (a sample — there are ~15):

```
drift_vpn_uptime_seconds 600
drift_vpn_tun_writes_total 12053
drift_vpn_egress_packets_total{outcome="ok"} 85234
drift_vpn_egress_packets_total{outcome="error"} 0
drift_vpn_egress_packets_total{outcome="no_route"} 4
drift_vpn_failover_commits_total{scheme="udp"} 0
drift_vpn_failover_commits_total{scheme="tcp"} 0
drift_vpn_failover_commits_total{scheme="other"} 0
drift_vpn_peer_established{peer="9f76ea7164c11021"} 1
drift_vpn_peer_srtt_seconds{peer="9f76ea7164c11021"} 0.000300
drift_vpn_peer_seconds_since_last_seen{peer="9f76ea7164c11021"} 0
```

Counter names follow Prometheus conventions (`_total` suffix, snake_case labels). Drop-in scrapeable, queries like `rate(drift_vpn_egress_packets_total{outcome="ok"}[5m])` or `topk(10, drift_vpn_peer_srtt_seconds)` work naturally.

## Performance

Numbers from the v0.10 real-Linux validation — Proxmox LXCs on Ryzen 7 6800H, 2 vCPU per LXC, 1500-byte packets:

| | Result |
|---|---|
| Host-to-host LXC bridge (no tunnel — the ceiling) | 28 Gbps |
| Through drift-vpn UDP tunnel | 1.0 Gbps lossless |
| Through drift-vpn TCP tunnel, single stream | 1.5 Gbps |
| WireGuard kernel on similar hardware | ~5–10 Gbps |

The userspace ceiling is the AEAD-per-task throughput in tokio. We attempted io_uring (regression — channel hops cost more than syscalls saved) and a single-task variant (regression — lost tokio's multi-task parallelism) in v0.11 prep work. The v0.7 two-task model is correctly tuned for tokio.

For ~95% of real workloads (interactive use, video calls, file sync, dev environments), 1.5 Gbps is more than enough. For datacenter-scale traffic, use WireGuard kernel.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  drift-vpn daemon                       │
│                                                         │
│  ┌───────────┐   ┌─────────┐    ┌──────────────────┐    │
│  │ tun_r     │──►│ batched │───►│  drift Transport │    │
│  │ tun reader│   │ sender  │    │  (UDP/TCP/TLS/   │    │
│  └───────────┘   └─────────┘    │   WS/HTTP/Onion) │    │
│                                  └────────┬─────────┘    │
│  ┌───────────┐   ┌─────────┐              │             │
│  │ tun_w     │◄──│ recv    │◄─────────────┘             │
│  │ tun writer│   │ + rpf   │                            │
│  └───────────┘   └─────────┘                            │
│                                                         │
│  Background tasks:                                      │
│  ── failover supervisor (per multi-endpoint peer)       │
│  ── mesh-peer warmup retrier                            │
│  ── status server (Unix socket)                         │
│  ── Prometheus HTTP server (optional)                   │
└─────────────────────────────────────────────────────────┘
```

The DRIFT transport handles handshake, AEAD, mesh routing, beacons, ping/pong RTT measurement, path probing, rekey. drift-vpn handles tun ↔ DRIFT bridging, L3 routing (which peer for which IP), reverse-path filtering, runtime failover.

Code:

```
drift-vpn/src/
├── main.rs       # CLI: up, keygen, show, status
├── config.rs     # TOML schema + loader
├── identity.rs   # hex-keyfile load + keygen
├── routing.rs    # IP-packet parsing + AllowedIPs lookup + L4 QoS classifier
├── metrics.rs    # atomic counters (DaemonMetrics)
├── status.rs     # status socket server + Prometheus exporter
├── tun_uring.rs  # (Linux only) io_uring side-thread for tun I/O
└── daemon.rs     # the rest: TUN ↔ DRIFT, supervisor, mesh warmup
```

## Build from source

Linux:

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo build --release -p drift-vpn
sudo cp target/release/drift-vpn /usr/local/bin/
```

The Linux daemon needs:
- `/dev/net/tun` accessible (kernel module loaded)
- `CAP_NET_ADMIN` capability (run as root, or use `setcap cap_net_admin+pe`)
- `ethtool` in `$PATH` for the offload-disable startup step (warns but continues if missing)

For containers (LXC, Docker), pass `--cap-add NET_ADMIN --device /dev/net/tun`. For Proxmox LXCs, append to the container's config:

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

macOS and Windows: build artifacts are not yet shipped. The underlying `tun` crate supports utun (macOS) and Wintun (Windows); the daemon's `#![cfg(target_os = "linux")]` gate is the only thing in the way. PRs welcome.

## Test suite

14 integration tests via `tests/run_all.sh`. Each runs in isolated Docker containers on its own subnet:

```bash
bash drift-vpn/tests/run_all.sh
```

Notable tests:
- `failover_basic.sh` — port-failover, asymmetric topology, graceful migration
- `failover_cross_scheme.sh` — UDP gets blocked entirely → tunnel migrates to TCP, session preserved
- `mesh_only.sh` — 3-node hub-and-spoke, A↔C ping via forwarding through B
- `lossy.sh` — `tc/netem 5%` loss + 20ms delay; tunnel survives, TCP slows but doesn't break
- `stability.sh` — 60s of continuous ping + parallel iperf3, no crashes / no `send_data dropped` warnings
- `spoof.sh` — reverse-path filter rejects an attacker peer with a forged source IP

## License

See [LICENSE](../LICENSE) at the repository root.

## See also

- [DRIFT](../) — the underlying transport. drift-vpn is a thin layer on top of `drift::Transport`.
- [drift-git](../drift-git) — git remote helper over DRIFT, sibling project.

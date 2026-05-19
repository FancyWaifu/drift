# drift-vpn

**An identity-based VPN that doesn't care what your network blocks.**

drift-vpn looks like WireGuard from the outside — TOML config, peers identified by an X25519 pubkey, `allowed_ips`-style routing — but the wire underneath is [DRIFT](../), and that gives it features WireGuard structurally cannot have:

- **Multi-transport.** UDP, TCP, TLS, WebSocket, HTTP, and Tor onion services in the same daemon.
- **Cross-scheme runtime failover.** UDP gets blocked mid-session? The tunnel migrates to TCP without dropping. WireGuard can't do this.
- **Hub-and-spoke mesh routing.** Spokes that can't accept incoming connections (mobile, behind NAT) reach each other via a hub. No manual routing-table config.
- **Operations built in.** `drift-vpn status` for one-shot ops, `/metrics` HTTP endpoint for Prometheus scrape.

If you already have a working WireGuard deployment, you don't need this. If your network is *hostile* — corporate firewall, censored country, asymmetric NAT, mobile clients behind carrier-grade NAT — drift-vpn is what works when WireGuard doesn't.

## Status: v0.14, production-ready for "tinker and homelab"

Validated on real Linux LXCs and macOS (Apple Silicon):

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
| v0.11 | perf experiments (io_uring side-thread, single-task collapse) — both regressed against the v0.7 two-task baseline and were reverted; v0.7 is the correctly-tuned model for tokio |
| v0.12 | **macOS daemon** (utun via the `tun` crate) + cross-platform release builds (Linux amd64/arm64, macOS arm64, Windows x86_64 keygen/show only). Intel macOS (`x86_64-apple-darwin`) was in earlier matrix plans but dropped for v0.14 after the macos-13 GitHub runner pool became unreliable; Intel-Mac users build from source. |
| v0.13 | **`drift-vpn doctor`** preflight (privilege, TUN, IP forwarding, identity, port, peers checks) + **`via_bridge` peer mode** (two peers behind unrelated NATs reach each other through a shared federation bridge — no port forwarding on either side, any drift adapter scheme: udp / tcp / tls / ws / …). Config-level error-out on MTU + via_bridge mismatch (the federation envelope eats 130 bytes of payload; tun MTU must be ≤ 1202). |
| v0.14 | **`drift-vpn install` / `uninstall`** — one-command service install (systemd unit on Linux, launchd plist on macOS), with `--dry-run` to preview, `--start` to boot it, `--no-enable` to skip autostart, and `--service-name` for multi-instance hosts. + **`drift-vpn rotate` / `rotate-verify`** — owner-driven identity rotation via signed XEdDSA announce; peers verify and paste the new pubkey instead of receiving it through a back-channel. + **QUICKSTART.md** + **ROTATION.md** docs. + **Windows build fix** (sendmmsg call site cfg-gated) so the five-platform release matrix actually builds. |
| v0.15 | **macOS utun fixes** — drift-vpn's TUN setup on macOS was missing two things: an explicit subnet route (`tun` crate's default destination on macOS is wrong, kernel had no route for the configured CIDR), and BSD address-family framing on tun reads/writes (macOS utun prepends 4-byte AF_INET/AF_INET6 headers; Linux doesn't). Both gated with `#[cfg(target_os = "macos")]`. End-to-end Mac↔LXC tunnel via router-bridge over public WAN IP: 12ms RTT, 0% loss. + **Federation peer discovery (Phases A–F)** at the transport layer — `via_bridge`/`target_bridge` are now optional; the on-ramp bridge resolves cross-federation routes via proactive `FederationDirectory v3/v4` announces, reactive `FindPeer` queries, and (opt-in) DP-noised bloom-filter pre-narrowing + Poisson-timed cover traffic. See [`FEDERATION_DISCOVERY.md`](../FEDERATION_DISCOVERY.md). |

What's NOT yet there:

- **Windows daemon.** `keygen` and `show` work on Windows today; the `up` daemon needs a Wintun port. WSL2 is the recommended Windows path until then.
- **No coordination service.** Peers find each other via static config — no Tailscale-style coordinator.
- **NAT hole-punching is via-bridge only.** v0.13 added `via_bridge` for peers behind unrelated NATs to find each other through a federation bridge. UDP-hole-punching (STUN-style direct path discovery) isn't yet implemented; if both sides have NATs that block inbound, all traffic flows through the bridge.
- **Lost-laptop identity rotation** still requires manual config edits on every peer (same as WireGuard/Tailscale today). **Owner-driven rotation** (you still have the old secret — routine key hygiene, hardware swap, planned roll) is automated as of v0.14 via `drift-vpn rotate` + `rotate-verify`; see [ROTATION.md](ROTATION.md).
- **Userspace, not kernel.** With UDP GSO/GRO (v0.15), single-stream TCP on Proxmox-LXC iperf3 reaches **1.96 Gbps vs WireGuard kernel's 1.85 Gbps** on the same fabric (+6% raw throughput, near-parity per-Gbps CPU). See `bench/drift-vpn-vs-wireguard.md`. Earlier builds were closer to ~1.3 Gbps.

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
| Throughput (1-stream LXC iperf3) | 1.85 Gbps (kernel) | **1.96 Gbps** (userspace, post-GSO/GRO) |
| Platforms | Linux/Windows kernel; userspace on Mac/iOS/Android | Linux + macOS daemon (Windows: keygen/show; daemon via WSL2) |
| Maturity | Years of audits + production use | New project, 16-test suite |

**One-line summary**: WireGuard works great until your network blocks UDP. drift-vpn doesn't care what your network blocks — it switches protocols mid-session.

## Quick start (5 minutes, two Linux hosts)

For a complete walkthrough that covers system-service install, preflight, and
verification, see **[QUICKSTART.md](QUICKSTART.md)**. The 5-minute path below
gets a tunnel up in the foreground.

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
| `via_bridge` | no | DRIFT federation bridge URL + pubkey to reach this peer through. Format: `"<scheme>://host:port@<bridge-pubkey-hex>"` — any scheme drift's adapter registry knows about (udp, tcp, tls, ws, http, …). UDP reuses the daemon's primary listen socket; connection-oriented schemes get a dedicated outbound interface. The bridge must actually be listening on the chosen scheme. Both ends can set the *same* bridge to reach each other without direct endpoints. See "Bridge-fallback" below. |
| `target_bridge` | no | Pubkey hex of the federation bridge the *peer* is connected to. Defaults to the pubkey in `via_bridge` (the "both peers share one bridge" case). Set explicitly when the peer's on-ramp differs from yours in a multi-bridge federated mesh. With federation discovery (Phase A+) you can omit this — the on-ramp bridge resolves the peer's current location via `FindPeer` / proactive `FederationDirectory` cache. |
| `keepalive` | no | Periodic NAT-keepalive interval in seconds. |

A peer with no `endpoint`/`endpoints`/`via_bridge` is a **mesh-only peer**: reachable only via forwarding through another peer that has a direct path. See "Hub-and-spoke" below.

With **federation discovery** enabled (default in drift v0.15+) the peer's on-ramp bridge can be resolved automatically: a peer with just a `pubkey` and a `via_bridge` pointing at *any* bridge in your federation is reachable as long as some bridge in the federation hosts the peer. Cold-path lookups go through `FindPeer` (1-2 RTT, capped at 4 hops); steady-state lookups hit the bridge's `peer_directory` cache populated by proactive 7-second announcements. See `FEDERATION_DISCOVERY.md` at the workspace root.

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

### Bridge-fallback (two peers behind unrelated NATs)

Hub-and-spoke needs the hub to have a direct path to both spokes. If you have two spokes behind unrelated NATs and *neither* can accept inbound, hub-and-spoke doesn't help — there's no spoke to anoint as the hub.

**Bridge-fallback** flips the model: a third-party DRIFT bridge (run on anyone's hardware — a $5/month VPS, an always-on home router running `drift bridge`, a Raspberry Pi in someone's closet) sits in the public internet. Both spokes connect *outbound* to the bridge — no inbound port forwarding on either side — and reach each other through it via DRIFT's federation routing.

```
   Spoke A (behind NAT)  ──outbound──▶ DRIFT bridge ◀──outbound── Spoke C (behind NAT)
                            (public IP, drift bridge running)
```

**Spoke A**:
```toml
[interface]
address = "10.99.0.1/24"
listen  = "udp://0.0.0.0:51820"   # we still bind locally, but no one
                                  # needs to inbound-reach us
mtu     = 1200                    # leave room for federation header

[[peer]]  # spoke C, reached only through the bridge
public_key  = "<spoke-C-pubkey>"
allowed_ips = ["10.99.0.3/32"]
via_bridge  = "udp://bridge.example:51820@<bridge-pubkey-hex>"
# no endpoint — bridge is the only reach path
# target_bridge defaults to the bridge in via_bridge (correct when
# spoke C uses the same bridge — the common case)
```

**Spoke C**: mirror of A — same `via_bridge`, peer entry for spoke A.

**Bridge** (any DRIFT instance with `drift bridge --listen ... --accept-any-peer` running and inbound-reachable):
```sh
drift --identity bridge.key bridge --listen udp://0.0.0.0:51820
```

When A sends a packet for `10.99.0.3`:
1. drift-vpn's tun → drift sender sees the dst belongs to spoke C
2. Spoke C's peer is federated (`via_bridge` set), so the daemon wraps the IP packet in a DRIFT Federated envelope addressed to spoke C's pubkey + target_bridge
3. The envelope ships through the A↔bridge UDP session
4. The bridge unwraps, sees target_client = spoke C's pubkey, forwards through its B↔C session
5. Spoke C decrypts, hands the inner IP packet to its tun device
6. Reply takes the same path in reverse

**Why `mtu = 1200`?** The federation envelope adds 130 bytes inside DRIFT's `MAX_PAYLOAD` (1348). 1200 keeps full-MTU tun packets safely under the federated wire-payload cap. The daemon will refuse to send oversize packets with `PayloadTooLarge` if MTU is too aggressive — set 1200 for federated-only peers, leave 1340 if all peers are direct.

**A note on trust**: the bridge sees envelope metadata (who-talks-to-whom, sizes, timing) but never plaintext — the inner payload is AEAD-sealed between the two spokes. A malicious bridge can drop or delay traffic but can't read it. See `SPEC.md §10` and `drift/tests/adversarial_presence_tickets.rs` for the federation threat model.

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

Current numbers (v0.15 with UDP GSO/GRO) — Proxmox LXCs on Ryzen 7 6800H, iperf3 TCP, MTU 1200:

| | Throughput | System CPU |
|---|---|---|
| Host-to-host LXC veth (no tunnel — the ceiling) | ~28 Gbps | — |
| **drift-vpn UDP tunnel** | **1.96 Gbps** | 66% |
| WireGuard kernel, same fabric | 1.85 Gbps | 60% |

drift-vpn nudges ahead of WG kernel by +6% raw throughput at near-parity per-Gbps CPU (33.7% vs 32.4%). For a userspace Rust implementation vs kernel C with hand-tuned crypto, getting to per-Gbps parity is the meaningful result.

How we got there in v0.15:

- **UDP GSO sender** (`UDP_SEGMENT` cmsg) — one syscall + one skb segments to N MTU-sized packets at the NIC. Was the dominant cost pre-Phase 2.
- **UDP GRO receiver** (`UDP_GRO` sockopt + recvmsg cmsg parsing) — symmetric move; one recvmsg returns up to 64 KiB of coalesced packets.

Both are Linux-specific cfg-gated changes; macOS and Windows builds keep the existing paths. See [`bench/drift-vpn-vs-wireguard.md`](../bench/drift-vpn-vs-wireguard.md) for the full progression, what was tried and reverted, and what's left to chase next.

For >2 Gbps single-stream you currently still want WireGuard kernel or a multi-core deployment of drift-vpn (multi-core scaling via `SO_REUSEPORT` is a future direction, not yet implemented).

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
└── daemon.rs     # the rest: TUN ↔ DRIFT, supervisor, mesh warmup
```

## Install

### Pre-built binaries

Tagged releases (`drift-vpn-vX.Y.Z`) build a five-platform matrix and attach tarballs/zips to the GitHub release:

```bash
TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu,
                              # aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc
                              # Intel Mac: not pre-built in v0.14 — build from source
TAG=drift-vpn-v0.14.0
curl -L -o drift-vpn.tar.gz \
  https://github.com/FancyWaifu/drift/releases/download/$TAG/drift-vpn-$TAG-$TARGET.tar.gz
tar xzf drift-vpn.tar.gz
sudo mv drift-vpn-$TAG-$TARGET/drift-vpn /usr/local/bin/
```

### From source

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo build --release -p drift-vpn
sudo cp target/release/drift-vpn /usr/local/bin/
```

On **macOS** specifically, `cargo build` output has only an ad-hoc
codesign, and a plain `cp`/`install` strips the signature's xattr —
the kernel will then SIGKILL the binary on `sudo drift-vpn up` with
a bare `zsh: killed` and no log line. Use the included script
(builds, signs, installs, re-signs the installed copy, verifies):

```bash
./drift-vpn/scripts/install-mac.sh
```

CI-built release tarballs are properly signed (Apple Developer ID
+ notarized) and don't need this step. The script is for local
dev builds only.

### Platform notes

**Linux** — full daemon support. Needs:
- `/dev/net/tun` accessible (kernel module loaded)
- `CAP_NET_ADMIN` capability (run as root, or use `setcap cap_net_admin+pe`)
- `ethtool` in `$PATH` for the offload-disable startup step (warns but continues if missing)

For containers (LXC, Docker), pass `--cap-add NET_ADMIN --device /dev/net/tun`. For Proxmox LXCs, append to the container's config:

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

**macOS** — full daemon support via utun (Apple Silicon + Intel). Run with sudo so the kernel allocates a `utunN` device. Routes to peer addresses are not auto-installed by the `tun` crate on macOS — add them with `route -n add` after `up` if your config relies on them (Linux's `tun` install is automatic via the assigned netmask).

**Windows** — `keygen` and `show` work today. The `up` daemon is gated until a Wintun port lands. For Windows clients in the meantime, run drift-vpn inside WSL2.

### Run as a system service

Once the binary is on the host and `/etc/drift-vpn/config.toml` is in place, install drift-vpn as a managed service:

```bash
sudo drift-vpn install --start
```

This writes a **systemd unit** on Linux (`/etc/systemd/system/drift-vpn.service`) or a **launchd plist** on macOS (`/Library/LaunchDaemons/com.drift.vpn.plist`), reloads the service manager, enables it for boot, and starts it. The systemd unit is sandboxed (CAP_NET_ADMIN ambient, ProtectSystem=strict, PrivateTmp) and `Restart=on-failure` by default.

Useful flags:

- `--dry-run` — print the unit and the commands that would run, exit. No filesystem or systemctl/launchctl side effects. Good for previewing before committing.
- `--no-enable` — install but don't enable for boot.
- `--service-name <name>` — custom unit name. Default `drift-vpn` → `drift-vpn.service` on Linux, `com.drift.vpn.plist` on macOS.
- `--binary <path>` — point at a non-default binary location.
- `--config <path>` — point at a non-default config.

To remove:

```bash
sudo drift-vpn uninstall
```

Idempotent — safe to run a second time. Stops the service, disables it, removes the unit, reloads systemctl/launchctl. Does not touch your config or identity files.

## Test suite

16 integration tests via `tests/run_all.sh`. Each runs in isolated Docker containers on its own subnet:

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

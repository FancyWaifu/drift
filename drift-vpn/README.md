# drift-vpn

Identity-routed VPN built on DRIFT. WireGuard-shaped config, but the wire is DRIFT — which means **multi-transport fallback is on the roadmap**: same daemon, same identity, can ride UDP / TCP / TLS / WS / HTTP / Tor depending on what your network allows.

## Status: v0.1 (Linux, single-transport)

What works today:
- Linux TUN device, configurable address + MTU + interface name
- Single-transport (`udp://`) per peer
- `allowed_ips` routing (forward + reverse-path validation)
- WireGuard-shaped TOML config
- Two-node Docker test (`tests/two_node.sh`) verified pinging works

What's planned:
- v0.2 — Multi-transport `endpoints = [...]` lists with happy-eyeballs client and runtime fallover (this is the actual differentiator vs WireGuard / Tailscale)
- v0.3 — macOS + Windows TUN support
- v0.4 — Mesh peers (peers reachable via another peer, no direct endpoint)

## Quick start (two-node Docker test)

```bash
bash drift-vpn/tests/two_node.sh
```

Output ends with:
```
PASS: a → b ping works
PASS: b → a ping works
RESULT: drift-vpn two-node tunnel works — packets cross between containers via DRIFT
```

## Manual setup

### 1. Generate identities

```
drift-vpn keygen -o /etc/drift-vpn/identity.key
# prints the public key hex; share with your peer.
```

### 2. Write a config

`/etc/drift-vpn/config.toml`:

```toml
[interface]
identity_file = "/etc/drift-vpn/identity.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1380
name          = "tun0"

[[peer]]
public_key  = "abcdef012345...64-hex-chars..."
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://198.51.100.7:51820"
```

### 3. Bring it up

```
sudo drift-vpn up -c /etc/drift-vpn/config.toml
```

(Requires `CAP_NET_ADMIN` for the TUN device. systemd unit + sandboxed cap drop will land in v0.2.)

## How it differs from WireGuard

| | WireGuard | drift-vpn |
|---|---|---|
| Identity | X25519 pubkey | X25519 pubkey (same crypto) |
| Wire | UDP only | `udp://` today; `tls://`, `http://`, `onion://` planned |
| Routing | `AllowedIPs` per peer | Same — direct port of the model |
| First-contact | Static peer config | Same |
| Roaming | Endpoint update on incoming packet | Same (via DRIFT path validation) |
| Mesh routing | None (point-to-point only) | Planned via DRIFT mesh layer |
| Kernel module | Yes (Linux WG kernel mod) | Userspace only |

The architectural choice DRIFT makes that WG doesn't: separate the identity layer from the transport layer. WireGuard hardcodes UDP as the transport. drift-vpn doesn't — the same identity can be reached over any DRIFT adapter, swappable at runtime.

## Limitations (v0.1, listed honestly)

- **Single-transport per peer.** The multi-transport fallback story is the *headline differentiator* but isn't shipped yet. v0.2.
- **Linux only.** macOS utun + Windows WinTun are mostly portage work, not protocol; v0.3.
- **Userspace.** Kernel WireGuard is ~10× faster on raw throughput. We won't beat that. The win for drift-vpn is connectivity through hostile networks, not raw throughput.
- **No coordination service.** Peers find each other via static config; no Tailscale-like coordinator. Per-peer config files work for ≤dozens of peers; a discovery layer would land alongside mesh peers (v0.4).
- **No NAT traversal.** Both sides need a reachable endpoint. STUN/ICE-style hole-punching is a future feature.
- **No identity rotation.** Lost-laptop story: you have to update every peer's config manually. (Same problem as WireGuard.)
- **DNS in `endpoint` resolves once at startup.** No re-resolve if the IP changes mid-session. Static IPs work; static IPs are also what most VPN deployments use.

## Test setup details

The two-node Docker test:

1. Builds a multi-stage image (rust:slim builder, debian:slim runtime).
2. Generates two identity keys.
3. Brings up two containers on a `172.30.0.0/24` bridge, each with a TUN device on `10.99.0.x`.
4. Each container connects to the other's wire address (172.30.0.10 ↔ 172.30.0.11).
5. Pings the other peer's TUN address.

Static IPs are used (rather than Docker's hostname-based DNS) because Docker's embedded DNS isn't reliably populated *before* both containers start — node-a may try to resolve node-b before node-b is registered, and there's no retry in v0.1. v0.2 will add lazy + retried endpoint resolution; for now static IPs sidestep the race.

## Code layout

```
drift-vpn/src/
├── main.rs       # CLI: `up`, `keygen`, `show`
├── config.rs     # TOML schema + loader
├── identity.rs   # hex-keyfile load + keygen
├── routing.rs    # IP-packet dst parsing + AllowedIPs lookup table
└── daemon.rs     # TUN ↔ DRIFT bidirectional bridge (Linux-only)
```

The Linux-only daemon is `cfg(target_os = "linux")`-gated so the bin still compiles on macOS for `keygen` / `show` (only `up` errors out).

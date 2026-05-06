# drift-vpn

Identity-routed VPN built on DRIFT. WireGuard-shaped config, but the wire is DRIFT — which means **multi-transport fallback is on the roadmap**: same daemon, same identity, can ride UDP / TCP / TLS / WS / HTTP / Tor depending on what your network allows.

## Status: v0.2 (Linux, multi-listen)

What works today:
- Linux TUN device, configurable address + MTU + interface name
- **Server-side multi-listen** (`listen = [...]` array): one daemon binds UDP + TCP + TLS + WS + HTTP simultaneously. Each client picks whichever wire works for their network.
- WireGuard-shaped TOML config (forward-compatible array forms for both `listen` and peer `endpoints`)
- `allowed_ips` routing (forward + reverse-path validation)
- Tests: `tests/two_node.sh` (basic UDP) + `tests/two_node_fallback.sh` (multi-listen UDP+TCP)

What's *not* yet shipped (be honest):
- **Client-side runtime endpoint fallover.** v0.2 accepts `endpoints = [...]` in config but uses `endpoints[0]` only. Cross-endpoint switching during a session needs DRIFT primitives (`restart_handshake`, per-endpoint outbound Transports) we haven't built yet.
- **Cross-scheme outbound from one Transport.** If your *listen* is UDP and your *peer endpoint* is TLS, the daemon uses UDP for outbound (matching the primary listener). Per-peer outbound interface pinning lands in v0.3.

What's planned:
- v0.3 — Real client-side happy-eyeballs + runtime fallover (THE differentiator vs WireGuard). Needs DRIFT API additions.
- v0.4 — macOS + Windows TUN support
- v0.5 — Mesh peers (peers reachable via another peer, no direct endpoint)

## Quick start (Docker tests)

```bash
# v0.1 simple: single-listen UDP, ping across the tunnel
bash drift-vpn/tests/two_node.sh

# v0.2 multi-listen: bind UDP + TCP simultaneously, ping still works
bash drift-vpn/tests/two_node_fallback.sh
```

Both end with PASS/RESULT lines. The v0.2 test exercises the multi-listen path; the TCP listener is idle but live, demonstrating that one daemon can offer multiple wires for clients with diverse network constraints.

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
# v0.2 array form — bind multiple wires at once. Single-string
# form ("udp://...") is back-compat with v0.1.
listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:51821"]
mtu           = 1380
name          = "tun0"

[[peer]]
public_key  = "abcdef012345...64-hex-chars..."
allowed_ips = ["10.99.0.2/32"]
# Single-string form (back-compat) — uses this exact endpoint.
endpoint    = "udp://198.51.100.7:51820"
# OR v0.2 array form. v0.2 only uses endpoints[0]; v0.3 will
# do real runtime fallover across the list. Either way the
# config is forward-compatible.
# endpoints = [
#   "udp://198.51.100.7:51820",
#   "tls://198.51.100.7:443",
#   "http://198.51.100.7:80",
# ]
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

## Limitations (v0.2, listed honestly)

- **Server-side multi-listen ships; client-side runtime fallover does not yet.** v0.2 accepts `endpoints = [...]` in config (forward-compatible) but only uses `endpoints[0]`. Real "try UDP, fall back to TLS" requires per-peer outbound Transport instances or DRIFT-side `restart_handshake` — both v0.3 work.
- **Linux only.** macOS utun + Windows WinTun are mostly portage; v0.4.
- **Userspace.** Kernel WireGuard is ~10× faster on raw throughput. We won't beat that. The win for drift-vpn is connectivity through hostile networks, not raw throughput.
- **No coordination service.** Peers find each other via static config; no Tailscale-like coordinator. Per-peer config files work for ≤dozens of peers; a discovery layer would land alongside mesh peers (v0.5).
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

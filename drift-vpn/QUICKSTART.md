# drift-vpn — Quickstart

You have two Linux or macOS hosts and you want them to talk over an encrypted
tunnel that survives UDP being blocked. This walks through the full path:
**install → keygen → config → preflight → service → verify**, in under ten
minutes.

The two hosts in this example are called **A** and **B**. A has WAN IP
`203.0.113.10`, B is behind NAT on a laptop. We'll give A `10.99.0.1` inside the
tunnel and B `10.99.0.2`.

---

## 1. Install the binary on both hosts

Pick the option that fits your environment. The binary is the same regardless;
the rest of this doc treats both hosts identically.

### Option A — pre-built release (Linux + macOS)

```bash
TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu /
                              # aarch64-unknown-linux-gnu
TAG=drift-vpn-v0.14.0
curl -L -o drift-vpn.tar.gz \
  https://github.com/FancyWaifu/drift/releases/download/$TAG/drift-vpn-$TAG-$TARGET.tar.gz
tar xzf drift-vpn.tar.gz
sudo mv drift-vpn-$TAG-$TARGET/drift-vpn /usr/local/bin/
drift-vpn --help
```

### Option B — from source

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo build --release -p drift-vpn
sudo cp target/release/drift-vpn /usr/local/bin/
```

You need a Rust toolchain (any stable, 1.75+) for source builds.

---

## 2. Generate an identity on each host

Each host needs an X25519 keypair. drift-vpn generates one in two lines:

```bash
sudo mkdir -p /etc/drift-vpn
sudo drift-vpn keygen -o /etc/drift-vpn/identity.key
# wrote secret to /etc/drift-vpn/identity.key
# 7cc5e208c1b2a89ed9fa7474efc8afe8f024299d812ce65d5a2dd5083e01055b
```

The hex string printed to stdout is the **public key**. Save it — you'll paste
it into the other host's config below. Run the same command on both hosts and
keep the two pubkeys handy.

You can re-print the pubkey from the secret file at any time:

```bash
sudo drift-vpn show -i /etc/drift-vpn/identity.key
```

---

## 3. Write the config on each host

`/etc/drift-vpn/config.toml` looks almost exactly like WireGuard. The layout
intentionally mirrors `[Interface]` / `[Peer]` so you can move config knowledge
across.

**Host A** (`/etc/drift-vpn/config.toml`):

```toml
[interface]
identity_file = "/etc/drift-vpn/identity.key"
address       = "10.99.0.1/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340

[[peer]]
public_key  = "<paste host B's pubkey here>"
allowed_ips = ["10.99.0.2/32"]
endpoint    = "udp://<host-B's WAN IP>:51820"
```

**Host B**:

```toml
[interface]
identity_file = "/etc/drift-vpn/identity.key"
address       = "10.99.0.2/24"
listen        = "udp://0.0.0.0:51820"
mtu           = 1340

[[peer]]
public_key  = "<paste host A's pubkey here>"
allowed_ips = ["10.99.0.1/32"]
endpoint    = "udp://203.0.113.10:51820"
```

If B is behind NAT (laptop, mobile, home network) and A has a public IP, **only
A needs an open inbound port** — B will reach A outbound, and DRIFT will keep
the path open via its built-in keepalives. This is the same model as
WireGuard's "client" vs "server" pattern.

---

## 4. Run preflight: `drift-vpn doctor`

Before bringing it up, ask drift-vpn to check the host. This is read-only — no
state changes, no socket binds longer than a probe.

```bash
sudo drift-vpn doctor
```

Sample output:

```
drift-vpn doctor
================
  OK   privilege          running as root (uid 0)
  OK   config             /etc/drift-vpn/config.toml parses cleanly (1 peer, listen on udp://0.0.0.0:51820)
  OK   tun device         /dev/net/tun is present
  INFO ip forwarding      net.ipv4.ip_forward=0 (forwarding OFF — spoke-only fine)
  OK   identity           /etc/drift-vpn/identity.key is a well-formed 32-byte X25519 key
  OK   listen ports       1 UDP port available: 0.0.0.0:51820
  OK   peers              1 peer configured (udp×1)
  OK   status socket      parent dir /run/drift-vpn exists

8 pass · 0 warn · 0 fail · 0 info

All checks clear. You're ready to `drift-vpn up`.
```

Fix any FAIL items before moving on. WARN items aren't blockers — they're worth
reading but won't stop `drift-vpn up` from working.

Common fixes:
- **FAIL config** — `drift-vpn config init` to scaffold one, or hand-write per
  the example above.
- **FAIL identity** — run `drift-vpn keygen` again.
- **FAIL tun device** on Linux — `sudo modprobe tun`.
- **FAIL listen ports** — something else is on UDP 51820. Change the port or
  stop the conflicting process (`sudo ss -ulnp | grep 51820`).

---

## 5. Install as a system service

You can run `drift-vpn up -c /etc/drift-vpn/config.toml` directly in the
foreground for ad-hoc testing — Ctrl-C stops it. For anything you want to
survive a reboot, install the service:

```bash
sudo drift-vpn install --start
```

Under the hood this writes a **systemd unit** on Linux or a **launchd plist**
on macOS, reloads the service manager, enables it for boot, and starts it.

If you want to preview what would happen first, add `--dry-run`:

```bash
sudo drift-vpn install --dry-run
```

Other useful flags:

- `--config <path>` — point at a different config (default
  `/etc/drift-vpn/config.toml`).
- `--binary <path>` — point at a different binary (default
  `/usr/local/bin/drift-vpn`).
- `--service-name <name>` — name the unit something other than `drift-vpn`,
  useful when running multiple drift-vpn instances on one host.
- `--no-enable` — install but don't enable for boot. (No autostart on reboot.)

Verify the service is running:

```bash
# Linux
sudo systemctl status drift-vpn
sudo journalctl -u drift-vpn -f      # follow logs

# macOS
sudo launchctl print system/com.drift.vpn
tail -f /var/log/drift-vpn.log
```

To remove it (idempotent; safe to run twice):

```bash
sudo drift-vpn uninstall
```

This stops the service, disables it, removes the unit, and reloads the service
manager. It does **not** remove your config or identity files — those are
yours.

---

## 6. Verify the tunnel

From either host:

```bash
# Reach the peer through the tunnel
ping 10.99.0.2    # from host A
ping 10.99.0.1    # from host B
```

If ping works, you're done. The tunnel is up.

For the operator view of the daemon's peer table:

```bash
sudo drift-vpn status
```

```
local: peer=2676b1d3441c3828 iface=tun0 addr=10.99.0.1/24 uptime=42s
  pubkey: 7cc5e208c1b2a89ed9fa7474efc8afe8f024299d812ce65d5a2dd5083e01055b

peers: 1
  e44cd181b23aa9ae  203.0.113.20:51820  state=established srtt=18.4ms stale=0s
    allowed_ips=["10.99.0.2/32"]  tx=42 rx=42

counters:
  tun:      writes=42  bytes=4368  errs=0
  egress:   sent=42    errs=0  no-route=0
  rpfilter: config-mismatch=0  unknown-peer=0  parse-fail=0
  failover: total=0  udp=0  tcp=0  other=0  restart=0  hold-skipped=0
```

`state=established` is the bit you want. If it's `state=pending` after a few
seconds, the handshake hasn't completed — most likely network reachability
(check firewall, double-check the pubkey and IP in the config).

---

## What's next

You have a working point-to-point tunnel. drift-vpn has three further deployment
patterns worth knowing about; each is one config-file change away:

### Multi-transport (hostile network)

Add a second `listen` on the server, a second `endpoints` entry on the client.
If UDP gets blocked, drift-vpn migrates the live session to TCP without
dropping packets.

```toml
# server
[interface]
listen = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:443"]
```

```toml
# client
[[peer]]
endpoints = [
  "udp://server.example.com:51820",
  "tcp://server.example.com:443",
]
```

### Hub-and-spoke (three or more hosts, only some directly reachable)

A hub has direct paths to two spokes; the spokes can't reach each other
directly but can route through the hub. WireGuard needs manual `iptables` for
this; drift-vpn does it natively via mesh beacons. Spoke C in the hub's config
gets an `endpoint` (the hub knows how to reach C); Spoke A's config lists C as
a peer **with no endpoint** — A's daemon learns the route from the hub's
beacons.

### Bridge-fallback (both peers behind unrelated NATs)

If neither side can accept inbound, point both at a third-party DRIFT bridge
(a $5 VPS, an always-on Raspberry Pi, a router running `drift bridge`). Both
spokes connect *outbound* to the bridge and reach each other through it.

```toml
[[peer]]
public_key  = "<peer pubkey>"
allowed_ips = ["10.99.0.2/32"]
via_bridge  = "udp://bridge.example.com:51820@<bridge-pubkey-hex>"
# no endpoint — bridge is the only path
```

### Pattern 4: bridge-fallback with federation discovery

You only need `via_bridge` pointing at *some* bridge in your
federation — not necessarily the one the peer is actually on.
With federation discovery enabled (the default in v0.15+),
the local bridge resolves the peer's actual location via
proactive `FederationDirectory` announcements and reactive
`FindPeer` queries:

```toml
[[peer]]
public_key  = "<peer pubkey>"
allowed_ips = ["10.99.0.2/32"]
via_bridge  = "udp://my-local-bridge.example:51820@<my-bridge-pubkey>"
# target_bridge is OMITTED — the local bridge figures out which
# federated bridge actually hosts the peer
```

Useful when you have a multi-bridge federation and don't want
to bake the peer's specific on-ramp into every spoke's config.
For the privacy implications + opt-in `FindPeerMode` knobs
(hashed-target lookups, `NoForward` mode, DP-bloom announces),
see [`FEDERATION_DISCOVERY.md`](../FEDERATION_DISCOVERY.md) at
the workspace root.

Both of these patterns are documented in detail in the main
[README.md](README.md).

---

## Troubleshooting

**"Permission denied" on the identity file**

```
Error: failed to read /etc/drift-vpn/identity.key
```

Run with `sudo`. The identity file is mode 0600 root-only — that's by design.

**Daemon starts but no ping**

Run `sudo drift-vpn status` on both hosts. If state is `pending` on one side:
the handshake hasn't completed. Most common causes:
1. **Wrong pubkey** — copy/paste error. The two pubkeys must match exactly.
2. **Firewall** — UDP 51820 is blocked. Try `sudo ss -ulnp | grep 51820` to
   confirm the daemon is listening, and `nc -u <peer-ip> 51820` to test
   reachability.
3. **NAT** — peer behind NAT can't reach itself by WAN IP. If both peers are
   behind NAT, use bridge-fallback (above).

**"TCP throughput may be degraded" warning**

```
WARN drift_vpn::daemon: couldn't run ethtool (offload not disabled)
```

Install `ethtool` (`apt install ethtool` / `brew install ethtool`). This is a
performance warning, not a correctness issue — the tunnel still works, but
TCP-through-tunnel throughput is lower without offload disabled on the TUN
device.

**`systemctl status drift-vpn` says "failed"**

Check the journal:

```bash
sudo journalctl -u drift-vpn -n 100 --no-pager
```

Common causes: config parse error (line number is in the log), missing identity
file, port already in use. The error message points at the fix.

**Wanted: a hands-on reference for any of the above scenarios**

The test suite in `drift-vpn/tests/` runs each pattern end-to-end in Docker —
read those shell scripts as living examples. Notable:

- `tests/two_node.sh` — the basic point-to-point above
- `tests/failover_cross_scheme.sh` — UDP → TCP migration
- `tests/mesh_only.sh` — 3-node hub-and-spoke
- `tests/two_node_fallback.sh` — bridge-fallback with via_bridge

---

## Summary cheatsheet

```bash
# Install once
curl -L .../drift-vpn-vX.Y.Z.tar.gz | sudo tar xz -C /usr/local/bin/

# Bootstrap on each host
sudo mkdir -p /etc/drift-vpn
sudo drift-vpn keygen -o /etc/drift-vpn/identity.key   # prints pubkey
$EDITOR /etc/drift-vpn/config.toml                     # paste pubkeys, addrs
sudo drift-vpn doctor                                  # preflight
sudo drift-vpn install --start                         # service-managed

# Operate
sudo drift-vpn status         # peer state, RTT, counters
sudo systemctl status drift-vpn
sudo journalctl -u drift-vpn -f

# Decommission
sudo drift-vpn uninstall      # idempotent
```

That's the whole workflow. For deeper config, scenarios, and operations —
including Prometheus, failover policy, and mesh topology — see the main
[README.md](README.md).

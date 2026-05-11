# drift-config

**Identity + inventory manager for DRIFT deployments.**

One declarative `drift.toml` describes your DRIFT network — who's
in it, what their pubkeys are, where they're reachable. Every
DRIFT tool (`drift bridge`, `drift-vpn`, `drift-mosh`,
`drift-http`, …) reads from the same file. No more cross-filling
pubkeys by hand.

```bash
# Generate this device's identity + endpoints, register in drift.toml
drift-config keygen drift1 \
  --endpoint udp://0.0.0.0:51820 \
  --endpoint tcp://0.0.0.0:443

# Run this device as a multi-transport DRIFT bridge
drift bridge

# Or use the inventory to generate a full VPN deployment
drift-vpn config init --cidr 10.99.0.0/24
drift-vpn config assign drift1 --tun 10.99.0.1 --role hub
drift-vpn config gen
```

That's it. drift-config owns the inventory; other DRIFT tools
read it.

---

## A note on names — the only thing you actually name is **hosts**

drift-config has exactly one identifier you'll use for real: the **host name**. Each device that runs a DRIFT tool is a host (`drift1`, `boxa`, `macbook`, …). Host names are how peers find each other in the inventory — every config that references a peer references it by host name.

That's the only naming you do. There's also a cosmetic "network" label on the file as a whole (it shows up in `drift-config show` so you can tell `homenet.toml` apart from `worknet.toml`), but it's optional, defaults to `"drift-network"`, and nothing routes by it. **You don't need to think about it.**

## Why this exists

Without drift-config, deploying drift-vpn across N devices means:

- Generate an identity on each device → note the pubkey
- Add a `[[peer]]` block in every other device's config with
  that pubkey, allowed_ips, endpoints, …
- Repeat per device. With 5 devices that's ~20 cross-references.
- One typo on a 64-char hex pubkey breaks the deploy silently.

drift-config solves this by making the identity + endpoint info
**a single declarative file** that every DRIFT tool reads. Add a
new device once; every tool's config regenerates automatically.

It's roughly the role `wg-quick` plays for WireGuard, but
generalized — drift-config doesn't know what drift-vpn is. It
just owns the inventory; tools layer on top.

---

## Install

### From source (recommended)

drift-config is in the main DRIFT workspace. Build the whole repo
once and you get every tool:

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo build --release -p drift-config -p drift -p drift-vpn

# Drop the binaries somewhere on PATH
sudo cp target/release/drift-config target/release/drift target/release/drift-vpn /usr/local/bin/
```

That gives you all three commands. `drift-config` is the
inventory manager; `drift bridge` is the multi-transport bridge
daemon; `drift-vpn` is the full VPN.

### Verify

```bash
drift-config --version    # → drift-config 0.1.0
drift --help              # should show `bridge` in the subcommand list
drift-vpn config --help   # should show `init`, `assign`, `gen`
```

---

## Where files live

drift-config follows the same convention as every other DRIFT
tool: **system-wide as root, per-user otherwise.**

| As | drift.toml | identity.key |
|---|---|---|
| **root** | `/etc/drift/drift.toml` | `/etc/drift/identity.key` |
| **user** (Linux) | `~/.config/drift/drift.toml` | `~/.config/drift/identity.key` |
| **user** (macOS) | `~/Library/Application Support/drift/drift.toml` | `~/Library/Application Support/drift/identity.key` |

Override with `--config <path>` and `--identity <path>` on any
command. Most users don't need to.

**Permissions:** identity files are written 0600 (owner-only).
drift.toml is also written 0600 by default — it contains pubkeys
which are designed to be shared, but `chmod 644` it explicitly
if you want everyone to read it.

---

## 5-minute quickstart: 1 bridge + 1 client

The smallest end-to-end deployment. Box A becomes a public
"meeting point" bridge; box B is a client that connects to it.

### On Box A (the bridge — needs a stable IP / hostname)

```bash
# 1. Build, install (one-time)
cargo install --path drift-config --path drift

# 2. Initialize an inventory and generate this host's identity.
sudo mkdir -p /etc/drift
sudo drift-config init
sudo drift-config keygen boxa \
  --endpoint "udp://0.0.0.0:51820" \
  --endpoint "tcp://0.0.0.0:443"
# → prints box A's pubkey. Note it down.

# 3. Run the bridge in the foreground.
sudo drift bridge
# → "ready. share the pubkey above with anyone you want to bridge."
```

The bridge is now listening on UDP/51820 and TCP/443. Any device
with box A's pubkey can connect to it from anywhere with internet
access (assuming you've port-forwarded those ports through your
router for off-LAN clients).

### On Box B (the client)

```bash
# 1. Build, install
cargo install --path drift-config --path drift

# 2. Initialize the inventory.
drift-config init

# 3. Register box A as a peer (paste box A's pubkey from above).
drift-config peer add boxa \
  --pubkey <BOX_A_PUBKEY_HEX> \
  --endpoint "udp://<box-a-host-or-ip>:51820" \
  --endpoint "tcp://<box-a-host-or-ip>:443"

# 4. Generate this client's identity (no endpoints — it's a roamer).
drift-config keygen boxb

# 5. Verify the inventory looks right.
drift-config show
```

Now box B has identity + can find box A. Whatever DRIFT tool you
want to use (drift-vpn, drift-mosh, drift-http) reads the same
drift.toml — you're done with setup.

---

## 6-minute quickstart: federation between two bridges

Same shape as the one-bridge setup, but with two bridges that
`--federate` to each other so clients on different bridges can
reach each other by pubkey. Useful when you have populations of
clients on two different networks (home + office, two regions,
two clouds) and you don't want either network's clients to need
direct connectivity to the other side.

```bash
# ─── On box A (bridge-A — needs a stable IP) ──────────────────────
sudo drift-config init
sudo drift-config keygen boxa --endpoint "udp://0.0.0.0:51820"
# → bridge-A's pubkey: <PUB_A>

# ─── On box B (bridge-B — also stable IP) ─────────────────────────
sudo drift-config init
sudo drift-config keygen boxb --endpoint "tls://0.0.0.0:51821" \
                              --endpoint "ws://0.0.0.0:51822"
# → bridge-B's pubkey: <PUB_B>

# ─── Cross-register so each side knows about the other ───────────
# On box A:
sudo drift-config peer add boxb --pubkey <PUB_B> \
  --endpoint "tls://<box-b-host>:51821"
# On box B:
sudo drift-config peer add boxa --pubkey <PUB_A> \
  --endpoint "udp://<box-a-host>:51820"

# ─── Start the bridges (symmetric --federate on both sides) ──────
# Federation trust is symmetric: each bridge declares the other
# via --federate. Inbound Federated envelopes from a peer not in
# the federation table are rejected — that's what blocks
# identity-spoofing by untrusted clients. Initial-connect failure
# on TCP/TLS/WS retries in the background, so start order doesn't
# matter.
#
# Box A: federates to bridge-B over TLS (the connection-oriented
#        link survives most middleboxes).
sudo drift bridge --listen udp://0.0.0.0:51820 \
                  --federate tls://<box-b-host>:51821@<PUB_B>

# Box B: also --federate's back to A over UDP (so the trust is
#        mutual).
sudo drift bridge --listen tls://0.0.0.0:51821 \
                  --listen ws://0.0.0.0:51822 \
                  --federate udp://<box-a-host>:51820@<PUB_A>
```

Any DRIFT client connected to bridge-A (over UDP) can now reach
any client on bridge-B (over WS) by pubkey:

```bash
# drift-mosh, talking from a client on bridge-A to a server on bridge-B
drift-mosh-client --server-pub <server_pub> \
                  --bridge udp://<box-a-host>:51820@<PUB_A> \
                  --target-bridge <PUB_B>
```

Bridges only ever see ciphertext + the four pubkeys in the
envelope header (source bridge, source client, target bridge,
target client) — DRIFT's end-to-end crypto stays between the
real client endpoints.

`drift-config peer add` / `drift bridge` don't yet have explicit
`--federate` wiring through `drift.toml`; pass `--federate` to
`drift bridge` on the command line for now.

### Zero-config client dial

Once the inventory above is in place, DRIFT tools that target a
host *by pubkey* can read it directly from `drift.toml` — no
need to pass `--server-addr` / `--bridge` / `--target-bridge` on
every invocation. Two fields drive this:

- `endpoints = [...]` on the target's host entry → tools dial
  it directly (the first endpoint wins).
- `via_bridge = "<bridge-pubkey-hex>"` → tools auto-route through
  that bridge using DRIFT federation. The bridge itself must
  also be in the inventory with `endpoints` so the dialing tool
  can reach it.

```bash
# Operator records the server's reachability:
drift-config peer add bridge-b --pubkey <BRIDGE_B_PUB> \
  --endpoint "tls://0.0.0.0:51821"
drift-config peer add my-server --pubkey <SERVER_PUB> \
  --via-bridge <BRIDGE_B_PUB>

# User just hands the pubkey to drift-mosh:
drift-mosh-client --server-pub <SERVER_PUB> --exec uptime
# → drift-mosh-client reads /etc/drift/drift.toml, sees my-server
#   is on bridge-b, dials tls://0.0.0.0:51821, federates to the
#   server. Works the same way for `drift-mosh user@host` once
#   the launcher knows the pubkey for `host`.
```

This is the "identity-first" promise: addresses are pubkeys, the
inventory tells the network how to deliver. Direct endpoints
beat bridged routes when both are available.

### Dynamic discovery — when you don't know the target's bridge

The fully zero-config flavor: set a `default_bridge` at the
top of `drift.toml` instead of recording every individual
target. Tools that look up an unknown target fall back to
dialing the default bridge with a "consult your directory"
sentinel — the bridge then routes via whichever federated peer
has announced the target.

```toml
# /etc/drift/drift.toml
default_bridge = "<bridge-pubkey-hex>"

[network]
name = "lab"

[hosts.bridge-x]
pubkey = "<bridge-pubkey-hex>"
endpoints = ["udp://bridge-x.example:51820"]
```

`drift bridge` instances announce their connected clients to
every federation peer (`--federate`) every 10 seconds. A
receiving bridge keeps the directory entries with a 60-second
TTL — stale entries evict at lookup time, so a client whose
bridge stops announcing drops out of routing in under a
minute. Only `--federate`'d bridges may write to the directory;
arbitrary clients can't poison it. (See `drift/tests/
adversarial_federation.rs::federation_directory_rejects_non_bridge_announcer`.)

---

## 10-minute quickstart: 3-node VPN

A full drift-vpn deployment using drift-config:

```bash
# On each of three boxes, build + install once:
cargo install --path drift-config --path drift --path drift-vpn

# ─── On box A (will be the hub) ──────────────────────────────────
sudo drift-config init
sudo drift-config keygen boxa \
  --endpoint "udp://0.0.0.0:51820" \
  --endpoint "tcp://0.0.0.0:443"
# → box A's pubkey: <PUB_A>

# ─── On box B (a spoke) ──────────────────────────────────────────
sudo drift-config init
sudo drift-config keygen boxb \
  --endpoint "udp://0.0.0.0:51820"
# → box B's pubkey: <PUB_B>

# ─── On box C (roaming client, no listener) ──────────────────────
drift-config init
drift-config keygen boxc
# → box C's pubkey: <PUB_C>

# ─── Build the full inventory ON ANY ONE OF THEM (e.g. your laptop) ─
drift-config peer add boxa --pubkey <PUB_A> \
  --endpoint "udp://1.2.3.4:51820" --endpoint "tcp://1.2.3.4:443"
drift-config peer add boxb --pubkey <PUB_B> \
  --endpoint "udp://5.6.7.8:51820"
drift-config peer add boxc --pubkey <PUB_C>

# ─── Generate per-host drift-vpn configs ──────────────────────────
drift-vpn config init --cidr 10.99.0.0/24
drift-vpn config assign boxa --tun 10.99.0.1  --role hub
drift-vpn config assign boxb --tun 10.99.0.2  --role spoke
drift-vpn config assign boxc --tun 10.99.0.10 --role client
drift-vpn config gen
# → out/boxa/config.toml, out/boxb/config.toml, out/boxc/config.toml

# ─── Deploy ──────────────────────────────────────────────────────
scp out/boxa/config.toml root@boxa:/etc/drift-vpn/config.toml
scp out/boxb/config.toml root@boxb:/etc/drift-vpn/config.toml
sudo cp out/boxc/config.toml /etc/drift-vpn/config.toml   # local
ssh root@boxa 'drift-vpn up -c /etc/drift-vpn/config.toml &'
ssh root@boxb 'drift-vpn up -c /etc/drift-vpn/config.toml &'
sudo drift-vpn up -c /etc/drift-vpn/config.toml &

# ─── Verify ──────────────────────────────────────────────────────
ping 10.99.0.1   # from boxc → reaches boxa over UDP
ping 10.99.0.2   # from boxc → routes through boxa to boxb (mesh)
```

Adding a fourth device is now: one `drift-config keygen` on the
new device, one `drift-config peer add` + `drift-vpn config
assign` on whichever box owns the inventory, one `drift-vpn
config gen`, then scp the new configs out.

---

## Subcommand reference

### `drift-config init [--network <label>] [--force]`

Create a starter `drift.toml`. Most users just run
`drift-config init` with no arguments — that's all you need.
Optional `--network <label>` sets a cosmetic name shown in
`drift-config show`; it's pure documentation, nothing routes by
it. Refuses to overwrite an existing file unless `--force`.

### `drift-config keygen [<host>] [--endpoint <url>]... [--force]`

Generate this device's X25519 identity and register it in
`drift.toml` as `[hosts.<host>]`. The `<host>` positional names
this entry; if omitted, defaults to the OS hostname
(`/etc/hostname` or `$HOSTNAME`). Repeat `--endpoint` for each
URL other peers should use to reach this host:

```bash
drift-config keygen drift1 \
  --endpoint udp://0.0.0.0:51820 \
  --endpoint tcp://0.0.0.0:443 \
  --endpoint ws://0.0.0.0:8443
```

Hosts with no `--endpoint` are roaming clients (laptops, phones)
that initiate outbound connections only.

`--force` regenerates the identity, **rotating the pubkey**. Every
peer's drift.toml will need to be updated. Don't pass it lightly.

### `drift-config peer add <name> --pubkey <hex> [--endpoint <url>]...`

Add a remote peer to the inventory by hand. Use this on whichever
device owns the master copy of drift.toml when adding peers you
generated identities for elsewhere.

```bash
drift-config peer add drift2 \
  --pubkey 1122…64-hex-chars \
  --endpoint udp://192.0.2.168:51820
```

Pubkey must be exactly 64 hex chars; endpoint URLs must start
with one of `udp://`, `tcp://`, `ws://`, `tls://`, `dns://`,
`doh://`, `http://`, `onion://`.

### `drift-config peer ls`

Print every host in the inventory in human form.

### `drift-config peer rm <name>`

Remove a host. Also strips any `[vpn.<name>]` overlay block so the
file stays consistent.

### `drift-config show`

Same as `peer ls` plus a header summarizing the network and any
VPN overlay.

### `drift-config validate`

Sanity-check the file: pubkey format, duplicate pubkeys,
duplicate tun addresses, valid endpoint schemes, valid roles.
Exits non-zero on any problem so you can use it in CI.

---

## Schema reference

`drift.toml` has three top-level namespaces:

```toml
# Cosmetic — used in `show` output.
[network]
name = "homenet"

# DRIFT inventory: one block per host. The `pubkey` is the long-
# term X25519 identity; `endpoints[]` lists DRIFT URLs other peers
# use to reach this host. Empty endpoints = roaming client.
[hosts.boxa]
pubkey = "abc123…64-hex"
endpoints = [
  "udp://0.0.0.0:51820",
  "tcp://0.0.0.0:443",
]

[hosts.boxb]
pubkey = "def456…"
endpoints = ["udp://192.0.2.168:51820"]

[hosts.boxc]
pubkey = "789abc…"
# no endpoints — roaming client

# drift-vpn-specific overlay. Only `drift-vpn config` reads this.
# Other DRIFT tools ignore it entirely.
[vpn]
cidr = "10.99.0.0/24"
mtu  = 1340

[vpn.boxa]
tun_addr = "10.99.0.1"
role     = "hub"

[vpn.boxb]
tun_addr = "10.99.0.2"
role     = "spoke"

[vpn.boxc]
tun_addr = "10.99.0.10"
role     = "client"
```

Future DRIFT tools follow the same pattern: `drift-mosh` would
add `[mosh]` + `[mosh.X]` blocks for shell-specific config without
touching `[hosts.X]`.

---

## How drift-config integrates with other DRIFT tools

| Tool | Reads | Writes |
|---|---|---|
| **drift-config** | drift.toml, identity.key | drift.toml, identity.key (in `init`/`keygen`/`peer add`/`peer rm`) |
| **drift bridge** | drift.toml (this host's `[hosts.X].endpoints`), identity.key | nothing |
| **drift-vpn config** | drift.toml | drift.toml (`init`/`assign` add `[vpn]` blocks); generated configs in `out/` |
| **drift-vpn up** | the generated `config.toml`, not drift.toml directly | nothing |
| **drift-mosh, drift-http, drift-git** | drift.toml (planned) | nothing |

**Identity file format:** drift-config writes the identity as 64
hex chars + newline — the same on-disk format `drift-vpn keygen`
writes. `drift` CLI accepts both this format and its older
DRFT-magic binary format, so a single identity.key works in every
DRIFT tool on the host.

---

## What it does NOT do (yet)

drift-config v0.1 is intentionally small. Things explicitly
**not** in scope right now:

- **No SSH-driven deploy.** The `--ssh` field was removed because
  drift.toml is meant to be shareable. A future `drift-vpn config
  push` will take ssh targets at deploy time, stored in a
  separate operator-local file (not the inventory).
- **No remote keygen.** Adding a new device today requires running
  `drift-config keygen` on it directly. A future
  `drift-config peer add-remote --ssh <target>` will ssh in, run
  keygen on the box, and pull the pubkey + endpoints back —
  one-command onboarding.
- **No coordinator.** Unlike Tailscale/Headscale, there's no
  central service that distributes configs. Every device reads
  its own drift.toml. By design — DRIFT's appeal is "no third
  party in the data path."
- **No hot-reload.** Editing drift.toml + regenerating configs +
  restarting daemons is the deploy loop. Daemons don't watch the
  file.
- **No ACL groups.** `[hosts.X]` knows nothing about which other
  hosts it should talk to. In drift-vpn, `allowed_ips` cidrs
  effectively gate traffic at the routing level. A future
  `[groups]` namespace could add explicit pubkey-level allow
  rules.

---

## Common pitfalls

- **"no [hosts.X] entry in drift.toml"** when running `drift
  bridge`: you forgot `drift-config keygen X` first.
  Pass `--host <name>` to the bridge if your inventory uses a
  different name than the OS hostname.
- **"identity already exists"** on `drift-config keygen`: the
  file is there. Pass `--force` if you really want a fresh
  identity (this rotates your pubkey — every peer's inventory
  needs the new one).
- **Permissions** when running as both root and as a user: the
  default config dir differs. Either `sudo` consistently or pass
  `--config <path>` consistently.
- **Sharing drift.toml**: it contains your peers' pubkeys. Pubkeys
  are public-by-design (every peer needs every other peer's), so
  this is fine. If your file ever included `--ssh` from a
  pre-v0.1 schema, strip those fields before sharing.

---

## License

MIT. Same as the rest of DRIFT.

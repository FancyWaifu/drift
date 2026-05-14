# Running a DRIFT bridge on a home router

This guide walks through installing `drift bridge` on an ASUS
router (RT-AX82U used as the running example; the steps generalize
to any AsusWRT-Merlin-supported model with USB) and exposing it as
a permanent federation endpoint.

## Why a router is a great bridge host

- **Always on.** Already running 24/7; no idle laptop blocking
  federation reachability for your other identities.
- **Static-ish DNS.** ASUS bundles DDNS support out of the box
  (`yourname.asuscomm.com`), so the bridge has a stable name even
  on residential dynamic-IP connections.
- **Owns the port forward.** The router IS the firewall — no
  upstream port-forward dance. Adding the inbound UDP rule is a
  one-click in the Merlin UI.
- **Tiny footprint.** `drift bridge` uses single-digit MB of RAM
  and is mostly idle. The Cortex-A53 in the RT-AX82U has plenty
  of headroom.

## What you'll end up with

A bridge reachable from anywhere as:

```
udp://yourname.asuscomm.com:51820@<bridge-pubkey-hex>
```

You can hand that string to anyone you want to federate with
(`drift bridge --federate udp://yourname.asuscomm.com:51820@<pub>`),
or use it directly as a `default_bridge` in `drift.toml` so
clients dial by pubkey alone.

## Prerequisites

- **ASUS RT-AX82U** running stock or Merlin firmware. Stock works
  but is much harder to script — strongly recommended path:
  flash AsusWRT-Merlin first.
- **A USB stick** (any size; 1 GB is plenty). Plugged into one of
  the router's USB ports, formatted ext4. This is where Entware
  lives.
- **A computer that can SSH** into the router. ASUS Merlin runs
  SSH on port 22 by default once you enable it in the UI.
- **A public WAN IP**. If you're behind CGNAT, the bridge won't
  be inbound-reachable; the router-as-bridge story doesn't work
  in that case. Run `dig +short myip.opendns.com @resolver1.opendns.com`
  and compare to the router's reported WAN IP.

## Step 1 — Flash AsusWRT-Merlin

If you're already on Merlin, skip ahead.

1. Download the matching Merlin build from
   https://www.asuswrt-merlin.net/download for RT-AX82U.
2. In the stock ASUS UI: Administration → Firmware Upgrade →
   upload the `.trx`. Router reboots, you keep your settings.
3. (Fully reversible: flash the official ASUS firmware to revert.)

Enable JFFS partition (Administration → System → "Enable JFFS
custom scripts and configs": **Yes**). This gives you persistent
scratch space for init scripts.

Enable SSH (Administration → System → SSH: enable on LAN, set a
strong password, optionally allow your specific WAN IP).

## Step 2 — Install Entware

Entware is an opkg-based package manager — same family as
OpenWrt's — that runs from the USB stick.

```bash
# SSH into the router as admin
ssh admin@192.0.2.1

# Plug in the USB stick BEFORE running this. Format it ext4 via
# the Merlin UI (USB Application → Servers Center → Servers
# Center → Format).
amtm
# Choose: "ep" (Entware install) → pick the USB partition.
```

Once installed, `/opt` is mounted from the USB stick and persists
across reboots.

## Step 3 — Install the drift binary

Drift is a single static binary — no library deps, no companion
files. You can cross-build it yourself from the workspace
(`cross build --target aarch64-unknown-linux-musl --release -p drift --bin drift`)
or grab a prebuilt release artifact.

Copy the binary to the router:

```bash
# From your dev machine
scp drift admin@192.0.2.1:/opt/sbin/drift
ssh admin@192.0.2.1 'chmod +x /opt/sbin/drift'
```

Verify it runs:

```bash
ssh admin@192.0.2.1 '/opt/sbin/drift --help'
```

You should see the drift CLI usage.

## Step 4 — Generate the bridge identity

The identity file holds the bridge's static X25519 keypair. Once
chosen, this is the bridge's "address" forever — every client
that connects to you points at this pubkey, so don't lose it.

```bash
ssh admin@192.0.2.1
mkdir -p /opt/etc/drift
/opt/sbin/drift keygen --output /opt/etc/drift/bridge.key
chmod 600 /opt/etc/drift/bridge.key
/opt/sbin/drift info /opt/etc/drift/bridge.key
```

Save the printed pubkey hex — that's what you share with anyone
who wants to reach the bridge.

## Step 5 — Open the firewall port

The bridge listens on UDP/51820 (configurable). The router needs
to allow inbound to its OWN UDP port (this is unusual — most
port-forward UIs assume the destination is a LAN device, but
here the destination is the router itself).

In Merlin: WAN → Virtual Server / Port Forwarding → add:

```
Service name:     drift-bridge
Source IP:        (leave blank — accept from any source)
Port Range:       51820
Local IP:         192.0.2.1   (the router's LAN IP)
Local Port:       51820
Protocol:         UDP
```

Apply.

## Step 6 — Set up DDNS (optional but recommended)

Administration → DDNS → enable "WWW.ASUS.COM" service. Pick a
name like `yourname.asuscomm.com`. Router updates the A record
whenever your WAN IP changes.

## Step 7 — Init script (auto-start on reboot)

Create `/jffs/scripts/services-start` if it doesn't exist:

```bash
ssh admin@192.0.2.1
cat >> /jffs/scripts/services-start <<'EOF'
#!/bin/sh
# Wait for /opt to mount before launching drift bridge.
for i in $(seq 1 30); do
  [ -x /opt/sbin/drift ] && break
  sleep 1
done

# Launch the bridge in the background with logging to /opt/var/log.
mkdir -p /opt/var/log
nohup /opt/sbin/drift --identity /opt/etc/drift/bridge.key bridge \
  --listen udp://0.0.0.0:51820 \
  --accept-any-peer \
  > /opt/var/log/drift-bridge.log 2>&1 &
EOF
chmod +x /jffs/scripts/services-start
```

If you have other federation peers to mesh with, add `--federate
udp://other-bridge:51820@<other-pub>` lines for each. Symmetric
federation: both sides must `--federate` each other.

Reboot to confirm it auto-starts:

```bash
reboot
# Wait 60 s, then check:
ssh admin@192.0.2.1 'ps | grep drift'
ssh admin@192.0.2.1 'tail -20 /opt/var/log/drift-bridge.log'
```

You should see the bridge's startup banner.

## Step 8 — Test from outside

From any other machine (NOT on your LAN — use cell tethering or a
remote VPS):

```bash
drift keygen --output /tmp/test.key
PUB_BRIDGE=$(ssh admin@192.0.2.1 '/opt/sbin/drift info /opt/etc/drift/bridge.key | grep -oE "[0-9a-f]{64}"')

# Try to send through the bridge — succeeds if the port forward
# + DDNS + drift bridge are all wired correctly.
drift --identity /tmp/test.key send "udp://yourname.asuscomm.com:51820@$PUB_BRIDGE" 'hello bridge'
```

The router's `/opt/var/log/drift-bridge.log` should show the
incoming session.

## Operating tips

- **Updates.** When you ship a new bridge build, just `scp` over
  `/opt/sbin/drift` and `killall drift; /jffs/scripts/services-start`.
  Or write a `/jffs/scripts/drift-restart` helper.
- **Resource usage.** `top -n 1 | grep drift` — drift uses
  ~5–15 MB RSS even with several connected clients. No tuning
  needed.
- **Log rotation.** `/opt/var/log/drift-bridge.log` grows
  forever otherwise. Either run a cron job to rotate, or pipe
  through `logger` to the router's syslog.
- **Reverting.** Stop the bridge with `killall drift`. Disable
  the init script by `chmod -x /jffs/scripts/services-start`.
  Remove `/opt/sbin/drift` and `/opt/etc/drift/`. The router
  goes back to a stock-Merlin state.

## What you can't do (yet)

- **CGNAT bypass.** If your ISP gives you a CGNAT-only address,
  the bridge isn't inbound-reachable from the public internet.
  Workarounds: rent a $5/month VPS as an outbound bridge that
  federates with this one; the router connects out, traffic flows
  through both.
- **WireGuard-style admin UI.** drift bridge is CLI-only today;
  there's no web UI for adding federation peers from the Merlin
  interface. Edit `/jffs/scripts/services-start` and reboot.
- **Multi-WAN load balancing.** If you have dual WAN, drift
  binds to one. ASUS's dual-WAN failover handles the IP switch
  but session continuity depends on DRIFT's path-validation
  kicking in within the new WAN's first 60 s of liveness — works
  for most cases, but isn't documented as "supported."

## Verifying it's actually a federation endpoint

Once it's up, you can:

1. **Add it to another bridge's `--federate` list.** That bridge
   announces clients to yours and vice versa.
2. **Use it as `default_bridge` in clients' `drift.toml`.** Any
   tool that dials `--server-pub <hex>` will route through this
   bridge if its directory has the target.
3. **Watch the metrics.** `drift bridge` ships with a debug
   socket; `drift status` (when you've built it) can query
   peer counts, route counts, federation traffic.

That's it — your router is now a permanent federation on-ramp for
your DRIFT identities.

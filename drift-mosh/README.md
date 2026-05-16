# drift-mosh

**A mobile-shell replacement that survives network changes.**

Like [mosh](https://mosh.org/), but built on [DRIFT](../README.md) — so reconnects, migration, and identity-first addressing come from the transport layer instead of a bespoke protocol. Use it as a drop-in for `ssh user@host` when you want your terminal session to survive wifi-to-cellular switches, laptop suspend, and long network glitches.

```
$ drift-mosh user@host
# [you're in a shell. close the lid, move to a different network, reopen.]
# [session is still there, scrollback intact.]
```

## Install

### From source

Requires Rust 1.80+.

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo install --path drift-mosh --bin drift-mosh
cargo install --path drift-mosh --bin drift-mosh-client
cargo install --path drift-mosh --bin drift-mosh-server
```

### From a release tarball

Pre-built tarballs for macOS (arm64, x86_64) and Linux (x86_64, arm64) are attached to every `drift-mosh-v*` GitHub release:

```bash
TARGET=aarch64-apple-darwin   # pick yours
VERSION=drift-mosh-v0.1.0
curl -L -o dm.tar.gz https://github.com/FancyWaifu/drift/releases/download/$VERSION/drift-mosh-$VERSION-$TARGET.tar.gz
tar xzf dm.tar.gz
sudo mv drift-mosh-$VERSION-$TARGET/drift-mosh* /usr/local/bin/
```

On the remote host, install `drift-mosh-server` the same way. The `drift-mosh` launcher on your laptop runs it over SSH.

## Usage

```bash
drift-mosh user@host
```

Under the hood:
1. The launcher SSHs into `user@host` and runs `drift-mosh-server`.
2. The server prints its pubkey + bound UDP address on stdout.
3. The launcher pins the pubkey on first connect (TOFU, same as SSH's `known_hosts`).
4. It hands off to `drift-mosh-client`, which opens a DRIFT session and drops you into a shell.

### Options

```
drift-mosh [OPTIONS] <TARGET>

Arguments:
  <TARGET>                    user@host or just host

Options:
  -p, --ssh-port <PORT>       SSH port [default: 22]
      --no-ssh                Skip SSH launch; connect to a server you started manually
      --server-pub <HEX>      Server pubkey (required with --no-ssh)
      --server-addr <ADDR>    Server address. Bare host:port = UDP (default).
                              Scheme prefix selects transport:
                                udp://host:port  (UDP, the default)
                                tcp://host:port  (TCP — firewalled networks)
                                ws://host:port   (WebSocket)
                                tls://host:port  (TLS-wrapped TCP)
      --bridge <URL@PUB>      Reach the server through a DRIFT bridge instead
                              of a direct connection. URL is the bridge's
                              listen URL; PUB is its pubkey.
      --target-bridge <PUB>   Pubkey of the bridge the server is connected to.
                              Required when the server is on a different bridge
                              from the client (cross-bridge federation).
      --host <NAME>           Look the server up by its drift.toml `[hosts.<NAME>]`
                              entry. Resolves pubkey + route (direct or via_bridge)
                              from the inventory; lets you replace the
                              --server-pub / --bridge / --target-bridge triplet
                              with a single short name. Mutually exclusive with
                              those flags.
      --exec <CMD>            Non-interactive mode: run CMD in the remote shell,
                              drain its output, exit. Skips raw-mode; useful for
                              scripts and CI.
      --exec-timeout <SECS>   Cap --exec output draining at SECS seconds [default: 5]
      --remote-server-path <PATH>
                              Path to drift-mosh-server on the remote host
```

### Transport selection

`drift-mosh-server` and `drift-mosh-client` both accept scheme-prefixed addresses, so you can pick whichever wire works for the network you're on. UDP is the default and fastest; TCP/WebSocket are firewall-friendly fallbacks that get through corporate networks blocking UDP:

```bash
# UDP (default, lowest latency):
drift-mosh-server --bind 0.0.0.0:9400

# TCP (corporate firewall fallback):
drift-mosh-server --bind tcp://0.0.0.0:9400
drift-mosh-client --server-pub <pub> --server-addr tcp://host:9400

# WebSocket (port-443 friendly, gets through HTTP-only proxies):
drift-mosh-server --bind ws://0.0.0.0:443
drift-mosh-client --server-pub <pub> --server-addr ws://host:443
```

A single drift-mosh-server runs over one transport at a time — sessions are point-to-point, so simultaneous-multi-bind isn't useful here. (drift-http needs that pattern; drift-mosh doesn't.) The transport choice is in the URL the launcher persists, so `drift-mosh user@host` Just Works once the server is configured.

### Zero-config dial — `drift-mosh-client --host <name>`

If the server is registered in your `drift.toml` (the shared
inventory written by `drift-config`), the client doesn't need any
flags except the host name. It looks up the entry, pulls the
pubkey + route (`endpoints` for direct dial, `via_bridge` for
federation), and fills everything in automatically:

```bash
# One-time inventory setup: bridge the server federates to, then
# the server itself.
drift-config peer add bridge-d3 --pubkey <BRIDGE_PUB> \
  --endpoint udp://bridge.example:51820
drift-config peer add mosh-srv  --pubkey <SERVER_PUB> \
  --via-bridge <BRIDGE_PUB>

# After that, connect with a short name:
drift-mosh-client --host mosh-srv --exec 'whoami'
# → routes through bridge-d3 via federation, runs `whoami`.
```

You can also pass `--server-pub <hex>` if you'd rather identify
the server by pubkey directly — drift-mosh-client falls back to
the same drift.toml lookup keyed on pubkey. `--host <name>` is
the shorter form when you've already named the host.

When the same target host has both `endpoints` and `via_bridge`,
the direct dial wins — fewer hops, no bridge operator in the
middle. `--server-addr` / `--bridge` on the command line still
override the inventory if you want to force a particular route.

`via_bridge` is **optional**. If a target host entry has only a
`pubkey` (no endpoints, no via_bridge), drift-mosh-client routes
through your configured `default_bridge` with the all-zero
"consult your directory" sentinel and the bridge resolves the
target via federation discovery — proactive multi-hop announce
fills caches at steady state, reactive `FindPeer` covers the cold
path for clients that joined since the last announce. See
`FEDERATION_DISCOVERY.md` at the workspace root for the protocol
spec and `SPEC.md §10` for the wire-format reference.

The bridge's discovery layer has opt-in privacy modes (set on the
bridge process, not drift-mosh): `FindPeerMode::OriginateHashed`
hashes target pubkeys before sending queries — transit bridges
see only `SHA-256(target || salt)`. `bloom_announce_noise` adds
a DP-noised bloom filter to directory announces so originators
skip bridges whose filter says "definitely not." `cover_traffic_rate_hz`
emits Poisson-timed decoys to smother real query patterns. All
three stack; none requires drift-mosh-client to know they're on.

For the **fully zero-config** case, set a `default_bridge` at
the top of drift.toml instead of recording every individual
target. `drift-mosh-client --server-pub <X>` then dials the
default bridge with the all-zero "consult your directory"
sentinel, and the bridge resolves `<X>` via its federation
directory (populated by 7 s announcements from federation
peers, each entry signed by the announced client with an
XEdDSA presence ticket — drift-mosh-server auto-emits one
every 5 min so the bridge can include it). See
[`drift-config/README.md`](../drift-config/README.md) for the
discovery flow + threat-model gates.

### Federation — reaching a server through one or two bridges

When client and server can't directly reach each other — different networks, NAT on both sides, firewalls that block everything except outbound HTTPS — DRIFT bridges relay the session. drift-mosh speaks federation natively via two flags:

```bash
# Server: don't bind a listener; instead connect out to a bridge.
drift-mosh-server --bridge tcp://bridge.example:51820@<BRIDGE_PUB> --shell /bin/sh

# Client (one bridge between us):
drift-mosh-client --server-pub <SERVER_PUB> \
                  --bridge udp://bridge.example:51820@<BRIDGE_PUB>

# Client (two bridges — client and server on different bridges that
# --federate to each other):
drift-mosh-client --server-pub <SERVER_PUB> \
                  --bridge udp://bridge-a:51820@<BRIDGE_A_PUB> \
                  --target-bridge <BRIDGE_B_PUB>
```

The two bridges talk over their `--federate` link, whichever transport they were configured with. The wire from client → bridge-A, bridge-A → bridge-B, and bridge-B → server can all be different DRIFT transports — `mixed_transport_federation_test.sh` runs `UDP → TLS → WebSocket` end-to-end and gets a real shell prompt back.

### Non-interactive shells (`--exec`)

For scripts and CI, `--exec` runs one command and returns:

```bash
$ drift-mosh-client --no-ssh --server-pub <pub> --server-addr ws://host:443 \
    --exec 'uname -a; whoami' --exec-timeout 5
DRIFT_MOSH_SESSION_ID=1f212ad0a9f0d828acf0c17f5a4f8f31
# uname -a; whoami
Linux drift-4 6.8.12-9-pve ... x86_64
root
# exit
```

Skips raw-mode entry (works fine without a tty), pipes `cmd\nexit\n` to the pty, and drains output until the deadline or the shell exits. Combines with `--bridge` / `--target-bridge` for end-to-end federation tests.

### Config file

`$XDG_CONFIG_HOME/drift-mosh/config.toml` (or `~/Library/Application Support/drift-mosh/config.toml` on macOS):

```toml
ssh_port = 22                              # default SSH port for user@host launches
remote_server_path = "drift-mosh-server"   # path on the remote; override if needed
keepalive_secs = 600                       # server keeps session alive N secs after disconnect
bind_addr = "0.0.0.0:0"                    # what the remote server binds to (0 = ephemeral)
```

### Where things live

- `~/.config/drift-mosh/client.key` — your persistent 32-byte client identity. Auto-created on first run, mode 0600. Keep it like you'd keep `~/.ssh/id_ed25519`.
- `~/.config/drift-mosh/known_hosts` — SSH-style TOFU pins for remote server pubkeys.
- `~/.config/drift-mosh/sessions/<host>_<port>.session` — per-host session ids, used for reattach.

## How it's different from SSH

| | SSH | drift-mosh |
|---|---|---|
| Works after network change | ❌ (TCP breaks) | ✅ (DRIFT migrates the path) |
| Survives laptop suspend | ❌ | ✅ |
| Reattach after client crash | ❌ | ✅ (within `keepalive_secs`) |
| Identity-first (no hostnames) | ❌ | ✅ (pubkey is the address) |
| Multi-medium (UDP / TCP / WS) | TCP only | any DRIFT transport, scheme-prefix CLI |
| Restart migration across IPs | ❌ | ✅ (verified cross-loopback in CI) |
| Coalesced rendering | ❌ | ✅ (~6.5× faster than the MVP for bursty output) |

## How it's different from mosh

| | mosh | drift-mosh |
|---|---|---|
| Connection migration | built from scratch | inherited from DRIFT |
| Identity-first | ❌ | ✅ |
| Lines of code | ~15k | ~1.5k |
| Terminal state sync | ✅ full | ❌ byte stream¹ |
| Local echo prediction | ✅ | ❌² |

¹ Today drift-mosh sends raw pty bytes over a reliable stream. True mosh-style state sync (with DRIFT's `supersedes` coalescing) is a planned follow-up — see "Future work" below.

² Local echo prediction is planned. For now keystrokes round-trip like SSH.

## Architecture

```
 drift-mosh-client                        drift-mosh-server
 ─────────────────                        ─────────────────
  stdin (raw mode)   ──┐           ┌──   pty master → shell
  stdout             ←─┤ pty stream├──   pty master ← shell
                       │ (DRIFT)   │
  SIGWINCH handler   ──┤           ├──   pty.resize()
                       │ ctrl stream│
                       │ (DRIFT)   │
                       └───────────┘
```

Two DRIFT streams per session:
- **pty stream** — raw bytes in both directions. Your local terminal emulator handles VT100/xterm escape sequences.
- **control stream** — bincode-encoded messages: `Attach`, `AttachAck`, `Resize`, `Bye`.

Server convention: accept first stream as pty, second as control. Client opens in the same order.

### Reattach

1. On first connect, the server mints a 16-byte `session_id` and returns it in `AttachAck`.
2. The `drift-mosh` launcher persists it to `~/.config/drift-mosh/sessions/<host>_<port>.session`.
3. On reconnect, the launcher passes it via `--session-id`. The server looks up the session in its table (keyed by client pubkey), re-wires the streams, and replays scrollback.
4. Sessions stay alive for `keepalive_secs` after disconnect. Default 10 minutes, configurable.

### Authentication

- **Server authenticates to client** by its pubkey. The launcher pins it TOFU-style on first connect. Pubkey changes scream loudly (same model as SSH).
- **Client authenticates to server** by its persistent `client.key`. The server accepts any client whose handshake succeeds — server-side access control is what SSH gave you (the `drift-mosh-server` only runs because you SSH'd in with your SSH key).

## Tests

```bash
cd drift-mosh/tests

# Basic end-to-end over UDP: handshake, echo round-trip, resize.
./smoke.exp

# Same shape but over TCP — firewall-fallback path.
./tcp_transport.exp

# Same shape but over WebSocket — port-443 / HTTP-proxy fallback.
./ws_transport.exp

# Session/reattach protocol — session_id is well-formed and
# round-trips through Attach/AttachAck.
./reattach.exp

# Cross-transport federation: drift-mosh shell session through
# two bridges, each leg of the chain on a different DRIFT
# transport. Needs four reachable Linux hosts; the script
# defaults to a Proxmox LXC quad at 192.168.50.{52,168,253,33}
# but the IPs are at the top of the file. Verifies
# UDP → TLS → WS round-trips a real shell command.
./mixed_transport_federation_test.sh
```

Plus the scrollback unit tests:

```bash
cargo test -p drift-mosh --lib
```

## Manual migration demo

The headline feature. Needs two machines or a way to swap network interfaces on one machine.

```bash
# On the remote host:
drift-mosh-server --bind 0.0.0.0:9400

# Grab its DRIFT_MOSH_PUB=... and DRIFT_MOSH_ADDR=... lines.

# On your laptop:
drift-mosh --no-ssh --server-pub <pub> --server-addr <addr>

# Start a long-running thing so you can see it resume:
watch -n 1 date

# While that's running, disable wifi, enable ethernet (or
# tether to cellular). The `watch` output continues after a
# brief pause — no session reset, no lost scrollback.
```

## Future work

Called out honestly:

- **Mosh-style state sync with coalescing.** The real mosh sends terminal-state diffs and uses `supersedes`-style overwrite so lost packets never get retransmitted — the next snapshot wins. DRIFT's `supersedes` groups are a perfect fit; adding a terminal emulator on the server (via [`vte`](https://docs.rs/vte) or [`alacritty_terminal`](https://docs.rs/alacritty_terminal)) would give us flawless typing over 30 % packet loss. ~1 week of work.
- **Local echo prediction.** Type keystrokes locally with a "pending" style, reconcile on next server snapshot. Mosh's key UX feature over high-latency links.
- **Rude-disconnect recovery.** When a client dies without sending `Bye` (SIGKILL, network partition), DRIFT takes ~30 s by default to notice the peer is gone. Reattach works once that window elapses; we could tune peer timeouts down or add an explicit server-side session-liveness check to make it faster.
- **Public-key client pinning on the server.** Today the server uses `accept_any_peer: true` (trust the SSH-gated access). For multi-user deployments an `authorized_keys`-style file would let the server enforce per-client pinning without an SSH wrapper.
- **Homebrew tap.** `brew install fancywaifu/drift/drift-mosh`. Trivial once the release workflow is landed.

## License

MIT. See [`LICENSE`](../LICENSE).

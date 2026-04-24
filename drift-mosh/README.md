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
      --server-addr <IP:PORT> Server address (required with --no-ssh)
      --remote-server-path <PATH>
                              Path to drift-mosh-server on the remote host
```

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
| Multi-medium (UDP/TCP/WS) | TCP only | any DRIFT transport |

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

# Basic end-to-end: handshake, echo round-trip, resize.
./smoke.exp

# Session/reattach protocol — session_id is well-formed +
# round-tripped.
./reattach.exp
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

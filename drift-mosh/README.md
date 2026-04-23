# drift-mosh

A [mosh](https://mosh.org/)-style mobile-shell replacement built on DRIFT.

Same idea as mosh: keep your remote terminal session alive across network changes (wifi → cellular, laptop suspend/resume, coffee-shop roaming). Different implementation — where mosh had to design SSP from scratch, drift-mosh inherits **connection migration**, **session resumption**, and **identity-first addressing** from the DRIFT transport.

## Why

SSH breaks when your network changes. Mosh fixes this with its own UDP-based protocol. DRIFT already solved the same problem at the transport layer — so drift-mosh is a thin shell around a `Transport` + a pty. Roughly **300 lines of code** per side.

| Feature | SSH | mosh | drift-mosh |
|---------|-----|------|-----------|
| Survives network change | ❌ | ✅ | ✅ |
| Identity-first (no hostname) | ❌ | ❌ | ✅ |
| Multi-medium (UDP/TCP/WS) | TCP only | UDP only | any |
| Terminal state sync | byte stream | full | byte stream¹ |
| Local echo prediction | ❌ | ✅ | ❌² |

¹ Mosh-style state sync + `supersedes`-based coalescing is a planned follow-up (see below).
² No local echo yet — keystrokes round-trip like SSH. Planned.

## Quick start

```bash
# Build both binaries.
cargo build --release -p drift-mosh

# Terminal 1 — start the server on the remote host.
./target/release/drift-mosh-server --bind 0.0.0.0:0
# Prints a startup banner:
#   drift-mosh-server ready
#   pub = bd179b57...
#   addr = 127.0.0.1:54506
#   (paste into client: --server-pub ... --server-addr ...)

# Terminal 2 — connect from your laptop.
./target/release/drift-mosh-client \
    --server-pub bd179b57e52e6cb0e28fa9b0d4ccfd5cf9e399cd533ed199637780712a875c71 \
    --server-addr 127.0.0.1:54506
# You're in a remote shell.
```

Close the client's lid, switch networks, reopen — the session resumes transparently. DRIFT's path validation handles the address change; mosh had to build this itself.

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
1. **pty stream** — raw bytes in both directions. The local terminal emulator (whatever you're running `drift-mosh-client` inside of) handles all VT100/xterm-256color escape sequences.
2. **control stream** — bincode-encoded `Ctrl` messages: `Resize { rows, cols }` and `Bye`. Sent on window resize (SIGWINCH) and clean exit.

Server accepts streams in order: first = pty, second = control. Client opens in that same order.

## Authentication model

The server is authenticated by its **public key** (the 32 bytes after `pub =` in the startup banner). The client pins that pubkey via `--server-pub`; a MITM would need to forge a DRIFT handshake against that specific key, which is cryptographically infeasible.

The server runs with `accept_any_peer: true` — it doesn't know in advance what client will connect. This is the same trust model as SSH's `AuthorizedKeysCommand` or mosh's bootstrapping: you trust the transport to identify the server, and the server trusts whoever can handshake with the pubkey of record.

A future version could add **client-side pubkey pinning on the server** (like SSH `authorized_keys`) by setting `accept_any_peer: false` and explicitly registering each client. That's what you'd want for multi-user deployment.

## Tests

```bash
cd drift-mosh/tests
./smoke.exp       # handshake, echo round-trip, resize control stream
```

Uses `expect(1)` (shipped with macOS + most Linuxes) to drive a fake tty around the client.

## Manual migration demo

The headline feature. Requires two machines or a way to swap network interfaces.

```bash
# On host A (server-facing):
./target/release/drift-mosh-server --bind 0.0.0.0:9400

# On host B (client), note the pub + addr from A's banner:
./target/release/drift-mosh-client --server-pub <pub> --server-addr <A_wifi_ip>:9400
# Start typing. Run something like `watch -n 1 date`.

# While the session is alive: disable wifi on host B, enable ethernet,
# (or: tether your laptop to cellular)
# The `watch` output resumes after a second or two with no session reset.
```

## Future work

- **Mosh-style state sync.** True mosh sends *terminal state diffs* with `supersedes`-style overwrite semantics — packet loss is never retransmitted because the next snapshot supersedes the lost one. DRIFT has `supersedes` groups built in; adding a terminal-emulator layer to the server (via [`vte`](https://docs.rs/vte) or similar) would give us this for ~2 days of work. Payoff: flawless typing over 30% loss links.
- **Local echo prediction.** Client types keystrokes locally with a "pending" style, reconciles with server state on next sync. Mosh's polished frontend is what makes it feel instant over transcontinental latency.
- **SSH bootstrap.** Today the client needs the server's pub + addr pasted in manually. A `drift-mosh user@host` wrapper would SSH-launch the server, parse the banner from the SSH session's stdout, and hand it to the client — making drift-mosh a drop-in replacement for `mosh user@host`.
- **Persistent sessions.** Today, killing the client closes the server. A "reattach" mode (session survives client exit, client can reconnect by peer_id) would give us what `tmux over mosh` gives today.

# drift-wormhole

**Magic-Wormhole-shaped file transfer over [DRIFT](../README.md).**

Send a file from one machine to another by pasting one line. End-to-end encrypted, no rendezvous server, no port forwarding, no certificate.

```
# sender:
$ drift-wormhole send vacation-photos.zip
hashing vacation-photos.zip (412.6 MiB)...

Ready to send: vacation-photos.zip (412.6 MiB)

Run on the recipient:

    drift-wormhole recv abc123...@192.168.1.42:54293

Waiting for them to connect... (Ctrl-C to cancel)
```

```
# recipient:
$ drift-wormhole recv abc123...@192.168.1.42:54293
connecting to peer abc123de...

Receiving: vacation-photos.zip (412.6 MiB)
  ================================  412.6 MiB / 412.6 MiB    187.4 MiB/s  ETA 0s

done — saved to ./vacation-photos.zip
```

## How it differs from Magic Wormhole

[Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) uses a SPAKE2 password-authenticated key exchange against a public mailbox server (`relay.magic-wormhole.io`) so the two sides identify each other by short codeword (e.g. `7-crossover-clockwork`). drift-wormhole instead identifies sides by their DRIFT pubkey:

| | Magic Wormhole | drift-wormhole |
|---|---|---|
| Side identity | ephemeral SPAKE2 codeword | persistent X25519 pubkey |
| Rendezvous server required | yes (`relay.magic-wormhole.io`) | no — direct or via any DRIFT bridge |
| Code is | 3 short words | full pubkey hex (long but pasteable) |
| Encrypted | yes (PAKE-derived) | yes (DRIFT AEAD between pubkeys) |
| Survives network change mid-transfer | partial | yes (DRIFT migration) |
| Multi-transport (UDP / TCP / WebSocket) | TCP-only | yes (`--bind` accepts scheme prefix) |
| Same identity across tools | n/a | yes (shares `~/.config/drift/identity.key` with drift-mosh, drift-http) |

The tradeoff drift-wormhole accepts: the "address" you paste is longer than `7-crossover-clockwork` (a 64-char hex pubkey + a host:port). In exchange, the dependency on a public mailbox server goes away, and the same pubkey works across every DRIFT-based tool you run.

## Install

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo install --path drift-wormhole --bin drift-wormhole
```

## Usage

### Send

```bash
drift-wormhole send <file>
```

By default binds UDP on an ephemeral port. To listen on multiple transports simultaneously (so the recipient can pick whichever wire works for their network), use repeated `--bind`:

```bash
drift-wormhole send vacation.zip \
    --bind udp://0.0.0.0:9100 \
    --bind tcp://0.0.0.0:9100 \
    --bind ws://0.0.0.0:443
```

The recipient command will be printed once per scheme; pick the one that fits their environment.

### Receive

```bash
drift-wormhole recv <PUBHEX>@<HOST>:<PORT> [--out-dir DIR] [--out NAME]
```

Forms accepted:

```
abc123...@192.168.1.42:54293          (defaults to udp://)
abc123...@udp://192.168.1.42:54293
abc123...@tcp://example.com:9100
abc123...@ws://relay.example.com:443
```

`--out-dir` overrides where the file is saved (default: current dir). `--out` overrides the filename — by default the recipient gets the sender's filename, sanitized to drop any path components.

### Verification

The sender hashes the file with SHA-256 before sending, includes the digest in the header, and the recipient verifies after writing. Mismatch → recipient rejects, sender exits non-zero, the on-disk file is left in place but flagged as corrupt in stderr.

## Where things live

- `~/.config/drift/identity.key` — your persistent 32-byte X25519 identity. **Shared across all DRIFT tools** (drift-mosh, drift-http, drift-wormhole). Auto-created on first run, mode 0600.

## Architecture

```
sender                                    recipient
──────                                    ─────────
 SHA-256 hash file                            
 bind DRIFT (udp/tcp/ws)                      
 print "drift-wormhole recv PUB@addr"         
 wait for stream ──┐                          
                   │                          │
                   │   open stream            │
                   │◀─────────────────────────┤
                   │                          │
                   │   bincode(Header)        │
                   ├─────────────────────────▶│
                   │                          │
                   │   raw file bytes         │
                   ├─────────────────────────▶│  write + hash
                   │                          │
                   │   bincode(Ack)           │
                   │◀─────────────────────────┤  verify SHA-256
                   │                          │
```

A single DRIFT stream carries the whole transfer. DRIFT's stream layer handles reliability, congestion control, and ordering; the wormhole layer is just `Header → bytes → Ack`.

## Tests

```bash
cd drift-wormhole/tests
./e2e.sh    # 256 KB random blob, two distinct identities, SHA-256 byte-fidelity check
```

## Future work

- **Multiple files / directories.** Currently single-file; recursive directory transfer would be a tarpipe wrapper or a header extension.
- **Resume on disconnect.** DRIFT migration handles transient network changes mid-transfer; an app-level resume marker (offset checkpoint) would let interrupted transfers pick up where they left off.
- **Short codeword UX.** A public DRIFT relay running a `code → pubkey` directory could give Magic-Wormhole-style "drift-wormhole recv 7-crossover-clockwork" UX without giving up the pubkey trust model. Out of scope for v1.
- **Native compression.** zstd over the stream for typically-compressible payloads.

## Portable (no-tokio) build

The default build is the full async tool over the tokio transport — every wire (udp/tcp/ws/iroh), progress bars, contacts. A second build drops tokio entirely and runs on [`drift-proto-std`](../drift-proto-std), so it compiles where tokio can't (Redox, other no-async std targets):

```bash
cargo build -p drift-wormhole                                          # native (default) — all wires
cargo build -p drift-wormhole --no-default-features --features portable # no tokio, tcp-only
```

Same `Header → bytes → Ack` protocol with SHA-256 verification, carried over `drift-proto-std::Connection`. Scope: **tcp-only**, and **not** wire-interoperable with the native build (native runs over DRIFT streams, portable over raw DATA) — portable talks to portable. The default build is unchanged.

## License

MIT. See [`LICENSE`](../LICENSE).

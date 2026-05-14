# Identity rotation in drift-vpn

drift-vpn identities are X25519 keypairs. When you want to retire one
keypair and start using a new one — routine key hygiene, hardware
swap, planned key roll — `drift-vpn rotate` generates the new
identity and a signed announce; each peer runs `rotate-verify` and
pastes the new pubkey into their config. No more re-typing 64 hex
chars on every host.

This document covers what rotation *can* do today (phase 1, shipped
in v0.14), what it *can't* do (lost-laptop is still hand-edited), and
the phase-2 plans that close the remaining gaps.

---

## TL;DR — what you run

You're rotating from old identity → new identity on this host:

```bash
sudo drift-vpn rotate \
    --in  /etc/drift-vpn/identity.key \
    --out /etc/drift-vpn/identity.new \
    --announce-out /tmp/rotation.hex
# prints: new pubkey + a 168-byte signed announce (hex)
```

You hand the announce blob to every peer (Signal, email, paste,
whatever you trust):

```bash
# Each peer runs:
drift-vpn rotate-verify \
    --expect-old-pub <your-old-pubkey-hex> \
    --announce       /tmp/rotation.hex
# prints: <new-pubkey-hex>   (on stdout, after verifying the signature)
```

Each peer replaces the `public_key = "<old>"` line for your peer with
the new pubkey in their `/etc/drift-vpn/config.toml`, restarts
drift-vpn, and you're done.

To complete the rotation on your side:

```bash
sudo systemctl stop drift-vpn
sudo mv /etc/drift-vpn/identity.key /etc/drift-vpn/identity.key.archive
sudo mv /etc/drift-vpn/identity.new /etc/drift-vpn/identity.key
sudo systemctl start drift-vpn
```

The handshake immediately uses the new key; peers accept it because
they've already swapped their copy of your pubkey.

---

## What rotation does

A `RotationAnnounce` is a 168-byte structure:

```
old_pub      [32 bytes]    the pubkey being retired
new_pub      [32 bytes]    the pubkey replacing it
issued_at_ms [8 bytes, big-endian]   wall-clock timestamp
nonce        [32 bytes]    fresh CSPRNG output (replay defense)
sig          [64 bytes]    XEdDSA signature with old's secret
```

The signed body is `old_pub || new_pub || issued_at_ms || nonce` —
the trailing `sig` carries the proof that the **holder of old_pub**
authorized this rotation. Receivers verify the signature with
`old_pub`, check the timestamp is fresh (default ±5 minutes), and
recover `new_pub` as the legitimate replacement.

The XEdDSA construction is Signal's curve25519 variant — same one
drift uses for federation presence tickets. No second keypair, no
new cryptographic primitive: the existing X25519 identity key signs
the rotation announce.

## What rotation does NOT do

**Lost-laptop / compromised-key rotation.**

If an attacker captures the secret of `old_pub`, they can sign their
own `RotationAnnounce` pointing at a key they control. There is no
central authority and no fall-back signer to break the tie. For
lost-laptop the workflow today is the same as WireGuard's and
Tailscale's: edit each peer's config file by hand to remove the
compromised pubkey.

The reason: rotation is **owner-driven**. It assumes the rotating
party still possesses the old secret. That assumption fails when the
secret has leaked.

Future versions (see "Phase 2" below) can layer on multi-peer
cosigning — "M of N other peers vouch for the new key" — which is
the only model that survives losing the old secret without a central
authority.

---

## Threat model

| | Owner-driven | Lost-laptop |
|---|---|---|
| Attacker has the OLD secret? | No | Yes |
| Phase-1 protection | Full: announce can only be signed by owner | None: attacker can sign too |
| Replay protection | 32-byte nonce + ±5 min freshness window | Same, but doesn't help — attacker has the key |
| Future fix | — | Phase-2 cosigning ("M of N peers vouch") |

Within the owner-driven model:

- **Forged-announce attack** — adversary tries to claim
  `new_pub = attacker_key`. Blocked: requires the OLD secret to sign.
- **Replay attack** — adversary records a real announce and replays
  it later. Blocked by `issued_at_ms` freshness check + nonce
  tracking on the peer.
- **Pre-signed-announce attack** — attacker captures the key briefly,
  pre-signs an announce to a key they control, releases it later.
  Blocked by freshness window (a pre-signed announce becomes stale
  in 5 minutes).
- **Downgrade / partial rollout** — adversary stops some peers from
  receiving the announce, leaving them on the old pubkey. Mitigated
  by the operator confirming every peer has updated before retiring
  the old identity file.

---

## Phase 1 (v0.14) vs Phase 2 (future)

**Phase 1 — what shipped:**

- `drift-core::rotation` module with `RotationAnnounce` + sign/verify.
- `drift-vpn rotate` / `drift-vpn rotate-verify` CLI.
- Out-of-band announce distribution (you copy/paste, email, send via
  Signal, etc.).
- Manual config update on each peer.

**Phase 2 — roadmap:**

- **On-tunnel broadcast.** A new wire packet type that ships the
  announce over already-established sessions, so peers automatically
  see it without out-of-band action.
- **Peer-side rotation table.** Persisted state mapping
  `old_pub → new_pub` per peer, so the daemon transparently accepts
  handshakes from the new key after verifying the announce.
- **Auto-acceptance flag.** `[interface] auto_accept_rotations = true`
  for fully-automatic rotation (the daemon updates the running route
  table); default off so a human keeps control.
- **Config rewrite helper.** `drift-vpn rotate-confirm <peer>` mutates
  the config file in place after the operator says "yes, accept this
  rotation."
- **Cosigning / lost-laptop story.** Threshold cosigning over peer
  identities — N peers vouch that "X has lost their key; the new key
  is Y." This is the only path to closing the lost-laptop gap
  without a central authority.

The phase-1 ↔ phase-2 boundary was a deliberate scoping call: ship
the cryptographic primitive + the human workflow first, layer the
auto-distribution on top once the primitive is battle-tested.

---

## API reference

### `drift-vpn rotate`

```
drift-vpn rotate [OPTIONS] --in <IN> --out <OUT>

  -i, --in <IN>                    Path to the EXISTING identity file
                                   [default: /etc/drift-vpn/identity.key]
  -o, --out <OUT>                  Path to write the NEW identity file
                                   (must not exist; mode 0600 on Unix)
      --announce-out <PATH>        Path to write the announce blob (hex)
                                   If omitted, the blob prints to stdout
```

Outputs (stderr): old pubkey, new pubkey, issued_at_ms, instructions
for peers.

Outputs (stdout): the announce hex blob (single line, 336 chars =
168 bytes × 2).

### `drift-vpn rotate-verify`

```
drift-vpn rotate-verify --announce <ANNOUNCE> --expect-old-pub <PUB>

      --announce <ANNOUNCE>        Announce blob — either hex or a file path
      --expect-old-pub <PUB>       Pubkey hex you currently have configured
                                   for this peer (the announce is rejected
                                   if its embedded old_pub doesn't match)
```

Exit codes: `0` on a verified announce, `1` on any failure (bad sig,
mismatched old_pub, stale timestamp, malformed wire form).

Output (stderr): rotation summary (from → to, age in ms).
Output (stdout): the new pubkey hex (parseable by scripts).

---

## Cryptographic details

XEdDSA signature over the 104-byte signed body. Verification recovers
the Edwards point from `old_pub`'s Montgomery u-coordinate (the
standard `MontgomeryPoint::to_edwards(sign=0)` reconstruction); the
canonical `(R, s)` Edwards verification then runs. See
`drift-core/src/xeddsa.rs` for the construction and
`drift-core/src/rotation.rs` for the rotation-specific framing.

The nonce is 32 random bytes (independent of the XEdDSA hedged-nonce
input, which is separately 64 random bytes). Receivers SHOULD persist
recently-seen nonces and reject duplicates; phase-1 leaves this
persistence to the operator's discretion since announces are
out-of-band and a duplicate announce shows up as an obviously-stale
timestamp.

The wire form is **exactly 168 bytes**. There are no length-prefixes,
type tags, or version bytes — the format is fixed and any deviation
is a parse failure. Future wire-format changes will get a new
identifier (e.g., `RotationAnnounceV2`) rather than altering this one.

---

## See also

- `drift-core/src/rotation.rs` — the protocol module + 7 unit tests
- `drift-core/src/xeddsa.rs` — the underlying signature primitive
- `drift-vpn/src/rotate.rs` — the CLI implementation + tests
- `drift-vpn/README.md` — configuration reference
- `drift-vpn/QUICKSTART.md` — full new-deployment walkthrough

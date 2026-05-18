# sec — security research testbed

Tools and scaffolding used during DRIFT's security audits. Not
shipped to users; not part of any binary.

## attack-relay

A tiny Rust binary (`sec/attack-relay/`) that sends raw forged
DRIFT packets at a bridge. Three subcommands:

- `relay` — open-relay PoC: send `PacketType::Data` (or
  `PacketType::Federated` with `--federated`) with a chosen
  `dst_id`. Pre-SEC.FIX.1 the bridge re-emitted those bytes to
  the victim; post-fix it drops them and bumps
  `forward_unauth_drops`.
- `enumerate` — peer-membership oracle PoC: probe N candidate
  dst_ids and count "real vs random" outcomes. Post-fix the side
  channel is gone (both drop identically).
- `flood` — HELLO-flood DoS: bogus HELLOs from random src_ids.
  Already mitigated by the cookie path.

The library-level regression test
(`drift/tests/attack_open_relay.rs`) covers the same scenarios
in-process across five adapters and runs in CI. Use `attack-relay`
only when you want to demonstrate the attack against a
live external bridge (docker, remote, etc.) — the in-process
test is the source of truth.

## docker

`sec/docker/` boots a three-container topology for live demos:

- `bridge` (10.99.0.10) — runs `drift bridge`
- `victim` (10.99.0.20) — federates through the bridge
- `attacker` (10.99.0.99) — runs `attack-relay`

Steps:

```
# 1. Generate fresh keys (do NOT commit them — gitignored)
mkdir -p sec/docker/keys
drift --identity sec/docker/keys/bridge.key keygen
drift --identity sec/docker/keys/victim.key keygen
python3 -c "d=open('sec/docker/keys/victim.key','rb').read(); \
            assert d[:4]==b'DRFT'; \
            open('sec/docker/keys/victim.hex','w').write(d[4:].hex())"

# 2. Update compose-open-relay.yml's --bridge URL to embed the
#    bridge pubkey (printed by `drift --identity .../bridge.key info`).

# 3. Build the cross-compiled image (requires the `cross` cargo
#    helper for linux/musl on non-Linux hosts).
bash sec/docker/build.sh

# 4. Run
cd sec/docker
docker compose -f compose-open-relay.yml up -d bridge victim
sleep 10
docker compose -f compose-open-relay.yml up attacker
docker logs sec-bridge | grep -E "forwarded|open-relay guard"
```

Expected outcome on a patched bridge: 5 "open-relay guard" lines,
zero "forwarded" lines from the attacker IP.

# DRIFT Protocol Specification

**Version 1** — wire-compatible with protocol version `0x1` and short-header version nibble `0x2`. This document describes the protocol as implemented in `drift-core` and `drift` at workspace commit `c3a7b4d` and later.

> **Status.** This is the working specification, written alongside the reference implementation. It is intended to be precise enough for an independent reimplementation. Where this spec and the Rust code diverge, the Rust code is currently authoritative — but please file a discrepancy. KAT vectors lock the wire format.

## 1. Scope &amp; goals

DRIFT is a pubkey-addressed encrypted transport. A peer's identity *is* its X25519 public key; there is no separate "address" concept on the protocol layer. Sessions provide:

- Mutual authentication via static keys (X25519 DH).
- Forward secrecy via per-session ephemeral DH.
- Replay protection.
- Optional 0-RTT-ish resumption.
- Multi-path / address-migration via path validation.
- AEAD-protected payload (ChaCha20-Poly1305).
- A multiplexed stream layer on top.

DRIFT runs over any byte-preserving transport — UDP, TCP, WebSocket, TLS, WebRTC, in-memory channels — through a single `PacketIO` adapter trait. The protocol does not depend on any specific lower-layer addressing scheme.

This spec covers:
- §2 Notation, primitives, and constants
- §3 Identity model
- §4 Wire format (long + short header, AEAD framing)
- §5 Packet type catalog
- §6 Handshake protocol
- §7 Data plane (DATA, replay, rekey, path validation)
- §8 Stream layer
- §9 Mesh routing
- §10 Federation (envelope, directory v2, presence tickets)
- §11 Transport adapters
- §12 Threat model
- §13 Test vectors

Application-layer protocols (drift-mosh, drift-vpn, drift-http, drift-git, drift-wormhole, drift-doh-relay) are out of scope for this spec — they are tools that *use* DRIFT.

## 2. Notation &amp; primitives

### 2.1 Notation

- All integer fields on the wire are **big-endian** unless explicitly noted otherwise.
- Byte ranges are written `[a..b]` meaning offsets `a` (inclusive) through `b` (exclusive), zero-indexed.
- `‖` denotes byte concatenation.
- "MUST", "MUST NOT", "SHOULD" follow RFC 2119 senses.

### 2.2 Cryptographic primitives

| Use | Primitive | Reference |
|---|---|---|
| Key agreement | X25519 | RFC 7748 |
| AEAD (data) | ChaCha20-Poly1305 (IETF, 96-bit nonce) | RFC 8439 |
| Hash (KDF, MAC) | BLAKE2b-256 | RFC 7693 |
| Hash (XEdDSA) | SHA-512 | FIPS 180-4 |
| Signature (presence tickets) | XEdDSA over Curve25519 | Signal XEdDSA spec |
| PRF (random nonce, ephemeral keys) | OS CSPRNG | platform |

Implementations MAY substitute equivalent FIPS-approved primitives but MUST NOT substitute primitives with different security properties (e.g., MD5, SHA-1, DES). The wire format is locked to the primitives above.

### 2.3 Constants

| Name | Value | Meaning |
|---|---|---|
| `PROTOCOL_VERSION` | `1` | Long-header version nibble (`bytes[0] >> 4`) |
| `SHORT_HEADER_VERSION` | `2` | Short-header version nibble |
| `HEADER_LEN` | `36` | Long-header size in bytes |
| `SHORT_HEADER_LEN` | `7` | Short-header size in bytes |
| `AUTH_TAG_LEN` | `16` | ChaCha20-Poly1305 tag |
| `KEY_LEN` | `32` | Session key length |
| `STATIC_KEY_LEN` | `32` | Identity key length |
| `NONCE_LEN` | `16` | Handshake nonce length |
| `PEER_ID_LEN` | `8` | Short identifier derived from pubkey |
| `FED_HEADER_LEN` | `130` | Federation-envelope fixed-header size |
| `TICKET_LEN` | `96` | Presence-ticket wire size |
| `DIRECTORY_HEADER_LEN` | `4` | FederationDirectory v2 header |
| `DIRECTORY_ENTRY_LEN` | `128` | FederationDirectory v2 entry (pubkey + ticket) |
| `MAX_DIRECTORY_ENTRIES` | `10` | Per-packet entry cap (v2) |
| `MAX_PAYLOAD` | derived | `MAX_PACKET − HEADER_LEN − AUTH_TAG_LEN` |
| `MAX_PACKET` | `~1500` | Implementation default; configurable |

### 2.4 Nonce construction

ChaCha20-Poly1305 nonces are 12 bytes. DRIFT derives them deterministically per packet:

```
nonce = [direction(1) ‖ 0x00 ‖ 0x00 ‖ 0x00 ‖ packet_type(1) ‖ 0x00 ‖ 0x00 ‖ 0x00 ‖ seq(4 BE)]
```

Where:
- `direction = 0` for the initiator, `1` for the responder.
- `packet_type` is the 1-byte PacketType enum value (§5).
- `seq` is the 32-bit big-endian sequence number from the header.

The direction byte guarantees initiator and responder nonces are disjoint even if their `seq` counters overlap (which they normally do, since each side counts independently). The `packet_type` byte namespaces nonces across control and data packets within one direction.

### 2.5 Canonical AAD

The AEAD AAD for any DRIFT packet is the long header bytes with `hop_ttl` (offset 28) zeroed. This lets intermediate mesh forwarders decrement TTL without invalidating the end-to-end auth tag.

```
AAD = header_bytes[..36] with header_bytes[28] = 0
```

For short-header DATA packets, the AAD is the entire 7-byte short header (no field needs zeroing; short headers carry no TTL).

### 2.6 Session key derivation

The handshake produces a 32-byte session key via BLAKE2b:

```
session_key = BLAKE2b-256(
    "drift-session-v2" ‖
    static_dh(a_static, b_static) ‖
    ephemeral_dh(a_ephemeral, b_ephemeral) ‖
    client_nonce(16) ‖
    server_nonce(16)
)
```

Both sides compute the same key independently. `static_dh` provides authentication; `ephemeral_dh` provides forward secrecy.

Rekey derivation:

```
new_session_key = BLAKE2b-256("drift-rekey-v1" ‖ old_session_key ‖ salt(32))
```

## 3. Identity model

### 3.1 Static identity keys

Each DRIFT endpoint holds a long-term X25519 keypair (`Identity`). The public half — 32 bytes — is the endpoint's network identity. There is no notion of "username" or "address" on the protocol layer.

### 3.2 PeerId derivation

A short 8-byte identifier (`PeerId`) is derived from a static public key for wire compactness:

```
PeerId = BLAKE2b-256("drift-peer-id-v1" ‖ pubkey)[0..8]
```

`PeerId` appears in the long header's `src_id` and `dst_id` fields. Collisions in this 8-byte truncation are bounded by the birthday paradox at √(2^64) = ~4 billion peers; implementations MUST treat a PeerId collision as a hard error and refuse the colliding session.

### 3.3 ECDH contributory-behavior check

X25519 has a small subgroup of low-order points that produce a zero shared secret regardless of the other party's private key. An attacker who substitutes a peer's pubkey for one of these points can predict the session key without knowing the private key.

Implementations MUST check that the shared secret is non-zero before deriving keys. `x25519-dalek::SharedSecret::was_contributory()` is the reference check.

## 4. Wire format

### 4.1 Long header (`HEADER_LEN = 36` bytes)

Used for every packet type except DATA on established sessions.

```
[0]      version_and_flags  (u8)
              high nibble: version (= 1)
              low nibble: flags (FLAG_ROUTED = 0x1, FLAG_COALESCE = 0x2)
[1]      packet_type        (u8, see §5)
[2..4]   deadline_ms        (u16 BE — coalesce / deadline-aware traffic)
[4..8]   seq                (u32 BE — AEAD nonce + replay window)
[8..12]  supersedes         (u32 BE — coalesce group)
[12..20] src_id             (8-byte PeerId of sender)
[20..28] dst_id             (8-byte PeerId of recipient)
[28]     hop_ttl            (u8 — decremented by mesh forwarders; zeroed in AAD)
[29]     reserved           (u8, MUST be 0)
[30..32] payload_len        (u16 BE)
[32..36] send_time_ms       (u32 BE — ms since session epoch)
```

After the header, the AEAD-sealed body follows: `ciphertext ‖ auth_tag(16)`. The sealed plaintext is the packet-type-specific payload (§5).

### 4.2 Short header (`SHORT_HEADER_LEN = 7` bytes)

Used only for `PacketType::Data` on an Established direct session (no mesh forwarding, hop_ttl == 1). Saves 29 bytes per packet by replacing redundant fields with a 2-byte connection ID.

```
[0]      version_nibble_and_flags  (high nibble: version = 2)
[1..3]   connection_id             (u16 BE — receiver looks up in CID map)
[3..7]   seq                       (u32 BE)
[7..]    ciphertext ‖ auth_tag
```

Both sides derive each other's CIDs deterministically at session-key-installation time:

```
initiator_rx_cid = BLAKE2b-256("drift-cid-init-v1" ‖ session_key)[0..2]
responder_rx_cid = BLAKE2b-256("drift-cid-resp-v1" ‖ session_key)[0..2]
```

The initiator sends with `responder_rx_cid`, vice versa. No extra round-trips.

A receiver MUST first check `bytes[0] >> 4`: `0x1` → long header, `0x2` → short header. Anything else is invalid.

### 4.3 Decoding rules

A decoder MUST:

1. Reject packets shorter than `HEADER_LEN` (long) or `SHORT_HEADER_LEN + AUTH_TAG_LEN` (short).
2. Reject long headers whose version nibble ≠ `PROTOCOL_VERSION`.
3. Reject unknown `packet_type` values (return `DecodeError`).
4. Reject long headers whose `reserved` byte (offset 29) is nonzero. (RECOMMENDED — current implementations accept and ignore, but future versions may use this byte.)
5. Decrypt the body with AAD = `canonical_aad(header)`.

## 5. Packet type catalog

| Value | Name | Payload | Use |
|---|---|---|---|
| 1 | `Hello` | client_static_pub(32) ‖ client_ephemeral_pub(32) ‖ client_nonce(16) ‖ [cookie blob] | Handshake step 1 |
| 2 | `HelloAck` | server_ephemeral_pub(32) ‖ server_nonce(16) ‖ auth_tag(16) | Handshake step 2 |
| 3 | `Data` | application bytes | Established-session data |
| 6 | `Beacon` | mesh route advertisement | Periodic mesh keepalive + routing |
| 8 | `Challenge` | cookie blob | DoS mitigation pre-handshake |
| 9 | `PathChallenge` | 8 random bytes | Address-migration probe |
| 10 | `PathResponse` | echo of PathChallenge bytes | Confirms reachability at new addr |
| 11 | `Close` | (none) | Graceful session teardown |
| 12 | `RekeyRequest` | salt(32) | In-place rekey, sealed under OLD key |
| 13 | `RekeyAck` | salt(32) | Rekey confirmation, sealed under OLD key |
| 14 | `ResumeHello` | ticket_blob | Fast resumption attempt |
| 15 | `ResumeAck` | server_nonce(16) | Resumption confirmation |
| 16 | `ResumptionTicket` | ticket_blob | Server-issued resumption ticket |
| 17 | `Ping` | (timestamp) | RTT measurement |
| 18 | `Pong` | (echoed timestamp) | RTT response |
| 19 | `Federated` | federation envelope (§10.1) | Cross-bridge routing |
| 20 | `FederationDirectory` | directory payload (§10.3) | Bridge-to-bridge client announcement |
| 21 | `PresenceTicket` | ticket bytes (§10.2) | Client → bridge ticket emission |

Reserved / unassigned: `0`, `4`, `5`, `7`, `22+`. Implementations MUST reject unknown values.

## 6. Handshake protocol

### 6.1 State machine

Each peer's view of the session progresses through these states:

```
   Idle ──send Hello──▶ AwaitingAck ──recv HelloAck──▶ Established
                              │
                              │ (recv Challenge)
                              ▼
                       Cookie-In-Hand ──resend Hello+cookie──▶ AwaitingAck
```

- `Idle`: no in-flight handshake.
- `AwaitingAck`: client has sent HELLO and is waiting for HELLO_ACK.
- `Cookie-In-Hand`: server demanded a cookie; client must resend HELLO with the cookie blob attached.
- `Established`: session key derived; bidirectional encrypted traffic flows.

### 6.2 HELLO

The initiator sends:

```
plaintext = [
  client_static_pub  (32 bytes — sender's identity)
  client_ephemeral_pub (32 bytes — fresh per session)
  client_nonce       (16 bytes — fresh per session)
  [optional cookie blob — see §6.5]
]
```

`Hello.seq` MUST be a fresh value, monotonically larger than any previous Hello from this client to this destination.

The HELLO is sealed under a key derived from `static_dh(client, server)` alone (no ephemeral DH yet). The server uses its static private + client_static_pub from the payload to derive the same key.

### 6.3 HELLO_ACK

The responder sends:

```
plaintext = [
  server_ephemeral_pub (32 bytes — fresh per session)
  server_nonce         (16 bytes — fresh per session)
  auth_tag             (16 bytes — MAC over the static-DH session-derivation tag)
]
```

After both sides see each other's `(static_pub, ephemeral_pub, nonce)` they derive the full session key per §2.6 and transition to Established.

### 6.4 Replay window

Each direction maintains a sliding 256-bit replay window. A received DATA packet's `seq`:
- MUST be within `[max_seen − 255, max_seen + ∞)`.
- MUST NOT have been seen before (bit in the window set).

Packets older than the window are dropped. The window slides forward on every new max `seq`.

### 6.5 Challenge / cookie mechanism

To prevent amplification attacks (an attacker spoofing source addresses to make DRIFT send big HELLO_ACKs to victims), a server MAY respond to an initial HELLO with `Challenge` instead of `HelloAck`. The `Challenge` carries a cookie blob the client MUST echo in a follow-up `Hello`. The cookie binds the source address; mismatched-address replays fail.

Cookie blob structure:

```
[address(16) ‖ timestamp_ms(8) ‖ HMAC-BLAKE2b(server_cookie_key, address ‖ timestamp_ms)]
```

`server_cookie_key` is rotated every ~10 minutes. Cookies older than the rotation window are rejected.

### 6.6 Resumption

If a client holds a valid `ResumptionTicket` from a previous session with this server, it MAY send `ResumeHello` instead of `Hello`. The ticket carries an exportable copy of the previous session key sealed under the server's static identity. If the server accepts, it sends `ResumeAck` (16-byte nonce) and both sides derive a new session key from the resumed material.

Tickets have a 1-hour default TTL. A resumption attempt with an expired or rejected ticket falls back to a full handshake transparently.

After a `restart_handshake()` call, the cached ticket MUST be cleared — otherwise the next `send_data` will pick the now-invalid ticket and trigger a `ResumeHello` that the fresh-state server can't process.

### 6.7 Post-quantum hybrid handshake (`FLAG_PQ_HYBRID`)

DRIFT supports an X25519 + ML-KEM-768 hybrid key exchange for sessions whose long-term confidentiality must survive a future quantum adversary that can break X25519 (the "harvest now, decrypt later" threat). Both halves of the hybrid feed the session key — an attacker who breaks one must still solve the other, and ML-KEM-768 is post-quantum-secure.

**Default-on as of 2026-05-16.** `TransportConfig::default()` returns `hybrid_pq = true`. The originator's HELLO carries the header flag `FLAG_PQ_HYBRID` (`1 << 2`) and appends an ML-KEM-768 encapsulation key; the responder's HELLO_ACK mirrors the flag and appends the ciphertext. Classical peers (no flag) are still accepted for interop — see the negotiation table below. To opt out (legacy peers, bandwidth-constrained devices), set `hybrid_pq = false` in the config or pass `--no-hybrid-pq` to `drift bridge`.

#### Wire format

`Hello` body when `FLAG_PQ_HYBRID` is set:

```
[
  client_static_pub      (32)
  client_ephemeral_pub   (32)
  client_nonce           (16)
  [optional cookie blob — see §6.5] (24 if present)
  client_mlkem_ek        (1184)    ← always last; field order is: base ‖ cookie? ‖ pq_ek
]
```

`HelloAck` body when `FLAG_PQ_HYBRID` is set:

```
[
  server_ephemeral_pub   (32)
  server_nonce           (16)
  auth_tag               (16)      ← AEAD tag over header + server_eph_pub + server_nonce + server_mlkem_ct
  server_mlkem_ct        (1088)
]
```

The auth tag's AAD includes `server_mlkem_ct`, so any tampering with the ciphertext changes the client's derived session key and fails the AEAD open.

#### Session-key derivation

Hybrid mode replaces the classical `derive_session_key` with `derive_hybrid_key`:

```
session_key = BLAKE2b-256(
    "drift-hybrid-pq-v2"
  ‖ static_dh           (32)
  ‖ ephemeral_dh        (32)
  ‖ mlkem_ss            (32)   ← from ML-KEM-768 encap/decap
  ‖ client_nonce        (16)
  ‖ server_nonce        (16)
)
```

The transcript is the classical KDF's transcript with `mlkem_ss` inserted and a fresh domain separator. All classical properties (forward secrecy from the ephemeral DH, identity binding from the static DH) carry over unchanged.

#### Negotiation rules

A peer's `hybrid_pq` config setting is local. The wire signal is the per-handshake `FLAG_PQ_HYBRID` flag. The two interact as follows:

| Originator setting | `FLAG_PQ_HYBRID` on HELLO | Responder setting | Disposition |
|---|---|---|---|
| `false` | not set | `false` | Classical handshake (default behavior). |
| `false` | not set | `true` | Classical handshake — responder accepts non-PQ originators for backwards compatibility. |
| `true` | set | `true` | Hybrid handshake. |
| `true` | set | `false` | **Refused**. Responder logs `rejected HELLO with FLAG_PQ_HYBRID` and returns no reply. The originator MUST NOT silently retry without the flag (silent downgrade would defeat the PQ guarantee the application opted into). |

On the originator side, a `HelloAck` whose `FLAG_PQ_HYBRID` doesn't match the originator's outbound HELLO is treated as a protocol violation and the handshake is aborted.

#### Wire cost

Hybrid HELLO is ~1264 bytes (vs. 80 classical); hybrid HELLO_ACK is ~1152 bytes (vs. 64 classical). Both fit well under typical MTUs. The extra cost is per-handshake only — established sessions have identical DATA framing.

## 7. Data plane

### 7.1 DATA packet

Application payload sealed under the session key, sent in either long-header (with mesh routing / coalesce / deadline metadata) or short-header (the fast path on direct established sessions) form.

Long-header DATA may carry the `FLAG_COALESCE` flag to mark a packet as supersedable — a later DATA with the same `supersedes` value cancels delivery of earlier coalesced packets that haven't yet been read. Used for high-frequency state updates (cursor positions, telemetry) where only the latest matters.

### 7.2 Rekey

Either side MAY initiate an in-place rekey by sending `RekeyRequest(salt: 32 bytes)` sealed under the *current* session key. The recipient computes `new_key = BLAKE2b-256("drift-rekey-v1" ‖ old_key ‖ salt)` and replies with `RekeyAck(same salt)` also sealed under the old key.

For a grace window (typically 5 seconds), both peers accept packets sealed under either the old or the new key, then drop the old key. This prevents in-flight packets from being lost across the boundary.

Rekeys are triggered automatically after `2^28` packets or 1 hour, whichever comes first. Manual rekey via `Transport::rekey(peer_id)` is also supported.

### 7.3 Path validation (address migration)

A peer's `(IP, port)` may change mid-session (NAT rebinding, network handoff, multi-homing). DRIFT does NOT commit a new address based on receiving a DATA packet from it — that would let an attacker spoof the source address to redirect traffic.

Instead, when DATA arrives from an unexpected source address, the receiver SHOULD send `PathChallenge(8 random bytes)` to the *new* address. The sender at the new address MUST echo the bytes back in `PathResponse`. Only on receiving a matching `PathResponse` does the receiver commit the new address.

`PathChallenge` and `PathResponse` are sealed under the session key, so an off-path attacker can't forge a response without knowing the key.

## 8. Stream layer

DRIFT carries an optional reliable, multiplexed stream protocol over DATA. Streams are addressed by 32-bit IDs, assigned by parity (smaller PeerId uses even IDs, larger uses odd) to avoid collisions in concurrent open.

### 8.1 Stream frame types

DATA payloads (when used by the stream layer) are tagged with one of:

- `0x01` `Open(stream_id, initial_seq)` — declare a new stream.
- `0x02` `Data(stream_id, seq, body)` — payload chunk.
- `0x03` `Close(stream_id)` — graceful close.
- `0x04` `Ack(stream_id, seq)` — reliability ack.
- `0x05` `Bye(stream_id)` — abrupt close.
- `0x06` `Datagram(body)` — unreliable best-effort delivery (no stream state).

### 8.2 Reliability

Per-stream sequence numbers. Receivers buffer out-of-order chunks until contiguous, ACK individual `seq` values. Senders retransmit unacked chunks with exponential backoff.

A receiver SHOULD only auto-create stream state on receipt of `Data(stream_id, seq=0, …)` — implicitly opening a stream from a mid-stream chunk lets stale retransmits inject phantom streams under fresh-session ID ranges. (This was a real bug fixed during early protocol shakedown.)

### 8.3 Per-peer limits

- Maximum live streams per peer: `1024` (default; configurable).
- Receive buffer per stream: bounded; receivers SHOULD drop new out-of-order chunks rather than allow unbounded buffering.

## 9. Mesh routing

DRIFT supports protocol-level mesh forwarding. A peer with `hop_ttl > 1` in its outer header may be forwarded by intermediate nodes that hold a session with both endpoints (or with a learned next-hop).

### 9.1 Beacons

Peers periodically broadcast `Beacon` packets advertising routes:

```
beacon_payload = [
  count(u16 BE) ‖
  count * (peer_id(8) ‖ cost(u16 BE) ‖ hop_count(u8) ‖ last_seen_ms(u24 BE))
]
```

Each receiver merges advertised routes into its `RoutingTable`. Routes are scored by cost (lower = better) with hysteresis to avoid flapping.

### 9.2 Hop TTL

The outer-header `hop_ttl` decrements at each forwarder. A receiver with `hop_ttl > 1` and no local session for `dst_id` MUST consult its routing table and forward to the next hop (re-sealing the outer packet under the next-hop session key). When `hop_ttl <= 1` the receiver delivers locally or drops with `UnknownPeer`.

A forwarder MUST refuse to forward a packet whose `hop_ttl` exceeds an implementation cap (default 16) — prevents looping packets from saturating the mesh.

### 9.3 `peer.last_seen` updates

Beacons count as liveness signals — receivers MUST update `peer.last_seen` on every received Beacon, not only on DATA. Without this, idle-but-alive sessions look dead to watchdogs.

## 10. Federation

DRIFT supports cross-bridge routing through an explicitly-trusted set of peer bridges. Federation lets clients reach each other through one or more intermediate bridges they each trust, without either client running its own globally-reachable server.

The federation trust model is **per-bridge transitive trust**, equivalent to Matrix's homeserver-to-homeserver federation or XMPP's server-to-server. A client trusts its bridge to relay accurately; the bridge trusts its federation peers to relay accurately. There is no global trust root.

### 10.1 Federation envelope (`PacketType::Federated = 19`)

Cross-bridge packets carry a 130-byte envelope as the AEAD-sealed inner payload:

```
[0..32]    target_bridge_pub  (32 — next-hop bridge; all-zero sentinel = "consult directory")
[32..64]   target_client_pub  (32 — final recipient)
[64..96]   source_bridge_pub  (32 — originator's bridge, carried unchanged across hops)
[96..128]  source_client_pub  (32 — originating client)
[128..130] payload_len        (u16 BE)
[130..]    payload            (opaque to bridges — typically a full inner DRIFT packet
                               sealed under the client↔client session key)
```

The all-zero `target_bridge_pub` is the `UNKNOWN_BRIDGE_PUB` sentinel: clients that don't know which bridge holds the target can set this and let any bridge in the chain resolve via its directory.

### 10.2 Presence tickets (XEdDSA)

A presence ticket is a client's cryptographic attestation that it is connected to a specific bridge and authorizes that bridge to announce it in directory updates.

Without tickets, a malicious federated bridge could announce arbitrary pubkeys and hijack their inbound traffic. Tickets make announcements third-party-verifiable: the bridge can only announce pubkeys for which it holds a valid signed ticket.

#### 10.2.1 Wire format

```
[0..8]    expiry_ms  (u64 BE — unix-ms timestamp after which the ticket is invalid)
[8..32]   nonce      (24 bytes of caller-supplied randomness)
[32..96]  sig        (64-byte XEdDSA signature)
```

Total: 96 bytes.

#### 10.2.2 Signed message

The signature covers a canonical 64-byte message:

```
signed_msg = bridge_pub(32) ‖ expiry_ms(8 BE) ‖ nonce(24)
```

The `bridge_pub` here is the bridge the ticket is for. On the wire the ticket does NOT carry `bridge_pub` — receivers reconstruct it from context (the announcing bridge's identity in FederationDirectory, or the verifier's own identity when receiving a `PacketType::PresenceTicket`). This is the property that prevents ticket replay across bridges: a ticket signed for bridge X never verifies as a ticket-for-bridge-Y.

#### 10.2.3 XEdDSA construction

Per the Signal XEdDSA specification, curve25519 variant:

**Sign:**
1. Clamp the X25519 private key per RFC 7748 §5; treat as Edwards-curve scalar `a`.
2. Compute `A = a · B` (Ed25519 basepoint). If `A.y` sign bit is set, negate both `a` and `A`.
3. `r = SHA-512(prefix ‖ a_bytes ‖ M ‖ Z) mod q` where `prefix = 0xFE ‖ 0xFF×31` (Curve25519 domain separator) and `Z` is 64 bytes of fresh CSPRNG entropy.
4. `R = r · B`.
5. `h = SHA-512(R ‖ A_bytes ‖ M) mod q`.
6. `s = (r + h·a) mod q`.
7. Output: `R(32) ‖ s(32)`.

**Verify:**
1. Reconstruct `A` from the Montgomery u-coordinate with sign = 0.
2. Reject small-order points (`A.is_small_order()` or `R.is_small_order()`).
3. Decompress `R` from the first 32 bytes of the signature.
4. Parse `s`, rejecting non-canonical scalars (`s ≥ q`).
5. `h = SHA-512(R_bytes ‖ A_bytes ‖ M) mod q`.
6. Check `s · B == R + h · A`.

Reference implementation: `drift-core::xeddsa::{sign, verify}`.

#### 10.2.4 Lifetime &amp; refresh

A ticket's `expiry_ms` SHOULD be no more than 1 hour beyond emission. Clients SHOULD re-emit a fresh ticket at half-lifetime. drift-mosh-server's reference flow emits a 10-minute-lifetime ticket every 5 minutes.

### 10.3 FederationDirectory v2 (`PacketType::FederationDirectory = 20`)

Bridge-to-bridge announcement of connected clients. Sent only between bridges that hold each other in their `federation_table`; recipients drop announcements from non-federated senders.

#### 10.3.1 Wire format

```
[0]       version  (u8) = 2
[1]       reserved (u8) = 0
[2..4]    count    (u16 BE — number of entries)
[4..]     entries  (count * 128-byte entries)

Each entry:
  [0..32]    client_pub  (32 bytes)
  [32..128]  ticket      (96 bytes — see §10.2.1)
```

`MAX_DIRECTORY_ENTRIES = 10` per packet. Bridges with more clients send multiple announcements per cycle.

Receivers MUST:
1. Reject packets with `version ≠ 2` (silently drop — peer is on an incompatible version).
2. Reject packets with non-zero `reserved`.
3. Verify each entry's ticket against the announcing bridge's pubkey using `verify_ticket(client_pub, announcer_pub, ticket, now_ms)`.
4. Drop entries that fail verification individually, increment `federation_invalid_tickets_dropped`, and process the remaining entries normally — one bad entry MUST NOT invalidate the rest of the announcement.

#### 10.3.2 Idempotent-set semantics

Each FederationDirectory packet is the COMPLETE current client set of the announcing bridge, not a delta. Receivers MUST prune any previously-stored entries attributed to this announcer that are missing from the new set. This propagates disconnections within one announce interval (~7s) instead of waiting out the TTL.

#### 10.3.3 First-write-wins

If two announcers claim the same client pubkey, the receiver MUST retain the earlier entry. A malicious federated bridge cannot displace a legitimate routing entry by racing to announce. The first-write-wins property is bounded by the directory TTL (20s) and by send-failure eviction (entries pointing at unreachable next-hops are evicted on send failure).

#### 10.3.4 Source authentication

Only senders in the receiver's `federation_table` may write to the receiver's `peer_directory`. An ordinary connected client whose announcement bytes happen to decode as a valid v2 FederationDirectory MUST have their announcement rejected; the source-auth gate fires before the per-entry ticket check.

### 10.4 PresenceTicket emission (`PacketType::PresenceTicket = 21`)

Client → bridge path for tickets. The client signs a ticket for the bridge it's connected to and sends the 96-byte ticket as the inner payload of a `PresenceTicket` packet (sealed under the existing session). The bridge stores the ticket keyed by the client's session-authenticated static pubkey.

Bridges MUST verify the ticket signature against the sender's authenticated pubkey AND against the bridge's own pubkey before storing — a client trying to slip a ticket signed for a different bridge has the entry silently dropped.

### 10.5 `FindPeer` (`PacketType::FindPeer = 22`)

Reactive peer-lookup query. Sent by a bridge that receives a `Federated` envelope with `target_bridge_pub == UNKNOWN_BRIDGE_PUB` and either misses the local-clients table AND its `peer_directory`, OR (if the entry exists) finds it stale. Asks every federation peer "do you host `target_client_pub`?" Recipients reply with `PeerHere` on a local hit.

Wire format inside the AEAD-sealed body — 81 bytes:

```
[0..32]    target_client_pub        (the pubkey we're looking for)
[32..40]   query_id                 (u64 BE — random, used for dedup + reply correlation)
[40..41]   ttl                      (u8 — hops remaining; decremented at each forwarder, MUST be > 0)
[41..73]   originator_bridge        (the bridge that started the query)
[73..81]   originator_query_at_ms   (u64 BE — for deadline enforcement)
```

Constants (`drift::transport::find_peer`):

| Name | Value |
|---|---|
| `MAX_FIND_TTL` | 4 |
| `MAX_FIND_DEADLINE_MS` | 2000 |
| `QUERY_DEDUP_TTL_MS` | 10000 |
| `NEG_CACHE_TTL_MS` | 5000 |

Receiving bridges MUST:
1. Verify the sender is in `federation_table` (clients can't trigger searches of our local-clients table — information disclosure gate).
2. Drop on `query_id` already in `recent_queries` (loop prevention + replay dedup).
3. Drop on `originator_query_at_ms + MAX_FIND_DEADLINE_MS < now`.
4. On local hit (target is in our `presence_tickets` AND has an Established session), reply with `PeerHere` carrying our bridge's pubkey + the client's presence ticket.
5. On miss with `ttl > 1`, forward to every federation peer EXCEPT the sender; record `(query_id, sender_peer_id)` in `forwarded_queries` so the eventual `PeerHere` can be routed back upstream.
6. Otherwise drop silently.

### 10.6 `PeerHere` (`PacketType::PeerHere = 23`)

Reply to `FindPeer`. Carries a chain of `(bridge_pub, ticket)` entries ordered terminal-to-origin: index 0 is the bridge that actually hosts the client (whose ticket is the client-signed XEdDSA `PresenceTicket`); indices 1..N are intermediate forwarders (whose tickets are bridge-self-signed hop attestations — see §10.9).

Wire format — variable length, `41 + path_len * 128` bytes:

```
[0..32]    target_client_pub
[32..40]   query_id                 (matches the FindPeer)
[40..41]   path_len                 (u8 — 1..=MAX_FIND_TTL)
[41..]     path_entries             (path_len * 128 bytes)

Each path_entry (128 bytes):
  [0..32]    bridge_pub
  [32..128]  ticket                 (96 bytes — see §10.2.1)
```

Receivers MUST:
1. Source-auth (sender in `federation_table`).
2. Verify `path[0].ticket` against `(target_client_pub, path[0].bridge_pub, now)` using `verify_ticket` (§10.2).
3. Verify each `path[1..].ticket` as a hop attestation against `(path[i].bridge_pub, query_id, now)` using `verify_hop_attestation` (§10.9). A malicious bridge cannot forge a path entry for a bridge that didn't participate.
4. Insert `target_client_pub → (sender_peer_id, now)` into `peer_directory`.
5. If `query_id` is in our `pending_finds` (we originated): flush queued waiter envelopes through the resolved next-hop.
6. If `query_id` is in our `forwarded_queries` (we relayed for someone): append our own `(bridge_pub, hop_attestation)` to the path and re-emit upstream. `path.len() < MAX_FIND_TTL` MUST be checked before append.

### 10.7 `PeerGone` (`PacketType::PeerGone = 24`)

Broadcast emitted by a bridge to every federation peer the moment a local client disconnects. Lets receivers evict cached routing immediately instead of waiting for the next idempotent-set FederationDirectory announce (~7s).

Wire format — 72 bytes:

```
[0..32]   client_pub               (the disconnected client)
[32..40]  emitted_at_ms            (u64 BE — wall-clock at emission, for tiebreak)
[40..72]  bridge_pub               (emitting bridge; redundant with transport-level source but
                                    carried inside the AEAD for forward-compat with future
                                    multi-hop forwarding)
```

Reception:
1. Source-auth (sender in `federation_table`).
2. Anti-spoof: `bridge_pub` MUST equal the AEAD-authenticated sender's pubkey.
3. Evict the `peer_directory` entry for `client_pub` ONLY if the cached entry's next-hop pubkey is the emitting bridge. A `PeerGone` from bridge A MUST NOT evict a route through bridge B.

### 10.8 `FindPeerHashed` (`PacketType::FindPeerHashed = 25`)

Privacy-mode variant of `FindPeer`. The originator hashes the target pubkey with a fresh per-query salt; transit bridges that forward the query see only `SHA-256(target_pub || salt)`. Bridges that host local clients scan their presence tickets, hashing each client_pub under the same salt, and reply with `PeerHere` (carrying the real target pubkey) on a match.

Wire format — 97 bytes:

```
[0..16]    salt                       (16 bytes, per-query random)
[16..48]   target_hash                (SHA-256(target_pub || salt))
[48..56]   query_id                   (u64 BE)
[56..57]   ttl                        (u8 — same semantics as FindPeer)
[57..89]   originator_bridge          (32 bytes)
[89..97]   originator_query_at_ms     (u64 BE)
```

Hashing function:

```text
target_hash = SHA-256(target_pub(32) || salt(16))
```

Opt-in via `TransportConfig::find_peer_mode = OriginateHashed`. Receivers process exactly like `FindPeer` but compare hashes instead of pubkeys when scanning local clients.

Privacy property: a malicious forwarder logging every query it sees gets `(salt, hash)` pairs — useless without a candidate target list. A determined adversary with a precomputed table can still identify queries for known pubkeys. Once a bridge finds a match and replies with `PeerHere`, the reply path carries the real target pubkey through transit bridges; the privacy benefit is bounded to the query fan-out phase, not the answer phase.

### 10.9 Hop attestations

Bridge-self-signed XEdDSA attestations used in `PeerHere.path[1..]` (intermediate forwarders). Distinct from presence tickets (§10.2) via a domain-separation tag, so the two cannot be substituted for each other.

#### 10.9.1 Wire format

Same 96-byte shape as a presence ticket — identical bytes on the wire. The signed message differs.

```
[0..8]    expiry_ms  (u64 BE)
[8..32]   nonce      (24 bytes)
[32..96]  sig        (64-byte XEdDSA)
```

#### 10.9.2 Signed message

The signature covers a canonical 88-byte message:

```text
signed_msg = "DRIFT-HOP"(9) || bridge_pub(32) || query_id(8 BE) || expiry_ms(8 BE) || nonce(24)
```

`bridge_pub` is the forwarder signing the attestation. The `"DRIFT-HOP"` prefix is the domain-separation tag preventing presence-ticket / hop-attestation substitution.

#### 10.9.3 Lifetime

Hop attestations SHOULD use a short lifetime — 60s is the reference value. The expiry-binding limits the value of a stolen attestation.

#### 10.9.4 Verification

```text
verify_hop_attestation(bridge_pub, query_id, ticket, now_ms):
    require ticket.expiry_ms > now_ms
    msg = "DRIFT-HOP" || bridge_pub || query_id || ticket.expiry_ms || ticket.nonce
    return xeddsa.verify(bridge_pub, msg, ticket.sig)
```

### 10.10 `handle_federated` dispatch

When a receiver decrypts a `Federated` envelope, it dispatches one of three cases:

1. **`target_client_pub == our_pub`** — deliver to local app. Auto-update the federation-reply state for the source: `federated_via = sender_peer_id`, `federated_target_bridge_pub = source_bridge_pub`. Replies to the source go back through this path. The state MUST be refreshed on every receipt (not only first), so that a client roaming to a different on-ramp bridge has its replies routed to the current path.

2. **`target_bridge_pub == our_pub`** — forward to a local client whose pubkey matches `target_client_pub`. Bridges MUST NOT auto-register the original sender as a federated peer in this case (closes a routing-table-poisoning hole).

3. **else** — forward via federation. If `target_bridge_pub == UNKNOWN_BRIDGE_PUB`, FIRST check if `target_client_pub` is one of our own local clients (Established session + matching pubkey) — on hit, treat as case-2 (rewrite to our pubkey, deliver locally). On miss, look up `target_client_pub` in `peer_directory`. On miss + `find_peer_mode != Disabled`, originate a `FindPeer` (§10.5) or `FindPeerHashed` (§10.8 if `OriginateHashed`) to every federation peer and queue the envelope in `pending_finds`. If `target_bridge_pub != UNKNOWN_BRIDGE_PUB`, look up in `federation_table`. Rewrite the envelope's `target_bridge_pub` to the resolved next-hop bridge's pubkey before forwarding. On send failure, evict all directory entries pointing at the failed next-hop.

The source-authentication check fires before all three dispatch cases: when `target_client_pub != our_pub`, the envelope's `source_*_pub` fields MUST match the authenticated sender unless the sender is in our `federation_table`. Federation peers are trusted to attest source identities on behalf of their own clients; ordinary clients must name themselves.

## 11. Transport adapters

DRIFT's `PacketIO` trait is the single integration point for lower-layer transports:

```rust
trait PacketIO {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
```

A `send_to` MUST deliver `buf` as a single atomic unit. A `recv_from` MUST return one complete DRIFT packet per call, never a fragment.

### 11.1 UDP

Native packet boundaries. No framing needed. SocketAddr is the actual remote.

### 11.2 TCP

Stream-oriented; DRIFT applies a u16-big-endian length prefix per packet:

```
[len(u16 BE) ‖ packet_bytes(len)]
```

The deframer (`drift::io::read_one_tcp_frame`) reads exactly 2 bytes, then `len` bytes, returning one DRIFT packet. EOF mid-prefix or mid-body MUST return an error.

### 11.3 WebSocket

Each DRIFT packet maps to one WebSocket binary message. WS preserves message boundaries natively; no extra framing needed.

### 11.4 TLS

A TLS connection wrapping any of the above stream transports. The TLS handshake is independent of DRIFT's handshake; DRIFT does not require TLS's authentication property (DRIFT authenticates internally) but TLS is useful for traversing TLS-only middleboxes.

### 11.5 WebRTC

DRIFT runs over a WebRTC data channel (reliable mode). The data channel preserves message boundaries.

### 11.6 In-memory

`drift::io::MemPacketIO::pair()` returns a connected `(A, B)` pair over `tokio::sync::mpsc` channels. No sockets, no syscalls. Useful for tests and same-process IPC.

### 11.7 Adapter-private optimizations

Each adapter MAY optimize internally for its lower-layer protocol — TCP can pool framing buffers, WS can batch messages — but MUST NOT leak adapter-specific behavior into Transport-level code. The PacketIO contract is the only surface visible to Transport.

## 12. Threat model

### 12.1 In scope

DRIFT defends against:

- **Off-path attackers** (no network position): cannot inject, modify, replay, or decrypt any traffic.
- **On-path passive observers**: see ciphertext + metadata (pubkeys in headers, sizes, timing). Cannot decrypt; forward secrecy means past sessions stay safe even if static keys later leak (modulo §12.3).
- **On-path active attackers**: AEAD tag prevents modification; replay window prevents replay; cookie mechanism prevents amplification. Can disrupt by dropping packets.
- **Random impersonation attempts**: a peer who doesn't hold the correct static private key cannot complete a handshake.
- **Compromised non-bridge peers**: can only impersonate themselves; cannot affect other peers' sessions.
- **Compromised bridge in a non-federation context**: sees client metadata + ciphertext, can refuse to forward, cannot decrypt inner end-to-end-sealed client-client payloads.
- **Compromised federated bridge**: post-XEdDSA, can drop or delay traffic for its own clients but cannot announce pubkeys it doesn't actually host, cannot hijack victims' routing.
- **Wire-format adversaries**: every decoder is fuzz-tested; allocation bombs and panics on malformed inputs are caught.

### 12.2 Out of scope

DRIFT does NOT defend against:

- **Compromised endpoint hosts**: if the OS / userland on either end is rooted, the attacker has the identity key + plaintext.
- **Traffic analysis at the metadata layer**: bridge operators see who-talks-to-whom and traffic volumes/timings. Standard federation tradeoff. Mix-network properties are out of scope; users wanting that should layer Tor (which DRIFT also supports as an adapter) underneath.
- **Quantum adversaries (harvest-now-decrypt-later)**: classical X25519 + ChaCha20-Poly1305 is not post-quantum. `drift-core::pq` ships an ML-KEM module but it is not yet wired into the handshake. Captured wire traffic could be decrypted by future quantum computers.
- **Side channels** beyond constant-time crypto compares: timing attacks on application-layer code, power analysis, cache attacks.
- **Denial-of-service from a powerful adversary**: cookies mitigate amplification but a sufficiently large attacker can still exhaust uplink. Standard.

### 12.3 Known limitations

- **`ring::aead::LessSafeKey` does not zeroize on drop.** Session-key bytes inside `ring` linger in the allocator after `SessionKey::drop`. The bytes the caller holds (input to `SessionKey::new`) are scrubbed via `Zeroizing`. Bounded exposure window; documented in `drift-core/src/crypto.rs`.
- **Federation peer compromise is total compromise of routing for that peer's clients.** XEdDSA closes the "announce arbitrary pubkeys" hole, but a malicious federation peer can still drop traffic, refuse to announce its real clients (denial of service), or selectively withhold path information. Add federation peers deliberately.
- **No formal protocol audit.** This spec is a precondition for one; nothing more.

## 13. Test vectors

KAT (known-answer test) vectors live in `drift/tests/wire_format_kat.rs` and `drift/tests/kat_new_types.rs`. Implementations claiming conformance MUST reproduce these byte-for-byte:

- `header_kat_data_packet` — long-header DATA packet encoding.
- `header_kat_hello_packet` — long-header HELLO encoding.
- `canonical_aad_kat` — AAD derivation from header bytes.
- `aead_kat_fixed_inputs` — ChaCha20-Poly1305 seal/open with fixed inputs.
- `session_key_derivation_kat` — full handshake key-derivation result.

XEdDSA conformance is locked by `drift-core::xeddsa::tests` (6 tests) and `drift::transport::federated::tests` (presence-ticket codec + verification).

Federation directory v2 wire-format conformance: `drift::transport::federated::tests::directory_roundtrip` (produces 4-byte header + 128-byte entries; reject non-zero reserved; reject wrong version; reject truncation).

## 14. Versioning &amp; extensions

Protocol version is locked by the `PROTOCOL_VERSION = 1` byte in the long header's high nibble. Future incompatible changes increment this; receivers reject mismatching versions.

In-protocol extensions SHOULD use:
- New `PacketType` values (next free: 26 — 22 through 25 are claimed by federation discovery, §10.5–§10.8).
- New flag bits in the long header (next free: bit 2-7).
- The reserved byte at long-header offset 29.

Reserved fields MUST be set to zero by senders and MUST be rejected (or ignored — implementation-defined) when nonzero by receivers. Strict rejection (the current default) makes future version bumps cleaner.

## 15. Implementation references

| Component | File |
|---|---|
| Header codec | `drift-core/src/header.rs` |
| Short header | `drift-core/src/short_header.rs` |
| AEAD + session keys | `drift-core/src/crypto.rs` |
| Identity + KDF | `drift-core/src/identity.rs` |
| XEdDSA | `drift-core/src/xeddsa.rs` |
| Handshake FSM | `drift-core/src/session.rs` + `drift/src/transport/mod.rs` |
| Stream layer | `drift/src/streams.rs` |
| Mesh routing | `drift/src/transport/mesh.rs` |
| Federation codec | `drift/src/transport/federated.rs` |
| Federation dispatch | `drift/src/transport/mod.rs::{handle_federated, handle_federation_directory, handle_presence_ticket}` |
| PacketIO adapters | `drift/src/io.rs` |

---

This spec is maintained alongside the reference implementation. Submit corrections as PRs against `SPEC.md`; KAT vectors lock the wire format and any drift between spec and code is a bug.

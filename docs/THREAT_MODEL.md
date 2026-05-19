# DRIFT — Threat Model & Pen-Test Coverage Map

Canonical location for security claims that are either:

1. Covered by a real regression test (this doc names which one), or
2. Argued for by design analysis where a runtime assertion isn't
   meaningful (this doc gives the reasoning).

History: previously some of these items lived as empty-bodied
`#[test]` functions in `drift/tests/attack_sweep.rs`. Those stubs
were misleading — they passed trivially in CI even if the property
they claimed had been removed from the code. They were deleted on
2026-05-19; the prose moved here.

See also: `drift/tests/attack_*.rs` for the live regression suite.

---

## CRITICAL

Each CRITICAL item has a dedicated test file.

| ID | Item | Test |
|---|---|---|
| SEC.FIX.1 | Open-relay reflection primitive | `drift/tests/attack_open_relay.rs` (UDP/TCP/TLS/WS/HTTP) |
| SEC.PEN.HIGH-1 | Slowloris on WS/TLS listeners | `drift/tests/attack_slowloris.rs` |
| — | KCI / unknown-key-share | `drift/tests/attack_kci_unknown_key_share.rs` |
| — | PQ downgrade | `drift/tests/attack_pq_downgrade.rs` |
| — | Nonce rollover | `drift/tests/attack_nonce_rollover.rs` |
| — | Hello replay hijack | `drift/tests/attack_hello_replay_hijack.rs` |
| — | Cookie nonce replay | `drift/tests/attack_cookie_nonce_replay.rs` |
| — | Data-path hijack | `drift/tests/attack_data_path_hijack.rs` |
| — | Beacon poisoning | `drift/tests/attack_beacon_poisoning.rs` |
| — | Stream open / recv flood | `drift/tests/attack_stream_{open,recv}_flood.rs` |
| — | Attack surface sweep | `drift/tests/attack_surface_sweep.rs` |

---

## HIGH — covered by indirect test or dedicated file

### SEC.PEN.HIGH-2 — Resumption ticket replay

`drift/src/transport/resumption.rs#fn take` does
`entries.remove(ticket_id)` after successful redemption — single-use
enforced at the data-structure level. The entry is bound to a
`client_static_pub`, so presentation by any other identity returns
`None`. Expiry is checked before redemption.

Covered by:

- `drift/src/transport/resumption.rs` `#[cfg(test)]` unit tests for
  `take()` / `insert()`.
- `drift/tests/hybrid_pq_resumption.rs#pq_session_can_be_resumed`
  exercises the full end-to-end consume path.

### SEC.PEN.HIGH-3 — PeerHere / PeerGone forge

`verify_ticket` in `drift/src/transport/federated.rs` requires an
XEdDSA signature over `ticket_signed_msg(bridge_pub, expiry_ms,
nonce)`. A bridge claiming to host a client it doesn't have cannot
produce that signature (needs the client's private key).

Covered by `drift/tests/adversarial_presence_tickets.rs`:

- `announce_without_ticket_is_rejected`
- `announce_with_forged_ticket_is_rejected`
- `ticket_signed_for_other_bridge_is_rejected`
- `expired_ticket_is_rejected`

### SEC.PEN.HIGH-4 — FindPeer query flood

Per-query cost is dominated by signature verification on the
PeerHere response, not by the FindPeer itself. The bridge
rate-limits forwarded queries via `forwarded_queries` (best-effort
coalesce — concurrent queries for the same `dst_id` collapse to one
outbound). Federation peers exceeding `bridge_fault_skip_threshold`
get skipped from fanout, so a misbehaving federate can't keep
getting queries.

Covered by:

- `drift/tests/federation_discovery.rs#fanout_skips_peer_past_fault_threshold`
- `drift/tests/directory_flood.rs#register_churn_many_peers`

### SEC.PEN.HIGH-5 — Bloom-filter overclaim

Phase F bloom filters narrow `handle_unknown_bridge_pub` fanout to
peers whose advertised bloom indicates "might have this target." A
malicious peer setting all bloom bits would defeat the filter —
they'd claim everyone. The reputation system (Phase G
`bridge_fault_skip_threshold`) catches this: claims that don't
deliver bump `bridge_faults`, and high-fault peers get skipped from
fanout.

Covered by:

- `drift/tests/federation_discovery.rs#bloom_filter_says_no_suppresses_findpeer`
- `drift/tests/federation_discovery.rs#bridge_fault_counter_increments_on_unfulfilled_claim`
- `drift/tests/federation_discovery.rs#fanout_skips_peer_past_fault_threshold`
- `drift/tests/federation_discovery.rs#fault_decay_unblocks_recovered_peer`

### SEC.PEN.HIGH-6 — Federation envelope tx-replay

`drift/src/transport/mod.rs` `handle_federated` rejects envelopes
whose `source_bridge_pub` doesn't match either the authenticated
immediate-hop or the local pub, bumping `federation_spoof_drops`.
An envelope captured from one bridge can't be replayed via a
different bridge because the outer DRIFT packet (authenticated on
the wire) carries the actual sender, and the envelope's claim is
cross-checked against that.

Covered by `drift/tests/adversarial_federation.rs`:

- `forged_source_client_pub_is_rejected_at_source_bridge`
- `federation_table_cannot_be_poisoned_by_unrelated_client`
- `federation_directory_rejects_non_bridge_announcer`

---

## HIGH — design tradeoff (no test)

### SEC.PEN.HIGH-7 — drift-http CSRF

The `http://` adapter sends `Access-Control-Allow-Origin: *` — any
web origin can fetch `/drift-sse` and POST `/drift-send`. This is
by design: the http adapter is a transport, not an authenticated
API, and `accept_any_peer` semantics mean any peer with the
bridge's pubkey can connect regardless of origin. The DRIFT layer
above does the authentication (X25519 handshake + AEAD-sealed
packets). A CSRF attacker using a victim's browser as a relay
still needs their own drift identity to do anything meaningful —
they can't impersonate the victim.

**What CSRF buys an attacker:**

- SSRF-style reach to bridges on the victim's local network (the
  bridge's IP is reachable from the victim's browser, but not
  from the attacker's network).
- Resource use on that bridge (one peer slot).

**What it does NOT buy:**

- Impersonating the victim (no access to victim's identity secret).
- Reading other peers' E2E-encrypted traffic.
- Privilege escalation on the bridge process.

Documented as a design tradeoff; not patched. Operators who don't
want browser-driven access should not expose `http://`.

---

## MEDIUM

### SEC.PEN.MED-1 — Max-length frame storm

`TcpPacketIO::send_to` rejects `buf.len() > u16::MAX`. `recv_from`
reads at most `buf.len()` bytes (caller-supplied). Per-connection
memory cost is bounded by the buffer the transport allocates
(~64 KB). With the per-IP cap of 32, a single attacker IP can
pin ~2 MB max.

Tested: `drift/tests/attack_sweep.rs#med1_oversized_frame_is_rejected`.

### SEC.PEN.MED-2 — HTTP request smuggling

drift's HTTP adapter uses hyper's `http1::Builder` (post-HTTP.OPT1
port). hyper handles Transfer-Encoding / Content-Length / chunked
per RFC 9112 and rejects CL/TE conflicts. Anything malformed
produces a parse error and the connection is torn down — no
drift-layer code sees the bytes.

Tested: `drift/tests/attack_sweep.rs#med2_http_smuggling_malformed_headers_dont_panic`.

### SEC.PEN.MED-3 — WebSocket abuse (ping flood, oversized close)

`tokio-tungstenite` handles control-frame validation per RFC 6455.
Pings are auto-ponged; oversized close payloads are rejected.
drift's WS adapter passes only Binary messages to the DRIFT layer
(`WsPacketIO::recv_from` skips other types). A bad client gets a
closed connection.

Tested: `drift/tests/attack_sweep.rs#med3_ws_ping_flood_is_handled_by_tungstenite`.

### SEC.PEN.MED-4 — Route flap via authenticated neighbor

`RoutingTable::update_if_better` (`drift/src/transport/mesh.rs`)
enforces `ROUTE_HOLDDOWN = 2 s` and a 20% hysteresis threshold
(`HYSTERESIS_NUMERATOR / DENOMINATOR = 80 / 100`). During
hold-down, only a *significantly* better cost can preempt. This
caps the rate at which a single neighbor can thrash the table.

Verified by inspection of the hold-down logic. The constants
should be re-evaluated against route-flap CPU bound if changed.
See `drift/tests/routing_loop_terminates` for related dynamics.

### SEC.PEN.MED-5 — Beacon spam past MAX_ROUTES

`MAX_ROUTES = 4096` (`drift/src/transport/mesh.rs`). Once reached,
`update_if_better` rejects new `dst` entries unless they replace
an existing one. Memory ceiling: `4096 * sizeof(RouteEntry)` ≈
~200 KB per `Transport`.

Verified by inspection of the constant + `update_if_better`.

### SEC.PEN.MED-6 — Hop-TTL re-entry

`MAX_INCOMING_HOP_TTL = 16` (`drift/src/transport/mesh.rs`).
`hop_ttl` decrements per forward; 16 bounds the amplification
factor for one attacker datagram. Combined with SEC.FIX.1's
source-IP gate, an attacker can't even reach the forward path
without a known-peer `src_addr`.

Covered by `drift/tests/mesh_stress.rs#routing_loop_terminates`.

---

## LOW / OPERATIONAL — design analysis (no runtime test possible or useful)

### SEC.PEN.LOW-1 — Timing side-channel on identity comparison

DRIFT uses `ring`'s X25519 + BLAKE2 + ChaCha20-Poly1305 — all
constant-time at the primitive level. Identity equality goes
through `PeerId` byte comparison; not constant-time, but the
comparison is over an 8-byte derived id (the BLAKE2b-truncation
of the public key, not the secret), so timing oracles don't yield
key material.

Status: defense-in-depth, not exploitable. No runtime test is
meaningful — even a perfect side channel here leaks "which peer"
not "what secret."

### SEC.PEN.LOW-2 — Key material zeroization

Session keys live in `Zeroizing<[u8; 32]>` (see
`drift-core/src/identity.rs`). Ephemeral DH secrets are explicitly
dropped after use. Long-term `Identity` keys zero via
`x25519-dalek`'s `zeroize` feature.

`Zeroizing`'s scrub happens in `Drop`, after the value goes out of
scope — there is no runtime observable a test could check. The
property is verified by grep of `Zeroizing<` at every key-derivation
site in `drift-core/src/identity.rs`.

### SEC.PEN.LOW-3 — Identity file disk perms

`drift::keygen` writes identity files with `0o600` on Unix. The
default sits in `drift::cli::keygen` — operator responsibility to
manage permissions afterward. Backup hygiene is documented in
identity-rotation runbooks.

A runtime test would need to spawn a real keygen invocation under
`tempfile` and stat the result; the inspection check is in
`drift/src/cli/keygen.rs`.

### SEC.PEN.LOW-4 — Log injection via peer-supplied strings

DRIFT uses `tracing` macros with structured fields (`?peer`,
`?src`), not format-string interpolation. Terminal escape sequences
in peer-supplied strings (e.g. petnames) end up in the structured
field, not the log line's plaintext — any sensible log formatter
renders them safely. `tracing`'s `Debug` impls escape control
characters in the default formatter.

Code-review property: drift never logs raw user-supplied strings
via `info!("{}", peer_supplied)`.

### SEC.PEN.LOW-5 — drift-mosh shell blast radius

`drift-mosh-server` spawns a shell on session establishment. If an
attacker has the server's identity secret AND knows the authorized
client pubkey(s), they get shell. This is the documented design
(mosh-via-drift is a remote-shell product, not an authorization
framework).

Mitigation: identity rotation + principle-of-least-pubkey on the
server's authorized list. Treat `drift-mosh-server --identity`
like an SSH host key.

### SEC.PEN.LOW-6 — Persistence after compromise

A short root-on-bridge window lets an attacker drop a
`--peer <url>@<pubhex>` config that auto-rejoins on restart. This
is the same as an SSH `authorized_keys` insertion. Defense is
operational: log + alert on config drift; don't run `drift bridge`
as root if the binary is world-readable.

No code-level fix is meaningful here — `accept_any_peer` semantics
specifically allow this. Operators who want tighter control should
set `accept_any_peer = false` and manage a pubkey allowlist.

# drift-proto: the sans-IO protocol engine

**Status: Phases 1-3 landed (#52, #53, #54); phase 5 (wasm + Redox adoption) done — only phase 4 (Transport consumes the engine) remains, gated on explicit go-ahead.**

## Why

Porting DRIFT to two non-tokio platforms produced two hand-written
dialects of the same protocol:

- **drift-wasm** (browser) — depends only on `drift-core`, re-derives
  the session orchestration for the browser environment.
- **drift-redox** (Redox OS, standalone crate) — depends only on
  `drift-core`, re-derived the HELLO/CHALLENGE/HELLO_ACK choreography
  over std TCP. Tier-1 only (no rekey, no resumption), and **not
  byte-compatible with the real UDP transport**.

Both happened because the boundary between "portable protocol" and
"tokio plumbing" sits one layer too low. `drift-core` holds the
*primitives* (crypto, headers, KDFs, replay window, peer state) but
the *protocol* — wire construction, flight choreography, AAD rules,
retry/backoff, cookie gating, state transitions — lives braided
through `drift/src/transport/mod.rs` (7,739 lines), fused to
tokio/mio. Every new platform re-derives that layer and drifts from
canon.

The fix is the same one quinn uses (`quinn-proto` vs `quinn`),
smoltcp uses, and str0m uses: a **sans-IO state machine crate**.
Bytes in, bytes out, explicit time. No sockets, no runtime, no tasks.

## The crate

```
drift-core   (primitives: crypto, header, session state, pq, xeddsa)
    ↑
drift-proto  (protocol state machine: flights, retries, cookies, transitions)
    ↑
drift        (tokio driver: sockets, PacketIO, tasks, locks, mesh, federation)
```

`drift-proto` depends **only on drift-core** (plus `rand`/`thiserror`,
which drift-core already pulls). It compiles anywhere drift-core
compiles: native, wasm32, Redox.

### API shape (quinn-proto style)

```rust
let mut ep = Endpoint::new(identity, Config::default());
let peer = ep.connect(now, server_pub, server_addr);   // queues HELLO
ep.send(now, &peer, b"payload", 0, 0)?;                // queues or buffers DATA

// driver loop — the ONLY part a platform has to write:
while let Some(t) = ep.poll_transmit() { socket.send_to(&t.contents, t.dst)?; }
let (n, src) = socket.recv_from(&mut buf)?;
ep.handle_datagram(now, src, &buf[..n])?;
ep.handle_timeout(now);                                 // retries, cookie rotation
while let Some(ev) = ep.poll_event() { /* Connected / Data / HandshakeTimedOut */ }
```

A platform port is now a ~50-line pump loop instead of a protocol
reimplementation — and it is byte-compatible by construction because
the flight logic is the *same code* the main transport will
eventually run.

## Strategy: strangler fig, not surgery

The existing transport is battle-tested (K=17 soaks, attack-suite
tests, live deployments). We do NOT rip its internals out on day one.

1. **Build alongside.** drift-proto re-implements the protocol layer
   by *porting the exact logic* out of `transport/mod.rs`
   (`build_hello_wire`, `handle_hello`, `regenerate_session`,
   `handle_hello_ack`, cookie machinery, `build_data_packet`),
   preserving wire bytes and behavioral quirks.
2. **Prove byte-compat with interop tests.** `drift/tests/
   proto_interop.rs` runs a drift-proto endpoint over a plain
   `std::net::UdpSocket` against a real `drift::Transport` (tokio) —
   both directions, classical + PQ-hybrid, cookie flight included.
   These tests are the contract: if the engine ever diverges from the
   transport, CI fails.
3. **Adopt at the edges.** drift-wasm and drift-redox switch to
   drift-proto, deleting their dialects.
4. **Swap the core last.** Once the engine covers the full feature
   set, `drift::Transport` becomes a driver around it, and the
   protocol logic exists in exactly one place.

## Phases

| Phase | Scope | Status |
|---|---|---|
| **1** | Crate + Tier-1 engine: HELLO/CHALLENGE/HELLO_ACK (classical + ML-KEM hybrid), DoS cookies (issue/validate/rotate), dual-init tiebreak, cached-ACK duplicate-HELLO replay, 3× amplification budget, retry/backoff/give-up, long-header DATA with replay window + deadline + coalesce, AwaitingData→Established transition, pending-queue flush. Short-header/CID fast path (pulled forward from phase 2 — the transport speaks it immediately after handshake, so byte compat required it). Interop proof vs real Transport. | ✅ #52 |
| **2** | Close (send + authenticated receive), rekey: manual + auto at the seq watermark, RekeyRequest/RekeyAck, grace-window fallback on both header formats; half-open eviction (AwaitingData *and* parked AwaitingAck, mirroring the transport's eviction loop). Interop: rekey + Close in both roles. | ✅ #53 |
| **3** | 1-RTT resumption: ticket issue at handshake completion + on each resumption, single-use identity-bound server store, transport-compatible 97-byte export/import blobs, ResumeHello/ResumeAck (PSK + fresh ephemeral DH), ResumeHello retransmits, pre-resumption keys in the grace slot. Engine fallback divergences (safe direction, the transport parks instead): tickets cleared on Close (both directions) and burned on resume give-up, dropping the peer to Pending so the next send opens a full HELLO. Interop: resumption in both roles, incl. the transport's post-Close try-resume path. | this PR |
| **4** | Path validation/migration, mesh route tables/beacons — then `drift::Transport` consumes the engine internally (the actual de-braiding of transport/mod.rs). Deliberately LAST: by then the engine has survived three interop phases plus real adoption on two platforms. | |
| **5a** | drift-wasm adopts drift-proto: `session.rs` becomes a ~250-line driver around `Endpoint` (JS interval drives `handle_timeout`; placeholder SocketAddr since browser wires are single-pipe); `peer_session.rs` deleted. The browser gains PQ-hybrid handshakes, the replay window, HELLO retransmits, short headers, rekey, and Close — none of which the old dialect had. Prerequisites landed in the engine: wasm32 time shim (`drift_proto::time`), mesh hop-TTL support (`add_mesh_peer`/`connect_mesh`, via_mesh wiring ported from the transport). Verified e2e: node harness vs a native bridge — WS + HTTP/SSE handshakes, and WASM → bridge → native-UDP-peer mesh delivery. | this PR |
| **5b** | ✅ drift-redox adopted drift-proto (standalone crate at `~/redox-dev/drift-redox`, outside this repo): its hand-rolled Tier-1 dialect is replaced by an `Endpoint` over std TCP with the native `tcp://` 2-byte length framing (so it now dials real drift nodes directly). Cross-compiled for `x86_64-unknown-redox` via the redoxer rig on Proxmox — **drift-proto + drift-core + ML-KEM + ring all build for Redox** — injected into VM 109 via RedoxFS, and verified live: the Mac shell-client reached the engine-driven shell-server on the actual Redox box (`uname` → `Redox`). The browser-classical MTU caveat does not apply (Redox uses reliable std TCP), so Redox runs the **full PQ-hybrid** protocol. | done |

## Byte-compat invariants (ported verbatim, do not "improve")

- HELLO: long header `{type=1, seq=0, payload_len=80(+24 cookie)(+1184 ek), FLAG_PQ_HYBRID when ek present}`; body `static_pub ‖ eph_pub ‖ client_nonce ‖ [cookie 24] ‖ [ek 1184]`. Retransmits reuse the same nonce/ephemeral/ek so the server can replay its cached ACK.
- CHALLENGE: `{type=8, seq=0, payload_len=24}`; body `ts_be(8) ‖ blake2-MAC(16)` over `addr_bytes(src) ‖ static ‖ eph ‖ nonce ‖ ts`; MAC valid under current or previous rotating secret, max age 60 s.
- HELLO_ACK: `{type=2, seq=1, hop_ttl=8 → FLAG_ROUTED, payload_len=64(+1088 ct)}`; body `server_eph ‖ server_nonce ‖ tag ‖ [ct]`. Tag = `seal(seq=1, HelloAck, AAD, b"")` with `tx = SessionKey(key, Responder)`; **AAD = canonical_aad(header) ‖ server_eph ‖ server_nonce ‖ [ct]`.
- DATA: `{type=3, seq from next_seq_checked (starts 1 after reset), send_time_ms stamped, payload_len = plaintext len}`; AAD = canonical_aad(header); wire = header ‖ seal(seq, Data, aad, payload).
- Key derivation: classical `derive_session_key(static_dh, eph_dh, nc, ns)`; hybrid `derive_hybrid_key(static_dh, eph_dh, mlkem_ss, nc, ns)`. Client tx=Initiator/rx=Responder; server inverse.
- Order of server HELLO checks: length → dst → parse → zero-key reject → PQ posture (reject PQ-flagged HELLO when local `hybrid_pq=false`; no silent downgrade) → cookie gate (before any X25519) → register/dual-init/cached-ACK/regenerate → amplification spend → emit.
- Dual-init tiebreak: lower static pubkey becomes responder.
- Cached-ACK replay goes to the **trusted** `peer.addr`, never the datagram source (anti-redirect).
- Receive order for DATA: AEAD open → replay check → deadline → coalesce → transition/deliver.
- Give-up: after `handshake_max_attempts` the peer parks in AwaitingAck (no reset); engine additionally emits one `HandshakeTimedOut` event (additive, observability only).

## Known impurities (slice 1, documented trade-offs)

- **Wall clock for cookies**: `SystemTime::now()` for cookie
  timestamps, exactly like the transport. The one non-injected clock
  read; acceptable because cookie age tolerance is 60 s.
- **`drift_core::session::Peer` reads `Instant::now()`** internally in
  `Peer::new`/`mark_session_start`. Retry timing uses the injected
  `now` throughout, so tests can drive virtual time for retries; full
  virtual-time purity needs a tiny drift-core change (pass `now` into
  those two methods) — deferred, core is frozen.
- No path migration in the engine yet: DATA from an unexpected source
  address still decrypts (AEAD is the authority) but never migrates
  `peer.addr` — the conservative half of the transport's
  challenge/response migration. Phase 4.

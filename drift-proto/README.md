# drift-proto

**The DRIFT protocol as a sans-IO state machine — bytes in, bytes out, explicit time. No sockets, no runtime.**

`drift-proto` is the single source of truth for DRIFT's per-peer protocol: the handshake (X25519 + ChaCha20-Poly1305, optional X25519+ML-KEM-768 hybrid), DoS cookies, replay windows, HELLO retransmits, short headers, rekey, `Close`, and 1-RTT resumption. It owns none of the I/O — you feed it datagrams and a clock, and it tells you what to send and what happened.

This is the [quinn-proto](https://docs.rs/quinn-proto) pattern: the protocol lives in one place, and each environment writes a thin driver around it instead of re-deriving the wire format.

## Why it exists

Before this crate, DRIFT's protocol was braided into the tokio transport, so every new platform (the browser WASM build, a Redox port) re-implemented it by hand and silently diverged. Extracting the engine here means the protocol is written **once** and shared by:

- [`drift`](../drift) — the tokio transport consumes it internally (sharded async peer table, all wires, bridges, federation).
- [`drift-proto-std`](../drift-proto-std) — a blocking `std::net` driver (no tokio; runs on Redox).
- [`drift-wasm`](../drift-wasm) — the browser build.

Because every driver runs the *same* engine, they're byte-for-byte wire-compatible by construction — proven by the cross-implementation interop suite (`drift/tests/proto_interop.rs`).

## API

```rust
use drift_proto::{Endpoint, Config, Event, Identity};

let mut ep = Endpoint::new(Identity::generate(), Config::default());

// Drive it: feed inbound datagrams + an explicit `now`, drain outbound
// datagrams and protocol events. The caller owns the socket and the clock.
ep.handle_datagram(now, src_addr, &bytes)?;     // bytes in
ep.handle_timeout(now);                          // fire timers (retransmit, rekey, …)
while let Some(t) = ep.poll_transmit() { /* send t.contents to t.dst */ }
while let Some(ev) = ep.poll_event() {
    match ev {
        Event::Connected { peer } => { /* session established */ }
        Event::Data { payload, .. } => { /* authenticated, replay-checked DATA */ }
        Event::Closed { .. } | Event::HandshakeTimedOut { .. } => { /* … */ }
    }
}
```

It builds on [`drift-core`](../drift-core) for the cryptographic and wire-format primitives (`crypto`, `header`, `short_header`, `session::Peer`, `pq`). `drift-core` is the primitives; `drift-proto` is the state machine that drives them.

`pub mod wire` and `pub mod frame` expose the pure byte-layout and session-keyed packet builders shared with the transport, so the same code seals and parses packets on both sides.

## Portability

Compiles for `wasm32-unknown-unknown` (a `time` shim swaps in `web-time`) and `x86_64-unknown-redox` — anywhere `std` + the crypto crates build. No tokio, no async.

For a ready-made blocking driver over `std::net`, use [`drift-proto-std`](../drift-proto-std); to embed in the async stack, use [`drift`](../drift).

## License

MIT

# drift-proto-std

**A synchronous, runtime-free driver for the sans-IO DRIFT engine — blocking `std::net`, no tokio.**

[`drift-proto`](../drift-proto) is the DRIFT protocol as a pure state machine: bytes in, bytes out, explicit time, no sockets and no async runtime. `drift-proto-std` is the thin **blocking** I/O shell that turns it into a usable client/server over `std::net`, so portable tools don't each hand-roll the same framing + poll loop.

It pulls in **no tokio, no async** — only `std` and `drift-proto` — so it compiles and runs wherever those do, including **Redox** and other no-async std targets. A `drift-proto-std` peer is byte-for-byte wire-compatible with native [`drift`](../drift) `tcp://`/`udp://` nodes.

## When to use it

| You want… | Use |
|---|---|
| Async, all wires (ws/h2/iroh/webtransport/…), bridges, federation, scale | [`drift`](../drift) — the tokio transport |
| A DRIFT session with **no runtime** (Redox, embedded-ish std, anywhere tokio won't build) | **`drift-proto-std`** |
| To bring your own I/O entirely (custom executor, wasm, …) | [`drift-proto`](../drift-proto) directly |

All three speak the same protocol and interoperate on the wire — the choice is about your I/O environment, not a fork.

## Two shapes

- **`Connection`** — a blocking **datagram** channel for request/response tools. `connect` / `accept`, `send` / `recv` / `close`, `wait_established`. A `send` larger than `MAX_PAYLOAD` is split across DATA datagrams; `recv` returns one payload at a time. No hidden message framing (so the wire stays byte-identical to native drift DATA) — layer your own length prefix if you need boundaries.
- **`Session`** — a **full-duplex** channel for interactive/streaming tools (a remote shell, a tunnel/port-forward, a chat). A cloneable `SessionSender` any thread can `send` on, a `pump(callback)` that runs the receive side, and `pipe(reader, writer)` that wires both to ordinary `Read`/`Write` handles in one call.

## Two wires

| Scheme | Notes |
|---|---|
| **`tcp://`** (default) | engine packets with the native 2-byte length framing. **Reliable.** |
| **`udp://`** | one UDP datagram per engine packet. The handshake is retransmitted, but **DATA is best-effort** — there is no `StreamManager`-style reliability layer here. Fine for the handshake + small/idempotent exchanges; use `tcp://` for bulk/reliable transfer. |

`connect`/`Session::connect` take a `tcp://` / `udp://` scheme (bare `host:port` = tcp); servers use `accept(TcpStream)` / `accept_udp(UdpSocket)`.

> Only tcp and udp are addable to a *blocking* driver — `ws`/`h2`/`iroh`/`webtransport` are fundamentally async (they need an executor), and `tls` is redundant over an already-AEAD-encrypted DRIFT session. For those wires, use the [`drift`](../drift) tokio transport.

## Example (request / response)

```rust
use drift_proto_std::{Connection, Config, Identity, server_config};
use std::net::TcpListener;

// Server: accept one session, echo the first datagram.
let listener = TcpListener::bind("127.0.0.1:9100").unwrap();
std::thread::spawn(move || {
    let (stream, _) = listener.accept().unwrap();
    let id = Identity::from_secret_bytes([0x5d; 32]);
    let mut conn = Connection::accept(stream, id, server_config()).unwrap();
    if let Some(req) = conn.recv().unwrap() {
        conn.send(&req).unwrap();
    }
    let _ = conn.recv(); // linger until the client closes
});

// Client: dial (tcp:// / udp:// / bare = tcp), send, read the echo.
let server_pub = Identity::from_secret_bytes([0x5d; 32]).public_bytes();
let id = Identity::from_secret_bytes([0xc1; 32]);
let mut conn = Connection::connect("127.0.0.1:9100", server_pub, id, Config::default()).unwrap();
conn.send(b"hello").unwrap();
assert_eq!(conn.recv().unwrap().as_deref(), Some(&b"hello"[..]));
conn.close().unwrap();
```

The `Session` shape is a few lines too — see the `Session::pipe` doc example for a remote shell (`Session::accept(stream, …).pipe(child_stdout, child_stdin)`).

## What's built on it

- **drift-redox** — DRIFT on the Redox microkernel: an encrypted shell (`Session`) + file transfer (`Connection`), zero hand-rolled I/O.
- **Portable tool builds** — [`drift-wormhole`](../drift-wormhole) and [`drift-git`](../drift-git) carry a `--features portable` build on this crate (no tokio) alongside their default tokio build.

## License

MIT

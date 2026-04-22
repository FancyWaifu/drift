# drift-ffi

C ABI for DRIFT. Makes the transport callable from C, C++, Python (via ctypes / cffi), Go (via cgo), Swift, Kotlin, and anything else that speaks the C ABI.

## Build

```bash
# From the repo root. Produces both libdrift_ffi.a (staticlib)
# and libdrift_ffi.dylib / .so (cdylib), plus regenerates
# drift-ffi/drift.h via cbindgen.
cargo build -p drift-ffi --release
```

Output:
- `target/release/libdrift_ffi.a` — static archive
- `target/release/libdrift_ffi.dylib` (macOS) or `.so` (Linux) or `.dll` (Windows) — shared lib
- `drift-ffi/drift.h` — auto-generated C header

## C hello world

See `examples/hello.c`. Run it:

```bash
cd drift-ffi/examples
make hello    # compiles libdrift_ffi.a + examples/hello.c together
./hello
# Bob bound on 127.0.0.1:56422
# Bob received 12 bytes: "hello from C"
# Alice received echo (12 bytes): "hello from C"
# handshakes_completed: alice=1 bob=1
# PASS
```

## API overview

All functions live under the `drift_` prefix. Handles are opaque:

```c
#include "drift.h"

// Identity — X25519 keypair
struct DriftIdentity *id = drift_identity_generate();
uint8_t pub[32];
drift_identity_public_key(id, pub);

// Transport — bound UDP socket + handshake state machine.
// Passing `id` transfers ownership to the transport.
struct DriftTransport *t = NULL;
drift_transport_bind("0.0.0.0:9000", id, &t);

// Register a peer by its 32-byte pubkey + address.
uint8_t peer_id[8];
drift_transport_add_peer(t, peer_pub_bytes, "10.0.0.2:9000",
                         /*initiator=*/1, peer_id);

// Send / receive
drift_transport_send_data(t, peer_id, payload, len, /*deadline_ms=*/0, /*coalesce_group=*/0);

struct DriftMessage *msg = NULL;
drift_transport_recv(t, /*timeout_ms=*/5000, &msg);
// Use drift_message_payload(msg), drift_message_payload_len(msg),
// drift_message_peer_id(msg, buf8).
drift_message_free(msg);

// Clean up
drift_transport_free(t);
```

## Design notes

- **Shared tokio runtime.** The FFI lazily starts a 2-worker tokio runtime on first call and keeps it alive for the life of the process. Each `drift_*` call wraps its async internal work in `runtime.block_on(...)`, so the C caller sees a blocking API.
- **Error codes.** Every fallible function returns `DriftResult`. `DRIFT_OK = 0` is success; positive values are failure modes (see `drift.h`).
- **Thread safety.** Individual handles are not thread-safe. If you share a `DriftTransport` across multiple C threads, wrap it in your own mutex — the underlying Rust `Transport` is `Send` but most of its methods take `&self` and perform internal locking, so concurrent use is safe *in principle* but the FFI doesn't enforce it.
- **Memory model.** The library owns the memory behind every handle. Call the paired `drift_*_free` function to release. Passing `NULL` to a free function is a no-op (matches libc `free`).
- **Ownership transfer.** `drift_transport_bind` takes ownership of the `DriftIdentity` passed in — don't free it afterwards.

## Language bindings

The C ABI is the foundation; specific-language bindings build on top:

- **Python**: use `ctypes` or [`cffi`](https://cffi.readthedocs.io/).
- **Go**: `cgo` + `#include "drift.h"`.
- **Swift**: bridging header.
- **Node.js**: [`node-ffi-napi`](https://github.com/node-ffi-napi/node-ffi-napi) — though the `drift-wasm` crate already provides native Node bindings via WebAssembly, which is usually simpler.

## Limitations

The current surface covers the core UDP transport path. Not yet wired through FFI:

- Custom `PacketIO` adapters (TCP, WebSocket, WebRTC, WebTransport, in-memory). These are all first-class in the Rust API; exposing them through C would mean either (a) adding a callback-based adapter that lets C provide a custom `send_to` / `recv_from`, or (b) exposing each built-in adapter's constructor. Open follow-up.
- Stream API (`streams.rs`). The FFI only exposes raw datagram send/recv so far.
- Mesh routes (`add_route`). Static routes can be added from Rust; no FFI wrapper yet.
- Resumption tickets (`export_resumption_ticket` / `import_resumption_ticket`).

These are straightforward additions — each wraps an existing Rust method.

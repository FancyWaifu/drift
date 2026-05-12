# drift-fuzz

Coverage-guided fuzz targets for DRIFT, built on `cargo-fuzz` /
`libfuzzer-sys`. Kept out of the default workspace so `cargo test`
in the parent crate doesn't try to compile them — libfuzzer needs
a nightly toolchain and an `LD_LIBRARY_PATH` dance that's not
worth paying on every normal build.

## Tier-1 targets

Decoders that run on every packet from untrusted peers. Each
asserts no-panic plus the post-decode invariants documented in
the target.

| target | covers |
|---|---|
| `header_decode` | `Header::decode` — 36-byte long header; version, type, seq, ids, deadline, hop_ttl. |
| `short_header_decode` | `decode_short`/`is_short_header` — 7-byte short header for the established-DATA fast path. |
| `federated_envelope_decode` | `parse_federated` — 130-byte bridge envelope (four pubkeys + payload). |
| `federation_directory_decode` | `parse_directory` — bridge-to-bridge directory announcement. |
| `directory_decode` | `DirMessage::decode` — directory-server message (Register / Lookup / Listing). |
| `tcp_deframe` | `read_one_tcp_frame` — u16-BE-prefixed framing under `TcpPacketIO::recv_from`. |
| `stream_frame` | `StreamManager::test_handle_frame` — stateful stream-layer dispatch. |
| `handshake_fsm` | Two `Transport` instances over `MemPacketIO`, driven through randomized event sequences (`SendAtoB`, `SendBtoA`, `RestartA`, `RestartB`, `DrainA`, `DrainB`). Tier-2 — slower per iter; covers handshake / restart / rekey FSM bugs the byte-level targets can't reach. |

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly --component rust-src

# Smoke each target (10k iterations, ~seconds on a modern CPU):
cargo +nightly fuzz run --sanitizer none header_decode -- -runs=10000
cargo +nightly fuzz run --sanitizer none short_header_decode -- -runs=10000
cargo +nightly fuzz run --sanitizer none federated_envelope_decode -- -runs=10000
cargo +nightly fuzz run --sanitizer none federation_directory_decode -- -runs=10000
cargo +nightly fuzz run --sanitizer none directory_decode -- -runs=10000
cargo +nightly fuzz run --sanitizer none tcp_deframe -- -runs=10000
cargo +nightly fuzz run --sanitizer none stream_frame -- -runs=2000

# Long-run a single target until Ctrl-C:
cargo +nightly fuzz run --sanitizer none header_decode
```

### Note on `--sanitizer none`

The `inventory` crate (pulled in transitively via `wtransport`)
uses `#[link_section]` magic that conflicts with the AddressSanitizer
linker on `aarch64-apple-darwin`. We disable the sanitizer to keep
the build clean; the coverage signal libFuzzer uses is unaffected.
On Linux runners the default (`-Zsanitizer=address`) works fine —
the GitHub Actions workflow uses it there.

## Seed corpus

Run from the workspace root to (re)generate seed bytes from the
live codec functions:

```sh
cargo run --example fuzz_seeds -p drift
```

Seeds land under `fuzz/corpus/<target>/`. Re-run after wire-format
changes so the corpus tracks the code.

## Crashes

Crash artifacts land under `fuzz/artifacts/<target>/crash-<hash>`.
Replay with:

```sh
cargo +nightly fuzz run --sanitizer none header_decode fuzz/artifacts/header_decode/crash-...
```

Minimize a single repro:

```sh
cargo +nightly fuzz tmin --sanitizer none header_decode fuzz/artifacts/header_decode/crash-...
```

Promote a fixed crash to a permanent regression seed by copying
it into `fuzz/corpus/<target>/regression_<descr>`. The CI replays
the full corpus on every PR.

## Deferred targets

These were on the plan but need refactoring before a fuzz harness
can meaningfully exercise the code:

* **ECN cmsg walk** (`drift/src/transport/ecn.rs`). The unsafe
  cmsg-walking code operates on `*const libc::msghdr` populated
  by the kernel. To fuzz it we need to extract a free function
  `walk_cmsg(msg_control: &[u8]) -> Option<u8>` that doesn't go
  through `libc::CMSG_*` macros. Linux-only; macOS uses a no-op
  fallback. ~50 lines of refactor before a harness is useful.
* **drift-ffi entry points** (`drift-ffi/src/lib.rs`). Every
  function is `pub unsafe extern "C" fn` taking raw `*const u8`
  + `len`. A fuzz target would generate `(ptr, len)` pairs
  pointing into varying-size Vecs (or `MaybeUninit`-mapped
  pages for OOB detection). Bounded use case — the C ABI is
  trusted-caller territory — so lower priority than the
  packet-decode targets.
* **DNS-tunnel deframer** (`drift/src/wire_dns.rs`). Routine
  text-format parsing; would benefit from coverage-guided
  fuzzing but the `wire_dns.rs` and `wire_doh.rs` integration
  tests already cover the major cases.

## Findings so far

| date | target | fix |
|---|---|---|
| 2026-05-11 | `federation_directory_decode` | `parse_directory` accepted non-zero `reserved` byte; `build∘parse` not idempotent. Now strict-rejects. Regression seed: `corpus/federation_directory_decode/regression_nonzero_reserved`. |

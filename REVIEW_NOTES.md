# DRIFT — Harsh Review

Audit at commit `a5906da`, 2026-05-04. The previous version of this file was too generous. This one is what you asked for. None of this is fatal, but every item is real.

---

## 1. The "sans-io core" is not actually clean

`drift-core` exists; that's the easy part. But `drift/src/` *also* contains source files for the same modules:

- `drift/src/header.rs` (382 LOC)
- `drift/src/session.rs` (724 LOC)
- `drift/src/identity.rs` (145 LOC)
- `drift/src/fec.rs` (195 LOC)
- `drift/src/pq.rs` (183 LOC)
- `drift/src/short_header.rs` (224 LOC)
- `drift/src/directory.rs` (209 LOC)
- `drift/src/error.rs` (59 LOC)

**Total: ~2,121 LOC of dead source files.** None are declared as modules in `drift/src/lib.rs` or anywhere else, so cargo doesn't compile them. They're either pre-extraction leftovers from when `drift-core` was carved out, or worse, you weren't sure they were dead and left them around. Some have *drifted* (heh) from the `drift-core` versions — `session.rs` differs between the two trees. Anyone reading this repo can't tell which is canonical without running `git log` per file.

Action: delete them all. If something useful is in there that isn't in `drift-core`, port it across before deleting.

Also: `drift/src/cli/identity.rs` exists separately. Three "identity"s in one workspace is two too many.

---

## 2. `drift/src/transport/mod.rs` is a 3,233-line god module

Single file with:
- 5 structs (incl. `Inner` which has ~50 fields and is the de-facto God object)
- 62 functions
- 20 method implementations
- Handshake FSM, rekey, resumption, cookies, CIDs, mesh hooks, send loop, recv loop, batch send, eviction reaper, qlog hooks all interleaved

`Inner` is allocated as a single `Arc<Inner>` and every background task captures a clone. That's fine for ownership but it means there's no compile-time decomposition of subsystems — everything mutates everything via locks. The lock soup (`routes`, `cid_map`, `peer_out_cid`, `peers`, `cookies`, `resumption_store`, `client_tickets`, `qlog`, `session_reset_tx` — multiple `StdMutex` and `tokio::Mutex`) is a deadlock waiting to happen, especially when you start mixing `peer_lock_for(dst).await` with `routes.lock().unwrap()`.

Action: split `transport/mod.rs` into something like `handshake.rs`, `rekey.rs`, `recv_loop.rs`, `send_path.rs`, `eviction.rs`. Move `Inner`'s field clusters onto sub-structs. The compiler is currently the only thing reasoning about which subsystems can interact.

---

## 3. The benchmark numbers in the README are not what they look like

This is the worst finding. The README's headline performance claims:

> **Cold handshake: DRIFT 330 µs (8.6× faster than QUIC).**
> **Throughput: 1,672 Mbps (real flow control).**

Look at `drift-bench/src/drift_proto.rs`:

- `run_handshake` (line 130) uses `let client_id = Identity::from_secret_bytes(CLIENT_SEED);` *inside* the loop — same hardcoded `[0xBB; 32]` seed every iteration. The comment claims "fresh client identity (new static keys, new session state)". The static keys are not fresh. Same long-term keypair every time.
- The handshake measurement boundary is `send_data` → `recv` (line 156–161): handshake **plus** one full data round-trip. So "330 µs" is "handshake + 1 RTT echo". You can't separate the two from this measurement.
- `run_throughput` (line 195–219) is `while elapsed < duration { client.send_data(...).await?; bytes += payload.len(); }`. There is no "real flow control" anywhere here. There is no receiver-side draining. There is no ack. The Mbps number is bytes-pushed-into-the-API divided by wall clock. The README's "real flow control" parenthetical is a false claim.

Action:
1. Either fix the bench to actually do what the README claims, or rewrite the README to describe what the bench actually measures.
2. Generate a fresh client identity per iteration (`Identity::generate()`).
3. Separate "handshake completion" from "first echoed data" with timestamps inside the protocol or by using a non-data signal.
4. For throughput: drain the recv channel concurrently and report goodput (bytes acknowledged / wall clock), not pump-rate.
5. Re-run all numbers, report new ones, note the methodology change in the commit.

This isn't a small thing — the perf claims are the strongest pitch DRIFT has, and they're currently not credible the moment a reviewer reads `drift_proto.rs`.

---

## 4. Zero key zeroization despite "security-conscious" framing

`drift-core/Cargo.toml`:
```
x25519-dalek = { version = "2", features = ["static_secrets"] }
```

Note what's missing: `"zeroize"`. Without that feature, `x25519_dalek::StaticSecret` does **not** zero its bytes on drop. Nothing else in `drift-core` zeroes anything either:

- `Identity` holds `StaticSecret` and `PublicKey`; no `Zeroize`/`Drop` impl, no feature flag.
- `derive_session_key` returns a plain `[u8; 32]` byte array. These get passed by value, copied, never zeroed.
- `rekey_derive` same.
- The `SessionKey` wraps `Arc<ring::aead::LessSafeKey>`. Ring deliberately does **not** zero key material on drop — it's a documented design choice. So when a session ends, the key sits in process memory until the allocator overwrites it.
- Resumption PSKs flow through the same path with the same problem.

Forward secrecy as a property is not just "destroy the ephemeral pointer", it's "make sure the bytes are gone". Right now `core dump` of a long-running DRIFT process includes every session key, every static identity, every resumption PSK.

Action: add `zeroize` as a dep, derive `Zeroize`/`ZeroizeOnDrop` on `Identity`, on a wrapper around `[u8; 32]` for derived keys, and on the resumption ticket store. Switch from ring's `LessSafeKey` to a wrapper that zeroes the key bytes when the wrapper is dropped (you'll need to keep the bytes around to do this since ring doesn't expose them — derive into a `Zeroizing<[u8; 32]>`, then `UnboundKey::new` from a borrow and drop the borrow when the session ends). Or pick a different AEAD impl that zeroizes (the rustcrypto `chacha20poly1305` crate does).

This one undermines the entire identity-is-key pitch if you're targeting any threat model that includes memory disclosure (cold-boot, swap, debugger, hostile co-tenant). Fix this.

---

## 5. The cookie MAC is cryptographically dubious as written

`drift-core/src/crypto.rs:48` uses **SipHash-1-3** for the stateless DoS cookie, with this justification in the source comment:

> 128 bits of output is plenty for a 30-second rotation window — finding a collision takes ~2^64 probes, infeasible even at billions of guesses per second.

Two problems:
1. **Wrong security property.** What you need from a cookie MAC is *forgery resistance*, not *collision resistance*. Birthday-bound 2^64 is the wrong analysis. The relevant question is: can an attacker who has seen N (cookie, input) pairs forge a valid (cookie, input) for a new input? For a perfect MAC that's 2^128. SipHash isn't a perfect MAC.
2. **SipHash-1-3 is the speed-tuned variant.** It's used in Rust's HashMap to defeat hash-flooding, where the threat is much weaker than MAC forgery. It's not standardized as a cryptographic MAC, and Aumasson's reduced-round analyses raise concerns. SipHash-2-4 (HalfSipHash, etc.) at minimum.

In practice the 30-second rotation probably saves you, since by the time anyone breaks anything the secret is gone. But the *argument* in the source comment is wrong, and a reviewer at any maturity level will flag it.

Action: either switch to a vetted MAC (HMAC-SHA-256, BLAKE2b-MAC, KMAC) — performance on 30-byte inputs is fine — or rewrite the comment to argue forgery resistance honestly and cite the analysis you're relying on. SipHash-2-4 if you really need the speed.

---

## 6. CI is less strict than you think

`.github/workflows/ci.yml` has this comment in the clippy job:

```yaml
# Clippy runs for visibility but doesn't fail CI on style-
# level lints (needless_range_loop, while_let_loop,
# type_complexity, etc).
```

`cargo clippy --all-targets --all-features` will fail the step (and CI) if it returns nonzero, unless you've added `--no-deps` or pinned per-lint allows. So either:

- The comment is wrong about its own behavior (clippy *does* gate CI), or
- You've discovered a config such that clippy doesn't gate, in which case the comment hides what's effectively a permission-to-skip-clippy.

Either way it's confusing. Plus there's no `#![deny(...)]` config, no `clippy.toml`, no MSRV pin, and crucially:

- **Fuzz targets are not run in CI.** `fuzz/` is excluded from the workspace; the three libfuzzer targets are dormant unless someone manually `cd fuzz && cargo +nightly fuzz run`. Three fuzz targets that never run are zero fuzz targets.
- **Bench is not in CI.** The "330 µs / 1.67 Gbps" numbers in the README aren't regression-tested.
- **No miri, asan, tsan.** Given the heavy `unsafe` libc work in `transport/ecn.rs` and `batch.rs`, miri on a small subset would catch real things.

Action: pin `rust-version = "1.70"` (or current), make clippy gate CI explicitly with whatever `--allow` set you actually want, add a nightly fuzz job (even 5 minutes per target on PR), wire bench into a regression-tracking job (criterion-compare-action, or a simple baseline JSON committed to the repo).

---

## 7. Dead binaries / sprawling demos

`drift/Cargo.toml` declares **24 binaries/examples** in addition to the main `drift` CLI:

```
bench-oneshot, drift-send, drift-recv, drift-mesh, lossy-proxy, drift-relay,
big-send, scale-client, scale-server, drift-ring, drift-dir-server,
drift-dir-client, drift-peer, drift-tun, resumption-server, resumption-client,
drift-reconnect-node, drift-mesh-node-v2, two-bridge-demo, drift-churn-node,
drift-medium-demo, drift-shell, drift-chat, drift-kv
```

Several are obvious duplicates: `drift-mesh`, `drift-mesh-node-v2`, `drift-reconnect-node`, `drift-churn-node`, `drift-medium-demo`, `two-bridge-demo` are all variations of "spin up some peers and watch them mesh". Pick one canonical demo binary, delete the rest.

The cost: every `cargo build --all-targets` (which CI runs) compiles all of these. Compile time and binary surface compound. `drift-shell`, `drift-chat`, `drift-kv` look like sub-projects that should live in their own crates if they're real, or be deleted if they're scratch.

Action: triage. Promote the survivors to `examples/` only (no `[[bin]]` entry), or move them into a `drift-demos` crate excluded from default builds. Delete duplicates.

---

## 8. `drift-ffi` is unsafe in ways the comments don't mention

Read `drift-ffi/src/lib.rs:243–264` (`drift_transport_send_data`):

```rust
if transport.is_null() || peer_id.is_null() || (payload.is_null() && payload_len != 0) {
    return DRIFT_ERR_INVALID_ARGUMENT;
}
...
let slice = std::slice::from_raw_parts(payload, payload_len);
```

That guard explicitly *allows* `payload` to be NULL when `payload_len == 0`. Then `from_raw_parts(payload, 0)` is called. Per Rust's safety contract, `slice::from_raw_parts` requires the pointer to be non-null **even for empty slices**. NULL + 0 is UB. This is a bug.

And much bigger: there is **no `std::panic::catch_unwind`** anywhere in the FFI surface. Any panic inside `block_on(...)` — mutex poisoning, overflow in debug, an `expect` in `crypto.rs:92` if an attacker somehow constructs an invalid key — will unwind across the FFI boundary into the C caller. That's UB on every supported target. For an FFI library you ship as `cdylib`, this is non-negotiable.

The README/notes also admit FFI lacks `bind_url`/`connect_url` and callback adapters — meaning the eight celebrated transport schemes (TCP, TLS, WS, WebRTC, WebTransport, HTTP/SSE, onion) are inaccessible to anyone using DRIFT from C/Python/Go/Swift. Right now the FFI is "UDP only with a few hundred lines of `unsafe`". That's a much smaller value prop than the README suggests.

Action:
1. Wrap every FFI entry point in `catch_unwind` returning `DRIFT_ERR_INTERNAL` on panic.
2. Use `NonNull::new(payload).map(|p| from_raw_parts(p.as_ptr(), len)).unwrap_or(&[])` for the empty-slice case, or just early-return if `payload_len == 0`.
3. Either ship URL-dispatcher FFI in the next minor version, or stop showcasing the eight-transport story until the FFI catches up.

---

## 9. Mutex `unwrap`s in the long-running daemon path

86 `.unwrap()` / `.expect()` calls in shipped code. Most of the dangerous ones are `std::sync::Mutex::lock().unwrap()` inside `transport/mod.rs:1522, 1526, 1683, ...` and `io.rs:512, 520, 525`. These propagate poisoning: if any thread ever panics while holding `routes`, `cid_map`, or `peer_out_cid`, every subsequent `lock()` panics too, and your "long-running transport" becomes a panic-loop daemon.

Idiom is common in Rust, but for a transport daemon that's supposed to survive — this is a daemon for a *mesh routing protocol* — you should use `lock().unwrap_or_else(|p| p.into_inner())` (recover from poison) or, better, design so the locked state can't enter an inconsistent state on panic in the first place (small critical sections, no `?` between lock and unlock).

---

## 10. The "vs Reticulum" table is marketing, not docs

```
| | Reticulum | DRIFT |
| Bandwidth | 300 bps – 10 Mbps | 1 Mbps – 10 Gbps |
| Encryption | X25519 + AES-CBC + HMAC | X25519 + ChaCha20-Poly1305 |
```

Reticulum targets LoRa-class radio mesh; DRIFT targets IP networks. They do not solve the same problem. The table reads like "look how much better DRIFT is at things Reticulum was never trying to do." This kind of comparison hurts your credibility with anyone who knows either project. Drop it, or reframe as "if you came from Reticulum, here's what's the same and what's different."

---

## 11. Documentation gaps that matter

You have a 462-line README, an `ADAPTER_SPEC.md`, and per-tool sub-READMEs. What you *don't* have:

- **A protocol reference.** No `docs/protocol.md` with the full packet diagrams, state machine diagrams, all 15 packet types and their semantics, the rekey grace window timing, the path validation flow, the resumption ticket lifecycle, the coalesce/supersedes precedence rules. A reviewer has to read `transport/mod.rs:2131–2580` (handle_hello, handle_hello_ack) to figure out the actual handshake. For a 16k-LOC transport, this is too much code-archaeology to ask of a user.
- **A threat model.** What does DRIFT defend against? On-path passive observer, on-path active attacker, off-path attacker with source-spoofing, hostile peer with valid identity, memory-disclosure adversary, post-compromise of static keys? Currently each of these is implicitly answered by some part of the code; none is stated.
- **Operator runbook.** Defaults are sane but unclear. When does adaptive cookie mode trip? What metrics should an operator watch? What does `Metrics` actually report? What logs/qlog events appear in which conditions?
- **A "known limitations" page.** Things like the 2^31 seq ceiling, the `LessSafeKey` non-zeroization, the FFI gaps, the TLS-as-camouflage caveat — all should be in one place an operator can read in five minutes before deploying.

---

## 12. Smaller things, no particular order

- **No MSRV declared.** README says 1.70, no `rust-version` field. Will silently break with future feature stabilizations.
- **`boringtun = "0.7"`** in `drift-bench` — Cloudflare hasn't released a new version in years. Stale dep on the flagship comparative bench.
- **`Identity::from_secret_bytes` takes `[u8; 32]` by value.** Caller's `Vec<u8>` source isn't zeroed. Document, or accept `Zeroizing<[u8; 32]>`.
- **`fuzz/` excluded from workspace** with no CI hook means it's effectively abandonware.
- **No `deny.toml`** for cargo-deny — license audit, banned-deps, duplicate-version detection are all absent.
- **`drift-bench/src/drift_proto.rs:124`** has `_ => unreachable!()` inside a match on `Workload`. Silent foot-gun if `Workload` gains a variant.
- **`Identity::generate` uses `OsRng`** directly — fine, but no abstraction means you can't inject a deterministic RNG for tests / replays / fuzzing.
- **The "8.6× faster than QUIC" RTT claim** says "Tokio's mpsc + task-wakeup tax" is the gap. That diagnosis is plausible but unsupported in the README. A flame graph or a one-paragraph profile breakdown would land better than a hand-wave.
- **No release versioning discipline.** `version = "0.1.0"` across the board, no CHANGELOG. For a transport people might depend on, this is going to bite.
- **Stream open/recv flood attack tests are short** (102, 118 LOC). They cover the "obvious" exploit but no fuzz/proptest pressure. Consider proptest-driven adversarial scheduling: random interleavings of open/send/close/migrate from many spoofed sources.

---

## What's actually solid

To keep the review honest:

- The protocol design (deadline + supersedes + identity-is-key + pluggable transport) is original and well-thought-out. The wire format is reasonable.
- The adapter abstraction (`PacketIO` + `Listener` + inventory registration) is clean and the new-adapter cost is genuinely low.
- The named "attack" tests, even short, are *the* right framing — most projects don't have any.
- `unsafe` is genuinely confined to libc CMSG handling; the protocol logic is safe Rust.
- Error handling is consistent (`thiserror` + explicit enum, no `Box<dyn Error>` slop).
- The choice of vetted crypto libraries (ring, x25519-dalek, blake2, ml-kem) is correct; the gaps are in *how* they're wrapped, not what's wrapped.
- The mesh routing + supersedes + coalescing combination is genuinely interesting and worth keeping.

---

## Priority order if you fix these

1. **Zeroization** (item 4) — biggest credibility hit, smallest code change.
2. **Bench honesty** (item 3) — the README's headline numbers misrepresent what the code does.
3. **FFI panic-safety + NULL slice UB** (item 8) — real soundness bug.
4. **Delete dead source files + duplicate binaries** (items 1, 7) — pure cleanup, makes the next reviewer's job 10× easier.
5. **Cookie MAC argument** (item 5) — small fix, removes a "wait what" moment.
6. **Split `transport/mod.rs`** (item 2) — biggest engineering effort, biggest payoff for future contributors.
7. **Protocol reference doc + threat model** (item 11) — without these, you can't get serious external review or adoption.

# DRIFT — Session Handoff

**Last updated:** 2026-05-18
**Branch:** `main`, clean, in sync with `origin/main`
**Latest commit:** `d699ef9 drift sec/fed-bench: per-wire-scheme throughput probe + first numbers`

This file is written so the next Claude Code session can pick up cold without re-deriving everything from `git log`. Read this first, then skim `README.md` and `SPEC.md` if you want the deep version.

---

## 1. What DRIFT is, in one paragraph

DRIFT is a Rust identity-based encrypted transport — pubkey *is* the address, no DNS/TLS/PKI required, X25519 + ChaCha20-Poly1305 with optional ML-KEM-768 hybrid PQ, runs over a `PacketIO` trait so any byte-preserving wire (UDP/TCP/TLS/WS/HTTP/DNS/WebRTC/h2/h2s/WebTransport/onion/in-memory) carries the same packets. Mesh routing + federation are built into `drift bridge`. Browser-side stack (`drift-wasm`) compiles `drift-core` to WASM and speaks the same wire byte-for-byte. Mental model: "Reticulum, but for production IP."

## 2. Workspace map (only the parts you'll touch)

```
drift-core/              sans-io protocol engine (WASM-safe, no tokio)
drift/                   native tokio stack
  src/cli/bridge.rs      `drift bridge` runner — federation gate lives here
  src/io.rs              PacketIO + Listener traits, all wire adapters
  src/wire_h2.rs         h2:// + h2s:// (hyper http2 + rustls)
  src/wire_webtransport.rs  webtransport:// (wtransport / QUIC / HTTP/3)
  src/wire_http.rs       http:// (now hyper-based after HTTP.OPT1)
  src/wire_dns.rs        dns://
  src/wire_onion.rs      onion://
  src/transport/         mesh.rs, federated.rs, find_peer.rs, dp_bloom.rs, ...
drift-wasm/              browser-side; same drift-core compiled to wasm32
drift-vpn/               killer-tool VPN (v0.14.0, latest release)
drift-mosh/              mosh-style remote shell
drift-http/              HTTP-over-DRIFT
drift-git/               git-over-DRIFT
drift-wormhole/          magic-wormhole-style file transfer
drift-config/            inventory manager (drift.toml)
sec/                     security probes + benches
  fed-bench/             per-wire-scheme throughput probe (NEW this session)
  attack-relay/          open-relay reflection probe
  http-probe/            slowloris/header-flood probe
  docker/                container demos (http-proxy-demo, http-mesh-demo)
bench/                   wire-matrix bench harness for drift-vpn
docs/                    operator-facing docs (reverse-proxy.md, router-bridge.md, ...)
SPEC.md                  authoritative wire-format spec (§1–§15)
FEDERATION_DISCOVERY.md  design doc + threat model for peer discovery
ADAPTER_SPEC.md          how to write a new wire adapter
```

## 3. What landed in the most recent arc (this session)

The big push since `b5ee1e9 docs: reframe drift-vpn perf plan around wire-agnostic principle` (commit base) was a security-then-federation push:

### 3.1 Adapter perf phase (PERF.WA / ADAPT.*)
- TCP/TLS/WS/HTTP/DNS adapters got per-thread wire-buffer pool, batched writes, dropped per-packet flushes. See `drift-core/src/pool.rs`, and the `ADAPT.*` commits `7527a4a` → `02a5950`.
- Cross-wire bench harness lives at `bench/bench-matrix.sh`; results in `bench/bench-matrix-*.md`.

### 3.2 Security audit + pen-test campaign (SEC.AUDIT / SEC.EXPLOIT / SEC.PEN / SEC.FIX)
- **SEC.FIX.1** — open-relay reflection primitive in `drift bridge`. Closed by `require_src_for_forward` config flag; default-on for `drift bridge`. `--allow-open-relay` opts back to the legacy permissive behaviour. Regression-locked in `drift/tests/attack_open_relay.rs` across UDP/TCP/TLS/WS/HTTP.
- **SEC.PEN.HIGH-1** — slowloris on WS/TLS listeners. Fixed by spawn-the-handshake pattern (`WS_TLS_HANDSHAKE_TIMEOUT=10s`, `DEFAULT_WS_TLS_CONNS_PER_IP=32`). Tests: `attack_slowloris.rs`.
- Pen tests written + green: `attack_kci_unknown_key_share.rs`, `attack_pq_downgrade.rs`, `attack_nonce_rollover.rs`, plus VPN-side TUN-injection test in drift-vpn.

### 3.3 HTTP rewrite (HTTP.OPT1 / OPT2)
- `wire_http.rs` was ~250 LOC of hand-rolled parser; ported to hyper http1::Builder. SSE downstream via `StreamBody<ReceiverStream>`, POST upstream for `/drift-send`. `--trust-proxy-headers` flag added: skips drift's per-IP cap (proxy now owns it) and reads `X-Forwarded-For` / `X-Real-IP` for log context. `docs/reverse-proxy.md` has caddy/nginx/HAProxy configs.

### 3.4 Federation backbone — h2/h2s/webtransport (HTTP.FED.*)
**Three new federation-grade schemes**, designed to ride the HTTPS-aware web stack:

| Scheme | Wire | Crate | Status |
|---|---|---|---|
| `h2://` | HTTP/2 cleartext (h2c) single bidi stream | `hyper` http2 | green, live-tested |
| `h2s://` | HTTP/2 over TLS, ALPN=h2 | `hyper` + `rustls` | green, live-tested |
| `webtransport://` | QUIC + HTTP/3 | `wtransport` | green, live-tested |

Each carries a single bidirectional stream pair carrying length-prefixed DRIFT packets (`[u16:len][packet]`). One TCP/QUIC connection per federation link, not one per packet.

**HTTP.FED.STRICT gate** (in `drift/src/cli/bridge.rs`): for `--federate <url>@<pub>`, refuses public-IP targets that aren't h2/h2s/webtransport. **LAN carve-out**: RFC1918, loopback, link-local IPv6, ULA, CGNAT (100.64/10) are exempted — homelab UDP federation still works automatically. Opt-out: `--allow-legacy-federation`.

Tests: `tests/federation_over_h2.rs`, plus h2/h2s/webtransport added to `tests/hybrid_pq_adapters.rs` (now 9/9 wires carrying full PQ hybrid handshake).

### 3.5 Container demos + live verification
- `sec/docker/http-proxy-demo/` — caddy + drift bridge end-to-end
- `sec/docker/http-mesh-demo/` — client hosts HTTP + reachable via mesh
- Deployed to ASUSWRT router (armv7l) and to Drift1/2/3 LXCs and verified live.

### 3.6 fed-bench (NEW, just before this handoff)
`sec/fed-bench/` — two-mode binary (`MODE=listen` / `MODE=send`) for per-scheme throughput. 5-second LAN run between Drift1 (192.168.50.52) and Drift2 (192.168.50.168) gave:

| Wire | Listener-measured MB/s |
|---|---|
| webtransport | **158** |
| udp | 135 |
| ws | 112 |
| h2s | 105 |
| tcp | 103 |
| h2 | 98 |
| tls | 97 |

**Headline:** h2/h2s/webtransport carry full drift sessions at the same speed as raw TCP/TLS/UDP. WebTransport is actually fastest on LAN (QUIC datagrams use coalesced sends + sendmmsg under the hood — drift's plain UDP path doesn't). All three modern federation backbones are operationally viable.

---

## 4. Active environment

### 4.1 Home network LAN fabric (works right now, don't re-derive)

| Host | IP | Role | SSH | Notes |
|---|---|---|---|---|
| Mac (Bryson's MacBook Pro) | LAN | dev box | — | drift-vpn client, sometimes bridge |
| Router (ASUS RT-AX82U V2) | 192.168.50.1 | permanent DRIFT bridge | `ssh admin@192.168.50.1` | armv7l, stock ASUSWRT, binary at `/jffs/drift/drift`. **No scp** — use `cat binary \| ssh admin@192.168.50.1 'cat > /jffs/drift/drift'`. Manual relaunch on reboot. Pubkey `426b1...`. Ports: udp/tcp/ws/tls 51820–51823, h2 51826, h2s 51827, webtransport 51828. |
| Drift1 LXC | 192.168.50.52 | test peer | `ssh root@192.168.50.52` | Proxmox LXC. Small disk — clean up `/tmp/` and `/root/*` after runs. |
| Drift2 LXC | 192.168.50.168 | test peer | `ssh root@192.168.50.168` | |
| Drift3 LXC | 192.168.50.253 | spare (~6.8G free, use for big deps like caddy) | `ssh root@192.168.50.253` | |
| Drift4 LXC | 192.168.50.33 | spare | `ssh root@192.168.50.33` | |

drift-mosh-server is running on the router under pubkey `92b706...`; connect via `drift-mosh-client --host router-mosh`.

### 4.2 Cross-compile targets
- Linux LXCs: `cargo build --release --target x86_64-unknown-linux-musl`
- ASUS router: `cargo build --release --target armv7-unknown-linux-musleabihf`
- `cross` is configured; the bench scripts know how to use it.

### 4.3 Memory layer (`~/.claude/projects/-Users-5speeddeasil-drift/memory/`)

Already-saved memories the next session inherits:
- `project_drift.md` — high-level project pitch
- `project_killer_tool.md` — drift-vpn is the polish/packaging target
- `project_wire_agnostic_vpn.md` — VPN perf must not assume UDP
- `project_drift_open_relay_fix.md` — SEC.FIX.1 mechanics
- `reference_router_bridge.md` — router bridge + federation ports
- `reference_router_mosh.md` — drift-mosh-server on router
- `reference_proxmox_lxcs.md` — LXC IPs
- `reference_websearch_cli.md` — use `websearch` CLI not built-in WebSearch
- `feedback_multi_transport.md` — tools must expose UDP/TCP/WS/etc. as configurable
- `feedback_workspace_test_after_perf.md` — always run `cargo test --workspace --release --lib --bins --tests` after drift-core perf changes
- `feedback_wire_agnostic_bench_methodology.md` — perf changes need BOTH `bench/bench-matrix.sh` (live cross-wire) AND `cargo bench --bench throughput` (criterion micro)

## 5. Where the project is right now

- **All security pen-test items closed.** Drift bridge is hardened: no open-relay primitive, no slowloris, no KCI / unknown-key-share, no PQ downgrade.
- **Federation backbone is "done":** h2/h2s/webtransport all work as `--federate` schemes. Strict gate is on by default. LAN carve-out lets homelab UDP federation work without flags. Speeds measured.
- **drift-vpn v0.14.0 cut + verified live** on Drift1 LXC + Mac.
- **Identity rotation** end-to-end works (Mac → announce → Drift1 verified).
- **Cross-wire bench harness** stable. Use `bench/bench-matrix.sh` for VPN-side, `sec/fed-bench` for raw drift-session-side.
- **Hybrid PQ default-on** across all 9 wire schemes.
- **9 wire adapters** in tree (udp/tcp/tls/ws/http/dns/webrtc/h2/h2s/webtransport + onion behind a feature flag).

### 5.1 Current task list status (sample)
- `#300 [pending]` — **drift-vpn Windows daemon (Wintun)** — only outstanding pre-existing task.
- All other tasks `#299`–`#440` are completed.

## 6. Open goals + what to implement next

Listed roughly in order of "size of the lever vs. effort." Pick whichever fits the user's mood; **none of these are blocked on anything**.

### 6.1 Investigate the WebTransport > UDP gap (½ day diagnostic first, then maybe 1–2 days)

**Correction to an earlier framing in this doc:** sendmmsg, UDP_GSO, and UDP_GRO are *already implemented* in `drift/src/transport/batch.rs` (raw `libc::sendmmsg` + `UDP_SEGMENT` cmsg + `UDP_GRO` cmsg parsing) and wired through `UdpPacketIO::send_to_batch` / `recv_from_batch` at `drift/src/io.rs:137,181`. The +65% post-GSO/GRO drift-vpn number in `bench/drift-vpn-vs-wireguard.md` is the proof. **Do not re-implement sendmmsg.**

The fed-bench gap (WebTransport 158 vs UDP 135 MB/s) is therefore *not* explained by "drift doesn't batch syscalls." The much more likely cause is at `drift/src/io.rs:150`:

```rust
if packets.len() == 1 {
    self.socket.send_to(&packets[0].0, packets[0].1).await?;
    return Ok(1);
}
```

`send_to_batch` short-circuits to plain `send_to` when only one packet is queued. On a single-stream tight-loop workload (like fed-bench in `sec/fed-bench`), the outbound worker may rarely accumulate ≥2 packets per drain, so sendmmsg / GSO never fire. WebTransport via `wtransport` almost certainly does internal QUIC-level coalescing that benefits from the underlying batching syscalls in `quinn`.

**Diagnostic first (~1 hour, do this before any patch):** instrument `send_batch_for` (`drift/src/io.rs:857`) and the call site at `drift/src/transport/mod.rs:3342` with a counter or trace logging the average batch size per call. Re-run fed-bench on the Drift1↔Drift2 LAN fabric. Two outcomes:

- **Batches dominated by N=1 → there's a real patch to write.** Add a small accumulation window in the outbound worker (drain up to ~16 packets per tick before calling `send_to_batch`). Watch for: partial-send handling (`PacketIO::send_to_batch` returns the count it actually sent — caller has to re-queue the remainder), packet-ordering tolerance in the session layer, and total-latency impact of the accumulation window.
- **Batches already N≥2 → no patch on drift's side.** The WT lead is wtransport's internal advantages (one QUIC datagram can carry multiple application messages, plus quinn's own optimizations). Move on to other items in §6.

Files to read first: `drift/src/io.rs:137-196` (the UDP `send_to_batch` + `recv_from_batch` overrides and the 1-packet short-circuit), `drift/src/transport/batch.rs` (the already-existing sendmmsg/GSO/GRO implementation, for context), `drift/src/transport/mod.rs:3342` (the call site that builds the outbound batch).

### 6.2 drift-vpn Windows daemon (Wintun) — task #300 (multi-day)
The pre-existing pending task. drift-vpn currently runs on Linux (systemd) + macOS (launchd). Windows needs a service wrapper + Wintun userspace driver integration. Reference: WireGuard's `wintun.dll` API is the canonical pattern; `boringtun` does roughly this on Windows. Files to extend: `drift-vpn/src/install.rs`, `drift-vpn/src/daemon.rs`, plus a new `drift-vpn/src/wintun.rs` or `tun_windows.rs`. The userspace daemon flow shouldn't need to change.

### 6.3 PIR-based "high-privacy" lookup (multi-week, research-grade)
Mentioned as deferred in the federation discovery README. Lattice-based homomorphic PIR for the case where you can't trust even the answering bridge. Multi-megabyte per query, real cryptographic engineering project. Only worth it if the user wants to spend that kind of time.

### 6.4 drift-mosh-client WASM build (1–2 days)
The browser-side stack is fully functional; drift-mosh-client just isn't built for it yet. Would give an in-browser remote shell with no system install, riding on the cross-stack story we already validated. Files to create: `drift-mosh/src/bin/drift-mosh-wasm.rs` or extend the existing wasm test scaffolding.

### 6.5 Documentation polish for production deployment (a few hours)
`docs/reverse-proxy.md` covers the bridge side; `docs/router-bridge.md` covers the ASUSWRT case. What's missing is an end-to-end "I want to deploy a drift bridge for my friends" walkthrough that ties together: drift-config inventory → drift bridge --listen + --federate → systemd unit (already in drift-vpn but not for `drift bridge`) → caddy in front for TLS + h2s federation → drift-vpn install on a phone or laptop.

### 6.6 drift bridge systemd unit (a few hours)
drift-vpn ships a systemd unit via `drift-vpn install --start`. `drift bridge` doesn't. Symmetric work; same shape.

### 6.7 Stale-bench audit (~1 hour)
Run `grep -r "Gbps\|MB/s\|Mbit" --include="*.md"` across the workspace; some workspace READMEs may quote pre-PERF numbers. Memory entry `feedback_workspace_test_after_perf.md` is the canonical "always re-bench after perf" rule. Audit was done after PERF Phase 2 (task #409) but adapter perf phase (#414–#418) shipped after that and the perf delta was small.

**Partial pass on 2026-05-19:** added a "current numbers" pointer at the top of `docs/DRIFT_VPN_PERFORMANCE.md` so cold readers don't anchor on the pre-GSO/GRO 1.31 Gbps figure, and fixed the stale `wire_http.rs:192 parse_request_head` reference in `drift/tests/attack_sweep.rs` (replaced with a hyper-aware note). A full sweep of `drift-vpn/README.md`'s version mentions (it claims "v0.15" for the GSO/GRO win, HANDOFF §5 says v0.14.0 is the current cut) is still open.

### 6.8 ✅ DONE (2026-05-19): SEC.FIX.1 gate uses addr→peer_id index

Landed. Summary of the change for context:
**Bug context:** `mesh.rs:613-637` (the SEC.FIX.1 open-relay guard) calls `self.peers.lock_all().await` on every forwarded packet that has a network source. `lock_all()` is the documented cold-path function (`peer_shards.rs:18-22`) — it acquires all 16 shard mutexes. Doing this per-packet defeats the entire sharded-peer-table optimization and creates a self-DoS: the cost of *rejecting* attack traffic is linear in peer count × 16 mutex acquires per packet.

**Fix:** add a secondary `Mutex<HashMap<SocketAddr, SmallVec<[PeerId; 1]>>>` index inside `PeerShards` (or as a sibling). The gate becomes one mutex acquire + one hash lookup instead of 16 acquires + linear scan. SmallVec because NAT'd peers can transiently share a `SocketAddr` (rare; usually len=1).

**Risk and why this needs care:** the index has to be maintained at *every* peer-table mutation. Missing one site = stale index = potential false positive on the gate = silent SEC.FIX.1 regression (open relay returns). Found ~12 mutation sites via `grep "peers\.insert\|peers\.remove\|\.addr =" drift/src/transport/` but a full sweep should walk every `lock_for` / `lock_all` site too because `.get_mut(...).addr = new` would also bypass the index.

**Required scaffolding before shipping:** a property/sweep test that interleaves random sequences of `add_peer`, `remove`, addr migration, and other transport mutations, then after each step asserts `addr_index` agrees with what `lock_all().iter()` shows. Without this test, the change is not safe to merge. The existing `attack_open_relay.rs` tests would catch a complete failure but not a subtle mutation-site miss that only triggers on some code path.

**Bench validation:** add a benchmark that forwards N packets through a bridge with M peers and confirms the per-packet gate cost is constant in M after the change. (Not yet added — landed code is correctness-verified, perf-validated by smaller-scale tests, but no formal bench exists. Add this if scaling load testing matters.)

**What landed:**
- `drift/src/transport/peer_shards.rs`: `addr_index: Mutex<HashMap<SocketAddr, Vec<PeerId>>>` field on `PeerShards`. Maintenance API: `note_inserted`, `note_removed`, `note_addr_changed`. Gate API: `addr_belongs_to_known_peer` with a **two-step verify pattern** — fast index check, then per-candidate shard verify. Stale-positive bugs (missed `note_removed` / `note_addr_changed`) are caught by the verify pass; worst case is one extra shard lock, never silent open relay.
- 12 unit tests in `peer_shards.rs::tests` including a randomized sweep that interleaves insert/remove/migrate and asserts the index matches ground truth after every step.
- All 12 peer-table mutation sites instrumented to call the `note_*` helpers: `add_peer`, `add_mesh_peer`, `add_federated_peer`, `update_peer_addr` in the public Transport API; `close_peer`, `handle_close`, `handle_hello` (auto-register + addr-migration on regenerate_session), `handle_federated` (auto-register), `run_handshake_eviction_loop` in `transport/mod.rs`; `handle_resume_hello` in `resumption.rs`; `handle_path_response` in `path.rs`.
- `mesh.rs:613-637`: swapped the `lock_all()` walk for `addr_belongs_to_known_peer`.
- All 8 `attack_open_relay.rs` tests pass with the new gate — including the peer-enumeration side-channel regression test. Full security suite (17 attack/federation test files) green.

### 6.9 ✅ DONE (2026-05-19): drift-core integration tests landed
Landed. Scope chosen: **stricter target — any no-tokio embedder**, since that's the discipline drift-core advertises and is a superset of WASM coverage.

**What landed:** `drift-core/tests/sans_io_composition.rs` — 8 integration tests that compose drift-core primitives (Identity, derive_session_key, SessionKey, Header, canonical_aad, pq) into real workflows without importing tokio or any async runtime. Covers: two-party AEAD round-trip, direction separation, tampered-ciphertext rejection, hop_ttl AAD masking, PQ hybrid key derivation + seal/open, header encode/decode round-trip, Identity::dh zero-pubkey rejection, derive_peer_id determinism. If a future change to drift-core breaks no-tokio embedders (drift-wasm being the obvious example), these tests stop compiling.

## 7. Conventions the user has actually validated

These were learned the hard way and the next session shouldn't re-litigate them.

1. **Tools must be wire-agnostic.** No tool hardcodes UDP. Every user-facing tool (drift-vpn, drift-mosh, drift-http, drift-git, drift-wormhole) exposes wire scheme as a config knob and supports the full menu. `drift bridge` accepts a repeatable `--listen <scheme>://addr` flag.
2. **Federation gate is correct as default-on with explicit opt-out.** User validated this after a back-and-forth where I implemented strict-mode-by-default first, then added the RFC1918 carve-out for LAN. Don't propose removing the gate or making it warning-only.
3. **Don't build auto-fallback for federation schemes.** Operators forwarding ports for a public bridge are technically literate enough to read the table and pick. Adding magic loses control. (Decided this session.)
4. **Use `websearch` CLI for web lookups**, not the built-in WebSearch tool. It's installed from FancyWaifu/websearch; call as `websearch search/research/fetch`.
5. **After drift-core perf commits, run `cargo test --workspace --release --lib --bins --tests`.** Single-peer bench misses fairness/starvation bugs that `loopback_full_mesh.rs` catches.
6. **Wire-agnostic perf changes need two benches: bench/bench-matrix.sh (live cross-wire VPN) AND `cargo bench --bench throughput` (criterion micro).** They catch different failure modes.
7. **Drift1 LXC has small disk.** Clean up after every run. Drift3 has 6.8G free for anything that pulls big deps (caddy install, target/release dirs).
8. **ASUSWRT quirks**: SSH as `admin@`, no scp/sftp/rsync (use `cat | ssh ... 'cat >'`), busybox netstat, killall not pkill, persistence is manual-relaunch (no systemd, no cron in jffs).
9. **For LXC SSH it's `root@`**, not admin.

## 8. Quick "I'm a new session, how do I verify everything still works"

```bash
# 1. From the repo root: clean build of the workspace.
cargo build --workspace --release

# 2. Workspace tests (this is the "did anything regress" gate).
cargo test --workspace --release --lib --bins --tests

# 3. Federation gate behavior:
cargo test -p drift --release --test federation_over_h2

# 4. Pen tests still green:
cargo test -p drift --release --test attack_open_relay
cargo test -p drift --release --test attack_slowloris
cargo test -p drift --release --test attack_pq_downgrade
cargo test -p drift --release --test attack_kci_unknown_key_share
cargo test -p drift --release --test attack_nonce_rollover

# 5. PQ-over-every-wire (9/9):
cargo test -p drift --release --test hybrid_pq_adapters

# 6. (Optional) Re-run the live wire matrix on LXCs:
./bench/bench-matrix.sh    # needs Drift1 + Drift2 reachable

# 7. (Optional) Re-run sec/fed-bench between two LXCs.
#    See sec/fed-bench/src/main.rs header for env-var contract.
```

If any of 2–5 fails, fix that before doing new work.

## 9. Files the next session is most likely to need

| What | Where |
|---|---|
| Federation strict gate + LAN carve-out | `drift/src/cli/bridge.rs` (search `is_lan_target`, `fed_gate_tests`) |
| URL dispatcher / adapter registry | `drift/src/io.rs` (search `inventory::submit!`) |
| h2 / h2s adapter | `drift/src/wire_h2.rs` |
| WebTransport adapter | `drift/src/wire_webtransport.rs` |
| HTTP adapter (hyper-based) | `drift/src/wire_http.rs` |
| Federation envelope (`PacketType::Federated`) | `drift/src/transport/federated.rs` |
| Peer discovery (FindPeer / PeerHere / PeerGone / hashed) | `drift/src/transport/find_peer.rs` |
| DP bloom filter | `drift/src/transport/dp_bloom.rs` |
| Wire-format spec (authoritative) | `SPEC.md` |
| Federation design doc | `FEDERATION_DISCOVERY.md` |
| Reverse-proxy operator doc | `docs/reverse-proxy.md` |
| Throughput probe | `sec/fed-bench/src/main.rs` |
| Cross-wire VPN bench | `bench/bench-matrix.sh` |

## 10. One-paragraph summary for the very impatient

DRIFT is in a good, stable place. The hard security and federation work is done. h2/h2s/webtransport are live federation backbones with measured speeds matching raw TCP/TLS/UDP, and the bridge has been hardened against the obvious bridge-grade attacks. The single most leverage-rich next task is **sendmmsg/recvmmsg for drift's UDP adapter** (the fed-bench result strongly implies free throughput is sitting on the table), and the only outstanding pre-existing task is the **Windows VPN daemon (#300)**. The user prefers wire-agnostic, operator-controlled, default-secure design — don't add fallback magic, don't hardcode UDP, don't propose making the federation gate warning-only.

---

*Next session: skim §1–§3, read §4 for environment, jump to §6 for what to actually work on, refer to §7 for what NOT to re-litigate.*

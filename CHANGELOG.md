# Changelog

All notable changes to DRIFT, the identity-based transport.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry includes the merged-PR number so consumers can find the
diff, and groups changes by the user-visible surface they affect
(Bridge, Federation, Wires, Tooling, …) rather than by internal
crate. A change that touches multiple surfaces appears under each.

## [Unreleased]

### Bridge / Federation

- **iroh is now the default federation wire** for `drift bridge`. The
  `--federate` allowlist is reordered to put `iroh://` / `iroh-n0://`
  first; h2s / h2 / webtransport remain preferred fallbacks. UDP/TCP
  federation still needs `--allow-legacy-federation`. (#13)
- **Fixed federation-directory propagation gap.** After
  `connect_federate` succeeded, bridges sat in `HandshakeState::Pending`
  with no traffic until the 2-second keep-alive ticker fired — but the
  FederationDirectory announcer started at +1 s and silently dropped its
  first announce. Bridges now send a one-byte warmup right after
  `connect_federate` to establish the session before the directory
  loop runs. Affects every wire, not just iroh. (#18)
- **Bridge spec parsing handles URLs with internal `@`.** The
  `--bridge` / `--peer` / `--target-bridge` parsers used `split_once('@')`
  which broke for `iroh://<id>@<host:port>@<pub>` shapes. Switched to
  `rsplit_once('@')`; works for both legacy and new URL formats. (#14)

### Wires — iroh

- **`iroh-n0://` scheme** added (N0 preset with PKARR DNS discovery
  + n0 relay fallback). Privacy trade-off — bridge pubkey gets
  published to `dns.iroh.link`; loud warn at bind time. (#6)
- **Iroh identity auto-binds to bridge identity** unless
  `DRIFT_IROH_SECRET_HEX` is set. Same 32-byte secret feeds both
  curves (X25519 for DRIFT, ed25519 for iroh); the iroh `EndpointId`
  is logged at bind so operators can share it. (#7)
- **Pre-bind sysctl check for `net.core.rmem_max`.** Bridge refuses
  to bind iroh listeners if the kernel UDP receive buffer is below
  4 MiB; warns if below the 128 MiB recommended value. Surfaces a
  silent-drop failure mode that previously needed K-large traffic
  to hit. (#8)
- **Map-based peer-addr dedup.** Replaced SipHash-truncated
  `EndpointId → SocketAddr` synthesis (24-bit collision window
  at ~4096 endpoints) with a `HashMap<EndpointId, SocketAddr>`
  that allocates 192.0.2.0/24 slots sequentially. ~16M collision-
  free assignments. (#12)
- **500 ms per-path keep-alive** in `QuicTransportConfig` so the
  Backup path stays alive through iroh's 15 s `PATH_MAX_IDLE_TIMEOUT`
  even when iroh's `biased_rtt_path_selector` switches selection
  to an ephemeral NAT-traversal path. Fixes cross-host LAN federation
  stability — pre-fix the connection died at 30 s–3 min, post-fix
  the 30-minute soak runs clean. (#17)
- **Three regression tests** for the two bugs we hit in K=17:
  MTU floor (`INITIAL_MTU >= 1400`), preset-mismatch detection,
  and `SHARED_ENDPOINT` sharing across binds. Each fault-injected
  to confirm it catches the bug it's named for. (#9)
- **Iroh pinned exactly** at `=1.0.0-rc.1` with an inline upgrade
  checklist in `Cargo.toml`. Cargo.lock is gitignored, so the
  spec is the only thing preventing a silent rc.2 / 1.0 upgrade.
  (#11)

### Tooling

- **K=17 long-soak monitor** (`drift-bench/scripts/k17-soak.sh`)
  watches an already-up federation for 24 h, snapshots RSS / FDs /
  loopback bytes / auth_failures every 5 min, emits a TSV + a
  PASS/WARN/FAIL verdict. Catches slow leaks that 5-min sweeps miss.
  (#10)
- **Soak script busybox-compatible** so it runs on the router-bridge
  itself: `MIN_PIDS` env gate (default 17, single-bridge soaks set 2),
  for-loop pidfile count instead of `find -maxdepth`, parameter-
  expansion split instead of `read < <(...)` process substitution.
  (#15)

### drift-vpn

- **`resolve_endpoint` now parses iroh:// URLs.** Strips the leading
  `<endpoint_id>@` before parsing host:port, errors cleanly on
  iroh-n0:// (which has no host:port — discovery resolves at dial
  time). Low practical impact (the actual dial path goes through
  `Transport::connect_federate` which already handles iroh), but
  closes the placeholder-address fallback bug. (#16)

## How to read this file

- **Unreleased** lists changes that have landed on `main` but
  haven't been tagged into a versioned release yet.
- Versioned sections (`## [0.x.y]`) list changes between releases
  in reverse chronological order.
- Each entry leads with the user-visible effect, then explains the
  rationale or the bug being fixed. PR numbers in parens link to
  the diff + the original discussion.

## How to add to this file

When you land a PR with a user-visible change (anything an
operator would notice — bug fixes, default changes, new features,
behavior changes, CLI surface), add a bullet to `## [Unreleased]`
under the appropriate section. Don't add entries for purely
internal refactors that don't change behavior.

If a category isn't listed under Unreleased yet, add it. Common
sections: **Bridge / Federation**, **Wires — &lt;name&gt;**,
**Tooling**, **drift-vpn**, **drift-mosh**, **drift-wormhole**,
**drift-http**, **drift-git**, **Security**, **Breaking**.

Breaking changes (anything that would force a downstream user to
adjust their config, code, or deployment) go under a top-level
`### Breaking` section. Include the migration path inline.

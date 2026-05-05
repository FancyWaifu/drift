# drift-git

Git over DRIFT. `git push drift://<peerhex>@<host>:<port>/<repo>` works against any DRIFT-addressed peer — no SSH keys, no DNS, no GitHub.

Two binaries:

- **`drift-git-server`** — daemon. Listens on a DRIFT URL, accepts authenticated peers, spawns `git-upload-pack` / `git-receive-pack` against bare repos under a configured root, ACL'd by pubkey.
- **`git-remote-drift`** — git remote helper. When git sees `drift://...`, it invokes this; we tunnel git's pack protocol over a DRIFT stream to the server.

We don't reimplement git. The user's installed `git` does all the actual git work on both ends; our two binaries are just the transport pipe.

## Run the e2e test

```bash
cargo build --release -p drift-git
bash drift-git/tests/e2e.sh
```

Sets up a bare repo, runs `drift-git-server` against it, then uses real `git push` and `git clone` over `drift://` to push a commit, clone it, push a second commit, and fetch it. Six PASS lines on success.

## Wire shape

```
drift://<64-hex-pubkey>@<host>:<port>/<repo-path>
```

- `<64-hex-pubkey>` — server's static pubkey
- `<host>:<port>` — DRIFT UDP socket (v1 always UDP; future versions can support `drift+tls://`, `drift+onion://`, etc.)
- `<repo-path>` — repo on the server, resolved relative to the server's `--root`

## Stream protocol

After the helper opens a DRIFT stream to the server, the first chunk is a small text envelope:

```
drift-git/1
git-upload-pack            (or git-receive-pack)
/srv/git/myrepo.git

```

(blank line terminates). Server replies on the same stream:

```
drift-git/1 ok

```

After the OK, both sides switch to a 1-byte framed tunnel — `[0x00, ...payload]` for data, `[0x01]` for end-of-data — so each direction can finish without tearing down the bidirectional DRIFT stream (DRIFT streams don't have half-close).

## Server flags

```
--bind <url>               DRIFT URL to listen on (default udp://0.0.0.0:9100)
--identity-file <path>     32-byte identity (raw or 64-char hex). Ephemeral if omitted.
--root <path>              Repo root. Client paths resolve relative to this.
--allow <pubhex>           Allow this pubkey (repeatable).
--allow-any                Disable ACL — testing only.
```

## Helper environment

```
DRIFT_GIT_HELPER_KEY=<64-hex>     Stable client identity. Random ephemeral if unset.
DRIFT_GIT_HELPER_LOG=1            Enable tracing to stderr.
```

## What this gives you

- **No SSH keys.** Client identity is X25519, server ACL is a list of pubkeys.
- **No DNS.** The `<host>:<port>` is the wire-level address. The user identifies the *server* by its 64-char pubkey, not by hostname.
- **Multi-transport, eventually.** v1 hardcodes UDP; once we add `drift+tls://` and `drift+onion://` URL prefixes, the same `git push` works through HTTPS-only proxies and over Tor.
- **Mobility.** Server's IP changes (laptop → coffee shop → home) and the URL stays the same identity — only the `@host:port` part needs updating.

## Limitations (v1)

- Single transport (UDP). Multi-transport URL prefix support is the obvious next step.
- ACL is a global allow-list, not per-repo. Per-repo + per-action (read vs write) ACL via TOML config is on the roadmap.
- Helper uses a fresh ephemeral identity per `git push` unless `DRIFT_GIT_HELPER_KEY` is set. Long-term auth wants a proper config file under `~/.config/drift/`.
- Server captures child stderr but doesn't forward it — git's `remote: ...` progress lines aren't shown to the client. Add sideband-2 forwarding when needed.

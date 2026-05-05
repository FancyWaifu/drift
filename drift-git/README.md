# drift-git

Git over DRIFT. `git push drift://<peerhex>@<host>:<port>/<repo>` works against any DRIFT-addressed peer — no SSH keys, no DNS, no GitHub.

Two binaries:

- **`drift-git-server`** — daemon. Listens on a DRIFT URL, accepts authenticated peers, spawns `git-upload-pack` / `git-receive-pack` against bare repos under a configured root, ACL'd by pubkey.
- **`git-remote-drift`** — git remote helper. When git sees `drift://...`, it invokes this; we tunnel git's pack protocol over a DRIFT stream to the server.

We don't reimplement git. The user's installed `git` does all the actual git work on both ends; our two binaries are just the transport pipe.

## Run the e2e tests

```bash
cargo build --release -p drift-git
bash drift-git/tests/e2e.sh           # UDP: push, clone, second push, fetch
bash drift-git/tests/multi_scheme.sh  # UDP, TCP, TLS, WS
bash drift-git/tests/mesh_hop.sh      # routed through a drift-chat bridge
```

`e2e.sh` is the canonical 4-PASS push/clone/fetch test on UDP. `multi_scheme.sh` repeats push+clone over each of `drift://`, `drift+tcp://`, `drift+tls://`, `drift+ws://`. `mesh_hop.sh` proves the server can sit *behind* a drift-chat bridge (NAT-traversal scenario): the server connects *out* to the bridge, helper connects to the same bridge, mesh routing carries the git pack protocol between them.

## Wire shape

```
drift[+<scheme>]://<64-hex-pubkey>@<host>:<port>/<repo-path>
```

- `<64-hex-pubkey>` — server's static pubkey
- `<host>:<port>` — DRIFT wire endpoint (server, or bridge if mesh-routed)
- `<repo-path>` — repo on the server, resolved relative to the server's `--root`

The `+<scheme>` suffix selects the underlying transport. Bare `drift://` defaults to UDP. Currently supported:

| URL prefix | Underlying DRIFT adapter |
|---|---|
| `drift://` | `udp://` |
| `drift+tcp://` | `tcp://` (length-prefixed) |
| `drift+tls://` | `tls://` (TCP wrapped in TLS — looks like HTTPS to middleboxes) |
| `drift+ws://` | `ws://` (WebSocket — survives HTTP-only proxies) |

Future prefixes: `drift+http://` (Server-Sent Events fallback), `drift+onion://` (Tor hidden services). Both work today on the underlying DRIFT layer; the URL prefix glue is one-line additions to `DriftGitUrl::parse`.

For the helper to use a non-UDP scheme, git needs a corresponding `git-remote-<scheme>` entry on PATH. A single binary serves all schemes via symlinks (the same trick `git-remote-https` uses for both `http://` and `https://`):

```bash
for s in drift+tcp drift+tls drift+ws; do
    ln -s git-remote-drift /path/to/git-remote-$s
done
```

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
--bind <url>               DRIFT URL to listen on. Mutually exclusive with --connect.
--connect <bridge-url>     Instead of listening, dial a bridge as outbound peer
                           and accept streams over the resulting mesh connection.
                           Use this when the server lives behind NAT/firewall.
--bridge-pub <hex>         Bridge node's pubkey. Required with --connect.
--identity-file <path>     32-byte identity (raw or 64-char hex). Ephemeral if omitted.
--root <path>              Repo root. Client paths resolve relative to this.
--allow <pubhex>           Allow this pubkey (repeatable).
--allow-any                Disable ACL — testing only.
```

## Helper environment

```
DRIFT_GIT_HELPER_KEY=<64-hex>     Stable client identity. Random ephemeral if unset.
DRIFT_GIT_HELPER_LOG=1            Enable tracing to stderr.
DRIFT_GIT_BRIDGE_URL=<url>        If set, the helper connects to this bridge URL
                                  instead of dialing the server directly. The URL
                                  in `git push drift://...` then identifies the
                                  *server's* pubkey; mesh routing finds it via
                                  the bridge.
DRIFT_GIT_BRIDGE_PUB=<hex>        Bridge's pubkey. Required when DRIFT_GIT_BRIDGE_URL
                                  is set.
```

## What this gives you

- **No SSH keys.** Client identity is X25519, server ACL is a list of pubkeys.
- **No DNS.** The `<host>:<port>` is the wire-level address. The user identifies the *server* by its 64-char pubkey, not by hostname.
- **Multi-transport, eventually.** v1 hardcodes UDP; once we add `drift+tls://` and `drift+onion://` URL prefixes, the same `git push` works through HTTPS-only proxies and over Tor.
- **Mobility.** Server's IP changes (laptop → coffee shop → home) and the URL stays the same identity — only the `@host:port` part needs updating.

## Limitations

- ACL is a global allow-list, not per-repo. Per-repo + per-action (read vs write) ACL via TOML config is on the roadmap.
- Helper uses a fresh ephemeral identity per `git push` unless `DRIFT_GIT_HELPER_KEY` is set. Long-term auth wants a proper config file under `~/.config/drift/`.
- Mesh-hop mode requires a 2-second beacon-propagation wait at startup (helper *and* server). On real networks (RTT > 100 ms) this may need to be longer; current value is tuned for loopback. A future enhancement is to detect "server route known" via the routing table directly instead of sleeping.
- Server captures child stderr but doesn't forward it — git's `remote: ...` progress lines aren't shown to the client. Add sideband-2 forwarding when needed.

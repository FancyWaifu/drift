# drift-http

**HTTP over DRIFT — Apache-style file server, Jellyfin-style proxy, and `drift://` URL handler.**

Built on [DRIFT](../README.md), the identity-based encrypted transport. Servers are addressed by their pubkey, not by hostname or IP, so you can run a public website (or expose Jellyfin, or proxy any HTTP service) without port forwarding, dynamic DNS, a reverse proxy, or a TLS cert.

```
# host a static site behind a pubkey:
$ drift-http serve --root ./my-site --bind 0.0.0.0:9100

# anyone with the pubkey can visit it:
$ drift-http connect --peer <PUB>@<HOST>:9100 --listen 127.0.0.1:8080
$ open http://127.0.0.1:8080/

# or clicking a drift:// link in any app, after one-time setup:
$ drift-http install-handler
$ open "drift://<PUB>@<HOST>:9100/"
```

## Install

### From source

Requires Rust 1.80+.

```bash
git clone https://github.com/FancyWaifu/drift
cd drift
cargo install --path drift-http --bin drift-http
```

## Three modes, one binary

`drift-http` has three subcommands. Pick whichever matches what you're doing:

### `serve --root <path>` — Apache-style file server

Serves static files from a directory. Hyper + tower-http does the actual HTTP work — range requests, MIME types, `index.html` resolution, 404 responses, byte-for-byte fidelity all come for free.

```bash
drift-http serve --root /var/www --bind 0.0.0.0:9100
```

Banner on stdout:
```
DRIFT_HTTP_PUB=<64 hex chars>      # the address — give this to anyone who should connect
DRIFT_HTTP_ADDR=0.0.0.0:9100       # actual bound UDP socket
DRIFT_HTTP_MODE=serve-files root=/var/www
DRIFT_HTTP_READY
```

### `serve --proxy <host:port>` — opaque tunnel to a local HTTP service

For things that already speak HTTP (Jellyfin, a Flask app, Grafana, etc.), `drift-http` just bridges DRIFT streams to a local TCP port. Each new stream becomes one TCP connection to the upstream — opaque, so WebSocket upgrades, range requests, HLS, multi-hour streams all work without any HTTP parsing in the middle.

```bash
drift-http serve --proxy 127.0.0.1:8096 --bind 0.0.0.0:9100
```

The Jellyfin server keeps doing exactly what it always did. `drift-http` just gives it a pubkey-addressed front door.

### `connect` — local listener that bridges to a remote `drift-http`

The consume side. Browsers, Jellyswarrm, anything else speaking plain HTTP hits a `localhost:NNNN` and the bytes flow over DRIFT to the remote server.

```bash
drift-http connect \
    --peer <PUB>@<HOST>:9100 \
    --listen 127.0.0.1:8080
# now `curl http://127.0.0.1:8080/` reaches the remote server
```

### `open <url>` — fire a `drift://` URL

Parses `drift://<PUB>@<HOST>:<PORT>/path?query`, ensures a background `connect` bridge to that peer is running on a free local port, and opens the resulting `http://127.0.0.1:NNNN/path` in the user's default browser. Repeat clicks reuse the same bridge per peer.

```bash
drift-http open drift://abc123...@1.2.3.4:9100/some/page
```

The most useful command is invoked indirectly: when someone clicks a `drift://` link in any app on a machine where the URL handler is installed (next section), it fires this command for them.

## `drift://` URL handler

One-time setup per machine:

```bash
drift-http install-handler
```

After that, **clicking a `drift://` link in any app** — Notes, Slack, Mail, the browser address bar, anywhere — opens a browser tab pointed at the right local bridge. Same UX as `spotify://` or `zoommtg://` URLs.

What the installer does:

- **macOS**: builds a small `.app` at `~/Library/Application Support/drift/DriftURLHandler.app` via `osacompile` (needed so the bundle has a real Apple Event handler — a plain shell-script launcher inside an `.app` does not receive `kAEGetURL` events). Patches `Info.plist` with `PlistBuddy` to declare `CFBundleURLTypes`. Runs `lsregister -f` and sets the default via `LSSetDefaultHandlerForURLScheme` (a one-line Swift call).
- **Linux**: writes `~/.local/share/applications/drift-url-handler.desktop` and runs `xdg-mime default ... x-scheme-handler/drift`.
- **Windows**: prints the registry-key instructions you need to add manually.

`--dry-run` prints what it would do without touching anything.

If anything misbehaves, every click logs to `~/Library/Logs/drift-url.log` (macOS) — useful when GUI launches don't have a terminal to print errors to.

## Where things live

- `~/.config/drift/identity.key` — your persistent 32-byte X25519 identity. **Shared across all DRIFT tools** (drift-mosh, drift-http, future ones), so a friend pins one pubkey for everything you run. Auto-created on first run, mode 0600. Treat it like `~/.ssh/id_ed25519`.
- `~/.config/drift/links/<pubhex>.json` — bridge state per peer (port + pid). Lets repeat `drift-http open` clicks reuse one local port instead of spawning a new bridge each time.
- `~/.config/drift/links/<pubhex>.log` — each background bridge's stderr.
- `~/Library/Application Support/drift/DriftURLHandler.app` (macOS) — the URL handler bundle.

## How it's different from Apache / nginx

| | Apache / nginx | drift-http |
|---|---|---|
| Addressed by | hostname (DNS) | pubkey (32 bytes) |
| TLS / cert mgmt | Let's Encrypt et al. | not needed (DRIFT is already AEAD-encrypted) |
| Reachable from outside without port forwarding | ❌ | ✅ |
| Survives ISP IP rotation | ❌ (need DDNS) | ✅ (DRIFT migration) |
| Range requests, MIME, ServeDir | ✅ | ✅ (uses tower-http) |

## How it's different from Tailscale Funnel / Cloudflare Tunnel / ngrok

| | Cloudflare Tunnel / ngrok | drift-http |
|---|---|---|
| Requires their account / their relay | yes | no |
| Edge node decrypts your traffic | yes (TLS termination at edge) | no (E2E AEAD between peers) |
| Pubkey-addressed | no (hostname-shaped) | yes |
| Connection migration | partial | yes (inherited from DRIFT) |
| Custom protocol handler | no | `drift://` |

## Architecture

```
                                 [identity:  ~/.config/drift/identity.key]
                                              │
  serve --root                                ▼
  ──────────────                       drift-http serve
   /var/www/  ──┐                          ▲
                │                          │  one DRIFT stream per inbound HTTP request
                ▼                          │
     hyper + tower-http::ServeDir          │
                ▲                          │
                │ AsyncRead/AsyncWrite     │
                │ via StreamIo adapter     │
                └──────────────────────────┘
                                           │
                                           ▼     ── DRIFT (UDP / TCP / WS) ──
                                           │
                                           ▼
  connect                                  ▲
  ───────                                  │
  TCP listener  ◀── browser / curl /       │
  127.0.0.1:N      Jellyswarrm / etc.      │
        │                                  │
        ▼                                  │
   one DRIFT stream per inbound TCP ───────┘
```

The linchpin is `StreamIo` (`src/io.rs`) — adapts a `drift::streams::Stream` so it satisfies `tokio::io::AsyncRead + AsyncWrite`. Hyper's connection builders accept any I/O matching that trait, so once a DRIFT stream looks like a TCP socket, the rest of the HTTP path is unchanged stock hyper + tower-http.

## Tests

```bash
cd drift-http/tests

./serve_static.sh   # 7 cases: index, nested, 404, SHA-fidelity, range
./serve_proxy.sh    # 64 KB through proxy mode against python -m http.server
./open_url.sh       # drift:// open: GET /, nested path, bridge-port reuse
```

URL parser unit tests:

```bash
cargo test -p drift-http url::tests
```

## Future work

Called out honestly:

- **HTTP/2.** Hyper supports it; we'd just wire `http2::Builder` and let clients negotiate. ~1 day.
- **Per-pubkey allowlist mode.** Today `serve` is `accept_any_peer: true` (anyone with the pubkey can connect, like a normal website). For private deployments, a flag that flips this and requires an `authorized_keys`-style file would let the server enforce per-client pinning.
- **Vhost / path routing.** One daemon serving multiple sites or multiple proxies, dispatched by `Host` header or path prefix.
- **WebSocket integration test.** Works in proxy mode for free (it's L4); a test that opens a WS connection and round-trips a frame would be worth adding for confidence.
- **Browser extension** that intercepts `drift://` URLs natively, so the address bar literally shows `drift://...` instead of the `localhost:NNNN` mapping. The current setup works in every browser without one, at the cost of address-bar fidelity.

## License

MIT. See [`LICENSE`](../LICENSE).

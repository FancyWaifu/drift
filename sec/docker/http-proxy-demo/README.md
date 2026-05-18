# End-to-end demo: drift http:// behind a caddy reverse proxy

Three-container compose that proves `drift bridge --listen http://… --trust-proxy-headers` works behind a real HTTP/1.1 reverse proxy (caddy).

## Run it

```
bash sec/docker/http-proxy-demo/run.sh
```

The script:

1. Generates an ephemeral bridge identity (under `keys/`, gitignored)
2. Brings up `drift-bridge` + `caddy` in the background
3. Runs `http-probe` (foreground) which:
   - Opens `connect_url("http://caddy:8080")` — the URL parser resolves the hostname via the OS resolver
   - Completes a full DRIFT X25519 + ML-KEM-768 hybrid handshake through caddy → drift-bridge
   - Polls `peer_metrics()` until `is_established = true`
4. Reports `PASS` or `FAIL` based on the probe's exit code
5. Tears down the containers

## What you see on success

```
==> RESULT: PASS — drift http:// session established through caddy reverse proxy
```

Plus caddy's access log line confirming the proxy actually forwarded the request:

```
"method":"GET","host":"caddy:8080","uri":"/drift-sse",
"upstream":"drift-bridge:51820","X-Forwarded-For":["<probe-ip>"]
```

## Topology

```
  http-probe (10.98.0.30)
      │  http://caddy:8080/drift-sse
      │  http://caddy:8080/drift-send?sid=...
      ▼
  caddy (10.98.0.20)            ── Caddyfile: reverse_proxy /drift-* drift-bridge:51820
      │  http://drift-bridge:51820/drift-sse
      │  http://drift-bridge:51820/drift-send?sid=...
      ▼
  drift-bridge (10.98.0.10)     ── drift bridge --listen http://0.0.0.0:51820
                                                --trust-proxy-headers
```

## Files

- `Caddyfile`           — minimal reverse-proxy config (HTTP/1.1, no TLS)
- `compose.yml`         — three-container topology
- `run.sh`              — wrapper that handles keygen + assertion
- `keys/`               — gitignored, regenerated per run

## What this proves

- The hyper-based `wire_http` server correctly handles requests forwarded by a real reverse proxy
- Caddy's default `transport http` settings work with drift's SSE long-poll
- `--trust-proxy-headers` doesn't break the wire path (per-IP cap is skipped, the proxy is now responsible for rate limiting)
- The full DRIFT crypto stack (X25519, ChaCha20-Poly1305, ML-KEM-768 hybrid) traverses the HTTP/1.1 framing without issue

## Not proved by this demo

- TLS termination at the proxy (the demo uses plain HTTP; production setups use caddy's auto-HTTPS or nginx with Let's Encrypt)
- HTTP/2 or HTTP/3 on the public side (drift backend stays HTTP/1.1)
- Rate-limit behavior under sustained load (the demo handshakes once)

For production reverse-proxy configs (caddy auto-TLS, nginx with HTTP/2, HAProxy), see `docs/reverse-proxy.md`.

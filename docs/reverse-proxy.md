# `drift bridge` behind a reverse proxy

The `http://` adapter accepts DRIFT-shaped traffic over plain HTTP/1.1 — by design, so middleboxes and corporate proxies that block UDP / TCP / WebSocket let it through. In production you almost always want a **battle-hardened reverse proxy** (nginx, caddy, HAProxy, Cloudflare, etc.) in front of `drift bridge --listen http://...`, for:

- TLS termination with a real cert (Let's Encrypt, etc.) instead of drift's self-signed `tls://`
- HTTP/2 / HTTP/3 between client and proxy (drift sees plain HTTP/1.1)
- Per-source-IP rate limiting tuned to your traffic shape
- DDoS / WAF / fail2ban / etc. that you already operate
- Logging into your existing observability stack
- Shared port 443 with the rest of your web infrastructure
- Connection multiplexing — proxy holds many client TCP connections, drift holds one (or a few) backend connections

DRIFT's own auth happens at the AEAD layer regardless of what's in front of the bridge, so the proxy adds nothing to confidentiality — it adds **operational** posture.

## Quick start: tell drift it's behind a proxy

```
drift bridge --listen http://127.0.0.1:51820 --trust-proxy-headers
```

`--trust-proxy-headers` does two things:

1. **Skips the per-IP TCP-connection cap.** Without the flag the cap would think every connection comes from the proxy's loopback IP (because it does), and would let through far too few real users. With the flag drift trusts the proxy to do its own per-source rate limiting.
2. **Reads `X-Forwarded-For` / `X-Real-IP` for log context** so trace logs show the real client IP rather than `127.0.0.1`.

**Never set `--trust-proxy-headers` on an internet-facing bridge.** Without a real proxy in front, clients can forge `X-Forwarded-For` and bypass the cap.

## Caddy

```caddyfile
drift.example.com {
    encode gzip
    reverse_proxy /drift-sse /drift-send 127.0.0.1:51820 {
        # SSE needs a long timeout — drift holds the GET open
        # for the lifetime of the session.
        transport http {
            response_header_timeout 24h
            read_timeout 24h
            keepalive 30s
        }
        # Trusted-by-default in caddy: X-Forwarded-For is
        # appended automatically.
    }
}
```

## nginx

```nginx
upstream drift_http {
    server 127.0.0.1:51820;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name drift.example.com;
    ssl_certificate     /etc/letsencrypt/live/drift.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/drift.example.com/privkey.pem;

    # /drift-sse is an SSE long-poll; no buffering, no timeout.
    location /drift-sse {
        proxy_pass http://drift_http;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 24h;
        proxy_send_timeout 24h;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # /drift-send is short-lived POST; standard handling.
    location /drift-send {
        proxy_pass http://drift_http;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 64k;
    }

    # Per-source-IP rate limit. Tune to your traffic. Drift's
    # own per-IP cap is disabled by --trust-proxy-headers; this
    # is now nginx's responsibility.
    limit_req_zone $binary_remote_addr zone=drift:10m rate=100r/s;
    limit_conn_zone $binary_remote_addr zone=drift_conn:10m;

    location ~ ^/drift- {
        limit_req  zone=drift  burst=200 nodelay;
        limit_conn drift_conn 64;
    }
}
```

## HAProxy

```haproxy
frontend drift_https
    bind *:443 ssl crt /etc/haproxy/certs/drift.example.com.pem alpn h2,http/1.1
    mode http
    http-request set-header X-Forwarded-For %[src]
    use_backend drift_http if { path_beg /drift- }

backend drift_http
    mode http
    timeout server 24h        # SSE long-poll
    timeout tunnel 24h
    option http-server-close
    server drift1 127.0.0.1:51820 check
```

## Why not just use `drift bridge --listen tls://...` directly?

`tls://` ships a self-signed cert and disables client-side cert validation — it's there to **look like HTTPS to middleboxes**, not to add a second crypto layer. Browsers and most HTTP clients will refuse it. If you want a real cert that browsers trust, terminate TLS in a real HTTP server in front.

drift's `tls://` and `--trust-proxy-headers` are complementary, not alternatives:
- **`tls://`**: drift listening on plain TCP+TLS, for situations where you can't deploy a reverse proxy (small bridges, IoT, dev/test)
- **`--trust-proxy-headers`**: drift listening on plain HTTP behind your existing TLS terminator, for production deployments where you already operate web infrastructure

## What the proxy buys you (and what it doesn't)

**Buys you:**

- Real TLS certificates that browsers and clients trust
- HTTP/2 / HTTP/3 on the public side (drift backend stays HTTP/1.1 for now)
- Real per-source-IP rate limiting (drift's per-IP cap is coarse)
- DDoS / WAF / GeoIP / etc. that your proxy already does
- Integration with your existing log aggregation, metrics, alerting
- Graceful proxy restarts without dropping drift sessions (drift's SSE survives)

**Does NOT change:**

- DRIFT's own X25519 + ChaCha20-Poly1305 + ML-KEM-768 hybrid handshake — every packet is still end-to-end encrypted between peer and bridge regardless of the proxy
- Peer authentication — every connection still needs the bridge's pubkey + a DRIFT identity
- The `accept_any_peer` semantics — if your bridge accepts any peer, anyone reaching the bridge through the proxy can also be a peer

## Client adapters vs federation adapters

`drift bridge` distinguishes two roles for its wire schemes:

**Client adapters** — every scheme drift speaks (`udp://`, `tcp://`, `tls://`, `ws://`, `http://`, `dns://`, `webrtc://`, `h2://`, `h2s://`, `webtransport://`). Use whatever your clients need:

```
drift bridge --listen udp://0.0.0.0:51820 \
             --listen tcp://0.0.0.0:51820 \
             --listen ws://0.0.0.0:51821 \
             --listen tls://0.0.0.0:51822 \
             --listen http://0.0.0.0:51823 \
             --listen webrtc://0.0.0.0:51825 \
             --listen h2://0.0.0.0:51826 \
             --listen h2s://0.0.0.0:51827 \
             --listen webtransport://0.0.0.0:51828
```

Each `--listen` accepts inbound connections from clients on that wire — phones, browsers, IoT devices, drift-vpn endpoints, anything.

**Federation adapters** — restricted to `h2://` / `h2s://` / `webtransport://` for public targets, but **LAN targets are exempted**:

```
# Public peer — must use h2/h2s/webtransport
drift bridge ... \
    --federate h2s://other-bridge.example.com:51827@<other-bridge-pubkey>

# LAN peer — any scheme works (the strict gate is skipped for
# RFC1918 / loopback / link-local / ULA / CGNAT addresses).
# UDP federation is genuinely faster on a LAN; this is the
# right answer for homelab and same-VPC setups.
drift bridge ... \
    --federate udp://192.168.50.1:51820@<lan-bridge-pubkey>
```

The strict default refuses `--federate <legacy-scheme>://` only when the target resolves to a public IP. The three modern schemes give you:

- **Multiplexing** — one TCP/QUIC connection per federation link, not one per packet
- **Middlebox-friendly** — any HTTPS-aware infra (caddy, nginx, Cloudflare, ALBs) just works
- **Reverse-proxy-ready** — terminate TLS at your proxy, speak `h2://` (h2c) to the bridge backend
- **Per-stream flow control** — h2 streams and QUIC streams both backpressure independently

To bridge with an older drift that doesn't support these schemes, pass `--allow-legacy-federation`. Use sparingly; the gate exists for a reason.

## See also

- `drift bridge --help` — full bridge CLI reference
- `wire_http.rs`, `wire_h2.rs`, `wire_webtransport.rs` — adapter sources
- `attack_open_relay.rs`, `attack_slowloris.rs` — security regression tests for the listeners

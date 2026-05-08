# drift-doh-relay

**Run your own Cloudflare Worker** as a rendezvous for DRIFT's
`doh://` adapter. Five-minute deploy, $0 in infrastructure cost,
no VPS / domain / public IP / port forwarding required.

Two DRIFT peers each `POST` DoH-shaped requests to your Worker;
the Worker routes encrypted fragments between them by destination
pubkey. Cloudflare's edge does the heavy lifting — DDoS
protection, TLS, global anycast. Your code is ~250 lines of
TypeScript on `src/index.ts`.

```
[Alice]                                              [Bob]
   │  doh://drift-doh-relay.<sub>.workers.dev/<a>/<b>   │
   │ ─────────────POST─────────────►                    │
   │             [Worker]                               │
   │   pushes fragment → inbox[b]                       │
   │   drains inbox[a] → TXT response                   │
   │ ◄────────────────────────────                      │
   │                                                    │
   │                          ◄─POST <b>/<a>──────────┐ │
   │                                                  │ │
```

## Why deploy your own (not share someone else's)

- **Trust boundary.** The Worker sees pubkey ↔ pubkey routing
  patterns even though it can't decrypt traffic. Running your own
  means the operator is *you*.
- **Quota.** Cloudflare's free tier gives 100k requests/day per
  account. Your friends sharing your Worker eat your quota.
- **DRIFT pubkey privacy.** A shared Worker can correlate which
  pubkeys are friends just by watching paired traffic patterns.
- **Reliability.** Your Worker, your uptime SLA. If a public
  one goes down or rate-limits you, your transport breaks.
- **It's free and easy.** Five minutes from `git clone` to
  deployed.

## Prerequisites

- Cloudflare account (sign up free at `dash.cloudflare.com`,
  no credit card required)
- Node.js + npm (any modern version, e.g. `brew install node`)

That's it. No domain, no VPS, no DNS records, no certs.

## Deploy

```bash
git clone https://github.com/FancyWaifu/drift
cd drift/drift-doh-relay
npm install
npx wrangler login          # opens browser to authorize wrangler
npx wrangler deploy         # uploads code, applies DO migration
```

On first deploy, you may also need to **visit the Cloudflare
dashboard once** to register your `workers.dev` subdomain — open
<https://dash.cloudflare.com/?to=/:account/workers-and-pages>
and let the page load. Cloudflare assigns you a subdomain
automatically (or prompts you to pick one).

When `wrangler deploy` succeeds it prints your live URL:

```
Deployed drift-doh-relay triggers (0.82 sec)
  https://drift-doh-relay.<your-subdomain>.workers.dev
```

That URL is what your DRIFT clients connect to.

## Verify it works

There's a small Rust smoke test in the parent crate that exercises
every endpoint and confirms fragments round-trip correctly:

```bash
cd ..   # back to repo root
cargo run --example doh-smoke -- \
    https://drift-doh-relay.<your-subdomain>.workers.dev
```

Expected output ends with `✅ All checks passed.`

## Use it from a DRIFT app

```rust
let url = format!(
    "doh://drift-doh-relay.<your-subdomain>.workers.dev/v1/{}/{}/dns-query",
    hex::encode(my_id.public_bytes()),
    hex::encode(peer_pubkey),
);
let (transport, addr) = drift::Transport::connect_url(
    &url,
    my_id,
    drift::TransportConfig::default(),
).await?;
let peer = transport.add_peer(peer_pubkey, addr, drift::Direction::Initiator).await?;
transport.send_data(&peer, b"hello-from-doh", 0, 0).await?;
```

The other peer constructs the **mirror URL** (their own pubkey
first, yours second) and calls `connect_url` similarly. The
Worker routes between them.

For a complete two-peer example, see `drift/examples/doh_chat.rs`
(interactive chat) and `drift/examples/doh_chat_demo.rs`
(self-driving end-to-end test).

## Wire format

Same encoding as `drift/src/wire_dns.rs`, so the native and
in-Worker codepaths speak identical bytes:

- **Request body**: standard DNS query (RFC 1035), QNAME encodes
  one DRIFT fragment as ≤3 base32 labels prefixed with a 4-byte
  reassembly header `[id u16 BE][idx u8][total u8]`, suffix
  `drift.local`.
- **Response body**: standard DNS response, one TXT record per
  pending fragment in `<my-pubkey>`'s inbox. Each TXT record's
  RDATA is the raw fragment bytes.
- **URL**: `/v1/<my-pubkey-hex>/<peer-pubkey-hex>/dns-query`
- **Empty poll**: any QNAME without leading base32 labels (e.g.
  `poll.drift.local`) is treated as "drain only, no data to
  push." Used by idle clients to fetch server-originated traffic.

A single request both *delivers* a fragment to the destination's
queue and *fetches* whatever's queued for the sender — half-duplex
per request, kept simple.

## State

Per-peer inboxes live in a Cloudflare Durable Object. The DO is
addressed by `idFromName(<pubkey-hex>)`, so all requests touching
the same pubkey land on the same DO instance — no race conditions
between concurrent pushes and drains.

- **Queue cap**: 1024 fragments per peer. Misbehaving senders
  hitting the cap have new packets dropped.
- **Drain batch**: 8 fragments per request. Larger backlogs are
  cleared across multiple polls.
- **Storage**: SQLite-backed Durable Objects (free-tier
  compatible).

## Logs

```bash
npx wrangler tail
```

Streams every request to your Worker in real time. Useful for
debugging — but be aware tail logs include URL paths, which
contain pubkey hexes.

## Updating the Worker

After changing `src/index.ts`:

```bash
npx wrangler deploy
```

That's it. The DO migration only runs once (gated by the `tag`
in `wrangler.toml`); subsequent deploys just swap the script.

## Tearing it down

```bash
npx wrangler delete
```

Deletes the script and the Durable Object data.

## Limits

- **Per-peer queue depth**: 1024 fragments.
- **Drain batch**: 8 fragments per request.
- **Free tier**: 100k requests/day total. With ~4 polls/sec per
  idle peer pair, that's ~7 hours of idle time per pair per day.
  Active peer pairs doing real traffic use far fewer requests
  because each request carries actual data instead of polling.
- **Cold-start latency**: first request to a fresh DO instance
  adds ~30 ms. Subsequent requests are sub-10 ms in the same
  region.
- **Worker CPU**: 50 ms per request on the free tier. Our handler
  averages 1-3 ms — plenty of headroom.

## Not here (yet)

- **No authentication.** Anyone with both pubkey hexes can drain
  / push to the relevant inbox. DRIFT itself is AEAD end-to-end
  so the Worker only sees ciphertext, but if you'd rather not
  expose pubkey ↔ pubkey routing patterns to the Worker operator,
  see the `dns://` adapter (direct peer-to-peer, no relay).
- **No persistence beyond DO lifetime.** DO state is in memory.
  If an instance is reclaimed, queued fragments are lost. DRIFT's
  retransmit layer recovers, but apps with strict delivery
  windows should be aware.
- **No rate-limiting.** A peer hammering at 100 req/sec uses your
  free-tier budget fast. If you publish your Worker URL widely,
  add a rate-limit layer (Cloudflare's WAF rules, or a token in
  the URL path) before deploying for friends.

## Not for production-scale traffic

This is "good enough for personal use, plus a handful of friends,
plus debugging hostile networks." If you need 100k+ active peer
pairs, talk to a real backend engineer — at that scale you'd
want Workers KV + a custom protocol with proper persistence,
backpressure, and observability, not a 250-line script.

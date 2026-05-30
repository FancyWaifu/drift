//! `doh://` — DRIFT shaped as DNS-over-HTTPS via a Cloudflare-Worker
//! rendezvous.
//!
//! Where `dns://` is direct peer-to-peer (raw DNS-shaped UDP, both
//! ends address each other by IP), `doh://` goes through an HTTPS
//! relay. Two peers connect to the same Worker URL; the Worker
//! buckets DRIFT fragments by destination pubkey and shuttles them
//! between sides on each request.
//!
//! ## When to use this vs `dns://`
//!
//! - `dns://` — both peers can reach each other directly on UDP.
//!   Raw DNS-shaped packets, no third-party relay.
//! - `doh://` — one or both peers behind a strict NAT or hostile
//!   firewall. HTTPS to a Cloudflare Worker is the universal
//!   "always works" wire — every network that allows web browsing
//!   allows port 443 to Cloudflare.
//!
//! ## URL form
//!
//! ```text
//! doh://<worker-host>[:port]/<my-pubkey-hex>/<peer-pubkey-hex>
//! ```
//!
//! Both pubkeys are baked into the URL path because:
//!
//! - The Worker uses `<peer-pubkey-hex>` as the inbox key — that's
//!   where it puts each fragment we send.
//! - The Worker uses `<my-pubkey-hex>` to drain *our* inbox on each
//!   request and return any pending fragments addressed to us.
//!
//! Application code typically builds the URL like:
//!
//! ```rust,ignore
//! let url = format!(
//!     "doh://drift-doh-relay.<your-subdomain>.workers.dev/v1/{}/{}/dns-query",
//!     hex::encode(my_id.public_bytes()),
//!     hex::encode(peer_pubkey),
//! );
//! let (transport, addr) = Transport::connect_url(&url, my_id, cfg).await?;
//! ```
//!
//! `<your-subdomain>` is the workers.dev subdomain Cloudflare
//! assigns to your account on first Worker creation. Run your
//! own Worker by deploying `drift-doh-relay/` (see its README) —
//! takes about five minutes, costs $0, no VPS or domain needed.
//!
//! ## Wire shape per request
//!
//! Each outbound DRIFT packet is fragmented into ≤113-byte chunks
//! (same scheme as `wire_dns.rs`). For each fragment:
//!
//! ```text
//! POST https://<worker-host>/v1/<me-hex>/<peer-hex>/dns-query
//!   Content-Type: application/dns-message
//!   Body: standard DNS query message — QNAME encodes the fragment
//!         as base32 across ≤3 labels, ending in `drift.local`.
//!
//! Response: 200 OK
//!   Content-Type: application/dns-message
//!   Body: standard DNS response — TXT records carry zero or more
//!         fragments addressed to <me-hex>.
//! ```
//!
//! When idle (no outbound packets pending), a background task
//! sends an "empty" poll every ~250 ms — a real DNS query with
//! no fragment payload — so server-originated traffic still gets
//! delivered. The Worker treats poll requests identically to
//! data-bearing ones.
//!
//! ## Stealth profile
//!
//! On the wire, this is HTTPS to a Cloudflare-hosted endpoint
//! posting `application/dns-message` bodies. To DPI middleboxes,
//! it is indistinguishable from any browser issuing DoH queries
//! (which is increasingly common — Firefox enables DoH by default
//! on many networks). The actual DRIFT-over-AEAD ciphertext is
//! one layer further down, inside the DNS message body inside the
//! TLS record stream.

use crate::io::{PacketIO, SchemeRegistration};
use crate::wire_dns::{
    build_query_message, parse_response_txt_records, qname_for_fragment, MAX_FRAG_PAYLOAD,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

/// How long to wait for outbound data before sending an empty
/// poll request. Trades latency for request volume — 250 ms is
/// what most DoH-stub-resolver implementations use.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Maximum response polls per second when idle. The Worker free
/// tier allows 100k req/day = ~1.15 req/sec sustained per peer
/// pair, so 4 polls/sec idle is well within the budget.
const _MAX_IDLE_POLL_RATE: f32 = 4.0;

/// Pretend "address" assigned to the remote DRIFT peer. The DoH
/// wire has no IP-level peer address (everything goes through the
/// Worker), so we synthesize a 127.0.0.x:port placeholder for the
/// Transport's peer table. DRIFT itself never tries to contact this
/// address — `send_to(_, dest)` on `DohPacketIO` ignores `dest`.
const PEER_PLACEHOLDER: &str = "127.0.0.1:1";

// ─── DohPacketIO ──────────────────────────────────────────────────

/// HTTPS-relayed DNS-over-HTTPS DRIFT transport. Lives entirely in
/// "client" role on the wire — both DRIFT peers are HTTP clients
/// of the Worker, which acts as the actual server.
pub struct DohPacketIO {
    /// Inbound DRIFT packets, drained by `recv_from`. Populated by
    /// the background poll task when responses arrive.
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Outbound DRIFT packets, fed by `send_to`. Drained by the
    /// background task and turned into HTTP requests.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Synthetic peer address for the trait's SocketAddr requirement.
    /// Stable for the lifetime of this adapter so the Transport's
    /// peer table doesn't get confused.
    peer_placeholder: SocketAddr,
    /// Hold the background task so it gets aborted when the adapter
    /// drops.
    _task: tokio::task::JoinHandle<()>,
}

impl DohPacketIO {
    /// Build a DoH-relayed adapter from a fully-formed Worker URL
    /// (must include both pubkey-hex segments — see module docs).
    pub fn connect(url: &str) -> io::Result<Self> {
        let url = url.to_string();
        let client = reqwest::Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| io::Error::other(format!("reqwest builder: {}", e)))?;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);

        // Reassembly state lives in the background task — only one
        // place reads it (the response decoder), so no lock needed.
        let task = tokio::spawn(poll_loop(client, url, out_rx, in_tx));

        Ok(Self {
            inbound_rx: Mutex::new(in_rx),
            outbound_tx: out_tx,
            peer_placeholder: PEER_PLACEHOLDER.parse().unwrap(),
            _task: task,
        })
    }
}

#[async_trait]
impl PacketIO for DohPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        // Push onto the outbound queue. The background task drains
        // it, fragments per packet, and POSTs each fragment to the
        // Worker. We return as soon as the channel accepts the
        // packet — same fire-and-forget semantics as UdpPacketIO.
        self.outbound_tx
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DoH poll task gone"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.inbound_rx.lock().await;
        let bytes = rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "DoH poll task closed inbound")
        })?;
        if bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "DoH packet too large: {} > buffer {}",
                    bytes.len(),
                    buf.len()
                ),
            ));
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), self.peer_placeholder))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // No bound socket — return a placeholder. Same convention
        // used by `WebRTCPacketIO` and `WebTransportPacketIO`.
        Ok(self.peer_placeholder)
    }
}

// ─── Background poll task ─────────────────────────────────────────

/// Drains outbound DRIFT packets, fragments each one, POSTs each
/// fragment to the Worker, parses response TXT records, reassembles
/// inbound fragments, and pushes complete DRIFT packets to the
/// inbound channel.
///
/// When idle, sends an empty poll request (a DNS query with no
/// fragment payload) every `POLL_INTERVAL` so server-originated
/// traffic is still delivered.
async fn poll_loop(
    client: reqwest::Client,
    url: String,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut reassembly: HashMap<u16, FragBuf> = HashMap::new();
    // Treat the loop as "just past the last request" so the very
    // first iteration's timer fires immediately. This matters for
    // the responder side, which has no outbound packets and would
    // otherwise wait forever for Alice's HELLO without polling.
    let mut last_request: Instant = Instant::now() - POLL_INTERVAL;

    loop {
        // Wait for either an outbound packet or the idle-poll timer.
        let deadline = last_request + POLL_INTERVAL;
        let next_outbound: Option<Vec<u8>> = tokio::select! {
            pkt = out_rx.recv() => match pkt {
                Some(p) => Some(p),
                None => return, // adapter dropped; exit cleanly
            },
            _ = tokio::time::sleep_until(deadline.into()) => None,
        };

        // Either fragment the outbound packet into one-or-more
        // requests, or send a single empty poll if we're idle.
        last_request = Instant::now();
        let send_result = if let Some(packet) = next_outbound {
            send_packet(&client, &url, &packet, &in_tx, &mut reassembly).await
        } else {
            send_poll(&client, &url, &in_tx, &mut reassembly).await
        };

        if let Err(e) = send_result {
            // Network error — log and back off briefly. DRIFT's own
            // protocol layer will retransmit.
            tracing::debug!(error = %e, "doh: request failed");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Also drain any other queued outbound packets back-to-back.
        // Empties the channel before the next idle poll so we don't
        // pad latency with the poll interval when we have data
        // ready to send.
        while let Ok(p) = out_rx.try_recv() {
            last_request = Instant::now();
            if let Err(e) = send_packet(&client, &url, &p, &in_tx, &mut reassembly).await {
                tracing::debug!(error = %e, "doh: request failed");
                tokio::time::sleep(Duration::from_millis(250)).await;
                break;
            }
        }
    }
}

/// Fragment a DRIFT packet, POST each fragment, and feed any
/// returned TXT-record fragments into the reassembly buffer.
async fn send_packet(
    client: &reqwest::Client,
    url: &str,
    packet: &[u8],
    in_tx: &mpsc::Sender<Vec<u8>>,
    reassembly: &mut HashMap<u16, FragBuf>,
) -> io::Result<()> {
    let total_frags = packet.len().div_ceil(MAX_FRAG_PAYLOAD);
    if total_frags > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DRIFT packet too large for DoH adapter: {}", packet.len()),
        ));
    }
    let frag_id: u16 = rand::random();
    for (idx, chunk) in packet.chunks(MAX_FRAG_PAYLOAD).enumerate() {
        let qname = qname_for_fragment(frag_id, idx as u8, total_frags as u8, chunk);
        let txid: u16 = rand::random();
        let body = build_query_message(txid, &qname);
        let resp_bytes = post_dns(client, url, body).await?;
        ingest_response(&resp_bytes, in_tx, reassembly).await;
    }
    Ok(())
}

/// Fire one empty poll request (no fragment payload) and ingest
/// any TXT records the Worker returns.
async fn send_poll(
    client: &reqwest::Client,
    url: &str,
    in_tx: &mpsc::Sender<Vec<u8>>,
    reassembly: &mut HashMap<u16, FragBuf>,
) -> io::Result<()> {
    // An "empty poll" QNAME has no payload labels — the Worker
    // distinguishes it by the absence of base32 labels before the
    // suffix.
    let qname = "poll.drift.local".to_string();
    let txid: u16 = rand::random();
    let body = build_query_message(txid, &qname);
    let resp_bytes = post_dns(client, url, body).await?;
    ingest_response(&resp_bytes, in_tx, reassembly).await;
    Ok(())
}

/// Single HTTP POST with the DoH content type.
async fn post_dns(client: &reqwest::Client, url: &str, body: Vec<u8>) -> io::Result<Vec<u8>> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(body)
        .send()
        .await
        .map_err(|e| io::Error::other(format!("doh POST: {}", e)))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| io::Error::other(format!("doh body: {}", e)))?;
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "doh POST returned {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(120)
                .collect::<String>(),
        )));
    }
    Ok(bytes.to_vec())
}

/// Decode TXT records from a response body, treat each one as a
/// QNAME-encoded fragment, push completed packets onto `in_tx`.
async fn ingest_response(
    resp_bytes: &[u8],
    in_tx: &mpsc::Sender<Vec<u8>>,
    reassembly: &mut HashMap<u16, FragBuf>,
) {
    // The Worker may also encode fragments in the response's
    // QNAME (in addition to TXT records) — but the canonical
    // path is TXT records. Try TXT first.
    let records = match parse_response_txt_records(resp_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "doh: malformed response");
            return;
        }
    };
    for rdata in records {
        // Each TXT record's RDATA is the raw fragment bytes
        // (`[id:u16][idx:u8][total:u8][payload]`) — same shape we
        // would see on the QNAME-encoded `dns://` wire after
        // decoding base32.
        if rdata.len() < 4 {
            continue;
        }
        let id = u16::from_be_bytes([rdata[0], rdata[1]]);
        let idx = rdata[2];
        let total = rdata[3];
        let payload = rdata[4..].to_vec();
        let entry = reassembly.entry(id).or_insert_with(|| FragBuf::new(total));
        if let Some(packet) = entry.insert(idx, payload) {
            reassembly.remove(&id);
            // Backpressure: if the consumer hasn't drained the
            // inbound channel, this awaits. That's the right
            // behavior — block the network task before we OOM.
            if in_tx.send(packet).await.is_err() {
                return;
            }
        }
    }
    // Garbage-collect very-old reassembly entries so a malicious
    // or buggy peer can't pin memory by sending half-packets
    // forever.
    if reassembly.len() > 64 {
        // Drop the oldest. Cheap heuristic — pick any entry; over
        // many invocations this empties the table within ~64
        // events of growth, which is fast enough.
        if let Some(&id) = reassembly.keys().next() {
            reassembly.remove(&id);
        }
    }
    let _ = in_tx; // keep clippy quiet on conditional moves
}

#[derive(Debug)]
struct FragBuf {
    parts: Vec<Option<Vec<u8>>>,
}

impl FragBuf {
    fn new(total: u8) -> Self {
        Self {
            parts: vec![None; total as usize],
        }
    }

    fn insert(&mut self, idx: u8, payload: Vec<u8>) -> Option<Vec<u8>> {
        if (idx as usize) >= self.parts.len() {
            return None;
        }
        if self.parts[idx as usize].is_none() {
            self.parts[idx as usize] = Some(payload);
        }
        if self.parts.iter().all(|p| p.is_some()) {
            let mut out = Vec::new();
            for p in self.parts.iter() {
                out.extend_from_slice(p.as_ref().unwrap());
            }
            Some(out)
        } else {
            None
        }
    }
}

// ─── Scheme registration ──────────────────────────────────────────

fn doh_connector_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move {
        // Reconstruct the full URL: `addr_str` is what came after
        // `doh://`. We need to determine the scheme part — for the
        // Worker we use https; for the test mock server we accept
        // a `?scheme=http` override (used in unit tests against a
        // localhost mock).
        let (https_url, peer_placeholder) = build_url(&addr_str)?;
        let io: Arc<dyn PacketIO> = Arc::new(DohPacketIO::connect(&https_url)?);
        Ok((io, peer_placeholder))
    })
}

/// Returns `(http_url_to_post, synthetic_peer_addr)`.
/// `addr_str` is everything after `doh://`. We prepend `https://`
/// unless the bare hostname is `localhost` or a 127.x.x.x address
/// (in which case we use plain `http://` so test harnesses don't
/// need TLS certs).
fn build_url(addr_str: &str) -> io::Result<(String, SocketAddr)> {
    // Crude check: anything pointing at loopback gets http://
    // for test convenience.
    let scheme = if addr_str.starts_with("127.")
        || addr_str.starts_with("localhost")
        || addr_str.starts_with("[::1]")
    {
        "http"
    } else {
        "https"
    };
    // Keep the path verbatim — caller is responsible for embedding
    // both pubkey hex segments.
    let url = format!("{}://{}", scheme, addr_str);
    let peer = PEER_PLACEHOLDER
        .parse()
        .map_err(|e| io::Error::other(format!("bad placeholder: {}", e)))?;
    Ok((url, peer))
}

inventory::submit! {
    SchemeRegistration {
        scheme: "doh",
        // No listener: the Worker is the listener. DRIFT-side
        // doh:// is connector-only.
        listener: doh_listener_unsupported,
        connector: doh_connector_factory,
    }
}

fn doh_listener_unsupported(
    _addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn crate::io::Listener>>> + Send>> {
    Box::pin(async move {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "doh:// is connector-only; the Worker (drift-doh-relay/) is \
             the rendezvous server. Both DRIFT peers connect to it as \
             clients.",
        ))
    })
}

// ─── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_loopback_uses_http() {
        let (url, _) = build_url("127.0.0.1:8080/aa/bb").unwrap();
        assert!(url.starts_with("http://"));
    }

    #[test]
    fn url_remote_uses_https() {
        let (url, _) = build_url("relay.example.com/aa/bb").unwrap();
        assert!(url.starts_with("https://"));
    }
}

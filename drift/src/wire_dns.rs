//! `dns://` — DRIFT shaped as DNS queries over UDP.
//!
//! For environments where every other DRIFT transport (UDP /
//! TCP / WS / TLS / HTTP) gets blocked but DNS gets through —
//! virtually anywhere on the public internet, since blocking
//! DNS breaks the network for everyone. The wire on port 53 (or
//! any UDP port we choose) looks like normal DNS A-record
//! queries to middleboxes and tcpdump.
//!
//! ## Wire shape
//!
//! Each DRIFT packet rides as one or more DNS query messages.
//! The query QNAME embeds a base32-encoded fragment of the
//! packet plus a small reassembly header:
//!
//! ```text
//! <chunk1>.<chunk2>.<chunk3>.drift.local
//! ```
//!
//! Each `<chunk>` is up to 63 base32 chars (the RFC 1035 label
//! limit). Three labels carry up to 189 base32 chars =
//! 117 raw bytes. The first 4 bytes of each fragment payload are
//! the reassembly header:
//!
//! ```text
//! [id: u16 BE][idx: u8][total: u8]
//! ```
//!
//! - `id`: random per DRIFT packet, lets the receiver bucket
//!   fragments from the same packet.
//! - `idx` / `total`: 0-based fragment index and total count.
//!
//! Fragments are sent as DNS QUERY messages (QR=0) with a
//! random transaction ID and QTYPE=A, QCLASS=IN — exactly the
//! shape a stub resolver emits when it asks the network for an
//! A record. Both sides send queries; nobody sends responses.
//! The DNS framing is camouflage, not a real DNS interaction —
//! middleboxes (and `tcpdump`) parse it as DNS, but neither end
//! is doing name resolution.
//!
//! ## Why this design
//!
//! - **Symmetric.** Same code on both ends. Mirrors the
//!   `UdpPacketIO` model: one bound UDP socket, packets demuxed
//!   by source address.
//! - **No DNS server in the loop.** We don't poke a real
//!   resolver — both peers talk directly. (A real DoH-wrapped
//!   variant would relay through `1.1.1.1` to bypass DNS
//!   blocking; that's a future extension.)
//! - **No allocator surprises.** Reassembly buffers are bounded
//!   per `(src_addr, id)`; pending fragments older than 5 s are
//!   evicted when new ones arrive.
//!
//! ## Limits
//!
//! - QNAME is capped at 255 octets total. We use ≤3 labels of
//!   ≤63 chars + `.drift.local` (12 chars) + null = 205 octets,
//!   safely under.
//! - Per-fragment raw payload: 117 bytes minus the 4-byte header
//!   = **113 bytes**.
//! - DRIFT's 1400-byte `MAX_PACKET` therefore takes
//!   `ceil(1400 / 113) = 13` DNS queries on the wire. Acks and
//!   small DATA packets typically fit in 1.

use crate::io::{Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use data_encoding::BASE32_NOPAD;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// ─── Tunables ─────────────────────────────────────────────────────

/// Suffix appended to each query QNAME so the wire looks like a
/// real domain. Receivers don't actually verify this — they just
/// strip the trailing labels — so different deployments can use
/// different suffixes without breaking interop.
const QUERY_SUFFIX: &str = "drift.local";

/// Maximum base32 chars per QNAME label (DNS RFC 1035 limit).
const LABEL_MAX: usize = 63;

/// Number of payload-carrying labels per QNAME. With 3 labels:
/// 3 × 63 = 189 base32 chars, decoding to 117 raw bytes. The
/// final QNAME (`a.b.c.drift.local.`) is 205 octets — under the
/// 255 limit with margin.
const LABELS_PER_QNAME: usize = 3;

/// Reassembly header length (id + idx + total).
const FRAG_HEADER_LEN: usize = 4;

/// Maximum DRIFT-packet bytes that fit in one DNS query.
/// 189 base32 chars → floor(189 × 5 / 8) = 118 raw bytes;
/// minus the 4-byte fragment header = 114. Round to 113 for
/// alignment safety.
pub const MAX_FRAG_PAYLOAD: usize = 113;

/// UDP receive buffer size. DNS over UDP is normally capped at
/// 512 bytes (RFC 1035) or 4096 with EDNS0; our queries are
/// well under either ceiling. 2048 is plenty.
const UDP_BUF: usize = 2048;

/// How long to keep a partial reassembly buffer before evicting
/// it. Anything older than this is treated as a stale or
/// abandoned packet.
const REASSEMBLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum number of in-flight reassembly buffers per peer
/// before we start dropping the oldest. Caps memory under
/// adversarial input.
const MAX_PENDING_PER_PEER: usize = 32;

// ─── DNS message encode / decode ──────────────────────────────────
//
// We hand-roll the bits of DNS we need rather than pulling in a
// full DNS library. The subset is tiny: build a query with one
// QNAME and a (QTYPE, QCLASS); parse a query out the other side
// to recover the QNAME labels. No compression pointers, no
// answer/authority/additional records — pure question section.

/// 12-byte DNS header followed by question section.
pub fn build_query_message(txid: u16, qname: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + qname.len() + 6);
    // Header: ID (2) + flags (2) + QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT (8)
    buf.extend_from_slice(&txid.to_be_bytes());
    // Flags: QR=0 (query), Opcode=0 (standard), RD=1 (recursion
    // desired) — matches what a stub resolver emits.
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_qname(&mut buf, qname);
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    buf
}

/// Each label is `[len: u8][bytes…]`; the QNAME ends with a
/// zero-length label.
fn encode_qname(buf: &mut Vec<u8>, qname: &str) {
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(LABEL_MAX) as u8;
        buf.push(len);
        buf.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    buf.push(0); // root label
}

/// Parse a DNS query message and return the QNAME labels (no
/// trailing root). Tolerates extra junk after the question
/// section (we don't read past it).
pub fn parse_qname_labels(msg: &[u8]) -> io::Result<Vec<String>> {
    if msg.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS message shorter than header",
        ));
    }
    // Skip the 12-byte header straight to the question.
    let mut off = 12;
    let mut labels = Vec::new();
    loop {
        if off >= msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QNAME truncated",
            ));
        }
        let len = msg[off] as usize;
        off += 1;
        if len == 0 {
            return Ok(labels);
        }
        if len > LABEL_MAX {
            // We never emit compression pointers (top bits set)
            // and refuse to follow them — they only matter for
            // multi-record responses, which we don't generate.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "label too long or compression pointer",
            ));
        }
        if off + len > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QNAME label exceeds message",
            ));
        }
        let label = std::str::from_utf8(&msg[off..off + len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 label"))?
            .to_string();
        labels.push(label);
        off += len;
    }
}

/// Build a DNS *response* message echoing `qname` and carrying
/// `fragments` as TXT records in the answer section. Used by the
/// DoH relay path: server-side packs pending DRIFT fragments for
/// a peer into TXT records; client decodes them via
/// `parse_response_txt_records`.
///
/// Each TXT RR's RDATA holds one fragment (raw bytes — not
/// base32-encoded, since TXT RDATA can carry arbitrary bytes
/// once you accept the per-string 255-byte cap, and our
/// fragments are ≤117 bytes including the 4-byte header).
pub fn build_response_message(
    txid: u16,
    qname: &str,
    fragments: &[Vec<u8>],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + fragments.iter().map(|f| f.len() + 12).sum::<usize>());
    buf.extend_from_slice(&txid.to_be_bytes());
    // QR=1, AA=1, RD=1, RA=1, RCODE=0 — looks like a normal
    // recursive resolver answering a stub query.
    buf.extend_from_slice(&0x8580u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&(fragments.len() as u16).to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section (echo).
    encode_qname(&mut buf, qname);
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A (the request was A)
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer section: one TXT RR per fragment. NAME points back
    // to the QNAME at offset 12 via DNS compression (`0xC0 0x0C`).
    for frag in fragments {
        debug_assert!(frag.len() <= 255, "fragment too large for one TXT string");
        buf.push(0xC0);
        buf.push(0x0C);
        buf.extend_from_slice(&16u16.to_be_bytes()); // TYPE = TXT
        buf.extend_from_slice(&1u16.to_be_bytes()); //  CLASS = IN
        buf.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (cache-busting)
        let rdlength = (1 + frag.len()) as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.push(frag.len() as u8); // TXT length-prefixed string
        buf.extend_from_slice(frag);
    }
    buf
}

/// Parse a DNS response message and extract every TXT record's
/// concatenated RDATA bytes (one Vec per record). Skips records
/// of any other type; returns an empty Vec if no TXT records
/// were present.
pub fn parse_response_txt_records(msg: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if msg.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response shorter than header",
        ));
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12;

    // Skip QDCOUNT question(s). Each: NAME (variable, terminated
    // by 0 or pointer) + 4 bytes (QTYPE+QCLASS).
    for _ in 0..qdcount {
        skip_name(msg, &mut off)?;
        if off + 4 > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "question section truncated",
            ));
        }
        off += 4;
    }

    // Walk the answer section. Each RR: NAME + TYPE(2) + CLASS(2)
    // + TTL(4) + RDLENGTH(2) + RDATA.
    let mut out = Vec::new();
    for _ in 0..ancount {
        skip_name(msg, &mut off)?;
        if off + 10 > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RR header truncated",
            ));
        }
        let rrtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        off += 8; // skip TYPE+CLASS+TTL
        let rdlength = u16::from_be_bytes([msg[off], msg[off + 1]]) as usize;
        off += 2;
        if off + rdlength > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RDATA truncated",
            ));
        }
        if rrtype == 16 {
            // TXT: a sequence of length-prefixed strings; concat
            // them back into one byte vector.
            let end = off + rdlength;
            let mut cur = off;
            let mut data = Vec::new();
            while cur < end {
                let strlen = msg[cur] as usize;
                cur += 1;
                if cur + strlen > end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TXT string overflows RDATA",
                    ));
                }
                data.extend_from_slice(&msg[cur..cur + strlen]);
                cur += strlen;
            }
            out.push(data);
        }
        off += rdlength;
    }
    Ok(out)
}

/// Skip over a DNS NAME at `off`. Handles both labels-and-zero
/// form and 2-byte compression pointers (which we treat as
/// terminal — we don't follow them, but we step past them).
fn skip_name(msg: &[u8], off: &mut usize) -> io::Result<()> {
    loop {
        if *off >= msg.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "NAME truncated"));
        }
        let len = msg[*off];
        if len == 0 {
            *off += 1;
            return Ok(());
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes total.
            if *off + 2 > msg.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compression pointer truncated",
                ));
            }
            *off += 2;
            return Ok(());
        }
        let len = len as usize;
        if *off + 1 + len > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "label overflows message",
            ));
        }
        *off += 1 + len;
    }
}

// ─── Fragmentation ────────────────────────────────────────────────

/// Build the QNAME for a single fragment by base32-encoding
/// `[header][raw]` and splitting across up to 3 labels.
pub fn qname_for_fragment(id: u16, idx: u8, total: u8, raw: &[u8]) -> String {
    debug_assert!(raw.len() <= MAX_FRAG_PAYLOAD);
    let mut payload = Vec::with_capacity(FRAG_HEADER_LEN + raw.len());
    payload.extend_from_slice(&id.to_be_bytes());
    payload.push(idx);
    payload.push(total);
    payload.extend_from_slice(raw);

    // Base32 (no padding). The alphabet is A-Z + 2-7, all
    // DNS-safe. NOPAD avoids the `=` characters which DNS
    // labels are not allowed to contain.
    let encoded = BASE32_NOPAD.encode(&payload);

    let mut labels = Vec::with_capacity(LABELS_PER_QNAME);
    let mut cursor = encoded.as_str();
    for _ in 0..LABELS_PER_QNAME {
        if cursor.is_empty() {
            break;
        }
        let take = cursor.len().min(LABEL_MAX);
        labels.push(&cursor[..take]);
        cursor = &cursor[take..];
    }
    debug_assert!(cursor.is_empty(), "fragment too large for QNAME");
    let mut qname = labels.join(".");
    qname.push('.');
    qname.push_str(QUERY_SUFFIX);
    qname
}

/// Decode a QNAME we built into `(id, idx, total, raw)`. Strips
/// the suffix labels (anything after the last payload label) by
/// taking only the leading labels that look like base32.
pub fn decode_fragment(labels: &[String]) -> io::Result<(u16, u8, u8, Vec<u8>)> {
    // Take leading labels until we hit the suffix. Labels are
    // base32 if they're all uppercase A-Z + 2-7.
    let mut payload_labels = Vec::new();
    for label in labels {
        if is_base32_label(label) {
            payload_labels.push(label.as_str());
        } else {
            break;
        }
    }
    if payload_labels.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no base32 labels in QNAME",
        ));
    }
    let joined: String = payload_labels.concat();
    let raw = BASE32_NOPAD
        .decode(joined.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base32 decode: {}", e)))?;
    if raw.len() < FRAG_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragment shorter than header",
        ));
    }
    let id = u16::from_be_bytes([raw[0], raw[1]]);
    let idx = raw[2];
    let total = raw[3];
    Ok((id, idx, total, raw[FRAG_HEADER_LEN..].to_vec()))
}

fn is_base32_label(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

// ─── Reassembly buffers ───────────────────────────────────────────

/// One in-flight DRIFT packet's worth of fragments, indexed by
/// (sender, frag_id).
struct Reassembly {
    started: Instant,
    parts: Vec<Option<Vec<u8>>>,
}

impl Reassembly {
    fn new(total: u8) -> Self {
        Self {
            started: Instant::now(),
            parts: vec![None; total as usize],
        }
    }

    /// Attempt to insert a fragment. Returns the assembled
    /// packet once all fragments are present.
    fn insert(&mut self, idx: u8, payload: Vec<u8>) -> Option<Vec<u8>> {
        if (idx as usize) >= self.parts.len() {
            return None;
        }
        // Idempotent: if we already have this fragment, ignore.
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

/// Per-(src, id) reassembly map. Capped to `MAX_PENDING_PER_PEER`
/// per source — the oldest entry is evicted when the cap is hit
/// to bound memory under adversarial input.
#[derive(Default)]
struct ReassemblyMap {
    inner: HashMap<(SocketAddr, u16), Reassembly>,
}

impl ReassemblyMap {
    fn insert(
        &mut self,
        src: SocketAddr,
        id: u16,
        idx: u8,
        total: u8,
        payload: Vec<u8>,
    ) -> Option<Vec<u8>> {
        // Evict stale entries from this source first.
        let now = Instant::now();
        self.inner
            .retain(|(s, _), v| *s != src || now.duration_since(v.started) < REASSEMBLY_TIMEOUT);

        // Hard cap: count how many entries this source has.
        let count = self.inner.keys().filter(|(s, _)| *s == src).count();
        if count >= MAX_PENDING_PER_PEER {
            // Drop the oldest entry from this source.
            if let Some(((_, oid), _)) = self
                .inner
                .iter()
                .filter(|((s, _), _)| *s == src)
                .min_by_key(|(_, v)| v.started)
                .map(|(k, v)| (*k, v.started))
            {
                self.inner.remove(&(src, oid));
            }
        }

        let entry = self
            .inner
            .entry((src, id))
            .or_insert_with(|| Reassembly::new(total));
        let done = entry.insert(idx, payload);
        if done.is_some() {
            self.inner.remove(&(src, id));
        }
        done
    }
}

// ─── DnsPacketIO ──────────────────────────────────────────────────

/// DNS-shaped packet I/O. One bound UDP socket; outgoing DRIFT
/// packets ride as DNS queries, incoming queries are decoded
/// back. Symmetric — server and client use the same struct.
pub struct DnsPacketIO {
    socket: Arc<UdpSocket>,
    /// Reassembly buffers, shared across all calls to
    /// `recv_from` (which serializes via the recv mutex anyway,
    /// since DRIFT only spawns one recv loop per interface).
    reassembly: Mutex<ReassemblyMap>,
    /// Cached local addr — UdpSocket::local_addr is cheap but
    /// allocs an `io::Result` on each call.
    local_addr: SocketAddr,
}

impl DnsPacketIO {
    /// Wrap an already-bound UDP socket. Both endpoints must
    /// agree on the QNAME suffix (currently hard-coded to
    /// `drift.local`); future versions may make it configurable.
    pub fn new(socket: Arc<UdpSocket>) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;
        Ok(Self {
            socket,
            reassembly: Mutex::new(ReassemblyMap::default()),
            local_addr,
        })
    }
}

#[async_trait]
impl PacketIO for DnsPacketIO {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        if buf.is_empty() {
            // DRIFT never sends zero-byte packets, but be
            // defensive — an empty fragment would be ambiguous
            // with a poll-only query.
            return Ok(0);
        }
        // Fragment.
        let total_frags = buf.len().div_ceil(MAX_FRAG_PAYLOAD);
        if total_frags > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "DRIFT packet too large for DNS adapter: {} bytes (max ~28 KiB)",
                    buf.len()
                ),
            ));
        }
        let frag_id: u16 = rand::random();
        // Build all fragment messages first, then ship the whole
        // batch via sendmmsg. Was a loop of N sequential `send_to`
        // awaits (one syscall per fragment); with batched send,
        // it's one syscall for the whole drift packet. For a
        // 1200-byte drift packet at MAX_FRAG_PAYLOAD = 113, that's
        // 11 fragments → 1 syscall instead of 11.
        let mut fragments: Vec<(Vec<u8>, std::net::SocketAddr)> =
            Vec::with_capacity(total_frags);
        for (idx, chunk) in buf.chunks(MAX_FRAG_PAYLOAD).enumerate() {
            let qname =
                qname_for_fragment(frag_id, idx as u8, total_frags as u8, chunk);
            let txid: u16 = rand::random();
            let msg = build_query_message(txid, &qname);
            fragments.push((msg, dest));
        }
        crate::transport::batch::send_batch(&self.socket, &fragments).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut udp_buf = [0u8; UDP_BUF];
        loop {
            let (n, src) = self.socket.recv_from(&mut udp_buf).await?;
            let labels = match parse_qname_labels(&udp_buf[..n]) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, src = %src, "dns: drop malformed query");
                    continue;
                }
            };
            let (id, idx, total, payload) = match decode_fragment(&labels) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, src = %src, "dns: drop undecodable fragment");
                    continue;
                }
            };

            let assembled = {
                let mut map = self.reassembly.lock().await;
                map.insert(src, id, idx, total, payload)
            };
            let Some(packet) = assembled else { continue };

            if packet.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "reassembled DRIFT packet too large: {} > buffer {}",
                        packet.len(),
                        buf.len()
                    ),
                ));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            return Ok((packet.len(), src));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

// ─── DnsListenerIO ────────────────────────────────────────────────
//
// Single-shot, just like `UdpListenerIO`. The bound socket is
// the only "interface" — DNS is connectionless on the wire, so
// per-peer state lives inside `DnsPacketIO`'s reassembly map and
// the Transport's own peer table.

pub struct DnsListenerIO {
    socket: Option<Arc<UdpSocket>>,
    addr: SocketAddr,
}

impl DnsListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr).await?;
        let local = sock.local_addr()?;
        Ok(Self {
            socket: Some(Arc::new(sock)),
            addr: local,
        })
    }
}

#[async_trait]
impl Listener for DnsListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
    fn is_multi(&self) -> bool {
        false
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        match self.socket.take() {
            Some(s) => Ok(Arc::new(DnsPacketIO::new(s)?)),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "DNS listener is single-shot and was already consumed",
            )),
        }
    }
}

// ─── Scheme registration ──────────────────────────────────────────

/// Thin async wrapper that defers to the shared
/// `crate::io::parse_ip_addr` (which handles IP literals + DNS).
async fn parse_ip_addr(addr_str: &str) -> io::Result<SocketAddr> {
    crate::io::parse_ip_addr(addr_str).await
}

fn dns_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str).await?;
        Ok(Box::new(DnsListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn dns_connector_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str).await?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let io: Arc<dyn PacketIO> = Arc::new(DnsPacketIO::new(Arc::new(sock))?);
        Ok((io, addr))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "dns",
        listener: dns_listener_factory,
        connector: dns_connector_factory,
    }
}

// ─── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qname_roundtrip_small() {
        let raw = b"hello world";
        let qname = qname_for_fragment(0xABCD, 0, 1, raw);
        assert!(qname.ends_with(QUERY_SUFFIX));
        // Build a fake message just to test the parser path too.
        let msg = build_query_message(0x1234, &qname);
        let labels = parse_qname_labels(&msg).unwrap();
        let (id, idx, total, payload) = decode_fragment(&labels).unwrap();
        assert_eq!(id, 0xABCD);
        assert_eq!(idx, 0);
        assert_eq!(total, 1);
        assert_eq!(payload, raw);
    }

    #[test]
    fn fragment_max_size() {
        // Confirm the largest legal fragment fits in the QNAME.
        let raw = vec![0xAB; MAX_FRAG_PAYLOAD];
        let qname = qname_for_fragment(0, 0, 1, &raw);
        // 3 labels of 63 + 2 dots + ".drift.local" (12 chars) = 203
        assert!(qname.len() <= 254, "qname={} len={}", qname, qname.len());
        let msg = build_query_message(0, &qname);
        let labels = parse_qname_labels(&msg).unwrap();
        let (_, _, _, decoded) = decode_fragment(&labels).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn reassembly_basic() {
        let mut map = ReassemblyMap::default();
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // total=3 fragments
        assert!(map.insert(src, 1, 0, 3, b"AAA".to_vec()).is_none());
        assert!(map.insert(src, 1, 2, 3, b"CCC".to_vec()).is_none());
        let done = map.insert(src, 1, 1, 3, b"BBB".to_vec()).unwrap();
        assert_eq!(done, b"AAABBBCCC");
    }

    #[tokio::test]
    async fn loopback_roundtrip_variable_length() {
        // Required by ADAPTER_SPEC.md: framing roundtrip with
        // variable-length packets, ranging from 1 byte up to
        // multi-fragment sizes.
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let server = DnsPacketIO::new(server_sock).unwrap();
        let client = DnsPacketIO::new(client_sock).unwrap();

        // Send packets of varying sizes from 1 byte up to 1400
        // bytes (DRIFT MAX_PACKET). Verify each arrives intact.
        let sizes = [1usize, 50, 113, 114, 226, 500, 1000, 1400];
        for &sz in &sizes {
            let payload: Vec<u8> = (0..sz).map(|i| (i & 0xFF) as u8).collect();
            client.send_to(&payload, server_addr).await.unwrap();
            let mut buf = vec![0u8; 1500];
            let (n, _src) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                server.recv_from(&mut buf),
            )
            .await
            .expect("recv timed out")
            .unwrap();
            assert_eq!(n, sz, "size mismatch for {}-byte packet", sz);
            assert_eq!(&buf[..n], &payload[..], "content mismatch at size {}", sz);
        }
    }
}

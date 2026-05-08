// Cloudflare Worker: DRIFT-over-DoH rendezvous.
//
// Two DRIFT peers each `POST` DNS messages to:
//
//   /v1/<my-pubkey-hex>/<peer-pubkey-hex>/dns-query
//
// On every request the Worker:
//
//   1. parses the DNS message body, decodes the QNAME-encoded
//      DRIFT fragment (3 base32 labels prefixed with a 4-byte
//      [id, idx, total] reassembly header — same encoding as
//      the native `wire_dns.rs` adapter),
//   2. appends that fragment to <peer-hex>'s inbox (the
//      destination's queue),
//   3. drains <my-hex>'s inbox into the response as TXT records,
//   4. returns a normal-looking DNS response with `application/
//      dns-message` Content-Type.
//
// Per-peer queues live in a Durable Object so two simultaneous
// requests for the same peer pubkey serialize correctly and don't
// race each other. The Durable Object name IS the peer's pubkey
// hex — Cloudflare hashes it to a single coordinator.

const BASE32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

interface Env {
    PEER_INBOX: DurableObjectNamespace;
}

// ─── Worker entrypoint ───────────────────────────────────────────

export default {
    async fetch(req: Request, env: Env): Promise<Response> {
        if (req.method !== "POST") {
            return new Response("method not allowed", { status: 405 });
        }
        const url = new URL(req.url);
        const parts = url.pathname.split("/").filter(p => p.length > 0);
        if (parts.length < 3) {
            return new Response(
                "expected /<v>/<me-hex>/<peer-hex>/...",
                { status: 400 },
            );
        }
        const meHex = parts[1];
        const peerHex = parts[2];
        if (!isPubkeyHex(meHex) || !isPubkeyHex(peerHex)) {
            return new Response("non-hex pubkey segment", { status: 400 });
        }

        const reqBody = new Uint8Array(await req.arrayBuffer());

        // Decode the QNAME so we can both echo it in the response
        // and pull out any payload fragment to forward.
        let qnameLabels: string[];
        try {
            qnameLabels = parseQnameLabels(reqBody);
        } catch (_) {
            return new Response("malformed DNS message", { status: 400 });
        }
        const txid = reqBody.length >= 2
            ? (reqBody[0] << 8) | reqBody[1]
            : 0;

        let frag: Uint8Array | null = null;
        try {
            frag = decodeFragment(qnameLabels);
        } catch (_) {
            // Empty-poll requests fail decode; that's fine.
            frag = null;
        }

        // 1. If this was a real fragment, push it to the
        //    destination's inbox.
        if (frag !== null) {
            const destStub = peerStub(env, peerHex);
            // Fire and forget — we don't need to await before
            // building the response, but we do for ordering: the
            // peer should never poll and miss a fragment we
            // already acknowledged accepting.
            await destStub.fetch("https://do/push", {
                method: "POST",
                body: frag,
            });
        }

        // 2. Drain my own inbox into TXT records.
        const myStub = peerStub(env, meHex);
        const drainResp = await myStub.fetch("https://do/drain", {
            method: "POST",
        });
        const drained = new Uint8Array(await drainResp.arrayBuffer());
        // The Durable Object packs the drained fragments as
        // `[u16 BE count][[u16 BE len][bytes]…]`.
        const fragments = unpackFragments(drained);

        // 3. Build a DNS response echoing the question + N TXT
        //    records (one fragment per record).
        const responseBody = buildResponseMessage(txid, qnameLabels, fragments);
        return new Response(responseBody, {
            status: 200,
            headers: {
                "Content-Type": "application/dns-message",
                "Cache-Control": "no-store",
            },
        });
    },
};

// ─── Durable Object: per-peer inbox ──────────────────────────────
//
// One instance per peer pubkey hex. Two endpoints over the in-
// process fetch interface:
//
//   POST /push  body=<raw fragment bytes>  → push onto queue
//   POST /drain                            → return all queued
//                                             fragments, packed
//
// Cloudflare's DO routing guarantees that all calls naming the
// same pubkey land on the same instance, so the queue is
// linearizable per peer with no extra locking.

export class PeerInbox {
    state: DurableObjectState;
    queue: Uint8Array[];

    constructor(state: DurableObjectState) {
        this.state = state;
        this.queue = [];
    }

    async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url);
        if (req.method === "POST" && url.pathname === "/push") {
            const buf = new Uint8Array(await req.arrayBuffer());
            // Cap queue depth so a peer that goes silent forever
            // doesn't pin unbounded memory in the DO.
            if (this.queue.length < 1024) {
                this.queue.push(buf);
            }
            return new Response("", { status: 204 });
        }
        if (req.method === "POST" && url.pathname === "/drain") {
            // Pop up to 8 fragments per drain — keeps response
            // sizes reasonable, leaves the rest for the next poll.
            const take = this.queue.splice(0, 8);
            const packed = packFragments(take);
            return new Response(packed, { status: 200 });
        }
        return new Response("not found", { status: 404 });
    }
}

function peerStub(env: Env, hex: string): DurableObjectStub {
    const id = env.PEER_INBOX.idFromName(hex);
    return env.PEER_INBOX.get(id);
}

// ─── Helpers: fragment packing for DO traffic ────────────────────

function packFragments(frags: Uint8Array[]): Uint8Array {
    let total = 2;
    for (const f of frags) total += 2 + f.length;
    const out = new Uint8Array(total);
    let off = 0;
    out[off++] = (frags.length >> 8) & 0xff;
    out[off++] = frags.length & 0xff;
    for (const f of frags) {
        out[off++] = (f.length >> 8) & 0xff;
        out[off++] = f.length & 0xff;
        out.set(f, off);
        off += f.length;
    }
    return out;
}

function unpackFragments(buf: Uint8Array): Uint8Array[] {
    if (buf.length < 2) return [];
    const count = (buf[0] << 8) | buf[1];
    let off = 2;
    const out: Uint8Array[] = [];
    for (let i = 0; i < count && off + 2 <= buf.length; i++) {
        const len = (buf[off] << 8) | buf[off + 1];
        off += 2;
        if (off + len > buf.length) break;
        out.push(buf.slice(off, off + len));
        off += len;
    }
    return out;
}

// ─── DNS message helpers ─────────────────────────────────────────
//
// Mirrors `drift/src/wire_dns.rs` exactly — same QNAME structure
// (3 base32 labels + suffix), same fragment header
// `[id u16 BE][idx u8][total u8]`. The native Rust adapter and
// this Worker speak the same wire bytes.

function parseQnameLabels(msg: Uint8Array): string[] {
    if (msg.length < 12) throw new Error("DNS message shorter than header");
    const labels: string[] = [];
    let off = 12;
    for (;;) {
        if (off >= msg.length) throw new Error("QNAME truncated");
        const len = msg[off++];
        if (len === 0) return labels;
        if (len > 63) throw new Error("label too long or compression");
        if (off + len > msg.length) throw new Error("QNAME exceeds message");
        let s = "";
        for (let i = 0; i < len; i++) {
            s += String.fromCharCode(msg[off + i]);
        }
        labels.push(s);
        off += len;
    }
}

function isBase32Label(s: string): boolean {
    if (s.length === 0) return false;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        const isUpper = c >= 65 && c <= 90; // A-Z
        const isDigit = c >= 50 && c <= 55; // 2-7
        if (!isUpper && !isDigit) return false;
    }
    return true;
}

/** Decode the QNAME labels as a fragment. Returns the raw
 *  `[id u16][idx u8][total u8][payload…]` bytes — same shape the
 *  native adapter pushes to the reassembly buffer. */
function decodeFragment(labels: string[]): Uint8Array {
    const payloadLabels: string[] = [];
    for (const l of labels) {
        if (isBase32Label(l)) payloadLabels.push(l);
        else break;
    }
    if (payloadLabels.length === 0) throw new Error("no base32 labels");
    return base32Decode(payloadLabels.join(""));
}

function base32Decode(s: string): Uint8Array {
    const out: number[] = [];
    let buf = 0;
    let bits = 0;
    for (let i = 0; i < s.length; i++) {
        const v = BASE32_ALPHA.indexOf(s[i]);
        if (v < 0) throw new Error("bad base32 char");
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push((buf >> bits) & 0xff);
        }
    }
    return new Uint8Array(out);
}

function encodeQname(buf: number[], qname: string): void {
    for (const label of qname.split(".")) {
        if (label.length === 0) continue;
        const len = Math.min(label.length, 63);
        buf.push(len);
        for (let i = 0; i < len; i++) buf.push(label.charCodeAt(i));
    }
    buf.push(0);
}

function buildResponseMessage(
    txid: number,
    qnameLabels: string[],
    fragments: Uint8Array[],
): Uint8Array {
    const buf: number[] = [];
    // Header: TXID, flags QR=1 AA=1 RD=1 RA=1, counts.
    buf.push((txid >> 8) & 0xff, txid & 0xff);
    buf.push(0x85, 0x80);
    buf.push(0x00, 0x01); // QDCOUNT = 1
    buf.push((fragments.length >> 8) & 0xff, fragments.length & 0xff); // ANCOUNT
    buf.push(0x00, 0x00); // NSCOUNT
    buf.push(0x00, 0x00); // ARCOUNT
    // Question section (echo the request's QNAME).
    encodeQname(buf, qnameLabels.join("."));
    buf.push(0x00, 0x01); // QTYPE = A (matches the request)
    buf.push(0x00, 0x01); // QCLASS = IN
    // Answer section: TXT record per fragment, NAME=ptr to QNAME at offset 12.
    for (const f of fragments) {
        if (f.length > 255) {
            // Spec for our adapter: every fragment is ≤ 117 bytes,
            // so this can never happen in practice. Skip if it
            // does — better than crashing the Worker.
            continue;
        }
        buf.push(0xc0, 0x0c); // pointer to qname
        buf.push(0x00, 0x10); // TYPE = 16 (TXT)
        buf.push(0x00, 0x01); // CLASS = IN
        buf.push(0x00, 0x00, 0x00, 0x00); // TTL = 0 (no caching)
        const rdlength = 1 + f.length;
        buf.push((rdlength >> 8) & 0xff, rdlength & 0xff);
        buf.push(f.length); // TXT length-prefixed string
        for (let i = 0; i < f.length; i++) buf.push(f[i]);
    }
    return new Uint8Array(buf);
}

function isPubkeyHex(s: string): boolean {
    if (s.length !== 64) return false;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        const isDigit = c >= 48 && c <= 57; // 0-9
        const isLower = c >= 97 && c <= 102; // a-f
        const isUpper = c >= 65 && c <= 70; // A-F
        if (!isDigit && !isLower && !isUpper) return false;
    }
    return true;
}

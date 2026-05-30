//! Smoke test for a deployed `drift-doh-relay` Cloudflare Worker.
//!
//! Doesn't run a full DRIFT handshake — just verifies the Worker
//! is reachable and parses our wire format correctly. Use the
//! integration test (`tests/wire_doh.rs`) for end-to-end DRIFT
//! coverage; that one uses a local hyper mock so it's fast and
//! offline.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example doh-smoke -- \
//!     https://drift-doh-relay.<your-subdomain>.workers.dev
//! ```

use drift::wire_dns::{
    build_query_message, build_response_message, parse_qname_labels, parse_response_txt_records,
    qname_for_fragment,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .ok_or("usage: doh-smoke <https://drift-doh-relay.<your-subdomain>.workers.dev>")?;
    let host = host.trim_end_matches('/').to_string();

    // Two arbitrary 64-char-hex pubkey placeholders. The Worker
    // doesn't actually verify these against any registry — it
    // just uses them as inbox keys.
    let alice_pub = "a".repeat(64);
    let bob_pub = "b".repeat(64);
    let alice_url = format!("{}/v1/{}/{}/dns-query", host, alice_pub, bob_pub);
    let bob_url = format!("{}/v1/{}/{}/dns-query", host, bob_pub, alice_pub);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    println!("=== Test 1: GET / (expect 405 Method Not Allowed)");
    let r = client.get(format!("{}/", host)).send().await?;
    println!("  status: {}", r.status());
    assert_eq!(r.status(), 405, "expected 405 for GET");

    println!();
    println!("=== Test 2: empty-poll request from Alice (expect 200, 0 TXT records)");
    let txid: u16 = 0xC0DE;
    let body = build_query_message(txid, "poll.drift.local");
    let r = client
        .post(&alice_url)
        .header("Content-Type", "application/dns-message")
        .body(body)
        .send()
        .await?;
    println!("  status: {}", r.status());
    let resp = r.bytes().await?;
    println!("  body: {} bytes", resp.len());
    let labels = parse_qname_labels(&resp)?;
    let records = parse_response_txt_records(&resp)?;
    println!("  echoed QNAME: {}", labels.join("."));
    println!("  TXT records: {}", records.len());
    assert_eq!(records.len(), 0, "Alice's inbox should be empty");

    println!();
    println!("=== Test 3: Alice sends a fragment to Bob (expect 200, 0 TXT records back)");
    let payload = b"hello-from-alice-via-doh";
    let qname = qname_for_fragment(0xBEEF, 0, 1, payload);
    let body = build_query_message(0x1234, &qname);
    let r = client
        .post(&alice_url)
        .header("Content-Type", "application/dns-message")
        .body(body)
        .send()
        .await?;
    assert_eq!(r.status(), 200);
    let resp = r.bytes().await?;
    let records = parse_response_txt_records(&resp)?;
    println!(
        "  status: {} | TXT records returned to Alice: {}",
        200,
        records.len()
    );
    assert_eq!(records.len(), 0, "no pending fragments for Alice");

    println!();
    println!("=== Test 4: Bob polls (expect 200 with 1 TXT record containing Alice's fragment)");
    let body = build_query_message(0x5555, "poll.drift.local");
    let r = client
        .post(&bob_url)
        .header("Content-Type", "application/dns-message")
        .body(body)
        .send()
        .await?;
    assert_eq!(r.status(), 200);
    let resp = r.bytes().await?;
    let records = parse_response_txt_records(&resp)?;
    println!("  TXT records returned to Bob: {}", records.len());
    assert_eq!(records.len(), 1, "Bob should have one fragment from Alice");
    let frag = &records[0];
    assert!(frag.len() >= 4);
    let id = u16::from_be_bytes([frag[0], frag[1]]);
    let idx = frag[2];
    let total = frag[3];
    let payload_back = &frag[4..];
    println!("  fragment id={:#06x} idx={} total={}", id, idx, total);
    println!(
        "  payload: {:?}",
        std::str::from_utf8(payload_back).unwrap_or("<non-utf8>")
    );
    assert_eq!(payload_back, payload, "payload round-trip mismatch");
    assert_eq!(id, 0xBEEF);

    println!();
    println!("=== Test 5: Bob polls again (expect 200 with 0 records — queue drained)");
    let body = build_query_message(0x6666, "poll.drift.local");
    let r = client
        .post(&bob_url)
        .header("Content-Type", "application/dns-message")
        .body(body)
        .send()
        .await?;
    let resp = r.bytes().await?;
    let records = parse_response_txt_records(&resp)?;
    println!("  TXT records: {} (should be 0)", records.len());
    assert_eq!(records.len(), 0);

    // Use build_response_message in the success line so it's not
    // dead-code-warned in the example. Build a tiny message just
    // for show.
    let _show = build_response_message(0, "ok.drift.local", &[]);

    println!();
    println!("✅ All checks passed. Worker is live and round-trips fragments correctly.");
    Ok(())
}

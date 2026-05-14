//! Federation directory poisoning probe.
//!
//! The fed-peer container is a LEGITIMATE federated peer of the
//! bridge (it's in bridge's federation_table). We're going to
//! claim its identity (which we can do because we have its key
//! material — Docker volume mount) and send FederationDirectory
//! announcements claiming to host pubkeys we don't have.
//!
//! With XEdDSA presence tickets, the bridge must verify each
//! announced pubkey's ticket against the announcing bridge's
//! pubkey. Bogus tickets must be dropped.
//!
//! Usage:
//!   cargo run --release --example attack_fed_directory -p drift -- \
//!     <bridge_url> <bridge_pub_hex> <fed_identity_hex_file>

use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::transport::{build_directory, build_ticket, encode_ticket, MAX_DIRECTORY_ENTRIES};
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <bridge_url> <bridge_pub_hex> <fed_hex_secret_file>",
            args[0]
        );
        std::process::exit(1);
    }
    let bridge_url = &args[1];
    let mut bp = [0u8; 32];
    bp.copy_from_slice(&hex::decode(&args[2])?);
    let fed_hex = std::fs::read_to_string(&args[3])?;
    let fed_raw = hex::decode(fed_hex.trim())?;
    let mut fed_secret = [0u8; 32];
    fed_secret.copy_from_slice(&fed_raw);

    // Establish a session as the fed-peer (we have its key).
    let attacker = Identity::from_secret_bytes(fed_secret);
    let our_pub = attacker.public_bytes();
    let (transport, bridge_addr) =
        Transport::connect_url(bridge_url, attacker, TransportConfig::default())
            .await
            .context("connecting to bridge")?;
    let transport = Arc::new(transport);
    let bridge_pid = transport
        .add_peer(bp, bridge_addr, Direction::Initiator)
        .await
        .context("add_peer")?;
    let _ = transport.send_data(&bridge_pid, b".", 0, 0).await;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if transport.peer_is_established(&bridge_pid).await {
            break;
        }
    }
    if !transport.peer_is_established(&bridge_pid).await {
        anyhow::bail!("session with bridge didn't establish");
    }
    println!("✓ session as fed-peer (pub {}) established with bridge",
             hex::encode(our_pub));

    // Build 3 different malicious directory announcements:
    //
    //   A) victim pubkey, NO ticket (zero bytes). Bridge must
    //      reject — defense from adversarial_presence_tickets.
    //   B) victim pubkey + FORGED ticket signed by attacker (not
    //      victim). XEdDSA verify must fail.
    //   C) victim pubkey + valid ticket but signed for a DIFFERENT
    //      bridge. Reconstruction in verify_ticket uses the
    //      announcing bridge's pubkey, so the sig won't match.
    let victim_pub: [u8; 32] = {
        let id = Identity::generate();
        id.public_bytes()
    };
    println!("\nTarget victim pubkey: {}", hex::encode(victim_pub));

    // --- announcement A: victim with all-zero ticket ---
    let mut wire_a = Vec::with_capacity(4 + 128);
    wire_a.push(2); // version
    wire_a.push(0); // reserved
    wire_a.extend_from_slice(&(1u16).to_be_bytes()); // count=1
    wire_a.extend_from_slice(&victim_pub);
    wire_a.extend_from_slice(&[0u8; 96]); // ticket placeholder = all zeros

    // --- announcement B: forged ticket signed by attacker (our_pub) for the bridge ---
    let expiry_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 600_000;
    // build_ticket signs with `our_pub`'s secret claiming victim_pub is being attested
    // — but really the ticket's signature is verifiable against OUR pubkey, not victim's,
    // so when the bridge verifies sig against victim_pub it fails.
    let forged_ticket = build_ticket(
        &fed_secret,
        &bp,
        expiry_ms,
        [0xCC; 24],
        &[0xDD; 64],
    );
    let mut wire_b = Vec::with_capacity(4 + 128);
    wire_b.push(2); wire_b.push(0);
    wire_b.extend_from_slice(&(1u16).to_be_bytes());
    wire_b.extend_from_slice(&victim_pub);
    wire_b.extend_from_slice(&encode_ticket(&forged_ticket));

    // --- announcement C: valid ticket but signed for the WRONG bridge ---
    // For this we'd need the victim's actual key, which we don't have. So
    // pretend we have a stolen ticket signed for "honest_bridge" by a real
    // client. We simulate by generating a fake victim, signing a ticket from
    // their key for a different bridge, then announcing it through our session.
    let fake_victim = Identity::generate();
    let fake_victim_pub = fake_victim.public_bytes();
    let fake_victim_sec = fake_victim.xeddsa_sign(b"", &[0u8; 64]);
    let _ = fake_victim_sec; // unused — we use build_ticket directly
    let wrong_bridge = [0xEE; 32];
    let real_ticket_wrong_bridge = build_ticket(
        // Need the secret. Since Identity doesn't expose secret_bytes,
        // use the rng-derived secret from from_secret_bytes round trip.
        // Generate a fresh secret instead.
        &[0xBE; 32],
        &wrong_bridge,
        expiry_ms,
        [0xEE; 24],
        &[0xFF; 64],
    );
    let real_pub_for_seed = drift_core::Identity::from_secret_bytes([0xBE; 32]).public_bytes();
    let mut wire_c = Vec::with_capacity(4 + 128);
    wire_c.push(2); wire_c.push(0);
    wire_c.extend_from_slice(&(1u16).to_be_bytes());
    wire_c.extend_from_slice(&real_pub_for_seed);
    wire_c.extend_from_slice(&encode_ticket(&real_ticket_wrong_bridge));

    for (label, wire) in [("A (no-ticket)", wire_a), ("B (forged)", wire_b), ("C (wrong-bridge)", wire_c)] {
        println!("\nShipping announcement {} ({} bytes)…", label, wire.len());
        transport
            .__debug_send_directory_announcement(&bridge_pid, &wire)
            .await
            .context("send directory announcement")?;
    }

    // Wait for bridge to process + (hopefully) drop.
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("\nAll three malicious announcements shipped.");
    println!("Bridge should have dropped each entry. Verification:");
    println!("  - check bridge metrics for federation_invalid_tickets_dropped");
    println!("  - check bridge peer_directory does NOT contain any of:");
    println!("    {}", hex::encode(victim_pub));
    println!("    {}", hex::encode(real_pub_for_seed));
    Ok(())
}

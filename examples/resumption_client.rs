//! Resumption client demo. Two modes, chosen by the presence
//! of a ticket file at `$TICKET_PATH`:
//!
//! * **First run** (no ticket file): does a full DRIFT
//!   handshake, sends one DATA packet, waits ~300 ms for the
//!   server's ResumptionTicket to land, exports the ticket to
//!   `$TICKET_PATH`, exits.
//! * **Subsequent run** (ticket file present): imports the
//!   ticket, sends one DATA packet (which triggers
//!   `send_resume_hello` under the hood), verifies no full
//!   handshake happened (metrics), exits.
//!
//! Used by the resumption compose test to prove 1-RTT
//! reconnect actually works end-to-end in a multi-container
//! setting.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::env;
use std::fs;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let ticket_path = env::var("TICKET_PATH").unwrap_or_else(|_| "/tmp/drift_ticket.bin".into());
    let server_addr: std::net::SocketAddr = env::var("SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".into())
        .parse()?;

    let client_identity = Identity::from_secret_bytes([0x11; 32]);
    let server_pub = Identity::from_secret_bytes([0x22; 32]).public_bytes();

    let transport = Transport::bind("0.0.0.0:0".parse()?, client_identity).await?;
    let server_peer = transport
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await?;

    let had_ticket = if let Ok(blob) = fs::read(&ticket_path) {
        match transport
            .import_resumption_ticket(&server_peer, &blob)
            .await
        {
            Ok(()) => {
                println!("client: imported ticket from {} ({} bytes)", ticket_path, blob.len());
                true
            }
            Err(e) => {
                eprintln!("client: failed to import ticket: {:?} (falling back to full handshake)", e);
                let _ = fs::remove_file(&ticket_path);
                false
            }
        }
    } else {
        println!("client: no ticket file at {}, full handshake", ticket_path);
        false
    };

    // Fire one DATA packet to trigger whatever handshake path
    // is active.
    transport
        .send_data(&server_peer, b"hello-from-client", 0, 0)
        .await?;

    // Wait briefly so the server has time to process + (on
    // first run) send its ResumptionTicket back.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let m = transport.metrics();
    println!(
        "client: metrics full_handshakes={} resumptions={} tickets_received={}",
        m.handshakes_completed, m.resumptions_completed, m.resumption_tickets_received
    );

    if had_ticket {
        // On a resumed run we MUST NOT have done a full handshake.
        if m.handshakes_completed > 0 {
            eprintln!("client: ERROR — resumption path did a full handshake");
            std::process::exit(2);
        }
        if m.resumptions_completed == 0 {
            eprintln!("client: ERROR — resumption did not complete");
            std::process::exit(3);
        }
        println!("client: OK — 1-RTT resumption worked, no full handshake");
    } else {
        // First run: export the ticket so the next run can
        // use it. Refuse to overwrite.
        match transport.export_resumption_ticket(&server_peer).await {
            Ok(blob) => {
                fs::write(&ticket_path, &blob)?;
                println!(
                    "client: OK — wrote {} byte ticket to {}",
                    blob.len(),
                    ticket_path
                );
            }
            Err(e) => {
                eprintln!("client: ERROR — could not export ticket: {:?}", e);
                std::process::exit(4);
            }
        }
    }
    Ok(())
}

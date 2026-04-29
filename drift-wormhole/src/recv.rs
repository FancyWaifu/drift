//! Receiver side: connect to the sender's pubkey, open one
//! stream, read header, write file with progress bar, verify
//! SHA-256, ack.

use crate::protocol::{Ack, Header};
use crate::RecvArgs;
use anyhow::{anyhow, Context, Result};
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub async fn run(args: RecvArgs) -> Result<()> {
    // The peer arg can be either:
    //   1. A petname registered in the local contacts file
    //      (e.g. `bob-laptop`) — resolves to pubkey + addr.
    //   2. The legacy `PUBHEX@<addr-or-url>` form — used on
    //      first contact when there's no contact entry yet.
    let (sender_pub, url) = if args.peer.contains('@') {
        let (pub_str, rest) = args.peer.split_once('@').unwrap();
        let bytes = hex::decode(pub_str.trim())
            .with_context(|| format!("pubkey {:?} is not valid hex", pub_str))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "pubkey must be 32 bytes (64 hex chars); got {}",
                bytes.len()
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        let url = if rest.contains("://") {
            rest.to_string()
        } else {
            format!("udp://{}", rest)
        };
        (pk, url)
    } else {
        // No `@` → treat as petname.
        let book = drift::contacts::Contacts::load_default()
            .context("loading contacts")?;
        let contact = book.resolve(&args.peer).ok_or_else(|| {
            anyhow!(
                "no contact named {:?} (and the value isn't a PUBHEX@addr literal). \
                 Run `drift contacts list` to see saved contacts.",
                args.peer
            )
        })?;
        let pk = drift::contacts::parse_pubkey_hex(&contact.pubkey)?;
        let url = if contact.address.contains("://") {
            contact.address.clone()
        } else {
            format!("udp://{}", contact.address)
        };
        (pk, url)
    };

    let identity = crate::load_identity(args.identity_file)?;
    let (transport, peer_addr) =
        Transport::connect_url(&url, identity, TransportConfig::default())
            .await
            .with_context(|| format!("connecting to {}", url))?;
    let transport = Arc::new(transport);
    let server_peer = transport
        .add_peer(sender_pub, peer_addr, Direction::Initiator)
        .await
        .context("registering sender")?;
    let mgr = StreamManager::bind(transport.clone()).await;

    eprintln!("connecting to peer {}...", short_pub(&sender_pub));
    let stream = tokio::time::timeout(Duration::from_secs(15), mgr.open(server_peer))
        .await
        .map_err(|_| anyhow!("timed out opening stream — is the sender still running?"))?
        .context("opening stream")?;

    // Read the header. DRIFT delivers the sender's first
    // .send() as one chunk on .recv() because the bincode
    // header is small (well under any DRIFT segment size).
    let header_bytes = stream
        .recv()
        .await
        .ok_or_else(|| anyhow!("sender closed stream before sending header"))?;
    let header: Header = bincode::deserialize(&header_bytes).context("decoding header")?;
    eprintln!();
    eprintln!(
        "Receiving: {} ({})",
        header.name,
        humansize::format_size(header.size, humansize::BINARY)
    );

    // Decide the output path. Resolve relative names against
    // --out-dir; --out overrides the file name entirely.
    let save_name = args.out.unwrap_or_else(|| sanitize_filename(&header.name));
    let mut out_path = args.out_dir.clone();
    out_path.push(&save_name);
    if let Some(parent) = out_path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    // Stream the bytes to disk + hash + progress.
    let bar = ProgressBar::new(header.size);
    bar.set_style(
        ProgressStyle::with_template(
            "  {bar:32.green/grey} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12} ETA {eta}",
        )
        .unwrap()
        .progress_chars("=> "),
    );

    let mut f = File::create(&out_path)
        .await
        .with_context(|| format!("creating {}", out_path.display()))?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;

    while received < header.size {
        let chunk = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("sender closed stream early at {} / {} bytes", received, header.size))?;
        // Guard against a runaway sender writing past the
        // declared size. If they overshoot we trim and reject.
        let max_take = (header.size - received) as usize;
        let take = chunk.len().min(max_take);
        f.write_all(&chunk[..take])
            .await
            .with_context(|| format!("writing to {}", out_path.display()))?;
        hasher.update(&chunk[..take]);
        received += take as u64;
        bar.set_position(received);
        if take < chunk.len() {
            // Sender wrote more than declared — note it but
            // we already trimmed to `size`. Reject.
            send_ack(
                &stream,
                Ack::Reject {
                    reason: "sender exceeded declared size".into(),
                },
            )
            .await?;
            return Err(anyhow!("sender exceeded declared size"));
        }
    }
    bar.finish();
    f.flush().await.ok();
    drop(f);

    let actual_sha: [u8; 32] = hasher.finalize().into();
    if actual_sha != header.sha256 {
        send_ack(
            &stream,
            Ack::Reject {
                reason: "SHA-256 mismatch".into(),
            },
        )
        .await
        .ok();
        // Best-effort: leave the file in place but warn.
        return Err(anyhow!(
            "SHA-256 mismatch! file written to {} but is corrupt",
            out_path.display()
        ));
    }

    // Send Ok ack with our self-name so the sender can record
    // us in their contacts under that petname.
    let our_name = drift::contacts::self_name::load().ok().flatten();
    send_ack(
        &stream,
        Ack::Ok {
            recipient_name: our_name,
        },
    )
    .await?;

    // Auto-record the sender in our contacts file under their
    // advertised name. Best-effort.
    if let Ok(mut book) = drift::contacts::Contacts::load_default() {
        let placeholder = "0.0.0.0:0".parse().unwrap();
        if book
            .record(sender_pub, placeholder, header.sender_name.as_deref())
            .is_ok()
        {
            let _ = book.save();
        }
    }

    eprintln!();
    eprintln!("done — saved to {}", out_path.display());
    Ok(())
}

async fn send_ack(stream: &drift::streams::Stream, ack: Ack) -> Result<()> {
    let bytes = bincode::serialize(&ack).context("encoding ack")?;
    stream.send(&bytes).await.context("sending ack")?;
    Ok(())
}

/// Don't let a malicious sender write `../../etc/passwd`.
/// Strip any path components, keep just the basename.
fn sanitize_filename(name: &str) -> String {
    let stripped = std::path::Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("received-file");
    if stripped.is_empty() {
        "received-file".to_string()
    } else {
        stripped.to_string()
    }
}

fn short_pub(p: &[u8; 32]) -> String {
    p.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

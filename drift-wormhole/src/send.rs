//! Sender side: bind DRIFT, print the recipient command,
//! wait for them to open a stream, ship the file with a
//! progress bar.

use crate::protocol::{Ack, Header, CHUNK_SIZE, MAX_HEADER_BYTES};
use crate::SendArgs;
use anyhow::{anyhow, Context, Result};
use drift::streams::StreamManager;
use drift::{Transport, TransportConfig};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub async fn run(args: SendArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(anyhow!("file not found: {}", args.file.display()));
    }
    let metadata = tokio::fs::metadata(&args.file)
        .await
        .with_context(|| format!("stat {}", args.file.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("not a regular file: {}", args.file.display()));
    }
    let size = metadata.len();
    let name = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("filename is not valid UTF-8: {}", args.file.display()))?
        .to_string();

    // Hash the file up front so the recipient can verify
    // byte-fidelity. For large files this is a couple of
    // seconds of disk I/O — perfectly acceptable for the
    // share-with-a-friend use case.
    eprintln!(
        "hashing {} ({})...",
        name,
        humansize::format_size(size, humansize::BINARY)
    );
    let sha256 = hash_file(&args.file).await?;

    // Identity + DRIFT transport.
    let identity = crate::load_identity(args.identity_file)?;
    let pub_hex: String = identity
        .public_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    if args.bind.is_empty() {
        return Err(anyhow!("at least one --bind is required"));
    }
    let cfg = TransportConfig {
        // accept_any_peer: anyone with our pubkey can connect.
        // The sender chose to share that pubkey, so this is
        // the right default for an ephemeral file-share.
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let (transport, primary_url) = Transport::bind_url(&args.bind[0], identity, cfg)
        .await
        .context("setting up DRIFT transport")?;
    let transport = Arc::new(transport);
    let mut bound_urls = vec![primary_url];
    for extra in &args.bind[1..] {
        let bound = transport
            .add_listener(extra)
            .await
            .with_context(|| format!("adding listener {}", extra))?;
        bound_urls.push(bound);
    }
    let mgr = StreamManager::bind(transport.clone()).await;

    // Print the recipient command. Prefer the UDP bind for
    // the suggested command since UDP is the lowest-latency
    // wire; the recipient can override the scheme themselves.
    let primary = bound_urls
        .iter()
        .find(|u| u.starts_with("udp://"))
        .or_else(|| bound_urls.first())
        .cloned()
        .unwrap();
    let primary_addr = primary.split_once("://").map(|x| x.1).unwrap_or(&primary);

    eprintln!();
    eprintln!(
        "Ready to send: {} ({})",
        name,
        humansize::format_size(size, humansize::BINARY)
    );
    eprintln!();
    eprintln!("Run on the recipient:");
    eprintln!();
    eprintln!("    drift-wormhole recv {}@{}", pub_hex, primary_addr);
    eprintln!();
    if bound_urls.len() > 1 {
        eprintln!("Or via another transport:");
        for url in &bound_urls {
            let scheme = url.split("://").next().unwrap_or("?");
            let addr = url.split_once("://").map(|x| x.1).unwrap_or(url);
            if scheme == "udp" {
                continue; // already printed
            }
            eprintln!("    drift-wormhole recv {}@{}://{}", pub_hex, scheme, addr);
        }
        eprintln!();
    }
    eprintln!("Waiting for them to connect... (Ctrl-C to cancel)");

    // Accept the first incoming stream.
    let stream = mgr
        .accept()
        .await
        .ok_or_else(|| anyhow!("stream manager closed before recipient connected"))?;
    eprintln!("[connected to peer {}]", hex_short(&stream.peer()));

    // Send header. Include our self-advertised petname so
    // the recipient can save us under that name in their
    // contacts file.
    let our_name = drift::contacts::self_name::load().ok().flatten();
    let header = Header {
        name: name.clone(),
        size,
        sha256,
        sender_name: our_name,
    };
    let header_bytes = bincode::serialize(&header).context("encoding header")?;
    if header_bytes.len() > MAX_HEADER_BYTES {
        return Err(anyhow!("filename too long"));
    }
    stream.send(&header_bytes).await.context("sending header")?;

    // Stream the file content. DRIFT's stream layer handles
    // reliability + congestion control; we just chunk so
    // the progress bar updates smoothly.
    let bar = ProgressBar::new(size);
    bar.set_style(
        ProgressStyle::with_template(
            "  {bar:32.green/grey} {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12} ETA {eta}",
        )
        .unwrap()
        .progress_chars("=> "),
    );

    let mut f = File::open(&args.file)
        .await
        .with_context(|| format!("opening {}", args.file.display()))?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut sent: u64 = 0;
    while sent < size {
        let n = f.read(&mut buf).await.context("reading file")?;
        if n == 0 {
            break;
        }
        stream.send(&buf[..n]).await.context("sending chunk")?;
        sent += n as u64;
        bar.set_position(sent);
    }
    bar.finish();

    // Wait for the recipient's ack — they verify the SHA-256
    // before sending Ack::Ok.
    let ack_bytes = tokio::time::timeout(Duration::from_secs(60), stream.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for receiver ack"))?
        .ok_or_else(|| anyhow!("receiver closed stream before sending ack"))?;
    let ack: Ack = bincode::deserialize(&ack_bytes).context("decoding ack")?;
    match ack {
        Ack::Ok { recipient_name } => {
            eprintln!();
            eprintln!(
                "done — sent {} ({})",
                name,
                humansize::format_size(size, humansize::BINARY)
            );
            // Record the recipient in our local contacts file
            // (we already have their pubkey from the DRIFT
            // handshake). Best-effort.
            let recipient_pid = stream.peer();
            if let Some(recipient_pub) = transport.peer_public(&recipient_pid).await {
                if let Ok(mut book) = drift::contacts::Contacts::load_default() {
                    let placeholder = "0.0.0.0:0".parse().unwrap();
                    if book
                        .record(recipient_pub, placeholder, recipient_name.as_deref())
                        .is_ok()
                    {
                        let _ = book.save();
                    }
                }
            }
        }
        Ack::Reject { reason } => {
            eprintln!();
            eprintln!("recipient rejected the file: {}", reason);
            std::process::exit(2);
        }
    }
    Ok(())
}

async fn hash_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let mut f = File::open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    f.rewind().await.ok();
    let out: [u8; 32] = hasher.finalize().into();
    Ok(out)
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

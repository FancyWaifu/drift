//! Portable (no-tokio) build of drift-wormhole, on
//! `drift_proto_std::Connection`.
//!
//! Same `Header → file bytes → Ack` protocol as the native path
//! ([`crate::protocol`]), but driven synchronously over the sans-IO
//! engine instead of the async tokio transport — so it compiles and
//! runs where tokio can't (Redox, other no-async std targets).
//!
//! Scope vs the native build:
//!   * **tcp-only** — the blocking driver speaks `tcp://`; no
//!     udp/ws/iroh.
//!   * **not wire-interoperable** with the native build — native runs
//!     the protocol over DRIFT *streams* (StreamManager), this runs it
//!     over raw DATA datagrams. Portable talks to portable.
//!   * no progress bars / contacts / self-name — just the core
//!     transfer with sha256 verification.

use crate::protocol::{Ack, Header, CHUNK_SIZE, MAX_HEADER_BYTES};
use crate::{RecvArgs, SendArgs};
use anyhow::{anyhow, Context, Result};
use drift_proto_std::{bind_retry, server_config, Config, Connection, Identity};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Strip an optional `scheme://` prefix — the portable build only
/// speaks tcp, so the scheme (if any) is informational.
fn strip_scheme(s: &str) -> &str {
    s.split_once("://").map(|x| x.1).unwrap_or(s)
}

/// Load (or create) the hex 32-byte seed identity. Same file format
/// as the native build, but without `dirs` (which may not resolve on
/// Redox): defaults to `drift-identity.key` in the cwd; pass
/// `--identity-file` for anything else.
fn load_identity(path: Option<PathBuf>) -> Result<Identity> {
    let p = path.unwrap_or_else(|| PathBuf::from("drift-identity.key"));
    if p.exists() {
        let hex_str = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let bytes =
            hex::decode(hex_str.trim()).with_context(|| format!("{} is not hex", p.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!("{} must be 32 bytes; got {}", p.display(), bytes.len());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Identity::from_secret_bytes(seed))
    } else {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let hex_key: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
        fs::write(&p, &hex_key).with_context(|| format!("writing {}", p.display()))?;
        eprintln!("created identity {}", p.display());
        Ok(Identity::from_secret_bytes(seed))
    }
}

/// Sender side: bind, wait for the recipient, push the file, await ack.
pub(crate) fn run_send(args: SendArgs) -> Result<()> {
    if !args.file.is_file() {
        return Err(anyhow!("not a regular file: {}", args.file.display()));
    }
    let size = fs::metadata(&args.file)?.len();
    let name = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("filename is not valid UTF-8: {}", args.file.display()))?
        .to_string();

    eprintln!("hashing {name} ({size} bytes)...");
    let data = fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let sha256: [u8; 32] = Sha256::digest(&data).into();

    let identity = load_identity(args.identity_file)?;
    let pub_hex: String = identity
        .public_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let bind = args
        .bind
        .first()
        .map(|s| strip_scheme(s).to_string())
        .unwrap_or_else(|| "0.0.0.0:0".into());
    let listener =
        bind_retry(&bind, 30, Duration::from_secs(1)).with_context(|| format!("binding {bind}"))?;
    let local = listener.local_addr()?;

    eprintln!();
    eprintln!("Ready to send: {name} ({size} bytes)  [portable / tcp]");
    eprintln!("Run on the recipient:");
    eprintln!();
    eprintln!("    drift-wormhole recv {pub_hex}@{local}");
    eprintln!();
    eprintln!("Waiting for them to connect... (Ctrl-C to cancel)");

    let (stream, who) = listener.accept().context("accept")?;
    eprintln!("[connected to peer {who}]");
    let mut conn = Connection::accept(stream, identity, server_config())?;

    // The recipient speaks first (a one-byte pull request): the
    // sans-IO server only learns its peer / fully establishes the
    // session on the first authenticated DATA, so we wait for that
    // before transmitting the header.
    conn.recv()
        .context("awaiting recipient")?
        .ok_or_else(|| anyhow!("recipient connected then closed"))?;

    let header = Header {
        name,
        size,
        sha256,
        sender_name: None,
    };
    conn.send(&bincode::serialize(&header).context("encoding header")?)
        .context("sending header")?;

    let mut sent = 0u64;
    for slab in data.chunks(CHUNK_SIZE) {
        conn.send(slab).context("sending file body")?;
        sent += slab.len() as u64;
        eprint!("\r  sent {sent}/{size} bytes");
    }
    eprintln!();

    match conn.recv().context("awaiting ack")? {
        Some(bytes) => match bincode::deserialize::<Ack>(&bytes).context("decoding ack")? {
            Ack::Ok { .. } => eprintln!("✓ recipient confirmed receipt"),
            Ack::Reject { reason } => return Err(anyhow!("recipient rejected: {reason}")),
        },
        None => return Err(anyhow!("peer closed before sending an ack")),
    }
    let _ = conn.close();
    Ok(())
}

/// Recipient side: connect, read the header + body, verify, ack.
pub(crate) fn run_recv(args: RecvArgs) -> Result<()> {
    let (pub_hex, addr_part) = args
        .peer
        .split_once('@')
        .ok_or_else(|| anyhow!("peer must be in PUBHEX@HOST:PORT form"))?;
    let addr = strip_scheme(addr_part).to_string();
    let server_pub = {
        let b = hex::decode(pub_hex).context("bad pubkey hex")?;
        if b.len() != 32 {
            anyhow::bail!("pubkey must be 32 bytes; got {}", b.len());
        }
        let mut p = [0u8; 32];
        p.copy_from_slice(&b);
        p
    };
    let identity = load_identity(args.identity_file)?;

    eprintln!("connecting to {addr} ... [portable / tcp]");
    let mut conn = Connection::connect(&addr, server_pub, identity, Config::default())
        .with_context(|| format!("connecting to {addr}"))?;

    // Speak first so the sender's session establishes and it learns
    // our peer id; the sender ignores the contents and replies with
    // the file header.
    conn.send(b"PULL").context("sending pull request")?;

    let hbytes = conn
        .recv()
        .context("receiving header")?
        .ok_or_else(|| anyhow!("sender closed before sending the header"))?;
    if hbytes.len() > MAX_HEADER_BYTES {
        anyhow::bail!("header too large ({} bytes)", hbytes.len());
    }
    let header: Header = bincode::deserialize(&hbytes).context("decoding header")?;
    eprintln!("Receiving: {} ({} bytes)", header.name, header.size);

    let save_name = args.out.unwrap_or_else(|| sanitize(&header.name));
    let mut out_path = args.out_dir.clone();
    out_path.push(&save_name);

    let mut buf: Vec<u8> = Vec::with_capacity(header.size as usize);
    let mut hasher = Sha256::new();
    while (buf.len() as u64) < header.size {
        let chunk = conn.recv().context("receiving file body")?.ok_or_else(|| {
            anyhow!(
                "sender closed early at {} / {} bytes",
                buf.len(),
                header.size
            )
        })?;
        let max_take = (header.size - buf.len() as u64) as usize;
        let take = chunk.len().min(max_take);
        hasher.update(&chunk[..take]);
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            let _ = conn.send(&reject("sender exceeded declared size"));
            return Err(anyhow!("sender exceeded declared size"));
        }
        eprint!("\r  received {}/{} bytes", buf.len(), header.size);
    }
    eprintln!();

    let got: [u8; 32] = hasher.finalize().into();
    if got != header.sha256 {
        let _ = conn.send(&reject("sha256 mismatch"));
        return Err(anyhow!("sha256 mismatch — file corrupted in transit"));
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&out_path, &buf).with_context(|| format!("writing {}", out_path.display()))?;
    conn.send(
        &bincode::serialize(&Ack::Ok {
            recipient_name: None,
        })
        .context("encoding ack")?,
    )
    .context("sending ack")?;
    eprintln!(
        "✓ saved {} ({} bytes, sha256 verified)",
        out_path.display(),
        header.size
    );
    let _ = conn.close();
    Ok(())
}

fn reject(reason: &str) -> Vec<u8> {
    bincode::serialize(&Ack::Reject {
        reason: reason.into(),
    })
    .unwrap_or_default()
}

/// Drop any path components from a sender-supplied name so it can
/// never write outside `--out-dir`.
fn sanitize(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("received.bin")
        .to_string()
}

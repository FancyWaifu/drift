//! Portable (no-tokio) `drift-git-server` on
//! [`drift_proto_std::Session`].
//!
//! Same role as the native daemon ([`crate::server`] — well, `server.rs`):
//! accept a peer, read the handshake envelope, ACL-check, spawn the
//! requested git subprocess (`git-upload-pack` / `git-receive-pack`),
//! and tunnel its stdio over the encrypted session using the shared
//! `FRAME_DATA`/`FRAME_EOD` framing ([`crate::frame_data`] etc.).
//!
//! It runs on the synchronous engine driver instead of the async
//! tokio transport, so the daemon compiles and runs where tokio can't
//! (Redox, …). tcp-only. Because it speaks raw DRIFT DATA (Session)
//! rather than DRIFT streams (StreamManager), it is **not**
//! wire-interoperable with the native `git-remote-drift` helper — a
//! portable helper would pair with it. ACL is by peer id
//! (`derive_peer_id(allowed_pubkey)`), the engine-level identity check.

use crate::{
    build_err_reply, build_ok_reply, frame_data, frame_eod, parse_frame, parse_request, Frame,
};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use drift_proto_std::{bind_retry, derive_peer_id, server_config, Identity, PeerId, Session};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[clap(
    name = "drift-git-server",
    about = "Git daemon over DRIFT (portable build)"
)]
struct Cli {
    /// Address to listen on (`host:port`; a `tcp://` prefix is
    /// tolerated). The portable build is tcp-only.
    #[clap(long, default_value = "0.0.0.0:9100")]
    bind: String,

    /// Path to a 32-byte identity seed (64-char hex). If omitted, a
    /// fresh one is written to `drift-git-server.key`.
    #[clap(long)]
    identity_file: Option<PathBuf>,

    /// Root directory holding the repos; client paths resolve under it.
    #[clap(long, default_value = ".")]
    root: PathBuf,

    /// Allow this pubkey (hex). Repeat for several. ACL is by the
    /// peer id derived from each key.
    #[clap(long = "allow")]
    allow: Vec<String>,

    /// Disable ACL — accept any peer. Testing only.
    #[clap(long)]
    allow_any: bool,
}

/// Portable `drift-git-server` entry point (called from the bin's
/// portable `main`).
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let allowed_ids: Vec<PeerId> = cli
        .allow
        .iter()
        .map(|s| parse_pubkey_hex(s).map(|pk| derive_peer_id(&pk)))
        .collect::<Result<_>>()?;

    let seed = load_seed(cli.identity_file.as_deref())?;
    let pub_hex = hex::encode(Identity::from_secret_bytes(seed).public_bytes());
    println!("DRIFT_GIT_PUB={pub_hex}");
    let _ = io::stdout().flush();

    let bind = strip_scheme(&cli.bind).to_string();
    let listener =
        bind_retry(&bind, 30, Duration::from_secs(1)).with_context(|| format!("binding {bind}"))?;
    let local = listener.local_addr()?;
    eprintln!("[drift-git-server] listening on {local} (portable / tcp)");
    println!("DRIFT_GIT_BIND=tcp://{local}");
    let _ = io::stdout().flush();

    let root = cli
        .root
        .canonicalize()
        .with_context(|| format!("canonicalizing root {:?}", cli.root))?;

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[drift-git-server] accept error: {e}");
                continue;
            }
        };
        let allowed_ids = allowed_ids.clone();
        let allow_any = cli.allow_any;
        let root = root.clone();
        // One blocking thread per connection — daemons serve few
        // concurrent git ops, so no async scheduler is needed.
        thread::spawn(move || {
            if let Err(e) = handle(stream, seed, &allowed_ids, allow_any, &root) {
                eprintln!("[drift-git-server] session error: {e:#}");
            }
        });
    }
    Ok(())
}

/// Serve one peer: handshake + ACL + spawn git + framed bidirectional
/// tunnel, all over a single [`Session`].
fn handle(
    stream: TcpStream,
    seed: [u8; 32],
    allowed_ids: &[PeerId],
    allow_any: bool,
    root: &Path,
) -> Result<()> {
    let session = Session::accept(stream, Identity::from_secret_bytes(seed), server_config())?;
    let sender = session.sender();

    // Receive-side state, advanced across pump callbacks: the FIRST
    // authenticated DATA is the handshake envelope (ACL, spawn,
    // reply); everything after is framed pack-protocol → child stdin.
    let allowed_ids = allowed_ids.to_vec();
    let root = root.to_path_buf();
    let tx = sender.clone();
    let mut handshaking = true;
    let mut child: Option<Child> = None;
    let mut child_stdin: Option<ChildStdin> = None;
    let mut stdout_thread: Option<thread::JoinHandle<()>> = None;

    let pump_result = session.pump(|data| {
        if handshaking {
            handshaking = false;
            // The peer id is known now (Connected fires just before
            // this first DATA). ACL by derived id.
            if !allow_any {
                let ok = tx.peer().map(|p| allowed_ids.contains(&p)).unwrap_or(false);
                if !ok {
                    let _ = tx.send(&build_err_reply("not authorized"));
                    return Err(io::Error::other("peer not authorized"));
                }
            }

            let (service, repo_path, consumed) = parse_request(data).map_err(to_io)?;
            let trailing = data[consumed..].to_vec();

            let resolved = match resolve_repo(&root, &repo_path) {
                Ok(p) if p.exists() => p,
                Ok(_) => {
                    let _ = tx.send(&build_err_reply(&format!("no such repo: {repo_path}")));
                    return Err(io::Error::other("no such repo"));
                }
                Err(e) => {
                    let _ = tx.send(&build_err_reply(&format!("bad repo path: {e}")));
                    return Err(to_io(e));
                }
            };

            let mut c = Command::new(service.binary_name())
                .arg(&resolved)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    io::Error::other(format!("spawning {}: {e}", service.binary_name()))
                })?;
            let mut cin = c.stdin.take().expect("child stdin piped");
            let cout = c.stdout.take().expect("child stdout piped");
            let cerr = c.stderr.take().expect("child stderr piped");

            tx.send(&build_ok_reply())?;

            // Any pack bytes the client packed alongside the
            // handshake (rare — git waits for our reply first).
            let mut closed_stdin = false;
            if !trailing.is_empty() {
                match parse_frame(&trailing) {
                    Frame::Data(p) => {
                        let _ = cin.write_all(p);
                    }
                    Frame::EndOfData => closed_stdin = true,
                    Frame::Unknown(_) => {}
                }
            }

            // child stdout → framed DATA on the session; EOD at EOF.
            let out_tx = tx.clone();
            stdout_thread = Some(thread::spawn(move || {
                let mut out = cout;
                let mut buf = [0u8; 1024];
                loop {
                    match out.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if out_tx.send(&frame_data(&buf[..n])).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = out_tx.send(&frame_eod());
            }));

            // Drain stderr so git doesn't block on a full pipe.
            thread::spawn(move || {
                let mut s = String::new();
                let _ = std::io::BufReader::new(cerr).read_to_string(&mut s);
                if !s.trim_end().is_empty() {
                    eprintln!("[drift-git-server] git stderr: {}", s.trim_end());
                }
            });

            child = Some(c);
            child_stdin = if closed_stdin { None } else { Some(cin) };
        } else {
            // Tunnel: framed bytes from the client → child stdin.
            match parse_frame(data) {
                Frame::Data(p) => {
                    if let Some(si) = child_stdin.as_mut() {
                        if si.write_all(p).is_err() || si.flush().is_err() {
                            child_stdin = None;
                        }
                    }
                }
                // Client finished sending — close child stdin so
                // upload-pack/receive-pack sees EOF and proceeds.
                Frame::EndOfData => child_stdin = None,
                Frame::Unknown(_) => {}
            }
        }
        Ok(())
    });

    // Session ended — make sure the child's stdin is closed, the
    // stdout pump drained, and the child reaped.
    drop(child_stdin);
    if let Some(t) = stdout_thread {
        let _ = t.join();
    }
    if let Some(mut c) = child {
        let _ = c.wait();
    }
    pump_result.map_err(|e| anyhow!("session pump: {e}"))
}

fn to_io(e: anyhow::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn strip_scheme(s: &str) -> &str {
    s.split_once("://").map(|x| x.1).unwrap_or(s)
}

/// Resolve a client repo path against `root`, refusing `..` escapes.
fn resolve_repo(root: &Path, requested: &str) -> Result<PathBuf> {
    let combined = root.join(requested.trim_start_matches('/'));
    let canonical = combined
        .canonicalize()
        .with_context(|| format!("canonicalize {combined:?}"))?;
    if !canonical.starts_with(root) {
        return Err(anyhow!(
            "repo path {requested:?} resolves outside root {root:?}"
        ));
    }
    Ok(canonical)
}

fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).with_context(|| format!("invalid hex pubkey {s:?}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes; got {}", bytes.len()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

/// Load (or create) the hex 32-byte seed. No `dirs` — defaults to
/// `drift-git-server.key` in the cwd; pass `--identity-file` otherwise.
fn load_seed(path: Option<&Path>) -> Result<[u8; 32]> {
    let p = path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("drift-git-server.key"));
    if p.exists() {
        let hex_str =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let bytes =
            hex::decode(hex_str.trim()).with_context(|| format!("{} is not hex", p.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!("{} must be 32 bytes; got {}", p.display(), bytes.len());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    } else {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let hex_key: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&p, &hex_key).with_context(|| format!("writing {}", p.display()))?;
        eprintln!("[drift-git-server] created identity {}", p.display());
        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_request, parse_reply, GitService};
    use drift_proto_std::{Config, Connection};
    use std::net::TcpListener;
    use std::process::Command as Pc;

    fn git(args: &[&str], dir: &Path) {
        let ok = Pc::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed");
    }

    /// End-to-end: a `Connection` client (interoperable with the
    /// `Session` server on the wire — both speak raw DRIFT DATA) does
    /// the handshake against the portable server, which spawns a real
    /// `git-upload-pack`; the ref advertisement must arrive back
    /// through the FRAME_DATA tunnel.
    #[test]
    fn portable_server_serves_upload_pack() {
        let base = std::env::temp_dir().join(format!("drift-git-pst-{}", std::process::id()));
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&["init", "-q"], &repo);
        git(&["commit", "--allow-empty", "-q", "-m", "init"], &repo);

        let seed = [0x5d_u8; 32];
        let server_pub = Identity::from_secret_bytes(seed).public_bytes();
        let root = base.canonicalize().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let root2 = root.clone();
        let srv = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle(stream, seed, &[], true, &root2);
        });

        let mut conn = Connection::connect(
            &addr.to_string(),
            server_pub,
            Identity::from_secret_bytes([0xc1; 32]),
            Config::default(),
        )
        .unwrap();
        conn.send(&build_request(GitService::UploadPack, "/repo"))
            .unwrap();

        let reply = conn.recv().unwrap().expect("handshake reply");
        parse_reply(&reply).expect("server replied OK");

        // Collect the framed ref advertisement.
        let mut adv = Vec::new();
        for _ in 0..100 {
            match conn.recv().unwrap() {
                Some(chunk) => match parse_frame(&chunk) {
                    Frame::Data(p) => {
                        adv.extend_from_slice(p);
                        if adv.windows(4).any(|w| w == b"HEAD") {
                            break;
                        }
                    }
                    Frame::EndOfData => break,
                    Frame::Unknown(_) => {}
                },
                None => break,
            }
        }
        assert!(
            adv.windows(4).any(|w| w == b"HEAD"),
            "expected git-upload-pack ref advertisement (with HEAD), got {} bytes",
            adv.len()
        );

        // Tell upload-pack we want nothing so it exits, then close.
        let _ = conn.send(&frame_data(b"0000"));
        let _ = conn.send(&frame_eod());
        let _ = conn.close();
        let _ = srv.join();
        std::fs::remove_dir_all(&base).ok();
    }
}

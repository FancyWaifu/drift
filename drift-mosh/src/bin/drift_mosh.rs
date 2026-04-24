//! drift-mosh — the user-facing launcher.
//!
//! Usage:
//!     drift-mosh user@host
//!
//! What it does:
//! 1. SSH into `user@host` and run `drift-mosh-server`.
//! 2. Read the banner (key=value lines) from the server's
//!    stdout until `DRIFT_MOSH_READY`.
//! 3. Do TOFU: if this `(host, port)` is in known_hosts,
//!    verify the banner's pub matches. If not, prompt the
//!    user once to pin it.
//! 4. Fetch/remember the per-host session id, so reconnects
//!    pick up the previous pty.
//! 5. Launch `drift-mosh-client` with the parsed args, let
//!    it inherit the current tty.
//!
//! We don't do the shell-level work ourselves (raw mode, pty
//! wiring) — that's what `drift-mosh-client` is for. This
//! binary is pure UX sugar.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use drift_mosh::known_hosts::prompt_yes_no;
use drift_mosh::{BannerLine, Config, HostKeyStatus, KnownHosts};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "drift-mosh",
    about = "Mobile shell over DRIFT — survives network changes.",
    long_about = "drift-mosh user@host — SSH-launches a drift-mosh-server on the \
                  remote and connects to it. Network changes, laptop suspend, and \
                  reconnects are transparent; your terminal session picks back up \
                  where you left it."
)]
struct Cli {
    /// `user@host` or just `host`. If `user@` is omitted we
    /// use the current username (same as ssh).
    target: String,

    /// Explicit SSH port. Overrides the config file default.
    #[clap(short = 'p', long)]
    ssh_port: Option<u16>,

    /// Skip launching via SSH; connect to an already-running
    /// drift-mosh-server. Useful when you're bootstrapping
    /// the server by hand.
    #[clap(long)]
    no_ssh: bool,

    /// Hex-encoded server pubkey — required when --no-ssh is
    /// set. Otherwise pulled from the banner automatically.
    #[clap(long)]
    server_pub: Option<String>,

    /// `ip:port` — required when --no-ssh is set.
    #[clap(long)]
    server_addr: Option<String>,

    /// Override the config-file path for the remote
    /// `drift-mosh-server` binary (useful if it's in a
    /// non-standard location like $HOME/.local/bin).
    #[clap(long)]
    remote_server_path: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load().unwrap_or_default();

    let (host_part, user_part) = parse_target(&cli.target)?;
    let ssh_port = cli.ssh_port.unwrap_or(config.ssh_port);
    let host_key = format!("{}:{}", host_part, ssh_port);
    let remote_server_path = cli
        .remote_server_path
        .unwrap_or_else(|| config.remote_server_path.clone());

    // Acquire the banner (pub + addr) either via SSH launch
    // or via the --no-ssh flags.
    let banner = if cli.no_ssh {
        let pub_hex = cli
            .server_pub
            .ok_or_else(|| anyhow!("--no-ssh requires --server-pub"))?;
        let addr = cli
            .server_addr
            .ok_or_else(|| anyhow!("--no-ssh requires --server-addr"))?;
        ServerBanner {
            pub_hex,
            peer_id_hex: String::new(),
            addr,
        }
    } else {
        ssh_launch_and_parse_banner(&host_part, user_part.as_deref(), ssh_port, &remote_server_path)?
    };

    // TOFU verify / pin.
    let mut known = KnownHosts::load().context("loading known_hosts")?;
    let pub_bytes = parse_pub_hex(&banner.pub_hex)?;
    match known.check(&host_key, &pub_bytes) {
        HostKeyStatus::Known => {
            // Silent success.
        }
        HostKeyStatus::Unknown => {
            let short = short_hex(&banner.pub_hex);
            eprintln!(
                "The authenticity of host '{}' can't be established.",
                host_key
            );
            eprintln!("Server pubkey fingerprint: {}", short);
            let ok = prompt_yes_no("Pin this key and continue? [y/N]")
                .context("reading answer")?;
            if !ok {
                return Err(anyhow!("host not pinned, aborting"));
            }
            known.add(&host_key, pub_bytes)?;
            eprintln!("Pinned {} for {}", short, host_key);
        }
        HostKeyStatus::Changed { pinned } => {
            let pinned_hex: String = pinned.iter().map(|b| format!("{:02x}", b)).collect();
            return Err(anyhow!(
                "\n\
                 ⚠  Server pubkey for {} has CHANGED.\n\
                    Pinned:   {}\n\
                    Got:      {}\n\
                 This could mean the server rotated its key, or someone is\n\
                 intercepting the connection. To accept the new key, edit\n\
                 {} and remove the old entry.\n",
                host_key,
                short_hex(&pinned_hex),
                short_hex(&banner.pub_hex),
                KnownHosts::path()?.display(),
            ));
        }
    }

    // Load (or create) the persistent session id for this host.
    let sessions_dir = Config::config_dir()?.join("sessions");
    std::fs::create_dir_all(&sessions_dir).ok();
    let session_file = sessions_dir.join(format!("{}.session", host_key.replace(':', "_")));
    let prior_session_id = std::fs::read_to_string(&session_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Spawn drift-mosh-client, inheriting our tty.
    let client_path = resolve_client_binary()?;
    let mut cmd = Command::new(&client_path);
    cmd.arg("--server-pub").arg(&banner.pub_hex);
    cmd.arg("--server-addr").arg(&banner.addr);
    if let Some(sid) = prior_session_id {
        cmd.arg("--session-id").arg(sid);
    }
    // We want drift-mosh-client's stdout to stream to our
    // stdout for the `DRIFT_MOSH_SESSION_ID=...` line, but
    // we also want the terminal to act normally. Pipe stdout
    // into a filter thread that saves the session_id then
    // transparently forwards the rest. Stdin + stderr go
    // through unchanged.
    cmd.stdout(Stdio::piped());
    let mut child = cmd.spawn().context("spawning drift-mosh-client")?;
    let stdout = child.stdout.take().unwrap();
    let sf = session_file.clone();
    let tee = std::thread::spawn(move || tee_and_capture_session_id(stdout, sf));
    let status = child.wait().context("waiting on drift-mosh-client")?;
    let _ = tee.join();

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

struct ServerBanner {
    pub_hex: String,
    /// Parsed for future use / logging, currently unused.
    #[allow(dead_code)]
    peer_id_hex: String,
    addr: String,
}

/// Parse `user@host` or just `host`. Returns (host, Option<user>).
fn parse_target(s: &str) -> Result<(String, Option<String>)> {
    if let Some((user, host)) = s.split_once('@') {
        if user.is_empty() || host.is_empty() {
            return Err(anyhow!("malformed target '{}'", s));
        }
        Ok((host.to_string(), Some(user.to_string())))
    } else {
        if s.is_empty() {
            return Err(anyhow!("empty target"));
        }
        Ok((s.to_string(), None))
    }
}

/// SSH into host, run drift-mosh-server, parse its banner.
/// We stop reading once we see DRIFT_MOSH_READY — the server
/// then switches to serving binary traffic on its UDP port
/// and its stdout/stderr are done.
fn ssh_launch_and_parse_banner(
    host: &str,
    user: Option<&str>,
    ssh_port: u16,
    remote_server_path: &str,
) -> Result<ServerBanner> {
    // SSH command. We disable SSH's own pty allocation (-T)
    // because the server doesn't need one — it's reading no
    // input and printing a banner.
    let mut ssh = Command::new("ssh");
    ssh.arg("-T");
    ssh.arg("-p").arg(ssh_port.to_string());
    if let Some(u) = user {
        ssh.arg(format!("{}@{}", u, host));
    } else {
        ssh.arg(host);
    }
    // Have the remote drop its stdio on background so SSH
    // doesn't hold the session open waiting for server
    // output.
    ssh.arg(format!(
        "{} --bind 0.0.0.0:0",
        shell_escape(remote_server_path)
    ));
    ssh.stdout(Stdio::piped());
    ssh.stderr(Stdio::piped());
    ssh.stdin(Stdio::null());

    let mut child = ssh.spawn().context("running ssh")?;
    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    let mut pub_hex = None;
    let mut peer_id_hex = None;
    let mut addr = None;

    let deadline = Instant::now() + Duration::from_secs(10);
    for line in reader.lines() {
        if Instant::now() > deadline {
            return Err(anyhow!(
                "timed out waiting for drift-mosh-server banner over SSH"
            ));
        }
        let line = match line {
            Ok(l) => l,
            Err(e) => return Err(anyhow!("error reading SSH stdout: {}", e)),
        };
        if let Some(v) = line.strip_prefix(BannerLine::Pub.prefix()) {
            pub_hex = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix(BannerLine::PeerId.prefix()) {
            peer_id_hex = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix(BannerLine::Addr.prefix()) {
            addr = Some(v.trim().to_string());
        } else if line.trim() == BannerLine::Ready.prefix() {
            break;
        }
    }

    let banner = ServerBanner {
        pub_hex: pub_hex.ok_or_else(|| anyhow!("banner missing pub line"))?,
        peer_id_hex: peer_id_hex.unwrap_or_default(),
        addr: addr.ok_or_else(|| anyhow!("banner missing addr line"))?,
    };

    // Let the server run detached from SSH. We don't wait on
    // the ssh child — on macOS it gets reaped when our
    // process exits; proper daemonization is left as a
    // follow-up.
    std::mem::drop(child);

    Ok(banner)
}

/// Copy child's stdout to our stdout, while also extracting
/// the first `DRIFT_MOSH_SESSION_ID=...` line and saving it to
/// `session_file`.
fn tee_and_capture_session_id(
    stdout: std::process::ChildStdout,
    session_file: PathBuf,
) -> Result<()> {
    use std::io::Write;
    let mut reader = BufReader::new(stdout);
    let mut out = std::io::stdout().lock();
    let mut saw_session = false;
    loop {
        let mut line = String::new();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        if let Some(sid) = line.strip_prefix("DRIFT_MOSH_SESSION_ID=") {
            if !saw_session {
                saw_session = true;
                let _ = std::fs::write(&session_file, sid.trim());
            }
            // Don't forward this machine-parseable marker.
            continue;
        }
        if line.starts_with("DRIFT_MOSH_REATTACH=") {
            continue;
        }
        out.write_all(line.as_bytes()).ok();
        out.flush().ok();
    }
    Ok(())
}

fn resolve_client_binary() -> Result<PathBuf> {
    // Two search paths:
    // 1. Alongside ourselves (`./drift-mosh-client` or
    //    platform-equivalent). This is how Homebrew-installed
    //    binaries work.
    // 2. `drift-mosh-client` on $PATH.
    let exe = std::env::current_exe().context("locating current exe")?;
    let parent = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    let sibling = parent.join(if cfg!(windows) {
        "drift-mosh-client.exe"
    } else {
        "drift-mosh-client"
    });
    if sibling.exists() {
        return Ok(sibling);
    }
    Ok(PathBuf::from("drift-mosh-client"))
}

fn parse_pub_hex(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("server pub isn't valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("server pub must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// First 12 chars + last 8 chars, for human-readable pinning
/// prompts. Shorter than the full 64 hex chars but still long
/// enough that a user could spot a mismatch visually.
fn short_hex(full: &str) -> String {
    if full.len() <= 20 {
        return full.to_string();
    }
    format!("{}…{}", &full[..12], &full[full.len() - 8..])
}

/// Minimal shell-escaping for the remote-command argument we
/// pass through SSH. We only need to quote spaces and dollar
/// signs; drift-mosh-server's path shouldn't contain anything
/// weirder.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '.' || c == '-' || c == '_') {
        s.to_string()
    } else {
        // POSIX-shell-safe: wrap in single quotes, and escape
        // any single quotes inside.
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

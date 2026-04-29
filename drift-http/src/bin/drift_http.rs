//! `drift-http` — Apache-style HTTP server / proxy that speaks
//! over DRIFT instead of TCP+TLS.
//!
//! Three modes share one binary:
//!
//! ```text
//! # 1. Apache-style: serve static files over DRIFT.
//! drift-http serve --root /var/www --bind 0.0.0.0:9100
//!
//! # 2. Proxy mode: bridge DRIFT streams to a local HTTP service
//! #    (e.g. Jellyfin on localhost:8096).
//! drift-http serve --proxy localhost:8096 --bind 0.0.0.0:9100
//!
//! # 3. Consume side: bind a local TCP port that tunnels to a
//! #    remote drift-http via DRIFT. Browsers and other HTTP
//! #    clients hit `localhost:9101` and get the remote site.
//! drift-http connect --peer <pubhex>@<ip:port> --listen 127.0.0.1:9101
//! ```
//!
//! Identity is shared across all DRIFT tools at
//! `~/.config/drift/identity.key` (auto-created on first run).
//! Override via `--identity-file` if you need per-instance keys.

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use drift_http::transport_url::{parse_drift_url, split_peer};
use drift_http::{identity as drift_identity, StreamIo};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;
use tower_http::services::ServeDir;

#[derive(Parser)]
#[command(name = "drift-http", about = "HTTP over DRIFT — Apache-shaped")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a server. Either serves static files (`--root`) or
    /// proxies inbound streams to a local HTTP service (`--proxy`).
    Serve(ServeArgs),
    /// Bridge a local TCP listener to a remote drift-http via
    /// DRIFT. Used by clients (browsers, Jellyswarrm, anything
    /// speaking HTTP) that don't speak DRIFT natively.
    Connect(ConnectArgs),
    /// Open a `drift://PUBHEX@HOST:PORT/path` URL in the
    /// default browser. Reuses an existing background bridge
    /// for the peer if one is alive, otherwise spawns one.
    Open(OpenArgs),
    /// Register `drift://` as a system URL handler so clicking
    /// a `drift://...` link in any app launches `drift-http
    /// open` automatically.
    InstallHandler(InstallHandlerArgs),
}

#[derive(Args)]
struct OpenArgs {
    /// `drift://PUBHEX@HOST:PORT/path` URL.
    url: String,

    /// Print the resulting `http://127.0.0.1:.../path` URL
    /// instead of launching a browser. Useful for scripting.
    #[clap(long)]
    no_browse: bool,

    /// Path to the identity key the bridge should use.
    /// Defaults to the shared `$CONFIG_DIR/drift/identity.key`.
    #[clap(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Args)]
struct InstallHandlerArgs {
    /// On macOS, install the .app bundle to `$HOME/Applications`
    /// instead of the user-only fallback location. Doesn't
    /// affect Linux/Windows.
    #[clap(long)]
    user_apps: bool,

    /// Print what would be installed without doing it.
    #[clap(long)]
    dry_run: bool,
}

#[derive(Args)]
struct ServeArgs {
    /// DRIFT bind address. Repeatable: pass `--bind` once per
    /// transport you want to listen on. Schemes: `udp://`,
    /// `tcp://`. A bare `host:port` defaults to UDP.
    ///
    /// Examples:
    ///   --bind 0.0.0.0:9100                  (UDP only, default)
    ///   --bind udp://0.0.0.0:9100 \
    ///   --bind tcp://0.0.0.0:9100            (UDP + TCP fallback)
    #[clap(long, default_value = "udp://0.0.0.0:9100")]
    bind: Vec<String>,

    /// Path to the identity key. Defaults to the shared
    /// location at `$CONFIG_DIR/drift/identity.key`.
    #[clap(long)]
    identity_file: Option<PathBuf>,

    /// **Apache mode** — serve static files from this directory.
    /// Mutually exclusive with `--proxy`.
    #[clap(long, conflicts_with = "proxy")]
    root: Option<PathBuf>,

    /// **Proxy mode** — forward each inbound DRIFT stream to
    /// this `host:port` over plain TCP. Mutually exclusive
    /// with `--root`.
    #[clap(long, conflicts_with = "root")]
    proxy: Option<String>,
}

#[derive(Args)]
struct ConnectArgs {
    /// Server peer. Forms accepted:
    ///   PUBHEX@host:port          (UDP, default)
    ///   PUBHEX@udp://host:port
    ///   PUBHEX@tcp://host:port
    /// Pubkey is 64 hex chars (32 bytes).
    #[clap(long)]
    peer: String,

    /// Local TCP listen address. Default `127.0.0.1:9101`.
    #[clap(long, default_value = "127.0.0.1:9101")]
    listen: String,

    /// Local UDP bind for outbound DRIFT (UDP transport only).
    /// Ignored when --peer uses tcp://. Default `0.0.0.0:0`
    /// (any interface, ephemeral port).
    #[clap(long, default_value = "0.0.0.0:0")]
    bind: String,

    /// Path to the identity key. Defaults to the shared
    /// location at `$CONFIG_DIR/drift/identity.key`.
    #[clap(long)]
    identity_file: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();

    if let Err(e) = match cli.cmd {
        Cmd::Serve(a) => run_serve(a).await,
        Cmd::Connect(a) => run_connect(a).await,
        Cmd::Open(a) => run_open(a).await,
        Cmd::InstallHandler(a) => run_install_handler(a).await,
    } {
        eprintln!("drift-http: {:#}", e);
        std::process::exit(1);
    }
    Ok(())
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_http=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
}

fn load_identity(path: Option<PathBuf>) -> Result<Identity> {
    let p = match path {
        Some(p) => p,
        None => drift_identity::default_path()?,
    };
    drift_identity::load_or_create(&p)
}

// ─── serve ────────────────────────────────────────────────────────

async fn run_serve(args: ServeArgs) -> Result<()> {
    if args.root.is_none() && args.proxy.is_none() {
        return Err(anyhow!(
            "serve mode requires either --root <dir> or --proxy <host:port>"
        ));
    }

    let identity = load_identity(args.identity_file)?;
    let pub_hex: String = identity
        .public_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    if args.bind.is_empty() {
        return Err(anyhow!("at least one --bind is required"));
    }

    // accept_any_peer: anyone with our pubkey can connect, like
    // a public website. App-layer auth (or Jellyfin's own login)
    // is what actually gates access.
    let tcfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    // First --bind becomes the primary; subsequent --binds are
    // attached via `add_listener`. All transport-specific logic
    // (UDP socket vs TCP accept-loop vs future WS upgrade) is
    // hidden inside `drift::Transport` — this binary doesn't
    // know or care which scheme is which.
    let (transport, primary_url) = Transport::bind_url(&args.bind[0], identity, tcfg)
        .await
        .context("setting up primary DRIFT transport")?;
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

    println!("DRIFT_HTTP_PUB={}", pub_hex);
    // `DRIFT_HTTP_ADDR=<host:port>` carries the first UDP bind
    // unprefixed for back-compat with anything that pre-dates
    // multi-transport (test scripts, drift-mosh launcher).
    // `DRIFT_HTTP_BIND=<scheme>://<addr>` is the new line per
    // bound transport — multi-transport-aware callers parse it.
    if let Some(udp_url) = bound_urls.iter().find(|u| u.starts_with("udp://")) {
        let bare = &udp_url[6..]; // strip "udp://"
        println!("DRIFT_HTTP_ADDR={}", bare);
    }
    for url in &bound_urls {
        println!("DRIFT_HTTP_BIND={}", url);
    }
    if let Some(root) = &args.root {
        println!("DRIFT_HTTP_MODE=serve-files root={}", root.display());
    } else if let Some(up) = &args.proxy {
        println!("DRIFT_HTTP_MODE=proxy upstream={}", up);
    }
    println!("DRIFT_HTTP_READY");
    use std::io::Write;
    std::io::stdout().flush().ok();
    tracing::info!(addrs = ?bound_urls, "drift-http serve ready");

    // Accept loop: each new DRIFT stream becomes one HTTP
    // connection (Apache mode) or one tunneled TCP connection
    // (proxy mode).
    loop {
        let stream = match mgr.accept().await {
            Some(s) => s,
            None => break,
        };
        if let Some(root) = args.root.clone() {
            tokio::spawn(async move {
                if let Err(e) = serve_files_on_stream(Arc::new(stream), root).await {
                    tracing::warn!(error = ?e, "file-serving stream ended");
                }
            });
        } else if let Some(upstream) = args.proxy.clone() {
            tokio::spawn(async move {
                if let Err(e) = serve_proxy_on_stream(Arc::new(stream), upstream).await {
                    tracing::warn!(error = ?e, "proxy stream ended");
                }
            });
        }
    }
    Ok(())
}

/// Apache-mode: run hyper http1 over the DRIFT stream and serve
/// files from `root` via `tower-http::ServeDir`.
async fn serve_files_on_stream(
    stream: Arc<drift::streams::Stream>,
    root: PathBuf,
) -> Result<()> {
    let io = TokioIo::new(StreamIo::new(stream));
    let serve_dir = ServeDir::new(root);

    // ServeDir is `tower::Service<Request<B>> -> Response<ServeFileSystemResponseBody>`.
    // Hyper's `serve_connection` is happy with any Service whose
    // response body implements `http_body::Body` — and ServeDir's
    // body does — so we just hand its response through unchanged
    // via `oneshot` (from `tower::ServiceExt`).
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let serve_dir = serve_dir.clone();
        async move { serve_dir.oneshot(req).await }
    });

    http1::Builder::new()
        .serve_connection(io, svc)
        .await
        .context("hyper serve_connection")?;
    Ok(())
}

/// Proxy-mode: dial the upstream `host:port` and bridge bytes
/// between the DRIFT stream and the TCP socket. Opaque — no HTTP
/// parsing, so WebSocket upgrades, range requests, long-poll,
/// etc. all just work.
async fn serve_proxy_on_stream(
    stream: Arc<drift::streams::Stream>,
    upstream: String,
) -> Result<()> {
    let mut tcp = TcpStream::connect(&upstream)
        .await
        .with_context(|| format!("dialing upstream {}", upstream))?;
    let mut io = StreamIo::new(stream);
    let (a, b) = tokio::io::copy_bidirectional(&mut io, &mut tcp).await?;
    tracing::debug!(client_to_upstream = a, upstream_to_client = b, "proxy stream done");
    Ok(())
}

// ─── connect ──────────────────────────────────────────────────────

async fn run_connect(args: ConnectArgs) -> Result<()> {
    let (server_pub, peer_url, _transport_kind) = split_peer(&args.peer)?;

    let identity = load_identity(args.identity_file)?;
    // `--bind` is now only used as a hint for UDP local-port
    // selection; ignored for TCP since `connect_url` dials and
    // owns the local end of the stream. We keep parsing it for
    // back-compat with old scripts that always passed it.
    let _local_udp_bind: SocketAddr = args
        .bind
        .parse()
        .with_context(|| format!("--bind {:?} is not a valid ip:port", args.bind))?;
    let listen: SocketAddr = args
        .listen
        .parse()
        .with_context(|| format!("--listen {:?} is not a valid ip:port", args.listen))?;

    let (transport, server_addr) =
        Transport::connect_url(&peer_url, identity, TransportConfig::default())
            .await
            .context("setting up DRIFT client transport")?;
    let transport = Arc::new(transport);
    let server_peer = transport
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .context("registering remote peer")?;
    let mgr = StreamManager::bind(transport.clone()).await;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding local TCP listener on {}", listen))?;
    // Crucial when --listen used port 0: print the actual bound
    // port so callers (and the bridge spawner in `open` mode)
    // can connect to the right place.
    let bound = listener.local_addr()?;
    tracing::info!(peer = %server_addr, listen = %bound, "drift-http connect ready");
    println!("DRIFT_HTTP_LISTEN={}", bound);
    println!("DRIFT_HTTP_READY");
    use std::io::Write;
    std::io::stdout().flush().ok();

    loop {
        let (mut tcp, src) = listener
            .accept()
            .await
            .context("accept on local TCP listener")?;
        let mgr = mgr.clone();
        tokio::spawn(async move {
            tracing::debug!(from = %src, "new local TCP connection");
            let stream = match mgr.open(server_peer).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = ?e, "failed to open DRIFT stream");
                    return;
                }
            };
            let mut io = StreamIo::new(Arc::new(stream));
            if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut io).await {
                tracing::debug!(error = ?e, "bridge ended");
            }
        });
    }
}

// ─── open ─────────────────────────────────────────────────────────

async fn run_open(args: OpenArgs) -> Result<()> {
    let url = parse_drift_url(&args.url).context("parsing drift:// URL")?;
    // The connect_url is what `Transport::connect_url` accepts
    // (e.g. `udp://host:9100`). We pass it through to the
    // bridge unchanged; the bridge persists it as the per-peer
    // identity for state tracking.
    let connect_url = url.connect_url();
    let port = drift_http::bridge::ensure_bridge(
        &url.pub_hex,
        &connect_url,
        url.transport,
        args.identity_file,
    )
    .await
    .context("ensuring background bridge")?;

    let http_url = format!("http://127.0.0.1:{}{}", port, url.path_and_query);

    if args.no_browse {
        // Machine-readable line so callers (tests, automation,
        // shell scripts) can pipe this into curl / xdg-open
        // themselves.
        println!("{}", http_url);
    } else {
        ::open::that(&http_url)
            .with_context(|| format!("launching browser for {}", http_url))?;
        eprintln!("opened {} in your default browser", http_url);
    }
    Ok(())
}

// ─── install-handler ──────────────────────────────────────────────

async fn run_install_handler(args: InstallHandlerArgs) -> Result<()> {
    let exe = std::env::current_exe().context("locating drift-http binary")?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);

    #[cfg(target_os = "macos")]
    {
        return install_handler_macos(&exe, args.user_apps, args.dry_run);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = args.user_apps; // unused on Linux
        return install_handler_linux(&exe, args.dry_run);
    }
    #[allow(unreachable_code)]
    {
        let _ = args;
        eprintln!(
            "install-handler is currently only implemented for macOS and Linux. \
             On Windows, register `drift` under `HKCU\\Software\\Classes\\drift` \
             with the default value pointing at: \"{}\" open \"%1\"",
            exe.display()
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn install_handler_macos(exe: &std::path::Path, user_apps: bool, dry_run: bool) -> Result<()> {
    // macOS gotcha: a `.app` bundle whose Mach-O is a plain
    // shell script does NOT receive URLs as argv. Launch
    // Services delivers URLs via the `kAEGetURL` Apple Event,
    // which only an app with a proper Apple Event handler can
    // receive. The simplest way to get one is to compile a tiny
    // AppleScript with `osacompile` — its `on open location`
    // handler is wired to GetURL automatically — and then patch
    // its Info.plist to declare the `drift://` scheme.
    let apps_dir = if user_apps {
        dirs::home_dir()
            .ok_or_else(|| anyhow!("no home dir"))?
            .join("Applications")
    } else {
        // Per-user but under ~/Library — quieter than ~/Applications.
        dirs::home_dir()
            .ok_or_else(|| anyhow!("no home dir"))?
            .join("Library/Application Support/drift")
    };
    let app = apps_dir.join("DriftURLHandler.app");

    // The AppleScript runs `drift-http open <url>` as a shell
    // command, capturing both stdout + stderr to a log file so a
    // failed open is debuggable after the fact (since GUI launches
    // have no terminal). `quoted form of` is AppleScript's safe
    // shell-escape — it handles spaces, quotes, $, etc.
    let log_path = format!("$HOME/Library/Logs/drift-url.log");
    let script_contents = format!(
        "on open location this_URL\n\
         \tdo shell script \"{} open \" & quoted form of this_URL & \" >> {} 2>&1\"\n\
         end open location\n",
        exe.display(),
        log_path
    );

    if dry_run {
        println!("[dry-run] would osacompile to {}", app.display());
        println!("[dry-run] AppleScript source:");
        for line in script_contents.lines() {
            println!("    {}", line);
        }
        println!("[dry-run] would patch Info.plist to declare drift:// scheme");
        println!("[dry-run] would lsregister + LSSetDefaultHandlerForURLScheme");
        return Ok(());
    }

    // Step 1: write the AppleScript source to a temp file.
    let tmpdir = tempdir_in_apps()?;
    let script_path = tmpdir.join("handler.applescript");
    std::fs::write(&script_path, &script_contents)
        .with_context(|| format!("writing {}", script_path.display()))?;

    // Step 2: build the .app via osacompile. Wipe any previous
    // attempt so we start clean — re-running install-handler
    // shouldn't pile up half-installed bundles.
    if app.exists() {
        std::fs::remove_dir_all(&app)
            .with_context(|| format!("removing prior {}", app.display()))?;
    }
    if let Some(parent) = app.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let osa_status = std::process::Command::new("/usr/bin/osacompile")
        .arg("-o")
        .arg(&app)
        .arg(&script_path)
        .status()
        .context("running osacompile (Xcode CLI tools may need to be installed)")?;
    if !osa_status.success() {
        return Err(anyhow!(
            "osacompile exited with status {} — could not build .app bundle",
            osa_status
        ));
    }

    // Step 3: PlistBuddy adds the URL-scheme + bundle-id +
    // LSUIElement keys osacompile didn't generate.
    let plist = app.join("Contents/Info.plist");
    let pb = "/usr/libexec/PlistBuddy";
    let plist_str = plist.to_str().ok_or_else(|| anyhow!("non-utf8 plist path"))?;
    // Bundle id — the LSSetDefault call below references it.
    plistbuddy(pb, plist_str, "Set :CFBundleIdentifier app.drift.urlhandler")
        .or_else(|_| {
            plistbuddy(
                pb,
                plist_str,
                "Add :CFBundleIdentifier string app.drift.urlhandler",
            )
        })
        .context("setting CFBundleIdentifier")?;
    // CFBundleURLTypes array (skip if it already exists; PlistBuddy
    // returns nonzero in that case but the structure is fine).
    let _ = plistbuddy(pb, plist_str, "Add :CFBundleURLTypes array");
    plistbuddy(pb, plist_str, "Add :CFBundleURLTypes:0 dict")
        .context("adding URL type dict")?;
    plistbuddy(
        pb,
        plist_str,
        "Add :CFBundleURLTypes:0:CFBundleURLName string DRIFT URL",
    )
    .context("adding URL name")?;
    plistbuddy(
        pb,
        plist_str,
        "Add :CFBundleURLTypes:0:CFBundleURLSchemes array",
    )
    .context("adding URL schemes array")?;
    plistbuddy(
        pb,
        plist_str,
        "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string drift",
    )
    .context("adding drift scheme")?;
    // LSUIElement makes it a "background utility" — no Dock icon
    // bouncing every time someone clicks a drift:// link.
    let _ = plistbuddy(pb, plist_str, "Add :LSUIElement bool true");

    // Two-step Launch Services dance:
    //
    // 1. `lsregister -f` registers the bundle so macOS knows
    //    *which* app can handle `drift:` URLs.
    // 2. `LSSetDefaultHandlerForURLScheme` (called from a tiny
    //    inline Swift script) marks our bundle as the *default*
    //    for the scheme. Without this, `open drift://...` falls
    //    back to "no handler" and silently does nothing — the
    //    bundle is registered but not chosen.
    let lsregister = "/System/Library/Frameworks/CoreServices.framework/\
        Versions/A/Frameworks/LaunchServices.framework/\
        Versions/A/Support/lsregister";
    let status = std::process::Command::new(lsregister)
        .arg("-f")
        .arg(&app)
        .status()
        .with_context(|| format!("running {}", lsregister))?;
    if !status.success() {
        eprintln!(
            "warning: lsregister exited with status {} — handler installed but may need a relog",
            status
        );
    }

    // Inline Swift call to LSSetDefaultHandlerForURLScheme.
    // This API is deprecated by Apple but still works on
    // current macOS, and the modern replacement
    // (NSWorkspace.setDefaultApplication) is async-only and
    // unreliable from a CLI context. Falls back gracefully if
    // swift isn't installed.
    let swift_src = r#"
import Foundation
import CoreServices
LSSetDefaultHandlerForURLScheme("drift" as CFString, "app.drift.urlhandler" as CFString)
"#;
    let swift_status = std::process::Command::new("/usr/bin/swift")
        .arg("-e")
        .arg(swift_src)
        .status();
    match swift_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!(
                "warning: setting default handler returned {} — \
                 you may need to pick DriftURLHandler manually the first time \
                 macOS prompts for a drift:// app",
                s
            );
        }
        Err(_) => {
            eprintln!(
                "note: /usr/bin/swift not found — drift:// is registered as \
                 *a* handler but not the default. Install Xcode CLI tools and \
                 re-run install-handler, or pick DriftURLHandler manually \
                 the first time macOS prompts."
            );
        }
    }

    println!("installed: {}", app.display());
    println!("clicking a drift:// link should now run drift-http open");
    Ok(())
}

/// Returns a temp directory under the user's home for staging
/// the AppleScript source. `std::env::temp_dir()` would also
/// work but `osacompile` occasionally chokes on `/var/folders`
/// path lengths.
#[cfg(target_os = "macos")]
fn tempdir_in_apps() -> Result<std::path::PathBuf> {
    let dir = dirs::cache_dir()
        .ok_or_else(|| anyhow!("no cache dir"))?
        .join("drift-http")
        .join("install");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(target_os = "macos")]
fn plistbuddy(pb: &str, plist: &str, op: &str) -> Result<()> {
    let status = std::process::Command::new(pb)
        .arg("-c")
        .arg(op)
        .arg(plist)
        .status()
        .with_context(|| format!("running {}", pb))?;
    if !status.success() {
        return Err(anyhow!("PlistBuddy `{}` returned {}", op, status));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_handler_linux(exe: &std::path::Path, dry_run: bool) -> Result<()> {
    // Linux uses the freedesktop.org spec: a .desktop file in
    // `~/.local/share/applications/` plus an xdg-mime call to
    // mark it as the default handler for the `x-scheme-handler/drift`
    // pseudo-MIME-type.
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?;
    let apps_dir = home.join(".local/share/applications");
    let desktop = apps_dir.join("drift-url-handler.desktop");

    let contents = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=DRIFT URL Handler\n\
         Comment=Opens drift:// URLs via drift-http\n\
         Exec={} open %u\n\
         Terminal=false\n\
         NoDisplay=true\n\
         MimeType=x-scheme-handler/drift;\n",
        exe.display()
    );

    if dry_run {
        println!("[dry-run] would write {}", desktop.display());
        println!("[dry-run] contents:\n{}", contents);
        println!("[dry-run] would run: xdg-mime default drift-url-handler.desktop x-scheme-handler/drift");
        return Ok(());
    }

    std::fs::create_dir_all(&apps_dir)
        .with_context(|| format!("creating {}", apps_dir.display()))?;
    std::fs::write(&desktop, contents).context("writing .desktop file")?;

    let status = std::process::Command::new("xdg-mime")
        .args([
            "default",
            "drift-url-handler.desktop",
            "x-scheme-handler/drift",
        ])
        .status()
        .context("running xdg-mime")?;
    if !status.success() {
        eprintln!(
            "warning: xdg-mime exited with status {} — install file written but \
             scheme not registered as default; run manually: \
             `xdg-mime default drift-url-handler.desktop x-scheme-handler/drift`",
            status
        );
    }

    println!("installed: {}", desktop.display());
    println!("clicking a drift:// link should now run drift-http open");
    Ok(())
}


//! `drift-vpn install` / `uninstall` — service-unit installer.
//!
//! Generates a platform-appropriate service unit (systemd on
//! Linux, launchd on macOS) for running `drift-vpn up` as a
//! managed system service, then installs / enables / starts it
//! through the OS's native tooling. Uninstall reverses the steps.
//!
//! Why this exists: every drift-vpn-vs-WireGuard comparison ends
//! with "and now I have to write a systemd unit by hand". This
//! removes that step. The unit it writes is also a useful
//! reference if a user wants to customize and own it themselves.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

/// Inputs to the installer. The same struct serves Linux and
/// macOS so the CLI surface is unified; per-platform code reads
/// only the fields it needs.
pub struct InstallOpts {
    /// Path to the config file the service will read on startup.
    pub config: PathBuf,
    /// Path to the drift-vpn binary the service will exec.
    pub binary: PathBuf,
    /// Service name. Linux: `drift-vpn` → `drift-vpn.service`.
    /// macOS: `drift-vpn` → `com.drift.vpn.plist` (we map
    /// service-name → reverse-DNS label deterministically).
    pub service_name: String,
    /// Don't enable for boot — install the unit, don't enable it.
    pub no_enable: bool,
    /// Start the service immediately after install.
    pub start: bool,
    /// Print the unit and exit; don't touch the filesystem or
    /// invoke systemctl/launchctl.
    pub dry_run: bool,
}

pub struct UninstallOpts {
    pub service_name: String,
    /// Print the actions and exit; don't touch the filesystem or
    /// invoke systemctl/launchctl.
    pub dry_run: bool,
}

// ─── Public entry points ──────────────────────────────────────────

pub async fn install(opts: InstallOpts) -> Result<()> {
    if !opts.binary.exists() {
        bail!(
            "drift-vpn binary not found at {}. Pass --binary <path> if it lives \
             elsewhere, or build + copy first (`cargo build --release -p drift-vpn && \
             sudo cp target/release/drift-vpn /usr/local/bin/`)",
            opts.binary.display()
        );
    }
    if !opts.binary.is_absolute() {
        bail!(
            "--binary must be an absolute path so the service unit can find it \
             from any working directory (got {})",
            opts.binary.display()
        );
    }

    #[cfg(target_os = "linux")]
    return install_linux(opts).await;
    #[cfg(target_os = "macos")]
    return install_macos(opts).await;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = opts;
        bail!(
            "drift-vpn install is supported on Linux (systemd) and macOS (launchd) \
             today. Other platforms must run `drift-vpn up` manually or through their \
             own service manager."
        );
    }
}

pub async fn uninstall(opts: UninstallOpts) -> Result<()> {
    #[cfg(target_os = "linux")]
    return uninstall_linux(opts).await;
    #[cfg(target_os = "macos")]
    return uninstall_macos(opts).await;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = opts;
        bail!("drift-vpn uninstall is supported on Linux and macOS today.");
    }
}

// ─── Linux (systemd) ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn install_linux(opts: InstallOpts) -> Result<()> {
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{}.service", opts.service_name));
    let unit = render_systemd_unit(&opts);

    if opts.dry_run {
        println!("# would write {} (dry-run)", unit_path.display());
        println!("{}", unit);
        println!();
        println!("# would run:");
        println!("#   systemctl daemon-reload");
        if !opts.no_enable {
            println!("#   systemctl enable {}", opts.service_name);
        }
        if opts.start {
            println!("#   systemctl start {}", opts.service_name);
        }
        return Ok(());
    }

    require_root_linux()?;
    write_unit_file(&unit_path, &unit).await?;
    println!("wrote {}", unit_path.display());

    run_cmd("systemctl", &["daemon-reload"]).await?;
    println!("ran: systemctl daemon-reload");

    if !opts.no_enable {
        run_cmd("systemctl", &["enable", &opts.service_name]).await?;
        println!("ran: systemctl enable {}", opts.service_name);
    } else {
        println!("(not enabling; pass --no-enable to skip on purpose)");
    }

    if opts.start {
        run_cmd("systemctl", &["start", &opts.service_name]).await?;
        println!("ran: systemctl start {}", opts.service_name);
        println!();
        println!("Check status with: systemctl status {}", opts.service_name);
        println!("Tail logs with:    journalctl -u {} -f", opts.service_name);
    } else {
        println!();
        println!(
            "Service installed. Start it with: sudo systemctl start {}",
            opts.service_name
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn uninstall_linux(opts: UninstallOpts) -> Result<()> {
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{}.service", opts.service_name));

    if opts.dry_run {
        println!("# would run:");
        println!("#   systemctl stop {}", opts.service_name);
        println!("#   systemctl disable {}", opts.service_name);
        println!("#   rm {}", unit_path.display());
        println!("#   systemctl daemon-reload");
        return Ok(());
    }

    require_root_linux()?;

    // Stop and disable are best-effort — the service may not be
    // running or may already be disabled. Either is fine for
    // uninstall.
    let _ = run_cmd_allow_fail("systemctl", &["stop", &opts.service_name]).await;
    println!("ran: systemctl stop {} (best effort)", opts.service_name);
    let _ = run_cmd_allow_fail("systemctl", &["disable", &opts.service_name]).await;
    println!("ran: systemctl disable {} (best effort)", opts.service_name);

    if unit_path.exists() {
        tokio::fs::remove_file(&unit_path)
            .await
            .with_context(|| format!("removing {}", unit_path.display()))?;
        println!("removed {}", unit_path.display());
    } else {
        println!("{} already absent", unit_path.display());
    }
    run_cmd("systemctl", &["daemon-reload"]).await?;
    println!("ran: systemctl daemon-reload");
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_systemd_unit(opts: &InstallOpts) -> String {
    // Hardening notes:
    //   - AmbientCapabilities=CAP_NET_ADMIN lets us create TUN
    //     devices and configure routes without running as full
    //     root if a future drop-privs version wants to.
    //   - We still launch as root by default because the daemon
    //     does a sysctl probe + opens /dev/net/tun before any
    //     drop. CAP_NET_ADMIN is set as the *boundary* so even
    //     compromised code can't grab unrelated caps.
    //   - ProtectSystem=strict makes /usr, /boot, /etc read-only.
    //     ReadWritePaths exposes /run/drift-vpn for the status
    //     socket dir.
    //   - PrivateTmp + ProtectHome harden filesystem access.
    //   - Restart=on-failure with 5s backoff matches WireGuard's
    //     wg-quick@.service expectations.
    format!(
        r#"# Generated by `drift-vpn install` on {date}.
# Edit at /etc/systemd/system/{name}.service; reload with
# `sudo systemctl daemon-reload` after changes.

[Unit]
Description=DRIFT VPN — identity-routed multi-transport VPN
Documentation=https://github.com/FancyWaifu/drift
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} up --config {cfg}
Restart=on-failure
RestartSec=5s

# Run as root by default — the daemon needs to create a TUN
# device and (optionally) flip sysctl net.ipv4.ip_forward for
# hub roles. To drop privileges, set User=/Group= and grant
# CAP_NET_ADMIN to the binary with `setcap`.

AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

# Sandbox the daemon's filesystem view. /run/drift-vpn must be
# writable for the status socket; everything else is read-only.
ProtectSystem=strict
ReadWritePaths=/run/drift-vpn
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Standard journal logging — `journalctl -u {name} -f` to tail.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        date = chrono_iso_date(),
        name = opts.service_name,
        bin = opts.binary.display(),
        cfg = opts.config.display(),
    )
}

#[cfg(target_os = "linux")]
fn require_root_linux() -> Result<()> {
    // SAFETY: geteuid is always safe; reads a process-local int.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!(
            "drift-vpn install needs root to write /etc/systemd/system/ and to \
             invoke systemctl. Re-run with sudo. (uid={})",
            uid
        );
    }
    Ok(())
}

// ─── macOS (launchd) ──────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn install_macos(opts: InstallOpts) -> Result<()> {
    let label = launchd_label(&opts.service_name);
    let plist_path = PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", label));
    let plist = render_launchd_plist(&opts, &label);

    if opts.dry_run {
        println!("# would write {} (dry-run)", plist_path.display());
        println!("{}", plist);
        println!();
        println!("# would run:");
        println!("#   launchctl bootstrap system {}", plist_path.display());
        if !opts.no_enable {
            println!("#   launchctl enable system/{}", label);
        }
        if opts.start {
            println!("#   launchctl kickstart -k system/{}", label);
        }
        return Ok(());
    }

    require_root_macos()?;
    write_unit_file(&plist_path, &plist).await?;
    // launchd is strict about plist ownership / permissions.
    set_root_owned_644(&plist_path).await?;
    println!("wrote {}", plist_path.display());

    // `bootstrap` loads + (by default) immediately enables. Use it
    // even when --no-enable is set; pair with `disable` afterward
    // to honor the user's intent.
    run_cmd(
        "launchctl",
        &["bootstrap", "system", &plist_path.to_string_lossy()],
    )
    .await?;
    println!("ran: launchctl bootstrap system {}", plist_path.display());

    if opts.no_enable {
        run_cmd("launchctl", &["disable", &format!("system/{}", label)]).await?;
        println!("ran: launchctl disable system/{}", label);
    }

    if opts.start {
        run_cmd(
            "launchctl",
            &["kickstart", "-k", &format!("system/{}", label)],
        )
        .await?;
        println!("ran: launchctl kickstart -k system/{}", label);
        println!();
        println!("Logs at: /var/log/drift-vpn.log + /var/log/drift-vpn.err");
    } else {
        println!();
        println!(
            "Service installed. Start it with: sudo launchctl kickstart -k system/{}",
            label
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn uninstall_macos(opts: UninstallOpts) -> Result<()> {
    let label = launchd_label(&opts.service_name);
    let plist_path = PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", label));

    if opts.dry_run {
        println!("# would run:");
        println!("#   launchctl bootout system/{}", label);
        println!("#   rm {}", plist_path.display());
        return Ok(());
    }

    require_root_macos()?;
    let _ = run_cmd_allow_fail("launchctl", &["bootout", &format!("system/{}", label)]).await;
    println!("ran: launchctl bootout system/{} (best effort)", label);

    if plist_path.exists() {
        tokio::fs::remove_file(&plist_path)
            .await
            .with_context(|| format!("removing {}", plist_path.display()))?;
        println!("removed {}", plist_path.display());
    } else {
        println!("{} already absent", plist_path.display());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn render_launchd_plist(opts: &InstallOpts, label: &str) -> String {
    // RunAtLoad=true → start on bootstrap. KeepAlive=true → restart
    // on exit. StandardOut/ErrPath → simple file logging (launchd
    // doesn't have journal). EnvironmentVariables sets the log
    // filter so the user can override at install time later.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>up</string>
        <string>--config</string>
        <string>{cfg}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/drift-vpn.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/drift-vpn.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>drift_vpn=info,drift=warn</string>
    </dict>
</dict>
</plist>
"#,
        label = label,
        bin = opts.binary.display(),
        cfg = opts.config.display(),
    )
}

#[cfg(target_os = "macos")]
fn launchd_label(service_name: &str) -> String {
    // Map `drift-vpn` → `com.drift.vpn`. Custom names get a
    // `com.drift.` prefix to keep launchd happy with reverse-DNS.
    if service_name == "drift-vpn" {
        "com.drift.vpn".to_string()
    } else {
        format!("com.drift.{}", service_name.replace('-', "."))
    }
}

#[cfg(target_os = "macos")]
fn require_root_macos() -> Result<()> {
    // SAFETY: geteuid is always safe.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!(
            "drift-vpn install needs root to write /Library/LaunchDaemons/ and \
             to invoke launchctl. Re-run with sudo. (uid={})",
            uid
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn set_root_owned_644(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = tokio::fs::metadata(path).await?;
    let mut perms = meta.permissions();
    perms.set_mode(0o644);
    tokio::fs::set_permissions(path, perms).await?;
    // chown root:wheel — done via libc::chown since std doesn't
    // expose it ergonomically.
    let c_path =
        std::ffi::CString::new(path.to_string_lossy().as_bytes()).context("path → CString")?;
    // SAFETY: ptr is a valid CString, ids are valid.
    let rc = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        bail!("chown root:wheel {} failed: {}", path.display(), e);
    }
    Ok(())
}

// ─── Shared helpers ───────────────────────────────────────────────

async fn write_unit_file(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    tokio::fs::write(path, body)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

async fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("spawning {} {:?}", prog, args))?;
    if !status.success() {
        return Err(anyhow!(
            "{} {:?} exited with {} — see above for details",
            prog,
            args,
            status
        ));
    }
    Ok(())
}

async fn run_cmd_allow_fail(prog: &str, args: &[&str]) -> Result<()> {
    // Used for uninstall: stop / disable / bootout can all fail
    // legitimately (service not running, already disabled). We
    // still want to attempt them so they're idempotent.
    let _ = Command::new(prog)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(())
}

/// Returns the date as "YYYY-MM-DD" using the system clock. We
/// avoid pulling in `chrono` for a single date string.
#[cfg(target_os = "linux")]
fn chrono_iso_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Days since 1970-01-01 (UTC), Howard Hinnant's algorithm.
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Howard Hinnant's "Civil from days" algorithm. Returns the
/// (year, month, day) for a count of days since 1970-01-01.
#[cfg(target_os = "linux")]
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn iso_date_is_well_formed() {
        let s = chrono_iso_date();
        // YYYY-MM-DD with sane components.
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 3, "got {}", s);
        let y: i32 = parts[0].parse().unwrap();
        let m: u32 = parts[1].parse().unwrap();
        let d: u32 = parts[2].parse().unwrap();
        assert!((2024..=2100).contains(&y), "year out of range: {}", y);
        assert!((1..=12).contains(&m), "month: {}", m);
        assert!((1..=31).contains(&d), "day: {}", d);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_unit_contains_required_directives() {
        let opts = InstallOpts {
            config: PathBuf::from("/etc/drift-vpn/config.toml"),
            binary: PathBuf::from("/usr/local/bin/drift-vpn"),
            service_name: "drift-vpn".to_string(),
            no_enable: false,
            start: false,
            dry_run: true,
        };
        let unit = render_systemd_unit(&opts);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit
            .contains("ExecStart=/usr/local/bin/drift-vpn up --config /etc/drift-vpn/config.toml"));
        assert!(unit.contains("CAP_NET_ADMIN"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_contains_required_keys() {
        let opts = InstallOpts {
            config: PathBuf::from("/etc/drift-vpn/config.toml"),
            binary: PathBuf::from("/usr/local/bin/drift-vpn"),
            service_name: "drift-vpn".to_string(),
            no_enable: false,
            start: false,
            dry_run: true,
        };
        let label = launchd_label(&opts.service_name);
        assert_eq!(label, "com.drift.vpn");
        let plist = render_launchd_plist(&opts, &label);
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.drift.vpn</string>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("/usr/local/bin/drift-vpn"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_label_mapping() {
        assert_eq!(launchd_label("drift-vpn"), "com.drift.vpn");
        assert_eq!(launchd_label("my-vpn"), "com.drift.my.vpn");
    }
}

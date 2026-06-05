//! Embed the current git commit short SHA and UTC build date as
//! compile-time env vars. Surfaced via `drift-vpn --version` so
//! operators can tell whether a deployed binary matches a known
//! main-branch commit. Both lookups are best-effort: on a tarball
//! build with no `.git`, we fall back to `unknown` / `unknown`,
//! and the version output prints just the crate version.

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    // Reflect a dirty working tree so `--version` makes it obvious
    // when a local build doesn't correspond to the published SHA.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let sha = if dirty && sha != "unknown" {
        format!("{}-dirty", sha)
    } else {
        sha
    };

    // UTC build date in YYYY-MM-DD form via `date -u +%Y-%m-%d`
    // (POSIX-portable; macOS + Linux + BSD all support it).
    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=DRIFT_VPN_GIT_SHA={}", sha);
    println!("cargo:rustc-env=DRIFT_VPN_BUILD_DATE={}", date);

    // Re-run when the HEAD changes (which moves on commits) or
    // when the index changes (which moves on add/reset).
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
}

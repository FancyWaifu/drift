//! Locate, read, write `drift.toml`. Default paths:
//!
//! - **As root**: `/etc/drift/drift.toml` (system-wide). Identity
//!   files default to `/etc/drift/identity.key`.
//! - **As a regular user**: `$XDG_CONFIG_HOME/drift/drift.toml`
//!   (Linux) / `~/Library/Application Support/drift/drift.toml`
//!   (macOS). Identity at `<dir>/identity.key`.
//!
//! Override via `--config <path>`. Same conventions as drift-vpn
//! and the `drift` CLI's contacts file, so a single host's
//! tools agree on where the inventory lives.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use crate::schema::DriftToml;

/// Standard filename inside the drift config dir.
pub const FILENAME: &str = "drift.toml";

/// Default identity key location. Same shape as drift-vpn's
/// `--identity` default.
pub const IDENTITY_FILENAME: &str = "identity.key";

/// Resolve the default config dir for the current uid.
///
/// As root → `/etc/drift`. Otherwise the OS-appropriate user
/// config dir (Linux: `$XDG_CONFIG_HOME/drift`, macOS:
/// `~/Library/Application Support/drift`).
pub fn default_dir() -> Result<PathBuf> {
    if is_root() {
        Ok(PathBuf::from("/etc/drift"))
    } else {
        let base =
            dirs::config_dir().ok_or_else(|| anyhow!("could not resolve user config dir"))?;
        Ok(base.join("drift"))
    }
}

/// Default `drift.toml` path: `<default_dir>/drift.toml`.
pub fn default_path() -> Result<PathBuf> {
    Ok(default_dir()?.join(FILENAME))
}

/// Default identity-key path: `<default_dir>/identity.key`.
pub fn default_identity_path() -> Result<PathBuf> {
    Ok(default_dir()?.join(IDENTITY_FILENAME))
}

#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: `geteuid()` has no preconditions and never fails.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Parse a `drift.toml` from `path`. Returns the deserialized
/// schema; missing file is an error (callers that want
/// "load-or-default" use `read_or_default`).
pub fn read(path: &Path) -> Result<DriftToml> {
    let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: DriftToml =
        toml::from_str(&s).with_context(|| format!("parse {}", path.display()))?;
    Ok(parsed)
}

/// Read if exists, return `Default` otherwise. Used by mutating
/// commands so `peer add` works even before `init`.
pub fn read_or_default(path: &Path) -> Result<DriftToml> {
    if path.exists() {
        read(path)
    } else {
        Ok(DriftToml::default())
    }
}

/// Serialize and write atomically (write-then-rename). Creates
/// parent directories if needed; chmod 0600 on the saved file
/// (same convention as identity keys and the contacts file).
pub fn write(path: &Path, doc: &DriftToml) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(doc).context("serialize drift.toml")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms).ok();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// 32-byte X25519 secret stored as 64 hex chars (with optional
/// surrounding whitespace). Same on-disk format `drift-vpn
/// keygen` writes, so a single file works for both tools.
pub fn read_identity(path: &Path) -> Result<[u8; 32]> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read identity {}", path.display()))?;
    let trimmed = body.trim();
    let bytes = hex::decode(trimmed)
        .with_context(|| format!("identity {} is not valid hex", path.display()))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "identity {} must be 32 bytes (64 hex chars), got {}",
            path.display(),
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn write_identity(path: &Path, secret: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    let secret_hex = hex::encode(secret);
    std::fs::write(path, format!("{}\n", secret_hex))
        .with_context(|| format!("write identity {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).ok();
    }
    Ok(())
}

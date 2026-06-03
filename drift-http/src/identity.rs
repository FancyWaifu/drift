//! Shared persistent identity for DRIFT-based tools.
//!
//! Stored as 32 hex-encoded bytes at:
//!   - Linux:   `~/.config/drift/identity.key`
//!   - macOS:   `~/Library/Application Support/drift/identity.key`
//!   - Windows: `%APPDATA%\drift\identity.key`
//!
//! Why a shared file? Friends pin one pubkey across every DRIFT
//! tool you run — adding a friend to drift-mosh and drift-http is
//! one paste, not two.
//!
//! On unix the file is written mode 0600, same posture OpenSSH
//! takes for `~/.ssh/id_ed25519`.

use anyhow::{Context, Result};
use drift::identity::Identity;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

/// Default config directory for shared DRIFT state.
pub(crate) fn config_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("could not locate the user config directory")?
        .join("drift"))
}

/// Default location for the shared identity key.
pub fn default_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("identity.key"))
}

/// Load the persistent identity from `path`. If the file is
/// missing, generates a fresh 32-byte X25519 secret and writes
/// it (mode 0600) before returning.
pub fn load_or_create(path: &PathBuf) -> Result<Identity> {
    if path.exists() {
        let hex_str =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let bytes = hex::decode(hex_str.trim())
            .with_context(|| format!("{} is not valid hex", path.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!("{} must be 32 bytes; got {}", path.display(), bytes.len());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Identity::from_secret_bytes(seed))
    } else {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let hex_key: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
        write_file_secure(path, &hex_key)?;
        Ok(Identity::from_secret_bytes(seed))
    }
}

/// Convenience: load (or create) at the default path.
#[allow(dead_code)]
pub(crate) fn load_default() -> Result<Identity> {
    load_or_create(&default_path()?)
}

fn write_file_secure(path: &PathBuf, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perm)
            .with_context(|| format!("setting perms on {}", path.display()))?;
    }
    Ok(())
}

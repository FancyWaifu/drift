//! Persistent client identity.
//!
//! The client key is a 32-byte X25519 secret stored at
//! `$CONFIG_DIR/drift-mosh/client.key`. It's identical in
//! spirit to `~/.ssh/id_ed25519` — the user has one durable
//! identity that servers can recognize across reconnects.
//!
//! Why persistent? So reattach actually works. The server
//! identifies a reconnecting client by pubkey, not by address
//! or session cookie. If we generated a fresh key on every
//! run, every reconnect would look like a new user to the
//! server, and the reattach path would never fire.
//!
//! Security: the file is written mode 0600 (user-readable
//! only). Same precaution OpenSSH takes for private keys.

use anyhow::{Context, Result};
use drift::identity::Identity;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

use crate::config::Config;

pub struct ClientKey;

impl ClientKey {
    pub fn path() -> Result<PathBuf> {
        Ok(Config::config_dir()?.join("client.key"))
    }

    /// Load the client identity from disk. If the file doesn't
    /// exist, generates a fresh identity and persists it.
    pub fn load_or_create() -> Result<Identity> {
        let path = Self::path()?;
        if path.exists() {
            let hex_str = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let bytes = hex::decode(hex_str.trim())
                .with_context(|| format!("{} is not valid hex", path.display()))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "{} must be 32 bytes; got {}",
                    path.display(),
                    bytes.len()
                );
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Identity::from_secret_bytes(seed))
        } else {
            // Fresh key, persisted.
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let hex_key: String = seed.iter().map(|b| format!("{:02x}", b)).collect();
            write_file_secure(&path, &hex_key)?;
            Ok(Identity::from_secret_bytes(seed))
        }
    }
}

/// Write the file with restrictive permissions (0600 on unix).
/// On Windows we just write normally — ACL enforcement there
/// is a whole other story and out of scope for now.
fn write_file_secure(path: &PathBuf, contents: &str) -> Result<()> {
    fs::write(path, contents)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perm)
            .with_context(|| format!("setting perms on {}", path.display()))?;
    }
    Ok(())
}

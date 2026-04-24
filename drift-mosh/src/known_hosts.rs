//! TOFU known-hosts store, SSH-style.
//!
//! On first connect to a host the client sees a pubkey it
//! doesn't recognize → prompt the user to pin it. Subsequent
//! connects verify the pubkey matches; if it doesn't, scream
//! loudly (key-change implies MITM or rotation).
//!
//! File format at `$CONFIG_DIR/drift-mosh/known_hosts`:
//!
//! ```text
//! <hostname>:<port> <64-hex-pubkey>
//! ```
//!
//! One line per entry. Lines starting with `#` are comments.
//! Identical format philosophy to OpenSSH's known_hosts but
//! much simpler since we don't support multiple key types.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::config::Config;

/// Result of checking a host's pubkey against the store.
pub enum HostKeyStatus {
    /// Pubkey matches the one we pinned. Normal operation.
    Known,
    /// Hostname isn't in the store. First contact; caller
    /// should prompt the user to pin.
    Unknown,
    /// Pubkey for this hostname is DIFFERENT from what we
    /// pinned. Almost certainly an attack or a server
    /// migration; either way, don't silently accept.
    Changed { pinned: [u8; 32] },
}

pub struct KnownHosts {
    path: PathBuf,
    entries: HashMap<String, [u8; 32]>,
}

impl KnownHosts {
    pub fn path() -> Result<PathBuf> {
        Ok(Config::config_dir()?.join("known_hosts"))
    }

    /// Load the store. Missing file is treated as empty (fresh
    /// install, no pinned hosts yet). Malformed lines are
    /// skipped with a warning rather than failing the whole
    /// load.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let mut entries = HashMap::new();
        if path.exists() {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            for (lineno, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let mut parts = trimmed.split_whitespace();
                let host = match parts.next() {
                    Some(h) => h,
                    None => continue,
                };
                let key_hex = match parts.next() {
                    Some(k) => k,
                    None => {
                        eprintln!(
                            "known_hosts:{}: missing pubkey, skipping",
                            lineno + 1
                        );
                        continue;
                    }
                };
                let bytes = match hex::decode(key_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        eprintln!(
                            "known_hosts:{}: invalid pubkey hex, skipping",
                            lineno + 1
                        );
                        continue;
                    }
                };
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                entries.insert(host.to_string(), key);
            }
        }
        Ok(Self { path, entries })
    }

    /// Look up whether we've seen this (hostname:port) before.
    pub fn check(&self, host: &str, pubkey: &[u8; 32]) -> HostKeyStatus {
        match self.entries.get(host) {
            None => HostKeyStatus::Unknown,
            Some(pinned) if pinned == pubkey => HostKeyStatus::Known,
            Some(pinned) => HostKeyStatus::Changed { pinned: *pinned },
        }
    }

    /// Pin a new host. Overwrites any existing entry (caller
    /// should check status + prompt first).
    pub fn add(&mut self, host: &str, pubkey: [u8; 32]) -> Result<()> {
        self.entries.insert(host.to_string(), pubkey);
        self.save()
    }

    /// Persist the store. Uses an atomic write (tempfile + rename)
    /// so a crash mid-write can't corrupt the file.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            writeln!(
                f,
                "# drift-mosh known_hosts — TOFU-pinned server pubkeys."
            )?;
            writeln!(f, "# One entry per line: <host>:<port> <pubkey-hex>")?;
            for (host, key) in &self.entries {
                let hex_key: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                writeln!(f, "{} {}", host, hex_key)?;
            }
        }
        fs::rename(&tmp, &self.path).with_context(|| {
            format!("renaming {} → {}", tmp.display(), self.path.display())
        })?;
        Ok(())
    }
}

/// Prompt the user y/n; returns true on y/Y, false on
/// anything else. Used by the first-connect TOFU flow.
pub fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::BufRead;
    print!("{} ", prompt);
    std::io::stdout().flush().ok();
    let stdin = std::io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| anyhow!("stdin closed before answer"))??;
    Ok(matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes"
    ))
}

//! Local petname → pubkey address book.
//!
//! Maps human-readable names (`bob-laptop`) to DRIFT pubkeys
//! and last-known addresses. The file lives at
//! `$CONFIG_DIR/drift/contacts.toml` and is shared across
//! every DRIFT-based tool (drift-mosh, drift-http,
//! drift-wormhole, …) so a name learned by one tool can be
//! used by another.
//!
//! ## Three-layer naming model
//!
//! Following Stiegler's petname literature and the consensus
//! of every shipping P2P messenger (Signal, Briar, Cwtch,
//! Session, Matrix, GNS):
//!
//!   - **pubkey** — the cryptographic identity. Globally
//!     unique, unforgeable, immutable. The truth.
//!   - **advertised_name** — what the peer calls themselves.
//!     Hearsay; recorded for display but never the resolution
//!     key. Two different peers may advertise the same name.
//!   - **assigned_name** (the petname) — the name THIS user
//!     types to reach the contact. Locally unique, chosen by
//!     auto-disambiguation when collisions occur, can be
//!     changed by the user with `drift contacts rename`.
//!
//! ## Auto-disambiguation policy
//!
//! When a peer with a *new* pubkey advertises a name already
//! claimed by an existing contact, we never silently rebind
//! the petname (impersonation prevention). Instead we suffix
//! `-2`, `-3`, etc. until we find an unused petname. Tailscale
//! does the same for tailnet device names. The receiving user
//! can rename later with `drift contacts rename`.
//!
//! ## Pubkey-stability invariant
//!
//! `assigned_name → pubkey` is a 1:1 mapping in this user's
//! address book. We never silently change a petname's pubkey
//! out from under the user — same TOFU rule SSH applies to
//! `~/.ssh/known_hosts`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// One address-book entry.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Contact {
    /// Petname — the name THIS user types to reach this peer.
    /// Locally unique within the contacts file. Auto-suffixed
    /// on collision (`bob-laptop`, `bob-laptop-2`, …).
    pub assigned_name: String,

    /// 32-byte X25519 pubkey, hex-encoded for human-friendly
    /// editing. Truth-of-identity for this contact.
    pub pubkey: String,

    /// Last-known network address. Updated on every successful
    /// `record` call so a contact whose IP changed (laptop
    /// moved networks) stays reachable. Format: standard
    /// `SocketAddr` text (e.g. `192.168.1.42:9100`).
    pub address: String,

    /// What the peer most recently said their name was.
    /// Display-only; never the resolution key.
    #[serde(default)]
    pub advertised_name: Option<String>,

    /// Unix-epoch seconds at which this contact was first
    /// added.
    pub added_at: u64,

    /// Unix-epoch seconds of the last successful contact.
    pub last_seen: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct ContactsFile {
    /// Format version. Bumped when the on-disk schema changes
    /// in a way that older `drift` binaries can't parse.
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    contacts: Vec<Contact>,
}

fn default_version() -> u32 {
    1
}

/// In-memory view of the contacts file, with mutators that
/// keep `pubkey ↔ assigned_name` 1:1 and auto-disambiguate on
/// collisions.
pub struct Contacts {
    path: PathBuf,
    file: ContactsFile,
}

impl Contacts {
    /// `$CONFIG_DIR/drift/contacts.toml` — the canonical
    /// location every DRIFT tool reads/writes.
    pub fn default_path() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .context("could not locate the user config directory")?
            .join("drift")
            .join("contacts.toml"))
    }

    /// Load from the default path, creating an empty file if
    /// it doesn't exist yet.
    pub fn load_default() -> Result<Self> {
        Self::load_from(Self::default_path()?)
    }

    pub fn load_from(path: PathBuf) -> Result<Self> {
        let file = if path.exists() {
            let body = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            toml::from_str(&body)
                .with_context(|| format!("parsing {}", path.display()))?
        } else {
            ContactsFile::default()
        };
        Ok(Self { path, file })
    }

    /// Persist to disk with a "version" header so we can
    /// migrate the schema later without breaking old files.
    /// Atomic via write-to-temp + rename.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let body = toml::to_string_pretty(&self.file).context("serializing contacts")?;
        let tmp = self.path.with_extension("toml.tmp");
        fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming {} → {}", tmp.display(), self.path.display()))?;
        Ok(())
    }

    pub fn list(&self) -> &[Contact] {
        &self.file.contacts
    }

    /// Resolve a typed petname to a contact. Returns `None`
    /// if the user hasn't saved anyone under that name.
    pub fn resolve(&self, name: &str) -> Option<&Contact> {
        let target = name.strip_suffix(".drift").unwrap_or(name);
        self.file
            .contacts
            .iter()
            .find(|c| c.assigned_name == target)
    }

    /// Lookup an existing contact by pubkey.
    pub fn find_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&Contact> {
        let hex = hex_encode(pubkey);
        self.file.contacts.iter().find(|c| c.pubkey == hex)
    }

    /// Auto-add a peer or update the timestamp on an existing
    /// one. Returns the petname this peer is now stored under.
    ///
    /// Behavior:
    ///  - Pubkey already in book → update `last_seen`,
    ///    `address`, and `advertised_name`. Petname unchanged.
    ///  - New pubkey + advertised name available → assign that
    ///    name, suffixing `-N` if it collides with an existing
    ///    contact's petname.
    ///  - New pubkey + no advertised name → generate a
    ///    placeholder petname from the first 8 hex chars of
    ///    the pubkey (e.g. `peer-3e4774db`).
    pub fn record(
        &mut self,
        pubkey: [u8; 32],
        addr: SocketAddr,
        advertised_name: Option<&str>,
    ) -> Result<String> {
        let now = unix_now();
        let pub_hex = hex_encode(&pubkey);
        let addr_str = addr.to_string();

        // Existing pubkey? Refresh metadata, keep petname.
        if let Some(idx) = self
            .file
            .contacts
            .iter()
            .position(|c| c.pubkey == pub_hex)
        {
            let c = &mut self.file.contacts[idx];
            c.last_seen = now;
            c.address = addr_str;
            if let Some(n) = advertised_name {
                if !n.is_empty() {
                    c.advertised_name = Some(n.to_string());
                }
            }
            return Ok(c.assigned_name.clone());
        }

        // New peer: pick a petname.
        let base = match advertised_name {
            Some(n) if !n.is_empty() => sanitize_name(n),
            _ => format!("peer-{}", &pub_hex[..8]),
        };
        let assigned = self.disambiguate(&base);

        let entry = Contact {
            assigned_name: assigned.clone(),
            pubkey: pub_hex,
            address: addr_str,
            advertised_name: advertised_name.map(|s| s.to_string()),
            added_at: now,
            last_seen: now,
        };
        self.file.contacts.push(entry);
        Ok(assigned)
    }

    /// Manually add a contact with an explicit petname.
    /// Errors if the petname is already taken or if the
    /// pubkey is already pinned to a different petname (to
    /// preserve the 1:1 invariant).
    pub fn add_manual(
        &mut self,
        name: &str,
        pubkey: [u8; 32],
        addr: SocketAddr,
    ) -> Result<()> {
        let pub_hex = hex_encode(&pubkey);
        let name_clean = sanitize_name(name);
        if self.has_name(&name_clean) {
            return Err(anyhow!("contact name {:?} already taken", name_clean));
        }
        if let Some(existing) = self.file.contacts.iter().find(|c| c.pubkey == pub_hex) {
            return Err(anyhow!(
                "pubkey already saved as {:?}",
                existing.assigned_name
            ));
        }
        let now = unix_now();
        self.file.contacts.push(Contact {
            assigned_name: name_clean,
            pubkey: pub_hex,
            address: addr.to_string(),
            advertised_name: None,
            added_at: now,
            last_seen: now,
        });
        Ok(())
    }

    /// Rename a contact in this user's address book. Errors
    /// if `old` doesn't exist or `new` is already taken by a
    /// different contact.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        let new_clean = sanitize_name(new);
        if old == new_clean {
            return Ok(());
        }
        if self.has_name(&new_clean) {
            return Err(anyhow!("contact name {:?} already taken", new_clean));
        }
        let entry = self
            .file
            .contacts
            .iter_mut()
            .find(|c| c.assigned_name == old)
            .ok_or_else(|| anyhow!("no contact named {:?}", old))?;
        entry.assigned_name = new_clean;
        Ok(())
    }

    pub fn forget(&mut self, name: &str) -> Result<()> {
        let before = self.file.contacts.len();
        self.file.contacts.retain(|c| c.assigned_name != name);
        if self.file.contacts.len() == before {
            return Err(anyhow!("no contact named {:?}", name));
        }
        Ok(())
    }

    fn has_name(&self, name: &str) -> bool {
        self.file.contacts.iter().any(|c| c.assigned_name == name)
    }

    fn disambiguate(&self, base: &str) -> String {
        if !self.has_name(base) {
            return base.to_string();
        }
        for n in 2u32..=u32::MAX {
            let candidate = format!("{}-{}", base, n);
            if !self.has_name(&candidate) {
                return candidate;
            }
        }
        unreachable!("u32 exhausted picking a petname suffix")
    }
}

// ─── Self-name (what THIS user advertises to peers) ──────────

/// Read/write the user's self-advertised name. Stored at
/// `$CONFIG_DIR/drift/self-name`. Tools that want to advertise
/// a name to peers (drift-mosh-server, drift-http serve, …)
/// read this on startup unless overridden by `--name`.
pub mod self_name {
    use super::*;

    pub fn default_path() -> Result<PathBuf> {
        Ok(dirs::config_dir()
            .context("no config dir")?
            .join("drift")
            .join("self-name"))
    }

    pub fn load() -> Result<Option<String>> {
        let p = default_path()?;
        if !p.exists() {
            return Ok(None);
        }
        let s = fs::read_to_string(&p)
            .with_context(|| format!("reading {}", p.display()))?;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
    }

    pub fn set(name: &str) -> Result<()> {
        let p = default_path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, name)?;
        Ok(())
    }

    pub fn clear() -> Result<()> {
        let p = default_path()?;
        if p.exists() {
            fs::remove_file(p)?;
        }
        Ok(())
    }
}

// ─── helpers ─────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Strip whitespace, lowercase, replace illegal chars. Petnames
/// should be filename-safe and shell-safe so users can paste
/// them anywhere.
fn sanitize_name(raw: &str) -> String {
    let raw = raw.trim();
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c.to_ascii_lowercase());
        } else if c.is_whitespace() {
            out.push('-');
        }
        // drop everything else
    }
    if out.is_empty() {
        return "peer".to_string();
    }
    out
}

/// Decode a 64-char hex pubkey into a 32-byte array.
pub fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("pubkey is not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "pubkey must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ─── tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pk(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn fresh() -> (TempDir, Contacts) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("contacts.toml");
        let c = Contacts::load_from(path).unwrap();
        (dir, c)
    }

    #[test]
    fn record_new_peer_with_advertised_name() {
        let (_d, mut c) = fresh();
        let n = c
            .record(pk(1), "1.2.3.4:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        assert_eq!(n, "laptop");
        assert!(c.resolve("laptop").is_some());
    }

    #[test]
    fn record_two_peers_same_name_disambiguates() {
        let (_d, mut c) = fresh();
        let a = c
            .record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        let b = c
            .record(pk(2), "2.2.2.2:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        assert_eq!(a, "laptop");
        assert_eq!(b, "laptop-2");

        // Third collision keeps suffixing.
        let c3 = c
            .record(pk(3), "3.3.3.3:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        assert_eq!(c3, "laptop-3");
    }

    #[test]
    fn record_same_pubkey_twice_keeps_petname_updates_metadata() {
        let (_d, mut c) = fresh();
        let n1 = c
            .record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        let n2 = c
            .record(pk(1), "5.5.5.5:9000".parse().unwrap(), Some("laptop"))
            .unwrap();
        assert_eq!(n1, n2);
        let entry = c.resolve("laptop").unwrap();
        assert_eq!(entry.address, "5.5.5.5:9000"); // updated
    }

    #[test]
    fn record_no_advertised_name_uses_pubkey_prefix() {
        let (_d, mut c) = fresh();
        let n = c
            .record(pk(0xAB), "1.1.1.1:9000".parse().unwrap(), None)
            .unwrap();
        assert!(n.starts_with("peer-"));
        assert_eq!(n.len(), "peer-".len() + 8);
    }

    #[test]
    fn rename_is_user_driven() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
        c.rename("laptop", "alice-laptop").unwrap();
        assert!(c.resolve("laptop").is_none());
        assert!(c.resolve("alice-laptop").is_some());
    }

    #[test]
    fn rename_to_taken_name_errors() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("alice")).unwrap();
        c.record(pk(2), "2.2.2.2:9000".parse().unwrap(), Some("bob")).unwrap();
        let err = c.rename("alice", "bob").unwrap_err();
        assert!(err.to_string().contains("already taken"));
    }

    #[test]
    fn forget_removes_entry() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
        c.forget("laptop").unwrap();
        assert!(c.resolve("laptop").is_none());
    }

    #[test]
    fn save_and_reload_roundtrips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("contacts.toml");
        {
            let mut c = Contacts::load_from(path.clone()).unwrap();
            c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
            c.record(pk(2), "2.2.2.2:9000".parse().unwrap(), Some("laptop")).unwrap();
            c.save().unwrap();
        }
        let c2 = Contacts::load_from(path).unwrap();
        assert!(c2.resolve("laptop").is_some());
        assert!(c2.resolve("laptop-2").is_some());
    }

    #[test]
    fn drift_suffix_strips_in_resolve() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
        assert!(c.resolve("laptop.drift").is_some());
        assert!(c.resolve("laptop").is_some());
    }

    #[test]
    fn add_manual_rejects_taken_name() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
        let err = c
            .add_manual("laptop", pk(2), "2.2.2.2:9000".parse().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("already taken"));
    }

    #[test]
    fn add_manual_rejects_existing_pubkey() {
        let (_d, mut c) = fresh();
        c.record(pk(1), "1.1.1.1:9000".parse().unwrap(), Some("laptop")).unwrap();
        let err = c
            .add_manual("alice-laptop", pk(1), "9.9.9.9:9000".parse().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("already saved"));
    }

    #[test]
    fn sanitize_name_lowercases_and_trims() {
        assert_eq!(sanitize_name("  Hello World "), "hello-world");
        assert_eq!(sanitize_name("abc/def"), "abcdef");
        assert_eq!(sanitize_name(""), "peer");
    }
}

//! `drift-vpn rotate` / `rotate-verify` — owner-driven identity
//! rotation CLI.
//!
//! Phase-1 implementation: generates a new keypair, signs a
//! `RotationAnnounce` with the OLD secret, writes both to disk.
//! Distributing the announce to peers and acceptance on the peer
//! side are out-of-band for now (covered by phase-2 follow-ups —
//! see drift-vpn/ROTATION.md).
//!
//! See `drift-core::rotation` for the protocol details and threat
//! model. The TL;DR: this command answers "I have my current
//! identity file and want to retire it for a fresh one, and have my
//! peers learn about the switch without me re-pasting hex into
//! every config file by hand."

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use drift_core::rotation::{
    self, RotationAnnounce, ROTATION_ANNOUNCE_LEN, ROTATION_FRESHNESS_WINDOW_MS,
};
use rand::RngCore;

/// Inputs for `drift-vpn rotate`.
pub struct RotateOpts {
    /// Path to the existing identity file. Will be left alone —
    /// the old secret is loaded, the announce is signed with it,
    /// but the file isn't modified. The user explicitly archives or
    /// removes it after they've shipped the rotation.
    pub r#in: PathBuf,
    /// Path to write the new identity file. Must not exist (we
    /// won't overwrite). Mode set to 0600 on Unix.
    pub out: PathBuf,
    /// Path to write the signed announce blob (hex). If `None`,
    /// the blob is printed to stdout instead.
    pub announce_out: Option<PathBuf>,
}

/// Inputs for `drift-vpn rotate-verify`.
pub struct RotateVerifyOpts {
    /// The announce blob — hex string or path to a file holding it.
    /// We accept both because the natural distribution channel
    /// (email, signal, paste) sometimes hands you the raw hex and
    /// sometimes a file attachment.
    pub announce: String,
    /// The expected pubkey hex of the peer whose identity is
    /// rotating. The verify step rejects the announce if its
    /// embedded `old_pub` doesn't match — even if the signature
    /// would otherwise be valid against the embedded pubkey.
    pub expect_old_pub: String,
}

pub async fn rotate(opts: RotateOpts) -> Result<()> {
    if opts.out.exists() {
        bail!(
            "--out path {} already exists. Refusing to overwrite — \
             remove or rename it first.",
            opts.out.display()
        );
    }

    let (old_secret, old_pub) = load_secret_and_pub(&opts.r#in).await?;

    // Generate the new keypair.
    let mut new_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut new_secret);
    let new_pub = derive_pub(&new_secret);

    // Sign the announce with the OLD secret. The CSPRNG inputs
    // here are independent of the new secret material — none of
    // these bytes leak through to the actual rotation, just into
    // the signature.
    let issued_at_ms = now_unix_ms();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut xn = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut xn);

    let announce = rotation::build(&old_secret, &new_pub, issued_at_ms, &nonce, &xn);
    let announce_hex = hex::encode(rotation::encode(&announce));

    // Write the new identity to disk with 0600 perms.
    write_secret_file(&opts.out, &new_secret).await?;

    // Write or print the announce.
    if let Some(path) = &opts.announce_out {
        tokio::fs::write(path, format!("{}\n", announce_hex))
            .await
            .with_context(|| format!("writing announce to {}", path.display()))?;
        eprintln!("wrote announce to {}", path.display());
    }

    eprintln!("wrote new secret to {}", opts.out.display());
    eprintln!("old pubkey: {}", hex::encode(old_pub));
    eprintln!("new pubkey: {}", hex::encode(new_pub));
    eprintln!("issued_at_ms: {}", issued_at_ms);
    eprintln!();
    eprintln!("Distribute the announce blob below to every peer over a channel");
    eprintln!("you trust. Each peer runs:");
    eprintln!();
    eprintln!(
        "    drift-vpn rotate-verify --expect-old-pub {} \\",
        hex::encode(old_pub)
    );
    eprintln!("        --announce <blob>");
    eprintln!();
    eprintln!("If verify succeeds, the peer replaces the old pubkey with the new one");
    eprintln!("in their drift-vpn config.toml for this peer.");
    eprintln!();
    println!("{}", announce_hex);
    Ok(())
}

pub async fn rotate_verify(opts: RotateVerifyOpts) -> Result<()> {
    let blob = load_announce_input(&opts.announce).await?;
    let bytes = hex::decode(blob.trim())
        .context("announce input is not valid hex")?;
    if bytes.len() != ROTATION_ANNOUNCE_LEN {
        bail!(
            "announce wire form is {} bytes, got {}",
            ROTATION_ANNOUNCE_LEN,
            bytes.len()
        );
    }
    let announce = rotation::decode(&bytes).map_err(|e| anyhow!("decode failed: {}", e))?;

    let mut expected = [0u8; 32];
    let raw = hex::decode(opts.expect_old_pub.trim())
        .context("expect-old-pub is not valid hex")?;
    if raw.len() != 32 {
        bail!(
            "expect-old-pub must be 32 bytes of hex (64 chars), got {} bytes",
            raw.len()
        );
    }
    expected.copy_from_slice(&raw);

    rotation::verify_against(&announce, &expected)
        .map_err(|e| anyhow!("verification failed: {}", e))?;

    // Freshness check. Reject announces too far in the past so a
    // stolen-but-old announce can't be replayed forever.
    let now = now_unix_ms();
    let age_ms = now.saturating_sub(announce.issued_at_ms);
    let future_ms = announce.issued_at_ms.saturating_sub(now);
    if age_ms > ROTATION_FRESHNESS_WINDOW_MS {
        bail!(
            "announce is {}ms old (max {}ms). Issuer should re-sign with a fresh \
             timestamp before distribution.",
            age_ms,
            ROTATION_FRESHNESS_WINDOW_MS
        );
    }
    if future_ms > ROTATION_FRESHNESS_WINDOW_MS {
        bail!(
            "announce is timestamped {}ms in the future (max {}ms tolerated). \
             Check the issuer's clock.",
            future_ms,
            ROTATION_FRESHNESS_WINDOW_MS
        );
    }

    eprintln!("Signature OK. Peer is rotating:");
    eprintln!("  from: {}", hex::encode(announce.old_pub));
    eprintln!("  to:   {}", hex::encode(announce.new_pub));
    eprintln!(
        "  issued_at_ms: {} ({}ms ago)",
        announce.issued_at_ms, age_ms
    );
    eprintln!();
    eprintln!("Update this peer's public_key in /etc/drift-vpn/config.toml:");
    eprintln!();
    println!("{}", hex::encode(announce.new_pub));
    Ok(())
}

// ─── Internal helpers ─────────────────────────────────────────────

async fn load_secret_and_pub(path: &Path) -> Result<([u8; 32], [u8; 32])> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let trimmed = body.trim();
    let raw = hex::decode(trimmed)
        .with_context(|| format!("{} is not valid hex", path.display()))?;
    if raw.len() != 32 {
        bail!(
            "identity {} must be 32 bytes (64 hex chars), got {}",
            path.display(),
            raw.len()
        );
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&raw);
    let public = derive_pub(&secret);
    Ok((secret, public))
}

fn derive_pub(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    let p = x25519_dalek::PublicKey::from(&s);
    *p.as_bytes()
}

async fn write_secret_file(path: &Path, secret: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }
    let hex_body = format!("{}\n", hex::encode(secret));
    tokio::fs::write(path, hex_body)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(path).await?.permissions();
        perms.set_mode(0o600);
        let _ = tokio::fs::set_permissions(path, perms).await;
    }
    Ok(())
}

/// Returns the contents to parse as hex. If `s` looks like an
/// existing file path, read it; otherwise treat it as the hex
/// directly. The "looks like a path" check is deliberately cheap
/// (existing on disk) — we don't try to be clever about /-prefixed
/// strings.
async fn load_announce_input(s: &str) -> Result<String> {
    let p = Path::new(s);
    if p.exists() {
        return tokio::fs::read_to_string(p)
            .await
            .with_context(|| format!("reading announce file {}", p.display()));
    }
    Ok(s.to_string())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_hex(path: &Path, bytes: &[u8]) {
        std::fs::write(path, format!("{}\n", hex::encode(bytes))).unwrap();
    }

    #[tokio::test]
    async fn rotate_and_verify_round_trip() {
        let dir = tempdir().unwrap();
        let old_path = dir.path().join("old.key");
        let new_path = dir.path().join("new.key");
        let announce_path = dir.path().join("announce.hex");

        // Write a deterministic old identity file.
        let old_secret = [0x42u8; 32];
        write_hex(&old_path, &old_secret);
        let old_pub = derive_pub(&old_secret);

        rotate(RotateOpts {
            r#in: old_path,
            out: new_path.clone(),
            announce_out: Some(announce_path.clone()),
        })
        .await
        .expect("rotate succeeds");

        // New secret file exists, parses as hex, decodes to 32 bytes.
        let new_body = std::fs::read_to_string(&new_path).unwrap();
        let new_raw = hex::decode(new_body.trim()).unwrap();
        assert_eq!(new_raw.len(), 32);
        // And isn't the same as the old.
        assert_ne!(new_raw, old_secret);

        // Verify the announce.
        rotate_verify(RotateVerifyOpts {
            announce: announce_path.to_string_lossy().to_string(),
            expect_old_pub: hex::encode(old_pub),
        })
        .await
        .expect("verify succeeds");
    }

    #[tokio::test]
    async fn rotate_refuses_to_overwrite() {
        let dir = tempdir().unwrap();
        let old_path = dir.path().join("old.key");
        let new_path = dir.path().join("new.key");
        write_hex(&old_path, &[0x11u8; 32]);
        std::fs::write(&new_path, "already-here").unwrap();

        let r = rotate(RotateOpts {
            r#in: old_path,
            out: new_path,
            announce_out: None,
        })
        .await;
        assert!(r.is_err(), "should refuse existing --out");
    }

    #[tokio::test]
    async fn verify_rejects_wrong_old_pub() {
        let dir = tempdir().unwrap();
        let old_path = dir.path().join("old.key");
        let new_path = dir.path().join("new.key");
        let announce_path = dir.path().join("announce.hex");
        write_hex(&old_path, &[0x22u8; 32]);

        rotate(RotateOpts {
            r#in: old_path,
            out: new_path,
            announce_out: Some(announce_path.clone()),
        })
        .await
        .expect("rotate");

        // Use a different pubkey for the verify.
        let bogus = derive_pub(&[0x33u8; 32]);
        let r = rotate_verify(RotateVerifyOpts {
            announce: announce_path.to_string_lossy().to_string(),
            expect_old_pub: hex::encode(bogus),
        })
        .await;
        assert!(r.is_err(), "verify must reject mismatched old_pub");
    }
}

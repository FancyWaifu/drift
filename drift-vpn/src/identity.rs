//! Identity-file loading. Format is 64 hex chars (32 bytes)
//! optionally with surrounding whitespace.
//!
//! `drift-vpn keygen` writes one to disk with mode 0600.
//! Anything else parsed here came from a user, who's
//! responsible for the protections.

use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use rand::RngCore;
use std::path::Path;

pub(crate) async fn load(path: &Path) -> Result<Identity> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading identity {}", path.display()))?;
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
    warn_if_world_or_group_readable(path).await;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(Identity::from_secret_bytes(secret))
}

/// Emit a `warn!`-level log if the identity file is readable by
/// anyone other than its owner. Matches wg-quick's "INSECURE
/// permissions" check — operators who `cp` a key around or
/// download one from a script often miss that the default mode
/// is 0644 even though `keygen` writes 0600.
///
/// Best-effort: a missing file or a metadata-read error means
/// the load itself would have failed already and we'd never
/// reach this; on FAT-like filesystems where mode bits are
/// meaningless, the warning is a false positive — operators on
/// those filesystems can ignore it.
async fn warn_if_world_or_group_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match tokio::fs::metadata(path).await {
            Ok(m) => m.permissions().mode(),
            Err(_) => return,
        };
        // Only the low 9 bits encode rwxrwxrwx. Anything in the
        // group or other bits means "someone else can read this".
        let other_bits = mode & 0o077;
        if other_bits != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                "identity file is readable by group or others — anyone with shell access on this host can copy the secret. Fix: `chmod 600 {}`",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Generate a fresh keypair and write the secret to `path` as
/// 64 hex chars. Returns the public key hex for the user to
/// share with the other peer's config.
pub(crate) async fn keygen(path: &Path) -> Result<String> {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let id = Identity::from_secret_bytes(secret);
    let pub_hex = hex::encode(id.public_bytes());
    let secret_hex = hex::encode(secret);

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    tokio::fs::write(path, format!("{}\n", secret_hex)).await?;
    // Tighten permissions on Unix so the secret isn't world-
    // readable. Best-effort; ignore failures (e.g. on FAT).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(path).await?.permissions();
        perms.set_mode(0o600);
        let _ = tokio::fs::set_permissions(path, perms).await;
    }
    Ok(pub_hex)
}

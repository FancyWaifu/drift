use anyhow::{bail, Context, Result};
use std::path::Path;

const MAGIC: &[u8; 4] = b"DRFT";
const FILE_LEN: usize = 4 + 32;

/// Save a 32-byte secret key to a DRIFT identity file.
/// Format: DRFT (4 bytes) + secret (32 bytes) = 36 bytes.
pub fn save_identity(secret: &[u8; 32], path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut data = Vec::with_capacity(FILE_LEN);
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(secret);
    std::fs::write(path, &data)
        .with_context(|| format!("writing {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }

    Ok(())
}

/// Load a 32-byte secret key from a DRIFT identity file.
pub fn load_identity(path: &Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    if data.len() != FILE_LEN {
        bail!(
            "invalid identity file: expected {} bytes, got {}",
            FILE_LEN,
            data.len()
        );
    }
    if &data[..4] != MAGIC {
        bail!("invalid identity file: bad magic (expected DRFT)");
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[4..]);
    Ok(secret)
}

/// Encode bytes as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex string to bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex"))
        .collect()
}

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
    std::fs::write(path, &data).with_context(|| format!("writing {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }

    Ok(())
}

/// Load a 32-byte secret key from a DRIFT identity file.
///
/// Accepts two on-disk formats so a single identity file works
/// across every DRIFT tool:
///
/// 1. **DRFT-magic binary** (legacy `drift` CLI format): 4-byte
///    `DRFT` magic + 32 raw bytes = 36 bytes total.
/// 2. **Hex** (drift-vpn / drift-config / drift-mosh format):
///    64 hex chars optionally followed by whitespace.
///
/// Anything else is an error.
pub fn load_identity(path: &Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    // Format 1: DRFT-magic binary.
    if data.len() == FILE_LEN && &data[..4] == MAGIC {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&data[4..]);
        return Ok(secret);
    }

    // Format 2: hex (the format drift-vpn keygen and drift-config
    // keygen both write). Trim ASCII whitespace and try to decode.
    if let Ok(s) = std::str::from_utf8(&data) {
        let trimmed = s.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = (0..trimmed.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
                .context("hex decode failed")?;
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            return Ok(secret);
        }
    }

    bail!(
        "invalid identity file at {}: expected either DRFT-magic binary \
         (36 bytes starting with `DRFT`) or 64 hex chars, got {} bytes",
        path.display(),
        data.len()
    );
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

use super::identity::{hex, load_identity};
use super::{expand_path, InfoArgs, OutputFormat};
use anyhow::Result;
use drift::crypto::derive_peer_id;
use drift::identity::Identity;

pub fn run(args: &InfoArgs, identity_path: &str, format: &OutputFormat) -> Result<()> {
    let path = match &args.file {
        Some(f) => expand_path(f),
        None => expand_path(identity_path),
    };

    let secret = load_identity(&path)?;
    let id = Identity::from_secret_bytes(secret);
    let pub_bytes = id.public_bytes();
    let peer_id = derive_peer_id(&pub_bytes);

    match format {
        OutputFormat::Human => {
            println!("path:       {}", path.display());
            println!("public_key: {}", hex(&pub_bytes));
            println!("peer_id:    {}", hex(&peer_id));
        }
        OutputFormat::Json => {
            let out = serde_json::json!({
                "path": path.display().to_string(),
                "public_key": hex(&pub_bytes),
                "peer_id": hex(&peer_id),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }

    Ok(())
}

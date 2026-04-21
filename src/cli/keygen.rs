use super::identity::{hex, save_identity};
use super::{expand_path, KeygenArgs, OutputFormat};
use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use anyhow::{bail, Result};

pub fn run(args: &KeygenArgs, identity_path: &str, format: &OutputFormat) -> Result<()> {
    let path = match &args.output {
        Some(p) => expand_path(p),
        None => expand_path(identity_path),
    };

    if path.exists() && !args.force {
        bail!(
            "identity file already exists: {}\nUse --force to overwrite.",
            path.display()
        );
    }

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    let id = Identity::from_secret_bytes(secret);
    let pub_bytes = id.public_bytes();
    let peer_id = derive_peer_id(&pub_bytes);

    save_identity(&secret, &path)?;

    match format {
        OutputFormat::Human => {
            eprintln!("Identity saved to {}", path.display());
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

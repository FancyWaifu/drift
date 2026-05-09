//! `drift-config` — inventory + identity manager for DRIFT
//! deployments. Generic across DRIFT tools: drift-vpn, drift-mosh,
//! drift-http, drift-git all read the same `drift.toml`.

use anyhow::Result;
use clap::Parser;

mod cli;
mod commands;
// Schema + io live in the library half so other crates
// (drift-vpn) can reuse them. The CLI uses them indirectly via
// `commands.rs` imports.

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    let config_path = commands::resolve_config_path(&args.config)?;
    let identity_path = commands::resolve_identity_path(&args.identity, &config_path)?;

    match &args.command {
        cli::Command::Init(a) => commands::init(a, &config_path),
        cli::Command::Keygen(a) => commands::keygen(a, &config_path, &identity_path),
        cli::Command::Peer(p) => match p {
            cli::PeerCommand::Add(a) => commands::peer_add(a, &config_path),
            cli::PeerCommand::Ls => commands::peer_ls(&config_path),
            cli::PeerCommand::Rm(a) => commands::peer_rm(a, &config_path),
        },
        cli::Command::Show => commands::show(&config_path),
        cli::Command::Validate => commands::validate(&config_path),
    }
}

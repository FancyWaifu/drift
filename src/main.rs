mod cli;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Command::Keygen(args) => cli::keygen::run(args, &cli.identity, &cli.format),
        Command::Info(args) => cli::info::run(args, &cli.identity, &cli.format),
        Command::Send(args) => cli::send::run(args, &cli.identity).await,
        Command::Listen(args) => cli::listen::run(args, &cli.identity).await,
        Command::Relay(args) => cli::relay::run(args).await,
    }
}

mod cli;

use clap::Parser;
use cli::{Cli, Command};

/// Tokio runtime worker thread override.
///
/// Default (env var unset): tokio's native `num_cpus` behavior, the
/// same as `#[tokio::main]`. Operators on constrained hosts can lower
/// it via `DRIFT_TOKIO_WORKER_THREADS=N`; setting it to 0 selects the
/// `current_thread` runtime.
///
/// Note on the "thread-per-core" experiment: capping bridges to 1
/// worker was attempted on Drift-4 (K=17 corporate federation bench)
/// and measurably regressed 4-hop reliability from 18/36 → 6/36.
/// hyper's h2 connection task, the per-stream body-drain task, and
/// the request handler task all need to run concurrently within a
/// single bridge process; forcing them onto a single worker
/// serializes head-of-line and starves transit hops. The
/// thread-per-core pattern still works as a deliberate operator
/// choice (set env to 1) but is not safe as a default.
fn tokio_workers_from_env() -> Option<usize> {
    std::env::var("DRIFT_TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
}

fn main() -> anyhow::Result<()> {
    let rt = match tokio_workers_from_env() {
        Some(0) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
        Some(n) => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(n)
            .enable_all()
            .build()?,
        None => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    };
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Command::Keygen(args) => cli::keygen::run(args, &cli.identity, &cli.format),
        Command::Info(args) => cli::info::run(args, &cli.identity, &cli.format),
        Command::Send(args) => cli::send::run(args, &cli.identity).await,
        Command::Listen(args) => cli::listen::run(args, &cli.identity).await,
        Command::Relay(args) => cli::relay::run(args).await,
        Command::Bridge(args) => cli::bridge::run(args, &cli.identity).await,
        Command::Contacts(args) => cli::contacts::run(args).await,
    }
}

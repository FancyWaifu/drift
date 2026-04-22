//! drift-bench — real-network comparison harness.
//!
//! One binary that speaks DRIFT, QUIC, and WireGuard. Runs as
//! either server or client. Three workloads per protocol:
//!   * handshake — time from connect() to first byte acked
//!   * rtt       — 1000 ping-pong iterations, report p50/p99
//!   * throughput — sustained send for N seconds, report Mbps
//!
//! Deployed via docker-compose: one container per role, shared
//! bridge network. Output is JSON to stdout so run.sh can
//! aggregate into a comparison table.

use anyhow::Result;
use clap::Parser;
use std::time::Duration;

mod drift_proto;
mod quic_proto;
mod report;
mod wg_proto;

#[derive(Parser, Clone)]
pub struct Cli {
    #[clap(long, value_enum)]
    pub protocol: Protocol,
    #[clap(long, value_enum)]
    pub mode: Mode,
    #[clap(long, value_enum)]
    pub workload: Workload,

    /// Server bind address (server mode) or connect target
    /// (client mode).
    #[clap(long, default_value = "0.0.0.0:9000")]
    pub listen: String,
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub target: String,

    /// Throughput test duration.
    #[clap(long, default_value = "10")]
    pub duration_secs: u64,
    /// Payload size used by throughput + rtt workloads.
    #[clap(long, default_value = "1024")]
    pub payload_bytes: usize,
    /// How many ping-pong iterations the rtt workload runs.
    #[clap(long, default_value = "1000")]
    pub rtt_iters: usize,
    /// How long the server waits for the client before exiting.
    #[clap(long, default_value = "60")]
    pub server_idle_secs: u64,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Protocol {
    Drift,
    Quic,
    Wg,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Drift => "drift",
            Protocol::Quic => "quic",
            Protocol::Wg => "wireguard",
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Mode {
    Server,
    Client,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Workload {
    Handshake,
    Rtt,
    Throughput,
}

impl Workload {
    pub fn name(&self) -> &'static str {
        match self {
            Workload::Handshake => "handshake",
            Workload::Rtt => "rtt",
            Workload::Throughput => "throughput",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Server mode auto-exits after `server_idle_secs`. Wrapping
    // the whole run in a timeout means orphaned servers can't
    // accumulate if the runner script dies mid-bench.
    let timeout = Duration::from_secs(cli.server_idle_secs.max(60));
    let run = async move {
        match (cli.protocol, cli.mode) {
            (Protocol::Drift, Mode::Server) => drift_proto::server(&cli).await,
            (Protocol::Drift, Mode::Client) => drift_proto::client(&cli).await,
            (Protocol::Quic, Mode::Server) => quic_proto::server(&cli).await,
            (Protocol::Quic, Mode::Client) => quic_proto::client(&cli).await,
            (Protocol::Wg, Mode::Server) => wg_proto::server(&cli).await,
            (Protocol::Wg, Mode::Client) => wg_proto::client(&cli).await,
        }
    };

    match tokio::time::timeout(timeout, run).await {
        Ok(Ok(Some(r))) => {
            println!("{}", serde_json::to_string(&r)?);
            Ok(())
        }
        Ok(Ok(None)) => Ok(()), // server finished cleanly, no report
        Ok(Err(e)) => Err(e),
        Err(_) => {
            eprintln!("server hit {}s idle timeout, exiting", timeout.as_secs());
            Ok(())
        }
    }
}

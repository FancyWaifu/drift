//! Config file loader.
//!
//! Lives at `$XDG_CONFIG_HOME/drift-mosh/config.toml` or the
//! platform-appropriate equivalent (via the `dirs` crate).
//!
//! The config's job is to hold defaults the user rarely needs
//! to override but might: SSH port, keepalive window,
//! `drift-mosh-server` path on the remote host. If the file
//! doesn't exist, we use hardcoded defaults without error.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// SSH port for the default `drift-mosh user@host` launch.
    /// Users with non-standard setups set it here instead of
    /// typing `--ssh-port` every time.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,

    /// Path to the `drift-mosh-server` binary on the remote
    /// host. Default assumes the binary is on $PATH; users can
    /// override to `~/.local/bin/drift-mosh-server` etc.
    #[serde(default = "default_remote_server_path")]
    pub remote_server_path: String,

    /// How long (in seconds) the server keeps a session alive
    /// after the client disconnects. This is the reattach
    /// window — network changes within this window reconnect
    /// to the existing pty; longer absences force a fresh
    /// session. Mosh's default is 10 minutes; we match.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,

    /// Address the server binds to when launched remotely.
    /// `0.0.0.0:0` lets the kernel pick a free port; servers
    /// behind firewalls may want a specific range here.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
}

fn default_ssh_port() -> u16 {
    22
}
fn default_remote_server_path() -> String {
    "drift-mosh-server".into()
}
fn default_keepalive_secs() -> u64 {
    600
}
fn default_bind_addr() -> String {
    "0.0.0.0:0".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ssh_port: default_ssh_port(),
            remote_server_path: default_remote_server_path(),
            keepalive_secs: default_keepalive_secs(),
            bind_addr: default_bind_addr(),
        }
    }
}

impl Config {
    /// Resolve the drift-mosh config directory:
    ///   Linux:   ~/.config/drift-mosh/
    ///   macOS:   ~/Library/Application Support/drift-mosh/
    ///   Windows: %APPDATA%\drift-mosh\
    pub fn config_dir() -> Result<PathBuf> {
        let base = dirs::config_dir()
            .context("could not resolve user config dir (set $XDG_CONFIG_HOME?)")?;
        Ok(base.join("drift-mosh"))
    }

    /// Path to config.toml. Does not create it; caller decides
    /// whether missing means "error" or "use defaults".
    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    /// Load config, falling back silently to defaults if the
    /// file doesn't exist. Errors only on malformed TOML.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))
    }
}

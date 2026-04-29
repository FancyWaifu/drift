//! `drift://` URL parsing.
//!
//! Format:
//!
//! ```text
//! drift://<PUBHEX>@<HOST>:<PORT><PATH>?<QUERY>
//! ```
//!
//! - `PUBHEX` is the 64-character hex encoding of the server's
//!   X25519 static pubkey (32 bytes). Required.
//! - `HOST` is a hostname or literal IP. Hostnames are resolved
//!   via DNS at connect time.
//! - `PORT` is the UDP port DRIFT is bound on. Required for v1
//!   (no implicit default — different deployments will use
//!   different ports).
//! - `PATH` and `QUERY` are passed through to the underlying
//!   HTTP request unchanged.

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use tokio::net::lookup_host;

#[derive(Debug)]
pub struct DriftUrl {
    pub pub_hex: String,
    pub pubkey: [u8; 32],
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl DriftUrl {
    pub async fn resolve(&self) -> Result<SocketAddr> {
        let target = format!("{}:{}", self.host, self.port);
        // First entry from getaddrinfo wins. For deployments
        // with both IPv4 and IPv6 records this picks whatever
        // the OS prefers (usually v6 if reachable, else v4).
        // Bind the iterator + extracted SocketAddr separately so
        // borrow of `target` (via `&str`) ends before we touch
        // it again in the error path.
        let mut iter = lookup_host(target.as_str())
            .await
            .with_context(|| format!("resolving {}", target))?;
        iter.next()
            .ok_or_else(|| anyhow!("no addresses for {}", target))
    }
}

pub fn parse(input: &str) -> Result<DriftUrl> {
    let parsed = url::Url::parse(input).context("parsing as URL")?;
    if parsed.scheme() != "drift" {
        return Err(anyhow!(
            "expected scheme `drift://`, got {:?}",
            parsed.scheme()
        ));
    }
    // The username slot of `drift://USER@HOST` carries the
    // pubkey. `url` percent-decodes it for us.
    let pub_hex = parsed.username();
    if pub_hex.is_empty() {
        return Err(anyhow!(
            "drift:// URL needs a pubkey: drift://<PUBHEX>@<host>:<port>/"
        ));
    }
    let bytes = hex::decode(pub_hex).context("pubkey is not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "pubkey must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes);

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("drift:// URL has no host"))?
        .to_string();
    let port = parsed
        .port()
        .ok_or_else(|| anyhow!("drift:// URL must include a port"))?;

    let path = parsed.path();
    let path = if path.is_empty() { "/" } else { path };
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{}", path, q),
        None => path.to_string(),
    };

    Ok(DriftUrl {
        pub_hex: pub_hex.to_string(),
        pubkey,
        host,
        port,
        path_and_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64() -> String {
        "00".repeat(32)
    }

    #[test]
    fn parses_basic() {
        let u = parse(&format!("drift://{}@example.com:9100/foo", hex64())).unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 9100);
        assert_eq!(u.path_and_query, "/foo");
    }

    #[test]
    fn parses_query() {
        let u = parse(&format!(
            "drift://{}@example.com:9100/path?a=1&b=2",
            hex64()
        ))
        .unwrap();
        assert_eq!(u.path_and_query, "/path?a=1&b=2");
    }

    #[test]
    fn defaults_path_to_slash() {
        let u = parse(&format!("drift://{}@host:9100", hex64())).unwrap();
        assert_eq!(u.path_and_query, "/");
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(parse("https://abc@host:9100/").is_err());
    }

    #[test]
    fn rejects_bad_pubkey_length() {
        assert!(parse("drift://abc@host:9100/").is_err());
    }
}

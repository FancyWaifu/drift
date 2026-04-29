//! Transport-aware bind / peer parsing.
//!
//! DRIFT decouples identity from transport: the same pubkey can
//! be reached over UDP, TCP, WebSocket, etc. Tools that hardcode
//! UDP defeat the project's central thesis. So both the `--bind`
//! flag (server) and the `--peer` flag (client) accept a small
//! URL-shaped grammar that picks the transport explicitly:
//!
//! ```text
//! udp://0.0.0.0:9100        # bind UDP
//! tcp://0.0.0.0:9100        # bind TCP listener (accept-loop pattern)
//! 0.0.0.0:9100              # no scheme = UDP (back-compat)
//!
//! <PUBHEX>@udp://host:9100  # peer over UDP
//! <PUBHEX>@tcp://host:9100  # peer over TCP
//! <PUBHEX>@host:9100        # no scheme = UDP
//! ```
//!
//! For `drift://` URLs in clickable links we extend the same
//! scheme via the `+` suffix (git's convention):
//!
//! ```text
//! drift://PUB@host:9100/path        # UDP
//! drift+udp://PUB@host:9100/path    # UDP (explicit)
//! drift+tcp://PUB@host:9100/path    # TCP
//! ```

use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::str::FromStr;

/// Which transport medium to use to reach (or accept) a peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

impl FromStr for Transport {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(Transport::Udp),
            "tcp" => Ok(Transport::Tcp),
            other => Err(anyhow!(
                "unknown transport {:?} (supported: udp, tcp)",
                other
            )),
        }
    }
}

/// A `--bind` or `--peer` target: which transport, which address.
#[derive(Clone, Debug)]
pub struct AddrSpec {
    pub transport: Transport,
    pub addr: SocketAddr,
}

/// Parse `<scheme>://host:port` or bare `host:port` (defaults to UDP).
pub fn parse_addr(s: &str) -> Result<AddrSpec> {
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        let addr_str = &s[idx + 3..];
        let transport = scheme.parse::<Transport>()?;
        let addr: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("address {:?} is not host:port", addr_str))?;
        Ok(AddrSpec { transport, addr })
    } else {
        // No scheme — back-compat default to UDP.
        let addr: SocketAddr = s
            .parse()
            .with_context(|| format!("address {:?} is not host:port", s))?;
        Ok(AddrSpec {
            transport: Transport::Udp,
            addr,
        })
    }
}

/// Parse `<PUBHEX>@<scheme>://host:port` (or `<PUBHEX>@host:port`)
/// for the `--peer` flag.
pub fn parse_peer(s: &str) -> Result<([u8; 32], AddrSpec)> {
    let (pub_str, rest) = s
        .split_once('@')
        .ok_or_else(|| anyhow!("--peer expects PUBHEX@HOST:PORT or PUBHEX@scheme://HOST:PORT"))?;
    let bytes = hex::decode(pub_str.trim())
        .with_context(|| format!("--peer pubkey {:?} isn't valid hex", pub_str))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "--peer pubkey must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes);
    let spec = parse_addr(rest)?;
    Ok((pubkey, spec))
}

/// Parse `drift://...` and `drift+<scheme>://...` URLs into the
/// transport + pubkey + address + path. Used by the URL handler.
#[derive(Debug)]
pub struct DriftUrl {
    pub transport: Transport,
    pub pub_hex: String,
    pub pubkey: [u8; 32],
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

pub fn parse_drift_url(input: &str) -> Result<DriftUrl> {
    let parsed = ::url::Url::parse(input).context("parsing as URL")?;
    let scheme = parsed.scheme();
    let transport = if scheme == "drift" {
        Transport::Udp
    } else if let Some(suffix) = scheme.strip_prefix("drift+") {
        suffix
            .parse::<Transport>()
            .with_context(|| format!("scheme {:?} is not a recognized DRIFT transport", scheme))?
    } else {
        return Err(anyhow!(
            "expected scheme `drift://` or `drift+<transport>://`, got {:?}",
            scheme
        ));
    };

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
        transport,
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
    fn bind_no_scheme_is_udp() {
        let s = parse_addr("0.0.0.0:9100").unwrap();
        assert_eq!(s.transport, Transport::Udp);
    }

    #[test]
    fn bind_explicit_tcp() {
        let s = parse_addr("tcp://0.0.0.0:9100").unwrap();
        assert_eq!(s.transport, Transport::Tcp);
    }

    #[test]
    fn bind_explicit_udp() {
        let s = parse_addr("udp://0.0.0.0:9100").unwrap();
        assert_eq!(s.transport, Transport::Udp);
    }

    #[test]
    fn bind_unknown_scheme_errors() {
        assert!(parse_addr("xyz://0.0.0.0:9100").is_err());
    }

    #[test]
    fn peer_no_scheme_is_udp() {
        let (_, s) = parse_peer(&format!("{}@1.2.3.4:9100", hex64())).unwrap();
        assert_eq!(s.transport, Transport::Udp);
    }

    #[test]
    fn peer_explicit_tcp() {
        let (_, s) = parse_peer(&format!("{}@tcp://1.2.3.4:9100", hex64())).unwrap();
        assert_eq!(s.transport, Transport::Tcp);
    }

    #[test]
    fn drift_url_default_udp() {
        let u = parse_drift_url(&format!("drift://{}@host:9100/p", hex64())).unwrap();
        assert_eq!(u.transport, Transport::Udp);
    }

    #[test]
    fn drift_url_explicit_tcp() {
        let u = parse_drift_url(&format!("drift+tcp://{}@host:9100/", hex64())).unwrap();
        assert_eq!(u.transport, Transport::Tcp);
    }

    #[test]
    fn drift_url_unknown_transport_errors() {
        assert!(parse_drift_url(&format!("drift+xyz://{}@host:9100/", hex64())).is_err());
    }
}

//! `drift://` and `PUB@host:port` URL parsing for the
//! drift-http binary.
//!
//! Generic transport bind / connect lives in `drift::io` and
//! `drift::Transport::{bind_url, connect_url, add_listener}` —
//! that's where new transport schemes (UDP, TCP, WebSocket, …)
//! plug in once and become usable across every DRIFT tool.
//!
//! What's left here is drift-http-specific URL handling:
//!
//!  * **`drift://PUB@host:port/path`** — the clickable URL
//!    handler. Splits the pubkey from the address part and
//!    canonicalizes the transport scheme so `drift://...`
//!    defaults to `udp`, while `drift+tcp://...` selects TCP.
//!
//!  * **`PUB@host:port` peer strings** — what the `connect`
//!    subcommand takes on the command line. Splits the pubkey
//!    from the URL portion that's then handed to
//!    `Transport::connect_url`.

use anyhow::{anyhow, Context, Result};

/// Identifies the DRIFT wire to talk to a peer over. Only
/// retained here so the URL handler's logged metadata is
/// human-readable; real adapter selection happens in
/// `drift::io::make_connector` / `make_listener`.
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

/// Pull the pubkey + connect URL out of a `PUB@<addr>` peer
/// string. The connect URL is whatever was on the right side of
/// `@`; if it had no `://` scheme, we prepend `udp://` so
/// `Transport::connect_url` accepts it directly.
pub fn split_peer(s: &str) -> Result<([u8; 32], String, Transport)> {
    let (pub_str, rest) = s
        .split_once('@')
        .ok_or_else(|| anyhow!("--peer expects PUBHEX@HOST:PORT (or PUBHEX@scheme://HOST:PORT)"))?;
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

    let (transport, url) = if let Some(idx) = rest.find("://") {
        let scheme = &rest[..idx];
        let t = match scheme.to_ascii_lowercase().as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            other => return Err(anyhow!("unknown transport {:?}", other)),
        };
        (t, rest.to_string())
    } else {
        (Transport::Udp, format!("udp://{}", rest))
    };
    Ok((pubkey, url, transport))
}

/// Result of parsing a `drift://` clickable URL.
#[derive(Debug)]
pub struct DriftUrl {
    pub transport: Transport,
    pub pub_hex: String,
    pub pubkey: [u8; 32],
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl DriftUrl {
    /// Construct the connect-URL string this peer should be
    /// reached over (`udp://host:port` or `tcp://host:port`).
    /// The `host` part is left as-is — name resolution happens
    /// inside `Transport::connect_url`.
    pub fn connect_url(&self) -> String {
        format!("{}://{}:{}", self.transport.as_str(), self.host, self.port)
    }
}

pub fn parse_drift_url(input: &str) -> Result<DriftUrl> {
    let parsed = ::url::Url::parse(input).context("parsing as URL")?;
    let scheme = parsed.scheme();
    let transport = if scheme == "drift" {
        Transport::Udp
    } else if let Some(suffix) = scheme.strip_prefix("drift+") {
        match suffix.to_ascii_lowercase().as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            _ => {
                return Err(anyhow!(
                    "scheme {:?} is not a recognized DRIFT transport",
                    scheme
                ));
            }
        }
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
    fn split_peer_no_scheme_is_udp() {
        let (_, url, t) = split_peer(&format!("{}@1.2.3.4:9100", hex64())).unwrap();
        assert_eq!(t, Transport::Udp);
        assert_eq!(url, "udp://1.2.3.4:9100");
    }

    #[test]
    fn split_peer_explicit_tcp() {
        let (_, url, t) = split_peer(&format!("{}@tcp://1.2.3.4:9100", hex64())).unwrap();
        assert_eq!(t, Transport::Tcp);
        assert_eq!(url, "tcp://1.2.3.4:9100");
    }

    #[test]
    fn drift_url_default_udp() {
        let u = parse_drift_url(&format!("drift://{}@host:9100/p", hex64())).unwrap();
        assert_eq!(u.transport, Transport::Udp);
        assert_eq!(u.connect_url(), "udp://host:9100");
    }

    #[test]
    fn drift_url_explicit_tcp() {
        let u = parse_drift_url(&format!("drift+tcp://{}@host:9100/", hex64())).unwrap();
        assert_eq!(u.transport, Transport::Tcp);
        assert_eq!(u.connect_url(), "tcp://host:9100");
    }
}

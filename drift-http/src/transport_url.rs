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
/// `drift::io::make_connector` / `make_listener`. Stored as a
/// short string rather than a closed enum so we don't need to
/// gate-keep new transports — when drift::io grows a new
/// scheme, the URL handler picks it up automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transport(pub String);

impl Transport {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn udp() -> Self {
        Transport("udp".to_string())
    }
    pub fn tcp() -> Self {
        Transport("tcp".to_string())
    }
}

/// Pull the pubkey + connect URL out of a peer string.
///
/// Two forms accepted:
///   1. **Petname** (e.g. `bob-laptop`) — looked up in the
///      shared `~/.config/drift/contacts.toml` address book.
///      Pubkey + last-known address come from the contact.
///   2. **Literal** (`PUBHEX@HOST:PORT` or
///      `PUBHEX@scheme://HOST:PORT`) — used on first contact
///      when no contact entry exists yet.
pub fn split_peer(s: &str) -> Result<([u8; 32], String, Transport)> {
    if !s.contains('@') {
        // Petname path. If a contact matches, use it.
        let book = drift::contacts::Contacts::load_default().context("loading contacts file")?;
        let contact = book.resolve(s).ok_or_else(|| {
            anyhow!(
                "no contact named {:?} (and the value isn't a PUBHEX@addr literal). \
                 Run `drift contacts list` to see saved contacts.",
                s
            )
        })?;
        let pubkey = drift::contacts::parse_pubkey_hex(&contact.pubkey)?;
        let (transport, url) = if let Some(idx) = contact.address.find("://") {
            let scheme = contact.address[..idx].to_ascii_lowercase();
            (Transport(scheme), contact.address.clone())
        } else {
            (Transport::udp(), format!("udp://{}", contact.address))
        };
        return Ok((pubkey, url, transport));
    }
    let (pub_str, rest) = s.split_once('@').unwrap();
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

    // Trust drift::io's URL dispatcher to validate the scheme.
    let (transport, url) = if let Some(idx) = rest.find("://") {
        let scheme = rest[..idx].to_ascii_lowercase();
        (Transport(scheme), rest.to_string())
    } else {
        (Transport::udp(), format!("udp://{}", rest))
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
    // `drift://...`         → UDP (back-compat default)
    // `drift+<wire>://...`  → that wire (udp / tcp / ws / …),
    //                          validated downstream by
    //                          `drift::io::make_connector`.
    let transport = if scheme == "drift" {
        Transport::udp()
    } else if let Some(suffix) = scheme.strip_prefix("drift+") {
        Transport(suffix.to_ascii_lowercase())
    } else {
        return Err(anyhow!(
            "expected scheme `drift://` or `drift+<wire>://`, got {:?}",
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
        assert_eq!(t, Transport::udp());
        assert_eq!(url, "udp://1.2.3.4:9100");
    }

    #[test]
    fn split_peer_explicit_tcp() {
        let (_, url, t) = split_peer(&format!("{}@tcp://1.2.3.4:9100", hex64())).unwrap();
        assert_eq!(t, Transport::tcp());
        assert_eq!(url, "tcp://1.2.3.4:9100");
    }

    #[test]
    fn drift_url_default_udp() {
        let u = parse_drift_url(&format!("drift://{}@host:9100/p", hex64())).unwrap();
        assert_eq!(u.transport, Transport::udp());
        assert_eq!(u.connect_url(), "udp://host:9100");
    }

    #[test]
    fn drift_url_explicit_tcp() {
        let u = parse_drift_url(&format!("drift+tcp://{}@host:9100/", hex64())).unwrap();
        assert_eq!(u.transport, Transport::tcp());
        assert_eq!(u.connect_url(), "tcp://host:9100");
    }
}

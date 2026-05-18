//! `webtransport://` listener adapter.
//!
//! Server side of the WASM `wire_webtransport.rs` adapter. Speaks
//! WebTransport (HTTP/3 + QUIC) and uses QUIC datagrams as the
//! byte-mover — one DRIFT packet per datagram, matching what the
//! browser sends through `wt.datagrams.writable.getWriter()`.
//!
//! Cert handling: WebTransport requires TLS. Browsers can either
//! trust the cert via the system CA store or pin it via the
//! `serverCertificateHashes` option (SHA-256 over the DER-encoded
//! cert). For the common dev/test/self-hosted-bridge case we
//! generate a fresh ECDSA-P256 self-signed cert on bind and print
//! its SHA-256 digest to STDERR — the operator copies that hash
//! into the client's `connectWebTransport` call.
//!
//! Production deployments with a real CA-issued cert can supply
//! the cert + key file paths through `DRIFT_WEBTRANSPORT_CERT` /
//! `DRIFT_WEBTRANSPORT_KEY` env vars (PEM-encoded). The same
//! `serverCertificateHashes` path still works for those — the
//! browser doesn't care whether the cert is CA-issued, it just
//! verifies the hash.

use crate::io::{Listener, PacketIO, WebTransportPacketIO};
use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::{Endpoint, Identity, ServerConfig};

/// WebTransport server listener. Wraps a `wtransport::Endpoint`
/// in server mode; each `accept()` waits for the next inbound
/// browser session, runs the WebTransport handshake, and yields
/// a `WebTransportPacketIO` for the resulting connection.
pub struct WebTransportListenerIO {
    endpoint: Endpoint<Server>,
    local_addr: SocketAddr,
}

impl WebTransportListenerIO {
    /// Bind the QUIC endpoint to `addr`. Cert + key are resolved
    /// from `DRIFT_WEBTRANSPORT_CERT` / `DRIFT_WEBTRANSPORT_KEY`
    /// env vars (PEM file paths) if both are set; otherwise a
    /// fresh self-signed ECDSA-P256 cert is generated for this
    /// process. Either way, the cert's SHA-256 digest is printed
    /// to STDERR so the operator can pin it on the client side.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let identity = load_or_generate_identity(addr).await?;

        // Print the cert hash to stderr in plain hex. Browsers
        // consume it via `serverCertificateHashes: [{ algorithm:
        // "sha-256", value: <ArrayBuffer> }]`, so we expose the
        // 32 bytes as 64 hex chars — easy to parse out of stderr
        // and easy to pass through env vars or CLI args.
        let cert = &identity.certificate_chain().as_slice()[0];
        let digest_hex = hex::encode(cert.hash().as_ref());
        eprintln!(
            "webtransport listener @ {} — cert SHA-256: {}",
            addr, digest_hex
        );

        let config = ServerConfig::builder()
            .with_bind_address(addr)
            .with_identity(identity)
            .keep_alive_interval(Some(std::time::Duration::from_secs(3)))
            .build();

        let endpoint = Endpoint::server(config)
            .map_err(|e| io::Error::other(format!("wtransport endpoint: {}", e)))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| io::Error::other(format!("wtransport local_addr: {}", e)))?;
        Ok(Self {
            endpoint,
            local_addr,
        })
    }
}

#[async_trait]
impl Listener for WebTransportListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn is_multi(&self) -> bool {
        true
    }

    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        // Three-phase handshake on the server side:
        //   1. `endpoint.accept()` — wait for a QUIC connect
        //   2. `IncomingSession.await` — read the WT session
        //      request (path, origin, etc.)
        //   3. `session_request.accept()` — send the response
        //      back and get the live `Connection`.
        let incoming = self.endpoint.accept().await;
        let remote = incoming.remote_address();
        let session_request = incoming
            .await
            .map_err(|e| io::Error::other(format!("wt incoming session: {}", e)))?;
        let connection = session_request
            .accept()
            .await
            .map_err(|e| io::Error::other(format!("wt session accept: {}", e)))?;
        Ok(Arc::new(WebTransportPacketIO::new(connection, remote)))
    }
}

/// Either load the operator-supplied cert/key PEM pair from env
/// vars, or generate a fresh self-signed one. The self-signed
/// path is what gets exercised by the browser harness and by
/// `drift bridge` runs without external cert config.
async fn load_or_generate_identity(addr: SocketAddr) -> io::Result<Identity> {
    let cert_path = std::env::var("DRIFT_WEBTRANSPORT_CERT").ok();
    let key_path = std::env::var("DRIFT_WEBTRANSPORT_KEY").ok();
    if let (Some(cp), Some(kp)) = (cert_path, key_path) {
        return Identity::load_pemfiles(&cp, &kp).await.map_err(|e| {
            io::Error::other(format!(
                "load DRIFT_WEBTRANSPORT_CERT={} + KEY={}: {}",
                cp, kp, e
            ))
        });
    }
    // Self-signed: cover loopback + the bound IP so the browser
    // can dial via 127.0.0.1 OR whatever interface the operator
    // exposes.
    let san: Vec<String> = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        addr.ip().to_string(),
    ];
    Identity::self_signed(&san)
        .map_err(|e| io::Error::other(format!("self-signed cert: {}", e)))
}

// ─── Scheme registration ───────────────────────────────────────────
//
// `webtransport://host:port` URLs route here. No connector — the
// native side has no WebTransport client; browser is the only
// implementer. The factory returns the listener; the connector
// errors out with an explanatory message so callers don't silently
// get a misleading scheme-not-found.

fn webtransport_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = crate::io::parse_ip_addr(&addr_str).await?;
        Ok(Box::new(WebTransportListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn webtransport_connector_factory(
    _addr_str: String,
) -> Pin<
    Box<
        dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send,
    >,
> {
    Box::pin(async move {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no native WebTransport client implemented; \
             use the browser-side `drift-wasm::wire_webtransport` instead",
        ))
    })
}

inventory::submit! {
    crate::io::SchemeRegistration {
        scheme: "webtransport",
        listener: webtransport_listener_factory,
        connector: webtransport_connector_factory,
    }
}

//! `onion://` — DRIFT over Tor via [arti].
//!
//! Two halves, both wrapping arti's `DataStream` (which impls
//! `AsyncRead + AsyncWrite`) in length-prefix framing identical
//! to `TlsPacketIO`:
//!
//! - **Connector** (`onion_connector_factory`) bootstraps a
//!   shared `TorClient` lazily on first use, dials a
//!   `<base32>.onion:<port>` address, and wraps the resulting
//!   `DataStream`.
//!
//! - **Listener** (`onion_listener_factory`) calls
//!   `TorClient::launch_onion_service` to publish a hidden
//!   service descriptor, then accepts each incoming
//!   `StreamRequest` from `tor_hsservice::handle_rend_requests`
//!   as a per-peer `OnionPacketIO`.
//!
//! Address shape: `onion://<base32-56-chars>.onion:<port>`. The
//! port is the *virtual* port inside the Tor network. The host
//! portion of a bind URL (`onion://localhost:80`) is ignored;
//! only the port matters there.
//!
//! TLS-style note: arti does its own end-to-end encryption to
//! the onion service, but DRIFT's own AEAD is what authenticates
//! the *peer*. The onion address is camouflage and reachability,
//! not authentication.

use crate::io::{Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use futures_util::stream::{Stream, StreamExt};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService, StreamRequest};
// `safelog::DisplayRedacted` lets us format an `HsId` as the
// canonical `<base32>.onion` string (the type's `Display` impl
// is only available via this trait to discourage accidental
// logging of in-the-clear identifiers).
use safelog::DisplayRedacted;
use tor_rtcompat::PreferredRuntime;

// ─── Shared TorClient ─────────────────────────────────────────────
//
// Bootstrapping arti takes 20–60s on first call; we want to pay
// that exactly once per process and then share the `TorClient`
// across every `onion://` connect/listen call.

static TOR_CLIENT: tokio::sync::OnceCell<TorClient<PreferredRuntime>> =
    tokio::sync::OnceCell::const_new();

async fn shared_tor_client() -> io::Result<&'static TorClient<PreferredRuntime>> {
    TOR_CLIENT
        .get_or_try_init(|| async {
            TorClient::create_bootstrapped(TorClientConfig::default())
                .await
                .map_err(|e| io::Error::other(format!("arti bootstrap: {}", e)))
        })
        .await
}

// ─── Synthetic peer addresses ─────────────────────────────────────
//
// Onion addresses don't fit in a `SocketAddr`. The actual
// destination lives inside the `OnionPacketIO`; the `SocketAddr`
// returned to `Transport::add_peer` is just a unique key in the
// peer table. Each onion peer gets a different loopback port via
// a process-wide counter.

fn synthesize_peer_addr() -> SocketAddr {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    SocketAddr::from(([127, 0, 0, 1], 60000u16.wrapping_add(n)))
}

// ─── OnionPacketIO ────────────────────────────────────────────────
//
// Same shape as `TlsPacketIO`: split into read/write halves,
// each behind a `tokio::sync::Mutex`, 2-byte BE length prefix
// per packet so DRIFT packets can be carved out of the byte
// stream.

pub struct OnionPacketIO {
    reader: tokio::sync::Mutex<
        Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync + 'static>,
    >,
    writer: tokio::sync::Mutex<
        Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync + 'static>,
    >,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl OnionPacketIO {
    pub fn new<S>(stream: S, peer_addr: SocketAddr, local_addr: SocketAddr) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        let boxed_r: Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync + 'static> =
            Box::new(r);
        let boxed_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> =
            Box::new(w);
        Self {
            reader: tokio::sync::Mutex::new(boxed_r),
            writer: tokio::sync::Mutex::new(boxed_w),
            peer_addr,
            local_addr,
        }
    }
}

#[async_trait]
impl PacketIO for OnionPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        if buf.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for onion framing (max 65535)",
            ));
        }
        let len_bytes = (buf.len() as u16).to_be_bytes();
        let mut writer = self.writer.lock().await;
        writer.write_all(&len_bytes).await?;
        writer.write_all(buf).await?;
        writer.flush().await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use tokio::io::AsyncReadExt;
        let mut reader = self.reader.lock().await;
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("onion frame too large: {} > buffer {}", len, buf.len()),
            ));
        }
        reader.read_exact(&mut buf[..len]).await?;
        Ok((len, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

// ─── Connector (client side) ──────────────────────────────────────

fn onion_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let client = shared_tor_client().await?;
        let stream = client
            .connect(addr_str.as_str())
            .await
            .map_err(|e| io::Error::other(format!("onion connect to {:?}: {}", addr_str, e)))?;
        let peer = synthesize_peer_addr();
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let io: Arc<dyn PacketIO> = Arc::new(OnionPacketIO::new(stream, peer, local));
        Ok((io, peer))
    })
}

// ─── Listener (server side) ───────────────────────────────────────
//
// Hosts an onion service. Keys are persisted to arti's state
// directory by default, so the .onion address is stable across
// restarts. Override the nickname (which determines the keystore
// path) via `DRIFT_ONION_NICKNAME` if you want multiple onion
// services from one process.

pub struct OnionListenerIO {
    // Keep the running service alive — dropping it stops
    // descriptor publication and tears down the introduction
    // points.
    _onion_service: Arc<RunningOnionService>,
    // Cached `<base32>.onion` address (Debug-formatted from
    // the `HsId`). Captured at bind time so tests / callers
    // can publish it out-of-band before boxing the listener
    // into `Box<dyn Listener>`.
    onion_addr: Option<String>,
    // The stream itself isn't `Sync`; wrap it in a Mutex so the
    // containing `OnionListenerIO` can satisfy the `Listener:
    // Send + Sync` bound. `accept(&mut self)` is the only place
    // we touch it, so contention is zero.
    stream_requests: tokio::sync::Mutex<
        Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
    >,
}

impl OnionListenerIO {
    /// The `<base32>.onion` address this listener is published
    /// at, if descriptor generation succeeded. Note: even when
    /// non-`None`, the descriptor may not yet be retrievable by
    /// clients on the live Tor network — publication takes
    /// 30–120s after `bind` returns.
    pub fn onion_address(&self) -> Option<&str> {
        self.onion_addr.as_deref()
    }
}

impl OnionListenerIO {
    pub async fn bind(addr_str: String) -> io::Result<Self> {
        // The host portion of an onion bind URL is meaningless
        // (services aren't bound to a local IP); we only use
        // the port to print a hint. The Tor network routes by
        // .onion identity, not by local socket.
        let _hint_port = addr_str
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok());

        let client = shared_tor_client().await?;
        let nickname_str = std::env::var("DRIFT_ONION_NICKNAME")
            .unwrap_or_else(|_| "drift".to_string());
        let nickname: HsNickname = nickname_str.clone().try_into().map_err(|e| {
            io::Error::other(format!("invalid nickname {:?}: {:?}", nickname_str, e))
        })?;
        let cfg = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .map_err(|e| io::Error::other(format!("onion service config: {:?}", e)))?;

        let (svc, rend_stream) = client
            .launch_onion_service(cfg)
            .map_err(|e| io::Error::other(format!("launch onion service: {:?}", e)))?
            .ok_or_else(|| {
                io::Error::other("onion service hosting disabled in TorClient config")
            })?;

        // `HsId`'s only Display path goes through `safelog`'s
        // `DisplayRedacted`; we explicitly use `display_unredacted`
        // because the actual `<base32>.onion` string is exactly
        // what callers need to publish to clients.
        let onion_addr = svc
            .onion_address()
            .map(|id| id.display_unredacted().to_string());
        if let Some(s) = &onion_addr {
            eprintln!("DRIFT_ONION_ADDR={}", s);
        }

        let stream_requests = handle_rend_requests(rend_stream);
        Ok(Self {
            _onion_service: svc,
            onion_addr,
            stream_requests: tokio::sync::Mutex::new(Box::pin(stream_requests)),
        })
    }
}

#[async_trait]
impl Listener for OnionListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Synthetic — onion services don't have a meaningful
        // IP local addr.
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
    fn is_multi(&self) -> bool {
        false
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let mut stream = self.stream_requests.lock().await;
        let req = stream.next().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "onion stream ended")
        })?;
        drop(stream);
        let stream = req
            .accept(Connected::new_empty())
            .await
            .map_err(|e| io::Error::other(format!("onion accept: {:?}", e)))?;
        let peer = synthesize_peer_addr();
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        Ok(Arc::new(OnionPacketIO::new(stream, peer, local)))
    }
}

fn onion_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        Ok(Box::new(OnionListenerIO::bind(addr_str).await?) as Box<dyn Listener>)
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "onion",
        listener: onion_listener_factory,
        connector: onion_connector_factory,
    }
}

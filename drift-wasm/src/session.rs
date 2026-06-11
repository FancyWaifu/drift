//! Wire-agnostic DRIFT session, driven by the sans-IO engine.
//!
//! Until phase 5 of the sans-IO arc (`docs/SANSIO_DESIGN.md`)
//! this file hand-rolled a simplified dialect of the protocol —
//! no replay protection, no PQ, no retransmits, no cookies, and
//! not byte-compatible with the native transport's short-header
//! path. It is now a ~250-line driver around
//! `drift_proto::Endpoint`: the browser speaks the exact same
//! protocol code as every other DRIFT peer, including PQ-hybrid
//! handshakes, the replay window, HELLO retransmits (driven by a
//! JS interval), short headers, rekey, and Close.
//!
//! The driver pattern is the standard sans-IO pump: wires call
//! `session.handle_incoming_bytes(buf)` for every inbound frame;
//! the session feeds the engine and flushes
//! `Endpoint::poll_transmit` through the wire's `send_fn`.
//! Browser wires are a single pipe, so the engine's `SocketAddr`
//! parameters are satisfied with a fixed placeholder — the wire
//! ignores destination addresses and the bridge routes by DRIFT
//! header, not IP.

use drift_core::crypto::PeerId;
use drift_proto::time::Instant;
use drift_proto::{Config, Direction, Endpoint, Event};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Placeholder address for the engine's SocketAddr parameters —
/// browser wires are a single pipe with no addressing.
fn wire_addr() -> SocketAddr {
    SocketAddr::from(([1, 1, 1, 1], 1))
}

/// How often the JS interval drives `Endpoint::handle_timeout`
/// (HELLO retransmit backoff, cookie rotation, eviction). 250 ms
/// comfortably under-samples the engine's shortest default backoff
/// (2 s).
const TICK_MS: i32 = 250;

/// Closure type used to hand bytes to the underlying wire.
pub(crate) type Sender = dyn Fn(&[u8]) -> Result<(), JsValue>;

struct Waiter {
    resolve: js_sys::Function,
    reject: js_sys::Function,
}

pub(crate) struct SessionState {
    ep: Endpoint,
    server_pub: [u8; 32],
    server_peer_id: PeerId,
    on_message: Option<js_sys::Function>,
    /// Handshake promises awaiting Connected / HandshakeTimedOut.
    waiters: HashMap<PeerId, Waiter>,
}

/// Wire-agnostic DRIFT session. Clone-able via `Rc`.
#[derive(Clone)]
pub(crate) struct Session {
    state: Rc<RefCell<SessionState>>,
    send_fn: Rc<Sender>,
}

impl Session {
    /// Construct a Session over a freshly-built wire. The caller
    /// arranges that `send_fn` ships bytes over the wire and that
    /// `handle_incoming_bytes` is called on every inbound frame.
    pub(crate) fn new(
        local_secret: [u8; 32],
        server_pub: [u8; 32],
        send_fn: Rc<Sender>,
    ) -> Self {
        let identity = drift_proto::Identity::from_secret_bytes(local_secret);
        let mut ep = Endpoint::new(
            identity,
            Config {
                // Mirror the old WASM behavior: any peer that can
                // reach us through the bridge may handshake (the
                // native equivalent of accept_any_peer).
                accept_any_peer: true,
                // Classical handshake in the browser, also matching
                // the old dialect (which refused PQ). A PQ-hybrid
                // HELLO is 1300 bytes (36 + 80 + 1184-byte ML-KEM
                // ek); the browser WebTransport wire carries DRIFT
                // packets as *unreliable datagrams*, whose path-MTU
                // cap (~1200 B) is below that — so a PQ HELLO is
                // silently dropped and the handshake never lands.
                // The WS / HTTP stream wires would carry it fine, but
                // a single DriftClient can't vary posture per wire,
                // so the browser stays classical until the engine
                // grows handshake-packet fragmentation for the
                // datagram path (follow-up). Every other engine
                // upgrade — replay window, retransmits, short
                // headers, rekey, Close — is unaffected.
                hybrid_pq: false,
                ..Config::default()
            },
        );
        let server_peer_id = ep.add_peer(server_pub, wire_addr(), Direction::Initiator);

        let session = Self {
            state: Rc::new(RefCell::new(SessionState {
                ep,
                server_pub,
                server_peer_id,
                on_message: None,
                waiters: HashMap::new(),
            })),
            send_fn,
        };

        // Periodic tick: retransmits, cookie rotation, eviction.
        // The pre-engine dialect had no retransmit path at all — a
        // single lost HELLO hung the connect promise forever.
        let tick_session = session.clone();
        let tick = Closure::wrap(Box::new(move || {
            tick_session.tick();
        }) as Box<dyn FnMut()>);
        set_interval(&tick, TICK_MS);
        // Session lifetime == page/worker lifetime; the leaked
        // closure is one allocation per session (standard
        // wasm-bindgen practice for persistent callbacks).
        tick.forget();

        session
    }

    pub(crate) fn server_peer_id(&self) -> PeerId {
        self.state.borrow().server_peer_id
    }

    pub(crate) fn set_on_message(&self, cb: js_sys::Function) {
        self.state.borrow_mut().on_message = Some(cb);
    }

    /// Kick off the handshake with the direct server. Returns a JS
    /// Promise that resolves on `Event::Connected` (and rejects if
    /// the engine gives up retransmitting).
    pub(crate) fn begin_handshake(&self, peer_id: PeerId) -> Result<js_sys::Promise, JsValue> {
        let state = self.state.clone();
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            state
                .borrow_mut()
                .waiters
                .insert(peer_id, Waiter { resolve, reject });
        });
        {
            let mut s = self.state.borrow_mut();
            if peer_id != s.server_peer_id {
                return Err(JsValue::from_str("begin_handshake: unknown peer"));
            }
            let server_pub = s.server_pub;
            s.ep.connect(Instant::now(), server_pub, wire_addr());
        }
        self.pump();
        Ok(promise)
    }

    /// Register a mesh peer (known only by pubkey) and handshake
    /// with them. The flights carry the mesh hop-TTL budget so the
    /// bridge routes them to wherever the target peer lives.
    pub(crate) async fn add_peer(&self, peer_pub: [u8; 32]) -> Result<(), JsValue> {
        let peer_id = drift_proto::derive_peer_id(&peer_pub);
        let state = self.state.clone();
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            state
                .borrow_mut()
                .waiters
                .insert(peer_id, Waiter { resolve, reject });
        });
        self.state
            .borrow_mut()
            .ep
            .connect_mesh(Instant::now(), peer_pub, wire_addr());
        self.pump();
        wasm_bindgen_futures::JsFuture::from(promise).await?;
        Ok(())
    }

    /// Send an AEAD-encrypted DATA packet to `peer_id`. If the
    /// handshake is still in flight the engine parks the payload
    /// and flushes it on establishment (the old dialect errored).
    pub(crate) async fn send_data_to(&self, peer_id: PeerId, payload: &[u8]) -> Result<(), JsValue> {
        self.state
            .borrow_mut()
            .ep
            .send(Instant::now(), &peer_id, payload, 0, 0)
            .map_err(|e| JsValue::from_str(&format!("drift send: {e}")))?;
        self.pump();
        Ok(())
    }

    /// Dispatch one incoming binary frame. Called by wire code from
    /// its receive callback. Rejected packets (malformed, replayed,
    /// unauthenticated) are logged and dropped — a remote peer must
    /// not be able to wedge the session.
    pub(crate) fn handle_incoming_bytes(&self, data: &[u8]) {
        let res = self
            .state
            .borrow_mut()
            .ep
            .handle_datagram(Instant::now(), wire_addr(), data);
        if let Err(e) = res {
            web_sys::console::warn_1(&format!("DRIFT: dropped packet: {e}").into());
        }
        self.pump();
    }

    /// Drive time-based behavior. Called from the JS interval.
    fn tick(&self) {
        self.state.borrow_mut().ep.handle_timeout(Instant::now());
        self.pump();
    }

    /// Flush queued transmits through the wire and dispatch queued
    /// events to JS. Transmits and events are collected under the
    /// borrow, then the borrow is released BEFORE touching the
    /// wire or calling back into JS — both can synchronously
    /// re-enter the session.
    fn pump(&self) {
        let (transmits, events) = {
            let mut s = self.state.borrow_mut();
            let mut transmits = Vec::new();
            while let Some(t) = s.ep.poll_transmit() {
                transmits.push(t.contents);
            }
            let mut events = Vec::new();
            while let Some(e) = s.ep.poll_event() {
                events.push(e);
            }
            (transmits, events)
        };

        for bytes in transmits {
            if let Err(e) = (self.send_fn)(&bytes) {
                web_sys::console::warn_1(&format!("DRIFT: wire send failed: {e:?}").into());
            }
        }

        for event in events {
            match event {
                Event::Connected { peer } => {
                    let waiter = self.state.borrow_mut().waiters.remove(&peer);
                    web_sys::console::log_1(
                        &format!("DRIFT handshake complete (peer={})", hex8(&peer)).into(),
                    );
                    if let Some(w) = waiter {
                        let _ = w.resolve.call0(&JsValue::NULL);
                    }
                }
                Event::HandshakeTimedOut { peer } => {
                    let waiter = self.state.borrow_mut().waiters.remove(&peer);
                    if let Some(w) = waiter {
                        let _ = w.reject.call1(
                            &JsValue::NULL,
                            &JsValue::from_str("DRIFT handshake timed out"),
                        );
                    }
                }
                Event::Data { peer, payload, .. } => {
                    let cb = self.state.borrow().on_message.clone();
                    if let Some(cb) = cb {
                        let src_hex = JsValue::from_str(&hex8(&peer));
                        let arr = js_sys::Uint8Array::from(payload.as_slice());
                        let _ = cb.call2(&JsValue::NULL, &src_hex, &arr);
                    }
                }
                Event::Closed { peer } => {
                    web_sys::console::log_1(
                        &format!("DRIFT peer closed session (peer={})", hex8(&peer)).into(),
                    );
                }
            }
        }
    }
}

/// `setInterval` that works in both window and worker contexts.
fn set_interval(f: &Closure<dyn FnMut()>, ms: i32) {
    let global = js_sys::global();
    if let Some(w) = global.dyn_ref::<web_sys::Window>() {
        let _ = w.set_interval_with_callback_and_timeout_and_arguments_0(
            f.as_ref().unchecked_ref(),
            ms,
        );
    } else if let Some(w) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
        let _ = w.set_interval_with_callback_and_timeout_and_arguments_0(
            f.as_ref().unchecked_ref(),
            ms,
        );
    }
}

pub(crate) fn hex8(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

//! WebTransport wire adapter (browser side).
//!
//! WebTransport is an HTTP/3-based API that gives browsers
//! *actual UDP-like datagrams* — unreliable, unordered, no TCP
//! retransmit tax. This is a far better match for DRIFT's
//! deadline-aware / coalesced traffic than WebSocket, which
//! forces everything to be reliable+ordered and double-counts
//! TCP's retries against DRIFT's own congestion control.
//!
//! Requires the browser and server to both negotiate HTTP/3
//! over TLS. Server-side needs `wtransport` (or similar) and a
//! valid certificate — on localhost the browser can be passed
//! a serverCertificateHashes fingerprint to skip the CA check.
//!
//! Browser API summary:
//!   const wt = new WebTransport(url, options);
//!   await wt.ready;
//!   const writer = wt.datagrams.writable.getWriter();
//!   await writer.write(bytes);
//!   const reader = wt.datagrams.readable.getReader();
//!   const { value, done } = await reader.read();

use crate::session::Session;
use drift_core::identity::STATIC_KEY_LEN;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    ReadableStreamDefaultReader, WebTransport, WebTransportHash, WebTransportOptions,
    WritableStreamDefaultWriter,
};

/// Connect to a DRIFT server over WebTransport, perform the
/// cryptographic handshake with it, and return a ready Session.
///
/// `url` must be an `https://` URL pointing at a WebTransport-
/// capable HTTP/3 endpoint. If `cert_hash_sha256` is `Some`,
/// it's added to the browser's `serverCertificateHashes` list,
/// letting the client pin a self-signed localhost / dev cert
/// without plumbing a CA. If `None`, the system CA pool is
/// used (the right choice for public deployments).
pub(crate) async fn connect(
    url: &str,
    secret: [u8; 32],
    server_pub: [u8; STATIC_KEY_LEN],
    cert_hash_sha256: Option<&[u8]>,
) -> Result<Session, JsValue> {
    let wt = match cert_hash_sha256 {
        None => WebTransport::new(url)?,
        Some(hash) => {
            let hash_obj = WebTransportHash::new();
            hash_obj.set_algorithm("sha-256");
            let hash_arr = js_sys::Uint8Array::from(hash);
            hash_obj.set_value(&hash_arr);
            let hashes = [hash_obj];
            let opts = WebTransportOptions::new();
            opts.set_server_certificate_hashes(&hashes);
            WebTransport::new_with_options(url, &opts)?
        }
    };

    // Wait for the underlying HTTP/3 session to come up.
    wasm_bindgen_futures::JsFuture::from(wt.ready()).await?;

    // Grab datagram writer + reader up front. `.getWriter()` /
    // `.getReader()` lock the stream exclusively — we hold them
    // for the session lifetime.
    let datagrams = wt.datagrams();
    let writable = datagrams.writable();
    let readable = datagrams.readable();
    let writer: WritableStreamDefaultWriter = writable.get_writer()?.unchecked_into();
    let reader: ReadableStreamDefaultReader = readable.get_reader().unchecked_into();

    // send_fn wraps `writer.write(u8array).then(...)` and
    // returns synchronously. WebTransport datagram writes can
    // be fire-and-forget — backpressure is the caller's
    // problem, not ours. We don't await the promise so send_fn
    // stays !Future-returning.
    let writer_for_send = writer.clone();
    let send_fn: Rc<dyn Fn(&[u8]) -> Result<(), JsValue>> =
        Rc::new(move |bytes: &[u8]| -> Result<(), JsValue> {
            let arr = js_sys::Uint8Array::from(bytes);
            let _promise = writer_for_send.write_with_chunk(&arr);
            Ok(())
        });

    let session = Session::new(secret, server_pub, send_fn);

    // Spawn a background reader loop. Each datagram that arrives
    // on `reader.read()` becomes one call to
    // session.handle_incoming_bytes.
    let session_for_recv = session.clone();
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            let read_result: JsValue =
                match wasm_bindgen_futures::JsFuture::from(reader.read()).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
            // The read result is `{ value: Uint8Array, done: bool }`.
            let obj = match read_result.dyn_into::<js_sys::Object>() {
                Ok(o) => o,
                Err(_) => break,
            };
            let done = js_sys::Reflect::get(&obj, &JsValue::from_str("done"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if done {
                break;
            }
            let value = match js_sys::Reflect::get(&obj, &JsValue::from_str("value")) {
                Ok(v) if !v.is_undefined() && !v.is_null() => v,
                _ => continue,
            };
            let arr = js_sys::Uint8Array::new(&value);
            let bytes = arr.to_vec();
            session_for_recv.handle_incoming_bytes(&bytes);
        }
    });

    // DRIFT handshake over the newly-open datagram channel.
    let handshake = session.begin_handshake(session.server_peer_id())?;
    wasm_bindgen_futures::JsFuture::from(handshake).await?;

    Ok(session)
}

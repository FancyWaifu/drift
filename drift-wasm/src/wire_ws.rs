//! WebSocket wire adapter.
//!
//! Opens a browser `WebSocket`, plugs its binary-message path
//! into a wire-agnostic `Session`, and does the initial
//! server handshake. All protocol logic lives in `session.rs`.

use crate::session::Session;
use drift_core::identity::STATIC_KEY_LEN;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};
// Keep `close` out — Session owns teardown semantics per-wire
// and the underlying WS closes when dropped.

/// Connect to a DRIFT server over WebSocket, perform the
/// cryptographic handshake with it, and return a ready Session.
pub(crate) async fn connect(
    url: &str,
    secret: [u8; 32],
    server_pub: [u8; STATIC_KEY_LEN],
) -> Result<Session, JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    // Wait for the TCP + WebSocket upgrade to complete before we
    // try to ship any bytes.
    let open_promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let onopen = Closure::once(move || {
            resolve.call0(&JsValue::NULL).unwrap();
        });
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();
    });
    wasm_bindgen_futures::JsFuture::from(open_promise).await?;

    // Session's send_fn closes over a clone of the WebSocket.
    let ws_for_send = ws.clone();
    let send_fn: Rc<dyn Fn(&[u8]) -> Result<(), JsValue>> =
        Rc::new(move |bytes: &[u8]| -> Result<(), JsValue> {
            ws_for_send
                .send_with_u8_array(bytes)
                .map_err(|e| JsValue::from_str(&format!("ws send: {:?}", e)))
        });

    let session = Session::new(secret, server_pub, send_fn);

    // Install the inbound hook: every Binary WS message flows
    // into session.handle_incoming_bytes.
    let session_for_recv = session.clone();
    let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();
        let buf = js_sys::Uint8Array::new(&data);
        let bytes = buf.to_vec();
        session_for_recv.handle_incoming_bytes(&bytes);
    }) as Box<dyn FnMut(MessageEvent)>);
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // Server handshake.
    let handshake = session.begin_handshake(session.server_peer_id())?;
    wasm_bindgen_futures::JsFuture::from(handshake).await?;

    Ok(session)
}


//! WebSocketStream wire adapter.
//!
//! Same wire as `wire_ws::connect` (both speak the WebSocket
//! protocol against a `ws://` or `wss://` server), but the
//! browser-side API is the streams-based [`WebSocketStream`]
//! instead of the classic event-driven `WebSocket`. The big
//! practical difference is automatic backpressure: writes block
//! the writer's `write()` promise when the underlying buffer
//! fills, so an over-eager DRIFT sender naturally throttles
//! itself instead of growing the browser's outbound queue
//! unbounded.
//!
//! Browser support is currently Chromium-only (Chrome / Edge /
//! Opera / Brave). Firefox and Safari fall back to `wire_ws`.
//! Server side is unchanged — the same `tokio-tungstenite`
//! listener that handles classic WebSocket connections handles
//! WebSocketStream clients without modification.
//!
//! [`WebSocketStream`]: https://developer.mozilla.org/en-US/docs/Web/API/WebSocketStream

use crate::session::Session;
use drift_core::identity::STATIC_KEY_LEN;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{ReadableStream, ReadableStreamDefaultReader, WritableStream, WritableStreamDefaultWriter};

// `WebSocketStream` isn't exposed by `web-sys` yet (it's still
// in Origin Trial), so we hand-bind the small API surface we
// need. Any browser that doesn't define `globalThis.WebSocketStream`
// will fail at the constructor and the caller can fall back to
// `connectWebSocket`.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = WebSocketStream)]
    type WebSocketStreamJs;

    #[wasm_bindgen(constructor, js_class = "WebSocketStream", catch)]
    fn new(url: &str) -> Result<WebSocketStreamJs, JsValue>;

    #[wasm_bindgen(method, getter, js_class = "WebSocketStream")]
    fn opened(this: &WebSocketStreamJs) -> js_sys::Promise;

    #[wasm_bindgen(method, js_class = "WebSocketStream")]
    fn close(this: &WebSocketStreamJs);
}

/// Connect to a DRIFT server over WebSocketStream and return a
/// ready Session. Wire-compatible with `connectWebSocket` —
/// the same server can serve both kinds of client.
pub(crate) async fn connect(
    url: &str,
    secret: [u8; 32],
    server_pub: [u8; STATIC_KEY_LEN],
) -> Result<Session, JsValue> {
    // Construct WebSocketStream. If the browser doesn't expose
    // it, the constructor throws — caller should catch and try
    // `connectWebSocket` as a fallback.
    let wss = WebSocketStreamJs::new(url).map_err(|e| {
        JsValue::from_str(&format!(
            "WebSocketStream not available in this browser ({:?}); fall back to connectWebSocket",
            e
        ))
    })?;

    // `opened` resolves to {readable, writable, protocol, extensions}.
    let opened: JsValue = wasm_bindgen_futures::JsFuture::from(wss.opened()).await?;
    let readable = js_sys::Reflect::get(&opened, &JsValue::from_str("readable"))?
        .dyn_into::<ReadableStream>()
        .map_err(|_| JsValue::from_str("WebSocketStream.opened.readable not a ReadableStream"))?;
    let writable = js_sys::Reflect::get(&opened, &JsValue::from_str("writable"))?
        .dyn_into::<WritableStream>()
        .map_err(|_| JsValue::from_str("WebSocketStream.opened.writable not a WritableStream"))?;

    // Lock the writer once. WritableStreamDefaultWriter is
    // single-owner; we hold it for the lifetime of the session.
    let writer: WritableStreamDefaultWriter = writable
        .get_writer()
        .map_err(|e| JsValue::from_str(&format!("get_writer: {:?}", e)))?;
    let writer_for_send = writer.clone();

    let send_fn: Rc<dyn Fn(&[u8]) -> Result<(), JsValue>> =
        Rc::new(move |bytes: &[u8]| -> Result<(), JsValue> {
            // `write()` is async; copy bytes into a Uint8Array
            // (the writer accepts ArrayBuffer-views as binary
            // messages) and fire-and-forget the resulting
            // promise. Browser-side queuing handles ordering.
            let chunk = js_sys::Uint8Array::from(bytes);
            let promise = writer_for_send.write_with_chunk(&chunk.into());
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = wasm_bindgen_futures::JsFuture::from(promise).await {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "WebSocketStream write error: {:?}",
                        e
                    )));
                }
            });
            Ok(())
        });

    let session = Session::new(secret, server_pub, send_fn);

    // Spawn a read loop that pumps every chunk into
    // `session.handle_incoming_bytes`. Each `read()` resolves to
    // `{value, done}`; `value` is a Uint8Array for binary
    // messages.
    let reader: ReadableStreamDefaultReader = readable
        .get_reader()
        .dyn_into::<ReadableStreamDefaultReader>()
        .map_err(|_| {
            JsValue::from_str("WebSocketStream readable.getReader() not a default reader")
        })?;
    let session_for_recv = session.clone();
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            let promise = reader.read();
            let result = match wasm_bindgen_futures::JsFuture::from(promise).await {
                Ok(v) => v,
                Err(e) => {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "WebSocketStream read error: {:?}",
                        e
                    )));
                    break;
                }
            };
            let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                .map(|v| v.as_bool().unwrap_or(true))
                .unwrap_or(true);
            if done {
                break;
            }
            let value = match js_sys::Reflect::get(&result, &JsValue::from_str("value")) {
                Ok(v) => v,
                Err(_) => break,
            };
            // `value` may be a Uint8Array (binary frame) or a
            // string (text frame). DRIFT only ever sends binary,
            // so we ignore non-Uint8Array messages.
            if let Ok(arr) = value.dyn_into::<js_sys::Uint8Array>() {
                let bytes = arr.to_vec();
                session_for_recv.handle_incoming_bytes(&bytes);
            }
        }
    });

    // Server handshake.
    let handshake = session.begin_handshake(session.server_peer_id())?;
    wasm_bindgen_futures::JsFuture::from(handshake).await?;

    Ok(session)
}

//! HTTP/SSE wire adapter (browser side).
//!
//! Pairs with `drift/src/wire_http.rs` on the server. Two HTTP
//! requests per logical session:
//!
//! - **Downstream**: `EventSource(url + "/drift-sse")`. The
//!   server's first event is `data: SID:<hex>` — we capture the
//!   sid and use it on every uplink POST. Subsequent events are
//!   base64-encoded DRIFT packets.
//!
//! - **Upstream**: `fetch(url + "/drift-send?sid=<hex>", {method:
//!   "POST", body: <bytes>})` — one POST per outbound packet.
//!
//! Use this when WebSocket upgrades get blocked but plain HTTP
//! gets through (some corporate proxies, captive portals, hostile
//! middleboxes). Latency is higher than WS — every uplink packet
//! is a full HTTP round trip — but the wire shape is
//! indistinguishable from a normal web app polling an API.

use crate::session::Session;
use base64::{engine::general_purpose, Engine as _};
use drift_core::identity::STATIC_KEY_LEN;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{EventSource, MessageEvent, Request, RequestInit, Response};

/// Connect to a DRIFT server over plain HTTP/SSE and return a
/// ready Session. `url` is the server origin without a trailing
/// slash, e.g. `http://relay.example.com:9000`.
pub(crate) async fn connect(
    url: &str,
    secret: [u8; 32],
    server_pub: [u8; STATIC_KEY_LEN],
) -> Result<Session, JsValue> {
    let base_url = url.trim_end_matches('/').to_string();

    // Open the SSE downstream channel. Constructor returns
    // immediately; readiness comes via the first onmessage.
    let sse_url = format!("{}/drift-sse", base_url);
    let sse = EventSource::new(&sse_url)?;

    // Wait for the SID handshake — the very first event the
    // server sends is `data: SID:<hex>`. Parse it into the
    // shared `sid_holder` before we do anything else.
    let sid_holder: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let sid_promise = {
        let sid_holder = sid_holder.clone();
        js_sys::Promise::new(&mut |resolve, reject| {
            // First-message handler: must be a SID:<hex> event.
            let resolve_msg = resolve.clone();
            let reject_msg = reject.clone();
            let reject_err = reject.clone();
            let sid_holder = sid_holder.clone();
            let onmessage = Closure::once(move |event: MessageEvent| {
                let data: String = match event.data().as_string() {
                    Some(s) => s,
                    None => {
                        let _ = reject_msg.call1(
                            &JsValue::NULL,
                            &JsValue::from_str("SSE first event not a string"),
                        );
                        return;
                    }
                };
                if let Some(sid) = data.strip_prefix("SID:") {
                    *sid_holder.borrow_mut() = Some(sid.to_string());
                    let _ = resolve_msg.call0(&JsValue::NULL);
                } else {
                    let _ = reject_msg.call1(
                        &JsValue::NULL,
                        &JsValue::from_str(&format!(
                            "SSE first event not SID handshake: {}",
                            data
                        )),
                    );
                }
            });
            sse.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();
            let onerror = Closure::once(move |_e: web_sys::Event| {
                let _ = reject_err.call1(
                    &JsValue::NULL,
                    &JsValue::from_str("SSE error before SID handshake"),
                );
            });
            sse.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onerror.forget();
        })
    };
    wasm_bindgen_futures::JsFuture::from(sid_promise).await?;
    let sid = sid_holder
        .borrow()
        .clone()
        .ok_or_else(|| JsValue::from_str("SID never arrived"))?;

    // send_fn: each outbound packet is one POST. Spawn-local so
    // the synchronous Sender contract is preserved; the fetch's
    // promise resolves in the background.
    let post_url = format!("{}/drift-send?sid={}", base_url, sid);
    let send_fn: Rc<dyn Fn(&[u8]) -> Result<(), JsValue>> =
        Rc::new(move |bytes: &[u8]| -> Result<(), JsValue> {
            let post_url = post_url.clone();
            let body = js_sys::Uint8Array::from(bytes);
            wasm_bindgen_futures::spawn_local(async move {
                let init = RequestInit::new();
                init.set_method("POST");
                init.set_body(&body);
                let req = match Request::new_with_str_and_init(&post_url, &init) {
                    Ok(r) => r,
                    Err(e) => {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "drift-send Request build error: {:?}",
                            e
                        )));
                        return;
                    }
                };
                if let Some(promise) = fetch_promise(&req) {
                    if let Err(e) = wasm_bindgen_futures::JsFuture::from(promise).await {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "drift-send fetch error: {:?}",
                            e
                        )));
                        return;
                    }
                } else {
                    web_sys::console::warn_1(&JsValue::from_str("no fetch in this context"));
                }
            });
            Ok(())
        });

    let session = Session::new(secret, server_pub, send_fn);

    // Re-install onmessage to handle ongoing packet events.
    let session_for_recv = session.clone();
    let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = match event.data().as_string() {
            Some(s) => s,
            None => return,
        };
        // Skip stray SID messages (shouldn't happen post-handshake
        // but be defensive).
        if data.starts_with("SID:") {
            return;
        }
        match general_purpose::STANDARD_NO_PAD.decode(data.as_bytes()) {
            Ok(bytes) => session_for_recv.handle_incoming_bytes(&bytes),
            Err(e) => {
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "SSE base64 decode error: {}",
                    e
                )));
            }
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    sse.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // Server handshake.
    let handshake = session.begin_handshake(session.server_peer_id())?;
    wasm_bindgen_futures::JsFuture::from(handshake).await?;

    Ok(session)
}

/// `fetch()` lives on `Window` in pages, `WorkerGlobalScope` in
/// workers, and is a top-level global in Node. Reflective lookup
/// covers all three without depending on the runtime exposing
/// one of the typed wrappers.
fn fetch_promise(req: &Request) -> Option<js_sys::Promise> {
    let global = js_sys::global();
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch")).ok()?;
    let fetch_fn: js_sys::Function = fetch_fn.dyn_into().ok()?;
    let result = fetch_fn.call1(&global, req.as_ref()).ok()?;
    result.dyn_into::<js_sys::Promise>().ok()
}

// Silence unused import lint when not all paths exercise it.
#[allow(dead_code)]
fn _silence(_r: Response) {}

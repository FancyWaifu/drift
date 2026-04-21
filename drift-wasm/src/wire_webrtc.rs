//! WebRTC data-channel wire adapter (browser side).
//!
//! Takes an already-open `RTCDataChannel` and plugs its message
//! path into a `Session`. SDP/ICE negotiation is the caller's
//! responsibility — browser apps typically do it through their
//! own signaling channel (a WebSocket to a matchmaking server,
//! an HTTP endpoint, a manual copy-paste, etc). This adapter
//! only cares about a channel that's already `open`.
//!
//! This is the browser-side counterpart to native DRIFT's
//! `WebRTCPacketIO` (in the `drift` crate's `io.rs`). Once both
//! sides wrap their respective data channels, they can run the
//! full DRIFT handshake + mesh protocol over the same wire —
//! the bytes between them travel directly (peer-to-peer through
//! any NAT, via ICE/DTLS) without any server in the data path.

use crate::session::Session;
use drift_core::identity::STATIC_KEY_LEN;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, RtcDataChannel};

/// Wrap an already-open `RTCDataChannel` and perform the DRIFT
/// server handshake over it. The channel MUST be in the `open`
/// readyState — this adapter doesn't wait for open, and doesn't
/// do SDP/ICE (bring your own signaling).
///
/// The caller-supplied `server_pub` is the DRIFT identity of
/// whatever's on the other end of the data channel — that peer
/// is treated as the "direct server" for routing purposes.
pub(crate) async fn from_data_channel(
    dc: RtcDataChannel,
    secret: [u8; 32],
    server_pub: [u8; STATIC_KEY_LEN],
) -> Result<Session, JsValue> {
    dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

    let dc_for_send = dc.clone();
    let send_fn: Rc<dyn Fn(&[u8]) -> Result<(), JsValue>> =
        Rc::new(move |bytes: &[u8]| -> Result<(), JsValue> {
            // RTCDataChannel.send can take ArrayBuffer / Blob /
            // string; mapping a Rust &[u8] through a JS
            // Uint8Array view then .buffer keeps it zero-copy.
            let arr = js_sys::Uint8Array::from(bytes);
            dc_for_send
                .send_with_array_buffer(&arr.buffer())
                .map_err(|e| JsValue::from_str(&format!("dc send: {:?}", e)))
        });

    let session = Session::new(secret, server_pub, send_fn);

    // Inbound: each DataChannelMessage binary event feeds
    // session.handle_incoming_bytes.
    let session_for_recv = session.clone();
    let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();
        // Binary data arrives as ArrayBuffer when binaryType is
        // 'arraybuffer'. Skip anything that isn't binary.
        if !data.is_instance_of::<js_sys::ArrayBuffer>() {
            return;
        }
        let buf = js_sys::Uint8Array::new(&data);
        let bytes = buf.to_vec();
        session_for_recv.handle_incoming_bytes(&bytes);
    }) as Box<dyn FnMut(MessageEvent)>);
    dc.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // Kick off the DRIFT handshake with the peer on the other
    // side of the data channel.
    let handshake = session.begin_handshake(session.server_peer_id())?;
    wasm_bindgen_futures::JsFuture::from(handshake).await?;

    Ok(session)
}

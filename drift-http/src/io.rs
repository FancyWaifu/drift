//! Adapter that lets a [`drift::streams::Stream`] act as
//! `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`.
//!
//! Why this matters: hyper 1.x's connection builders accept any
//! I/O matching that trait bound, and `tokio::io::copy_bidirectional`
//! does too. Once a DRIFT stream LOOKS like one of those, the rest
//! of the HTTP/proxy code is all stock hyper / tokio.
//!
//! Shape of the adapter:
//!
//! - **Reads** drain a leftover-bytes buffer first, then pull a
//!   whole chunk via `Stream::recv()`. DRIFT delivers chunks
//!   already segmented to roughly 1 KB — small enough that
//!   leftover handling is rare in practice.
//! - **Writes** turn each `poll_write` into one `Stream::send()`
//!   call. Backpressure is honored: if the underlying send hasn't
//!   completed, `poll_write` returns Pending until it does. The
//!   caller (hyper, copy_bidirectional, …) re-polls on the next
//!   wakeup, so progress is made by whoever is driving the
//!   connection.
//! - **Shutdown** runs the close future and clears state.
//!
//! There's no `unsafe` here. The struct is `Unpin` because every
//! field is `Unpin` (`Box<Pin<…>>` is `Unpin`, `Arc<…>` is `Unpin`,
//! `BytesMut` is `Unpin`), so we can implement the I/O traits
//! without pin-projection.

use bytes::{Buf, BytesMut};
use drift::streams::{Stream, StreamError};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type RecvFut = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;
type SendFut = Pin<Box<dyn Future<Output = Result<(), StreamError>> + Send>>;
type CloseFut = Pin<Box<dyn Future<Output = Result<(), StreamError>> + Send>>;

/// Wrapper that exposes a DRIFT stream as `AsyncRead + AsyncWrite`.
pub struct StreamIo {
    stream: Arc<Stream>,
    /// Bytes already pulled from the stream that the consumer
    /// hasn't taken yet. Flushed first on each `poll_read`.
    read_remainder: BytesMut,
    /// In-flight `recv()` future, if `poll_read` is waiting on
    /// the next chunk.
    recv_fut: Option<RecvFut>,
    /// True once `recv()` has returned `None` — the peer half-
    /// closed the stream and there will never be more bytes.
    eof: bool,
    /// In-flight `send()` future, if a previous `poll_write`
    /// hasn't completed yet.
    send_fut: Option<SendFut>,
    /// Number of bytes the in-flight send is expected to consume
    /// once it resolves (so we can return the right `n` to the
    /// caller).
    send_promised: usize,
    /// In-flight `close()` future, if `poll_shutdown` is in
    /// progress.
    close_fut: Option<CloseFut>,
    /// Once we've requested shutdown, refuse further writes.
    shut: bool,
}

impl StreamIo {
    pub fn new(stream: Arc<Stream>) -> Self {
        Self {
            stream,
            read_remainder: BytesMut::new(),
            recv_fut: None,
            eof: false,
            send_fut: None,
            send_promised: 0,
            close_fut: None,
            shut: false,
        }
    }
}

fn map_err(e: StreamError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("drift stream error: {:?}", e))
}

impl AsyncRead for StreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Step 1: drain any leftover bytes from a previous chunk
        // that didn't fit in the caller's buffer.
        if !me.read_remainder.is_empty() {
            let n = std::cmp::min(buf.remaining(), me.read_remainder.len());
            buf.put_slice(&me.read_remainder[..n]);
            me.read_remainder.advance(n);
            return Poll::Ready(Ok(()));
        }

        // Step 2: if we've seen EOF, return Ready with no bytes.
        // tokio's AsyncRead contract: `buf` left untouched +
        // Ready(Ok(())) signals end-of-stream.
        if me.eof {
            return Poll::Ready(Ok(()));
        }

        // Step 3: ensure we have a recv future in flight, then
        // poll it.
        let fut = me.recv_fut.get_or_insert_with(|| {
            let s = me.stream.clone();
            Box::pin(async move { s.recv().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                me.recv_fut = None;
                me.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(chunk)) => {
                me.recv_fut = None;
                me.read_remainder = BytesMut::from(&chunk[..]);
                let n = std::cmp::min(buf.remaining(), me.read_remainder.len());
                buf.put_slice(&me.read_remainder[..n]);
                me.read_remainder.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for StreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.shut {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "stream shut down",
            )));
        }

        // Pattern: hold one in-flight send future at a time. If
        // the buffer the caller passed is large, DRIFT internally
        // chunks it into MTU-sized segments before the future
        // resolves; we just wait for that batch of segments to
        // flush before accepting more bytes from the caller.
        if me.send_fut.is_none() {
            // Start a fresh send for the current buf.
            me.send_promised = buf.len();
            let chunk = buf.to_vec();
            let s = me.stream.clone();
            me.send_fut = Some(Box::pin(async move { s.send(&chunk).await }));
        }
        let fut = me.send_fut.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                me.send_fut = None;
                let n = std::mem::replace(&mut me.send_promised, 0);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                me.send_fut = None;
                me.send_promised = 0;
                Poll::Ready(Err(map_err(e)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // "Flushing" for us means draining the in-flight send.
        // DRIFT's stream layer doesn't have an explicit flush
        // call — once `send()` returns, the segments are queued
        // for transmission and the congestion window will push
        // them out as it can.
        if let Some(fut) = me.send_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    me.send_fut = None;
                    me.send_promised = 0;
                }
                Poll::Ready(Err(e)) => {
                    me.send_fut = None;
                    me.send_promised = 0;
                    return Poll::Ready(Err(map_err(e)));
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Drain any pending write first so its bytes aren't
        // lost on close.
        if let Some(fut) = me.send_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    me.send_fut = None;
                    me.send_promised = 0;
                }
                Poll::Ready(Err(e)) => {
                    me.send_fut = None;
                    me.send_promised = 0;
                    return Poll::Ready(Err(map_err(e)));
                }
            }
        }

        let fut = me.close_fut.get_or_insert_with(|| {
            let s = me.stream.clone();
            Box::pin(async move { s.close().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => {
                me.close_fut = None;
                me.shut = true;
                Poll::Ready(res.map_err(map_err))
            }
        }
    }
}

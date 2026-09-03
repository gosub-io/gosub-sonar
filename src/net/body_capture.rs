//! Teeing a response body to an observer.
//!
//! The body's real consumer -- the parser, the decoder -- consumes the stream as it arrives,
//! so the bytes are copied on their way past, up to a budget the observer sets.
//!
//! Teed rather than buffered ahead: reading the whole body first would delay every consumer
//! whenever capture is on, changing the timings being reported.

use crate::net::events::NetEvent;
use crate::net::observer::NetObserver;
use crate::NetError;
use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use url::Url;

/// Wraps a body stream, copying what passes through and reporting it once.
pub(crate) struct CapturingBody<S> {
    inner: S,
    observer: Arc<dyn NetObserver + Send + Sync>,
    url: Url,
    captured: Vec<u8>,
    /// Bytes still allowed. Reaching zero stops the copy but never the stream.
    remaining: usize,
    /// Set once anything was dropped, so the report can say the body continued.
    truncated: bool,
    /// Guards against reporting twice: the stream can be polled after it ends, and the drop
    /// below fires either way.
    reported: bool,
}

impl<S> CapturingBody<S> {
    pub(crate) fn new(
        inner: S,
        observer: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        limit: usize,
        // `prefix` is what the peek window already read: those bytes are part of the body
        // and the consumer will see them, so the capture has to start with them too.
        prefix: &[u8],
    ) -> Self {
        let take = prefix.len().min(limit);
        Self {
            inner,
            observer,
            url,
            captured: prefix[..take].to_vec(),
            remaining: limit - take,
            truncated: take < prefix.len(),
            reported: false,
        }
    }

    fn absorb(&mut self, chunk: &Bytes) {
        if self.remaining == 0 {
            // Still flowing, just no longer being copied.
            self.truncated = true;
            return;
        }
        let take = chunk.len().min(self.remaining);
        self.captured.extend_from_slice(&chunk[..take]);
        self.remaining -= take;
        if take < chunk.len() {
            self.truncated = true;
        }
    }

    fn report(&mut self) {
        if self.reported {
            return;
        }
        self.reported = true;
        self.observer.on_event(NetEvent::BodyPreview {
            url: self.url.clone(),
            body: std::mem::take(&mut self.captured),
            truncated: self.truncated,
        });
    }
}

impl<S> Stream for CapturingBody<S>
where
    S: Stream<Item = Result<Bytes, NetError>> + Unpin,
{
    type Item = Result<Bytes, NetError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.absorb(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                // A body that failed part way still reports what arrived.
                this.report();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.report();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for CapturingBody<S> {
    /// A consumer that stops reading early -- an aborted navigation, a decoder that has seen
    /// enough -- still leaves a partial body worth reporting.
    fn drop(&mut self) {
        if !self.reported {
            self.truncated = true;
            self.report();
        }
    }
}

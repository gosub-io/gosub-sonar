//! Tower layer that reports how long connection establishment took.
//!
//! Connecting - the TCP handshake, and for https the TLS handshake on top of it - happens
//! inside reqwest's connector, below the request layer. `ClientBuilder::connector_layer`
//! is the one seam that wraps it, so this times the connector's own future and reports the
//! result to the request that triggered it via the task-local observer.
//!
//! The layer only observes: it forwards the request untouched and returns the connector's
//! own result and error unchanged, so installing it changes no behaviour. That is why it
//! is installed unconditionally, unlike DNS timing, which needs a resolver to be
//! configured because it would otherwise replace reqwest's own resolution.
//!
//! Nothing is reported for a request served from the connection pool - it establishes no
//! connection, so it spent no time connecting.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tower_layer::Layer;
use tower_service::Service;

use crate::net::events::NetEvent;
use crate::net::observer::emit_to_current;

/// Wraps reqwest's connector so each established connection reports its duration.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConnectTimingLayer;

impl<S> Layer<S> for ConnectTimingLayer {
    type Service = ConnectTiming<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectTiming { inner }
    }
}

/// The service half of [`ConnectTimingLayer`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectTiming<S> {
    inner: S,
}

impl<S, Req> Service<Req> for ConnectTiming<S>
where
    S: Service<Req>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        // Start the clock at `call`, not at `poll_ready`: readiness can include waiting on
        // a concurrency limit, which is queueing rather than connecting.
        let started = Instant::now();
        let fut = self.inner.call(req);

        Box::pin(async move {
            let result = fut.await;

            // Only a connection that was actually established is reported. A failed
            // connect is already covered by the error events the fetch layer emits, and
            // reporting it here would put failures into a namespace that means "how long
            // connecting takes".
            if result.is_ok() {
                emit_to_current(NetEvent::Connected {
                    elapsed: started.elapsed(),
                });
            }

            result
        })
    }
}

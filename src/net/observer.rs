//! Observer trait for receiving events from the fetch stack.

use crate::net::events::NetEvent;
use std::sync::Arc;

/// A NetObserver allows sending NetEvents to emitters.
/// Emitters bridge the net stack to other parts of the system (e.g. engine events, logging).
pub trait NetObserver: Send + Sync {
    /// Called for every [`NetEvent`] emitted during a request's lifecycle
    fn on_event(&self, ev: NetEvent);

    /// How many bytes of this response body, if any, the observer wants copied.
    ///
    /// `None` -- the default -- captures nothing and costs nothing. `Some(n)` tees the body
    /// as it is consumed, stopping at `n`.
    ///
    /// Asked once per response, after the headers are in, so the answer can depend on them:
    /// a large or unwanted response can be refused before anything is copied. The answer is
    /// used as given.
    ///
    /// `content_length` is the declared length where the server gave one; it is absent for a
    /// chunked response.
    ///
    /// The body is teed rather than buffered ahead, so the consumer never waits for the
    /// capture and the reported timings are unchanged.
    fn body_capture_limit(
        &self,
        _headers: &http::HeaderMap,
        _content_length: Option<u64>,
    ) -> Option<usize> {
        None
    }
}

tokio::task_local! {
    /// Observer of the request currently being driven on this task.
    ///
    /// Some timings are produced below the request layer, where the observer is not in
    /// scope: DNS resolution happens inside the connection pool, per *connection*, and the
    /// resolver is shared by every request on the client. A task-local carries the right
    /// observer down without threading it through reqwest.
    ///
    /// Task-local rather than thread-local because the fetch is async and may resume on a
    /// different worker thread between polls.
    pub(crate) static CURRENT_OBSERVER: Arc<dyn NetObserver + Send + Sync>;
}

/// Emit `ev` to the observer of the request running on this task, if there is one.
///
/// Silently drops the event outside a request (a connection warmed by something other
/// than a fetch, say) - there is nobody to report it to.
///
/// Native-only: every producer of these below-the-request events - DNS resolution and the
/// connect-timing layer - is itself native-only.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn emit_to_current(ev: NetEvent) {
    let _ = CURRENT_OBSERVER.try_with(|o| o.on_event(ev));
}

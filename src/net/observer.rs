//! Observer trait for receiving events from the fetch stack.

use crate::net::events::NetEvent;
use std::sync::Arc;

/// A NetObserver allows sending NetEvents to emitters.
/// Emitters bridge the net stack to other parts of the system (e.g. engine events, logging).
pub trait NetObserver: Send + Sync {
    /// Called for every [`NetEvent`] emitted during a request's lifecycle
    fn on_event(&self, ev: NetEvent);
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
pub(crate) fn emit_to_current(ev: NetEvent) {
    let _ = CURRENT_OBSERVER.try_with(|o| o.on_event(ev));
}

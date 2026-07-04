//! Observer trait for receiving events from the fetch stack.

use crate::net::events::NetEvent;

/// A NetObserver allows sending NetEvents to emitters.
/// Emitters bridge the net stack to other parts of the system (e.g. engine events, logging).
pub trait NetObserver: Send + Sync {
    /// Called for every [`NetEvent`] emitted during a request's lifecycle
    fn on_event(&self, ev: NetEvent);
}

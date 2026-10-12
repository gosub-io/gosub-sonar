//! One request's events as its caller sees them.
//!
//! Every request a [`Fetcher`](crate::net::fetcher::Fetcher) takes gets a [`Lifecycle`] in front
//! of the observer its context gave it. It opens the request with [`NetEvent::Accepted`] and lets
//! exactly one end through: the first [`Finished`](NetEvent::Finished),
//! [`Failed`](NetEvent::Failed) or [`Cancelled`](NetEvent::Cancelled). Whatever path a request
//! takes, refused before it was sent, cancelled while it waited, retried, an observer sees one
//! `Accepted` and one end, and nothing after the end.

use crate::net::events::NetEvent;
use crate::net::observer::NetObserver;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use url::Url;

/// A request's observer, opened with `Accepted` and closed by its first end. See the
/// [module docs](self).
pub(crate) struct Lifecycle {
    inner: Arc<dyn NetObserver + Send + Sync>,
    url: Url,
    ended: AtomicBool,
}

impl Lifecycle {
    /// Open the lifecycle of a request for `url`, as the caller asked for it: emits
    /// [`NetEvent::Accepted`]. `joined` says the request shares a fetch another caller started.
    pub(crate) fn accept(
        inner: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        joined: bool,
    ) -> Arc<Self> {
        inner.on_event(NetEvent::Accepted {
            url: url.clone(),
            joined,
        });
        Arc::new(Self {
            inner,
            url,
            ended: AtomicBool::new(false),
        })
    }

    /// Whether the request has had its end.
    pub(crate) fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }
}

impl NetObserver for Lifecycle {
    fn on_event(&self, ev: NetEvent) {
        if ev.is_terminal() {
            if self.ended.swap(true, Ordering::AcqRel) {
                return;
            }
        } else if self.has_ended() {
            return;
        }
        self.inner.on_event(ev);
    }

    fn body_capture_limit(
        &self,
        headers: &http::HeaderMap,
        content_length: Option<u64>,
    ) -> Option<usize> {
        self.inner.body_capture_limit(headers, content_length)
    }
}

impl Drop for Lifecycle {
    /// A request that is let go of without an end still gets one, so no observer is left
    /// waiting for it.
    fn drop(&mut self) {
        if !self.has_ended() {
            self.inner.on_event(NetEvent::Cancelled {
                url: self.url.clone(),
                reason: "request dropped before it ended",
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::test_support::RecordingObserver;
    use std::time::Duration;

    fn url() -> Url {
        Url::parse("https://example.test/").unwrap()
    }

    #[test]
    fn opens_with_accepted_and_lets_one_end_through() {
        let rec = Arc::new(RecordingObserver::new());
        let lifecycle = Lifecycle::accept(rec.clone(), url(), false);
        lifecycle.on_event(NetEvent::Started { url: url() });
        lifecycle.on_event(NetEvent::Finished {
            received_bytes: 1,
            elapsed: Duration::ZERO,
            url: url(),
        });
        lifecycle.on_event(NetEvent::Cancelled {
            url: url(),
            reason: "late",
        });
        lifecycle.on_event(NetEvent::Started { url: url() });
        drop(lifecycle);
        assert_eq!(rec.event_names(), ["Accepted", "Started", "Finished"]);
    }

    #[test]
    fn a_request_dropped_without_an_end_is_cancelled() {
        let rec = Arc::new(RecordingObserver::new());
        drop(Lifecycle::accept(rec.clone(), url(), true));
        assert_eq!(rec.event_names(), ["Accepted", "Cancelled"]);
    }
}

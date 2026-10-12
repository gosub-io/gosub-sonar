//! One request's events as its caller sees them.
//!
//! Every request a [`Fetcher`](crate::net::fetcher::Fetcher) takes gets a [`Lifecycle`] in front
//! of the observer its context gave it. It opens the request with [`NetEvent::Accepted`] and lets
//! exactly one end through: the first [`Finished`](NetEvent::Finished),
//! [`Failed`](NetEvent::Failed) or [`Cancelled`](NetEvent::Cancelled). Whatever path a request
//! takes, refused before it was sent, cancelled while it waited, retried, an observer sees one
//! `Accepted` and one end, and nothing after the end.
//!
//! Requests that share one fetch (coalescing) each keep their own lifecycle. The fetch reports
//! to a [`Shared`] observer: the request that started it gets everything, every request
//! still attached gets the progress and the end, and a request whose caller cancels ends with
//! `Cancelled` there and then, however long the fetch goes on for the others.

use crate::net::events::NetEvent;
use crate::net::fetcher_context::FetcherContext;
use crate::net::observer::NetObserver;
use crate::net::request_ref::RequestReference;
use crate::net::types::NetError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use url::Url;

/// A request's observer, opened with `Accepted` and closed by its first end. See the
/// [module docs](self).
pub(crate) struct Lifecycle {
    inner: Arc<dyn NetObserver + Send + Sync>,
    url: Url,
    ended: AtomicBool,
    /// Cancelled with the end, for whoever waits on it.
    ended_signal: CancellationToken,
    /// Told the request is outstanding work from `Accepted` until its end.
    work: Option<(Arc<dyn FetcherContext>, RequestReference)>,
}

impl Lifecycle {
    /// Open the lifecycle of a request for `url`, as the caller asked for it: emits
    /// [`NetEvent::Accepted`]. `joined` says the request shares a fetch another caller started.
    /// With `work`, the request counts as outstanding work for its reference
    /// ([`FetcherContext::on_ref_active`]) until it ends ([`FetcherContext::on_ref_done`]).
    pub(crate) fn accept(
        inner: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        joined: bool,
        work: Option<(Arc<dyn FetcherContext>, RequestReference)>,
    ) -> Arc<Self> {
        if let Some((ref ctx, reference)) = work {
            ctx.on_ref_active(reference);
        }
        inner.on_event(NetEvent::Accepted {
            url: url.clone(),
            joined,
        });
        Arc::new(Self {
            inner,
            url,
            ended: AtomicBool::new(false),
            ended_signal: CancellationToken::new(),
            work,
        })
    }

    /// The request's work is done.
    fn done(&self) {
        if let Some((ref ctx, reference)) = self.work {
            ctx.on_ref_done(reference);
        }
    }

    /// Whether the request has had its end.
    pub(crate) fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    /// Fires once the request has had its end.
    pub(crate) fn ended(&self) -> CancellationToken {
        self.ended_signal.clone()
    }

    /// The URL the request was accepted for.
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }
}

impl NetObserver for Lifecycle {
    fn on_event(&self, ev: NetEvent) {
        let terminal = ev.is_terminal();
        if terminal {
            if self.ended.swap(true, Ordering::AcqRel) {
                return;
            }
        } else if self.has_ended() {
            return;
        }
        self.inner.on_event(ev);
        if terminal {
            self.done();
            self.ended_signal.cancel();
        }
    }

    fn body_capture_limit(
        &self,
        headers: &http::HeaderMap,
        content_length: Option<u64>,
    ) -> Option<usize> {
        self.inner.body_capture_limit(headers, content_length)
    }
}

/// The observer a shared fetch reports to: see the [module docs](self).
pub(crate) struct Shared {
    /// The request that started the fetch: gets every event.
    leader: Arc<Lifecycle>,
    /// The requests still waiting on the fetch, the leader among them until it ends, and the
    /// fetch's end once it has had one, for a request that joins after it.
    attached: Mutex<(Vec<Arc<Lifecycle>>, Option<NetEvent>)>,
}

impl Shared {
    pub(crate) fn new(leader: Arc<Lifecycle>) -> Arc<Self> {
        Arc::new(Self {
            attached: Mutex::new((vec![leader.clone()], None)),
            leader,
        })
    }

    /// Another request joins the fetch. One that joins once the fetch has ended (it can, until
    /// the fetch is out of the in-flight map) gets that end at once.
    pub(crate) fn attach(&self, request: Arc<Lifecycle>) {
        let end = {
            let mut state = self.lock();
            match state.1.as_ref() {
                Some(end) => copy(end),
                None => {
                    state.0.push(request.clone());
                    None
                }
            }
        };
        if let Some(end) = end {
            request.on_event(end);
        }
    }

    /// A request leaves the fetch, ending on its own.
    pub(crate) fn detach(&self, request: &Arc<Lifecycle>) {
        self.lock().0.retain(|r| !Arc::ptr_eq(r, request));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (Vec<Arc<Lifecycle>>, Option<NetEvent>)> {
        self.attached.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl NetObserver for Shared {
    fn on_event(&self, ev: NetEvent) {
        let shared = ev.is_terminal() || matches!(ev, NetEvent::Progress { .. });
        if !shared {
            self.leader.on_event(ev);
            return;
        }
        let attached: Vec<Arc<Lifecycle>> = if ev.is_terminal() {
            let mut state = self.lock();
            state.1 = copy(&ev);
            std::mem::take(&mut state.0)
        } else {
            self.lock().0.clone()
        };
        let mut ev = Some(ev);
        for (i, request) in attached.iter().enumerate() {
            let this = if i + 1 == attached.len() {
                ev.take()
            } else {
                ev.as_ref().and_then(copy)
            };
            if let Some(this) = this {
                request.on_event(this);
            }
        }
    }

    fn body_capture_limit(
        &self,
        headers: &http::HeaderMap,
        content_length: Option<u64>,
    ) -> Option<usize> {
        self.leader.body_capture_limit(headers, content_length)
    }
}

/// `ev` for another request of the same fetch: the progress and the ends, the only events
/// [`Shared`] hands to more than one. A `Failed` keeps its `NetError` when it carries one, and
/// its message otherwise.
fn copy(ev: &NetEvent) -> Option<NetEvent> {
    Some(match ev {
        NetEvent::Progress {
            received_bytes,
            expected_length,
            elapsed,
        } => NetEvent::Progress {
            received_bytes: *received_bytes,
            expected_length: *expected_length,
            elapsed: *elapsed,
        },
        NetEvent::Finished {
            received_bytes,
            elapsed,
            url,
        } => NetEvent::Finished {
            received_bytes: *received_bytes,
            elapsed: *elapsed,
            url: url.clone(),
        },
        NetEvent::Cancelled { url, reason } => NetEvent::Cancelled {
            url: url.clone(),
            reason,
        },
        NetEvent::Failed { url, error } => NetEvent::Failed {
            url: url.clone(),
            error: match error.downcast_ref::<NetError>() {
                Some(e) => anyhow::Error::new(e.clone()),
                None => anyhow::anyhow!("{error:#}"),
            },
        },
        _ => return None,
    })
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
            self.done();
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
        let lifecycle = Lifecycle::accept(rec.clone(), url(), false, None);
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

    /// A shared fetch: everything reaches the request that started it, the progress and the
    /// end reach every request attached, and one that left has nothing more.
    #[test]
    fn a_shared_fetch_reports_to_each_request() {
        let (lead, follow, gone) = (
            Arc::new(RecordingObserver::new()),
            Arc::new(RecordingObserver::new()),
            Arc::new(RecordingObserver::new()),
        );
        let leader = Lifecycle::accept(lead.clone(), url(), false, None);
        let shared = Shared::new(leader);
        let follower = Lifecycle::accept(follow.clone(), url(), true, None);
        let leaver = Lifecycle::accept(gone.clone(), url(), true, None);
        shared.attach(follower.clone());
        shared.attach(leaver.clone());
        shared.on_event(NetEvent::Started { url: url() });
        shared.on_event(NetEvent::Progress {
            received_bytes: 1,
            expected_length: None,
            elapsed: Duration::ZERO,
        });
        shared.detach(&leaver);
        leaver.on_event(NetEvent::Cancelled {
            url: url(),
            reason: "cancelled by the caller",
        });
        shared.on_event(NetEvent::Failed {
            url: url(),
            error: anyhow::Error::new(NetError::Timeout("slow".into())),
        });
        assert_eq!(
            lead.event_names(),
            ["Accepted", "Started", "Progress", "Failed"]
        );
        assert_eq!(follow.event_names(), ["Accepted", "Progress", "Failed"]);
        assert_eq!(gone.event_names(), ["Accepted", "Progress", "Cancelled"]);
    }

    /// A request that joins a fetch after the fetch's end still gets that end.
    #[test]
    fn a_request_that_joins_after_the_end_gets_it() {
        let lead = Arc::new(RecordingObserver::new());
        let shared = Shared::new(Lifecycle::accept(lead.clone(), url(), false, None));
        shared.on_event(NetEvent::Finished {
            received_bytes: 1,
            elapsed: Duration::ZERO,
            url: url(),
        });
        let late = Arc::new(RecordingObserver::new());
        let joined = Lifecycle::accept(late.clone(), url(), true, None);
        shared.attach(joined.clone());
        assert!(joined.has_ended());
        assert_eq!(late.event_names(), ["Accepted", "Finished"]);
    }

    #[test]
    fn a_request_dropped_without_an_end_is_cancelled() {
        let rec = Arc::new(RecordingObserver::new());
        drop(Lifecycle::accept(rec.clone(), url(), true, None));
        assert_eq!(rec.event_names(), ["Accepted", "Cancelled"]);
    }
}

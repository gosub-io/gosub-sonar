//! Retry of transient failures with exponential backoff.
//!
//! [`FetcherConfig::retry`](crate::net::fetcher::FetcherConfig::retry) holds a [`RetryPolicy`].
//! Retried are connect failures, transfers that broke off, and 502/503/504 responses, for
//! idempotent methods only. `Retry-After` is honoured. A custom `dns_resolver` failure shows up
//! as a connect failure and is retried like one.
//!
//! A streamed response is retried until the start of its body is in: the headers and the first
//! few kilobytes read to sniff the content (the peek). Nothing has reached the caller before
//! that, so a connection that breaks there is still recovered; after it the body belongs to the
//! caller. A buffered fetch is retried as a whole.
//!
//! The request still ends once: an attempt that is retried does not report its end. Each
//! attempt reports its own `Started`, `RequestSent`, headers and progress, and
//! [`NetEvent::Retrying`] comes before every wait, naming why the attempt before it failed. Only
//! the last attempt's `Finished`, `Failed` or `Cancelled` is reported.
use crate::net::events::NetEvent;
use crate::net::observer::NetObserver;
use crate::net::transport::TransportErrorKind;
use crate::net::types::NetError;
use http::{header, HeaderMap};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// When and how often a failed request is re-sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt. `0` disables retrying.
    pub max_retries: u32,
    /// Wait before the first retry. Doubles per retry up to `max_backoff`, with jitter down to
    /// half the value.
    pub initial_backoff: Duration,
    /// Longest wait between attempts. A `Retry-After` beyond it stops the retries.
    pub max_backoff: Duration,
    /// Response statuses that are retried. Default 502, 503, 504.
    pub statuses: Vec<u16>,
    /// Retry timeouts too. Off by default since it can blow past every other deadline.
    pub on_timeout: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(5),
            statuses: vec![502, 503, 504],
            on_timeout: false,
        }
    }
}

impl RetryPolicy {
    /// Whether an attempt that failed with `err` is retried.
    pub fn retries_error(&self, err: &NetError) -> bool {
        match err {
            NetError::Transport(t) => match t.kind {
                TransportErrorKind::Connect | TransportErrorKind::Body => true,
                TransportErrorKind::Timeout => self.on_timeout,
                _ => false,
            },
            NetError::Io(_) => true,
            NetError::Timeout(_) => self.on_timeout,
            _ => false,
        }
    }

    /// Whether a response with `status` is retried.
    pub fn retries_status(&self, status: u16) -> bool {
        self.statuses.contains(&status)
    }

    /// Wait before retry `retry` (1-based). `None` if `retry_after` exceeds `max_backoff`,
    /// meaning: stop retrying.
    pub fn backoff(&self, retry: u32, retry_after: Option<Duration>) -> Option<Duration> {
        if let Some(asked) = retry_after {
            return (asked <= self.max_backoff).then_some(asked);
        }
        let exp = retry.saturating_sub(1).min(31);
        let base = self
            .initial_backoff
            .checked_mul(1u32 << exp)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff);
        // equal jitter: [base / 2, base]
        let half = base / 2;
        let jitter = half.mul_f64(random_unit());
        Some(half + jitter)
    }
}

/// Uniform-ish number in `[0, 1)` from std's randomised hasher, so we need no rand crate.
fn random_unit() -> f64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(0x9e37_79b9_7f4a_7c15);
    (h.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// Parses `Retry-After` (seconds or HTTP date). `None` if absent or unparsable; a past date
/// gives zero.
///
/// A date may come in any of the three HTTP-date formats, as RFC 9110 §5.6.7 requires of a
/// recipient: IMF-fixdate, RFC 850 and asctime. An RFC 2822 date with a numeric zone is
/// accepted too.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    // delay-seconds is `1*DIGIT` (RFC 9110 §10.2.3): no sign, no bound. A number too large to
    // hold is still a long wait, so it saturates rather than being dropped and retried early.
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        let secs = value.parse::<u64>().unwrap_or(u64::MAX);
        return Some(Duration::from_secs(secs));
    }
    let at = crate::net::cache::parse_http_date(value).or_else(|| {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .map(|at| at.with_timezone(&chrono::Utc))
    })?;
    let wait = at.signed_duration_since(chrono::Utc::now());
    Some(wait.to_std().unwrap_or(Duration::ZERO))
}

/// Runs `attempt` until its result is not retryable or the policy is exhausted. `meta` gives
/// the status and headers of a completed attempt (a 503 is a success to the transport).
/// One attempt's view of the request's observer: everything passes, except the attempt's end,
/// which is held until [`with_retries`] knows whether the attempt is the last one. A retried
/// attempt's end is dropped with the view; the last attempt's is passed on, and so is anything
/// it reports later (the end of a streamed body).
struct AttemptView {
    inner: Arc<dyn NetObserver + Send + Sync>,
    held: Mutex<Option<NetEvent>>,
    last: AtomicBool,
}

impl AttemptView {
    fn new(inner: Arc<dyn NetObserver + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            held: Mutex::new(None),
            last: AtomicBool::new(false),
        })
    }

    /// This attempt is the last: pass on its end, now or when it comes.
    fn release(&self) {
        let held = {
            let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
            self.last.store(true, Ordering::Release);
            held.take()
        };
        if let Some(ev) = held {
            self.inner.on_event(ev);
        }
    }
}

impl NetObserver for AttemptView {
    fn on_event(&self, ev: NetEvent) {
        if ev.is_terminal() && !self.last.load(Ordering::Acquire) {
            let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
            if !self.last.load(Ordering::Acquire) {
                *held = Some(ev);
                return;
            }
        }
        self.inner.on_event(ev);
    }

    fn body_capture_limit(
        &self,
        headers: &HeaderMap,
        content_length: Option<u64>,
    ) -> Option<usize> {
        self.inner.body_capture_limit(headers, content_length)
    }
}

/// Run `attempt` until it succeeds, fails for good, or the policy runs out, handing each try
/// an observer that reports only the last attempt's end (see the module docs).
pub(crate) async fn with_retries<T, F, Fut>(
    policy: Option<&RetryPolicy>,
    method: &http::Method,
    url: &url::Url,
    cancel: &tokio_util::sync::CancellationToken,
    observer: &Arc<dyn NetObserver + Send + Sync>,
    mut attempt: F,
    meta: impl Fn(&T) -> (u16, &HeaderMap),
) -> Result<T, NetError>
where
    F: FnMut(Arc<dyn NetObserver + Send + Sync>) -> Fut,
    Fut: std::future::Future<Output = Result<T, NetError>>,
{
    let Some(policy) = policy.filter(|_| method.is_idempotent()) else {
        return attempt(observer.clone()).await;
    };
    let mut retries = 0;
    loop {
        let view = AttemptView::new(observer.clone());
        let result = attempt(view.clone()).await;
        let (reason, asked) = match &result {
            Ok(t) => {
                let (status, headers) = meta(t);
                if !policy.retries_status(status) {
                    view.release();
                    return result;
                }
                (format!("status {status}"), retry_after(headers))
            }
            Err(e) if policy.retries_error(e) => (e.to_string(), None),
            Err(_) => {
                view.release();
                return result;
            }
        };
        if retries >= policy.max_retries {
            view.release();
            return result;
        }
        retries += 1;
        let Some(delay) = policy.backoff(retries, asked) else {
            view.release();
            return result;
        };
        // The attempt is over and retried: its end is not the request's. A streamed response
        // being dropped here reports its cancel to the view, which drops it too.
        drop(result);
        drop(view);
        observer.on_event(NetEvent::Retrying {
            url: url.clone(),
            attempt: retries,
            delay,
            reason,
        });
        tokio::select! {
            _ = cancel.cancelled() => {
                observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "cancelled while waiting to retry" });
                return Err(NetError::Cancelled("cancelled while waiting to retry".into()));
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::transport::TransportError;
    use std::sync::Arc;

    fn transport(kind: TransportErrorKind) -> NetError {
        NetError::Transport(TransportError {
            kind,
            message: "x".into(),
        })
    }

    #[test]
    fn retries_transient_errors_only() {
        let p = RetryPolicy::default();
        assert!(p.retries_error(&transport(TransportErrorKind::Connect)));
        assert!(p.retries_error(&transport(TransportErrorKind::Body)));
        assert!(p.retries_error(&NetError::Io(Arc::new(std::io::Error::other("eof")))));
        assert!(!p.retries_error(&transport(TransportErrorKind::Timeout)));
        assert!(!p.retries_error(&NetError::Timeout("t".into())));
        assert!(!p.retries_error(&transport(TransportErrorKind::Builder)));
        assert!(!p.retries_error(&NetError::Redirect(Arc::new(anyhow::anyhow!("r")))));
        assert!(!p.retries_error(&NetError::Cancelled("c".into())));

        let p = RetryPolicy {
            on_timeout: true,
            ..Default::default()
        };
        assert!(p.retries_error(&transport(TransportErrorKind::Timeout)));
        assert!(p.retries_error(&NetError::Timeout("t".into())));
    }

    #[test]
    fn retries_configured_statuses_only() {
        let p = RetryPolicy::default();
        assert!(p.retries_status(503));
        assert!(!p.retries_status(500));
        assert!(!p.retries_status(429));
    }

    #[test]
    fn backoff_growth_jitter_and_cap() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(350),
            ..Default::default()
        };
        let within = |retry, lo: u64, hi: u64| {
            let d = p.backoff(retry, None).unwrap();
            assert!(
                d >= Duration::from_millis(lo) && d <= Duration::from_millis(hi),
                "retry {retry}: {d:?} not in {lo}..={hi} ms"
            );
        };
        within(1, 50, 100);
        within(2, 100, 200);
        within(3, 175, 350);
        within(40, 175, 350);
    }

    #[test]
    fn retry_after_overrides_backoff_or_stops() {
        let p = RetryPolicy::default();
        assert_eq!(
            p.backoff(1, Some(Duration::from_secs(2))),
            Some(Duration::from_secs(2))
        );
        assert_eq!(p.backoff(1, Some(Duration::from_secs(60))), None);
    }

    #[test]
    fn retry_after_header_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert(header::RETRY_AFTER, "7".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(7)));
        h.insert(header::RETRY_AFTER, "soon".parse().unwrap());
        assert_eq!(retry_after(&h), None);
        let future = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc2822();
        h.insert(header::RETRY_AFTER, future.parse().unwrap());
        let d = retry_after(&h).unwrap();
        assert!(
            d > Duration::from_secs(80) && d <= Duration::from_secs(90),
            "{d:?}"
        );
        h.insert(
            header::RETRY_AFTER,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&h), Some(Duration::ZERO));
    }

    /// RFC 9110 §10.2.3: `delay-seconds = 1*DIGIT`. A sign is not part of it; a number past
    /// what a u64 holds still asks for a very long wait.
    #[test]
    fn retry_after_seconds_are_digits_only() {
        let parsed = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::RETRY_AFTER, value.parse().unwrap());
            retry_after(&h)
        };
        assert_eq!(parsed("+5"), None);
        assert_eq!(parsed("-5"), None);
        assert_eq!(parsed("5.5"), None);
        assert_eq!(parsed(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(
            parsed("184467440737095516160"),
            Some(Duration::from_secs(u64::MAX))
        );
        // Past `max_backoff`, so the policy gives up rather than retrying soon.
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff(1, parsed("184467440737095516160")), None);
    }

    /// RFC 9110 §5.6.7: "A recipient that parses a timestamp value in an HTTP field MUST accept
    /// all three HTTP-date formats." An hour ahead, in each of them.
    #[test]
    fn retry_after_takes_every_http_date_format() {
        let ahead = chrono::Utc::now() + chrono::Duration::hours(1);
        for date in [
            ahead.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            ahead.format("%A, %d-%b-%y %H:%M:%S GMT").to_string(),
            ahead.format("%a %b %e %H:%M:%S %Y").to_string(),
        ] {
            let mut h = HeaderMap::new();
            h.insert(header::RETRY_AFTER, date.parse().unwrap());
            let wait = retry_after(&h).unwrap_or_else(|| panic!("{date}"));
            assert!(
                wait > Duration::from_secs(3500) && wait <= Duration::from_secs(3600),
                "{date}: {wait:?}"
            );
        }
    }
}

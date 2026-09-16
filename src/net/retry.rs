//! Retry of transient failures with exponential backoff.
//!
//! [`FetcherConfig::retry`](crate::net::fetcher::FetcherConfig::retry) holds a [`RetryPolicy`].
//! Retried are connect failures, transfers that broke off, and 502/503/504 responses, for
//! idempotent methods only. `Retry-After` is honoured. A custom `dns_resolver` failure shows up
//! as a connect failure and is retried like one.
//!
//! A streamed response is retried until its headers arrive; after that the body belongs to the
//! caller. A buffered fetch is retried as a whole. Each attempt emits its own events, plus
//! [`NetEvent::Retrying`] before every wait.
use crate::net::events::NetEvent;
use crate::net::transport::TransportErrorKind;
use crate::net::types::NetError;
use http::{header, HeaderMap};
use std::hash::{BuildHasher, Hasher};
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
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let wait = at.signed_duration_since(chrono::Utc::now());
    Some(wait.to_std().unwrap_or(Duration::ZERO))
}

/// Runs `attempt` until its result is not retryable or the policy is exhausted. `meta` gives
/// the status and headers of a completed attempt (a 503 is a success to the transport).
pub(crate) async fn with_retries<T, F, Fut>(
    policy: Option<&RetryPolicy>,
    method: &http::Method,
    url: &url::Url,
    cancel: &tokio_util::sync::CancellationToken,
    observer: &std::sync::Arc<dyn crate::net::observer::NetObserver + Send + Sync>,
    mut attempt: F,
    meta: impl Fn(&T) -> (u16, &HeaderMap),
) -> Result<T, NetError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, NetError>>,
{
    let Some(policy) = policy.filter(|_| method.is_idempotent()) else {
        return attempt().await;
    };
    let mut retries = 0;
    loop {
        let result = attempt().await;
        let (reason, asked) = match &result {
            Ok(t) => {
                let (status, headers) = meta(t);
                if !policy.retries_status(status) {
                    return result;
                }
                (format!("status {status}"), retry_after(headers))
            }
            Err(e) if policy.retries_error(e) => (e.to_string(), None),
            Err(_) => return result,
        };
        if retries >= policy.max_retries {
            return result;
        }
        retries += 1;
        let Some(delay) = policy.backoff(retries, asked) else {
            return result;
        };
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
}

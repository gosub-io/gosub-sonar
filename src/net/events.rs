//! Events emitted by the fetch stack to observers during a request lifecycle.

use http::HeaderMap;
use std::time::Duration;
use url::Url;

/// Events that are emitted by the net::fetch() functions
#[derive(Debug)]
pub enum NetEvent {
    /// Io error happened
    Io {
        /// Description of the I/O error
        message: String,
    },
    /// Warning happened
    Warning {
        /// URL the warning applies to
        url: Url,
        /// Description of the warning
        message: String,
    },
    /// Resource started loading
    Started {
        /// URL being fetched
        url: Url,
    },
    /// Resource was redirected to another URL
    Redirected {
        /// URL that issued the redirect
        from: Url,
        /// URL being redirected to
        to: Url,
        /// HTTP status code of the redirect response (e.g. 301, 302)
        status: u16,
    },
    /// Response headers were received
    ResponseHeaders {
        /// URL the response was received from
        url: Url,
        /// HTTP status code of the response
        status: u16,
        /// Response headers
        headers: HeaderMap,
    },
    /// Progress update: how many bytes have been read so far
    Progress {
        /// Number of body bytes received so far
        received_bytes: u64,
        /// Total expected body length, if known from headers
        expected_length: Option<u64>,
        /// Time elapsed since the request started
        elapsed: Duration,
    },
    /// Resource finished loading
    Finished {
        /// Total number of body bytes received
        received_bytes: u64,
        /// Time elapsed since the request started
        elapsed: Duration,
        /// URL that finished loading
        url: Url,
    },
    /// Resource failed to fetch
    Failed {
        /// URL that failed to load
        url: Url,
        /// Error that caused the failure
        error: anyhow::Error,
    },
    /// Resource fetching was cancelled
    Cancelled {
        /// URL whose fetch was cancelled
        url: Url,
        /// Short static description of why the fetch was cancelled
        reason: &'static str,
    },
}

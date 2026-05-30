//! Events emitted by the fetch stack to observers during a request lifecycle.

use http::HeaderMap;
use std::time::Duration;
use url::Url;

/// Events that are emitted by the net::fetch() functions
#[derive(Debug)]
pub enum NetEvent {
    /// Io error happened
    Io { message: String },
    /// Warning happened
    Warning { url: Url, message: String },
    /// Resource started loading
    Started { url: Url },
    /// Resource was redirected to another URL
    Redirected { from: Url, to: Url, status: u16 },
    /// Response headers were received
    ResponseHeaders {
        url: Url,
        status: u16,
        headers: HeaderMap,
    },
    /// Progress update: how many bytes have been read so far
    Progress {
        received_bytes: u64,
        expected_length: Option<u64>,
        elapsed: Duration,
    },
    /// Resource finished loading
    Finished {
        received_bytes: u64,
        elapsed: Duration,
        url: Url,
    },
    /// Resource failed to fetch
    Failed { url: Url, error: anyhow::Error },
    /// Resource fetching was cancelled
    Cancelled { url: Url, reason: &'static str },
}

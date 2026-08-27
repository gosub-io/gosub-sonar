//! Events emitted by the fetch stack to observers during a request lifecycle.

use crate::net::auth::{AuthChallenge, AuthTarget};
use crate::net::tls::TlsError;
use crate::net::types::BlockReason;
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
    /// TLS handshake failed for this hop. The request fails with the same error as
    /// [`NetError::Tls`](crate::net::types::NetError::Tls).
    TlsFailed {
        /// URL of the hop
        url: Url,
        /// The error
        error: TlsError,
    },
    /// A request hop was refused by policy and never sent
    Blocked {
        /// The refused hop (see [`NetError::Blocked`](crate::net::types::NetError::Blocked))
        url: Url,
        /// Why the request was refused
        reason: BlockReason,
    },
    /// A CORS preflight `OPTIONS` is about to be sent for this hop, because the request's
    /// method or headers need the server's approval and no cached grant covered them.
    /// See [`cors`](crate::net::cors).
    CorsPreflight {
        /// The hop being preflighted
        url: Url,
    },
    /// The origin server (`401`) or a proxy (`407`) demanded credentials for this hop.
    ///
    /// See [`auth`](crate::net::auth). Emitted once per challenged response, answered or not, so
    /// an embedder that cannot answer synchronously can prompt the user and re-submit the fetch.
    AuthRequired {
        /// The hop that was challenged
        url: Url,
        /// Whether the origin server or a proxy is asking
        target: AuthTarget,
        /// Every challenge the response offered, in the order the server listed them. Empty when
        /// the challenge header was missing or unparsable.
        challenges: Vec<AuthChallenge>,
        /// Whether credentials were found and the hop re-sent with them. `false` means the
        /// `401`/`407` is the response the caller gets.
        retried: bool,
    },
    /// Resource fetching was cancelled
    Cancelled {
        /// URL whose fetch was cancelled
        url: Url,
        /// Short static description of why the fetch was cancelled
        reason: &'static str,
    },
}

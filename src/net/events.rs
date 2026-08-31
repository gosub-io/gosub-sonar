//! Events emitted by the fetch stack to observers during a request lifecycle.

use crate::net::tls::TlsError;
use crate::net::types::BlockReason;
use http::HeaderMap;
use std::time::Duration;
use url::Url;

/// Events that are emitted by the net::fetch() functions
///
/// Non-exhaustive: new events are added as the stack learns to report more, so a `match`
/// over this needs a catch-all arm.
#[derive(Debug)]
#[non_exhaustive]
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
    /// A hostname was resolved to addresses.
    ///
    /// Only emitted when a connection actually had to be opened - a request served from
    /// the connection pool resolves nothing and reports nothing, which is the honest
    /// answer rather than a zero.
    ///
    /// Requires a [`DnsResolver`](crate::net::dns::DnsResolver) to be configured on the
    /// fetcher; reqwest's built-in resolution happens below our level and cannot be timed.
    /// [`SystemResolver`](crate::net::dns::SystemResolver) is the drop-in for embedders
    /// with no resolution policy of their own.
    DnsResolved {
        /// Hostname that was looked up
        host: String,
        /// How long resolution took
        elapsed: Duration,
        /// Number of addresses returned
        addr_count: usize,
    },
    /// A new connection was established: TCP handshake plus, for https, the TLS
    /// handshake.
    ///
    /// Like [`NetEvent::DnsResolved`], only emitted when a connection actually had to be
    /// opened. A request served from the pool reports nothing, because it spent no time
    /// connecting.
    ///
    /// Carries no host: reqwest's connector request type is opaque, so the layer cannot
    /// read it. The observer receiving this belongs to the request that caused the
    /// connect, which is the attribution that matters.
    Connected {
        /// How long the connection took to establish
        elapsed: Duration,
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
    /// A CORS preflight `OPTIONS` round-trip completed and a response came back. Paired
    /// with the [`NetEvent::CorsPreflight`] that announced it.
    ///
    /// A preflight blocks the request that needs it, so this is real latency the embedder
    /// would otherwise see as unexplained time before the response.
    ///
    /// Emitted for a response that arrived, whatever it said: if validation then rejects
    /// it the request fails with [`BlockReason::Cors`](crate::net::types::BlockReason),
    /// but the round-trip was still paid for. A preflight that never got a response - the
    /// send failed, or the fetch was cancelled - reports nothing here and is covered by
    /// the resulting [`NetEvent::Failed`] or [`NetEvent::Cancelled`].
    ///
    /// A hop covered by a cached grant emits neither this nor
    /// [`NetEvent::CorsPreflight`]: no `OPTIONS` was sent.
    CorsPreflightDone {
        /// The hop that was preflighted
        url: Url,
        /// How long the `OPTIONS` round-trip took
        elapsed: Duration,
    },
    /// Resource fetching was cancelled
    Cancelled {
        /// URL whose fetch was cancelled
        url: Url,
        /// Short static description of why the fetch was cancelled
        reason: &'static str,
    },
}

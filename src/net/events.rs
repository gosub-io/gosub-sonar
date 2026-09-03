//! Events emitted by the fetch stack to observers during a request lifecycle.

use crate::net::auth::{AuthChallenge, AuthTarget};
use crate::net::cache::CacheOutcome;
use crate::net::tls::TlsError;
use crate::net::types::BlockReason;
use http::{HeaderMap, Method};
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
    /// A new connection was established.
    ///
    /// This *encloses* [`NetEvent::DnsResolved`] rather than following it: resolution
    /// happens inside reqwest's connector and this times the connector, so the span covers
    /// name resolution, the TCP handshake, and for https the TLS handshake on top. The
    /// timing phases nest rather than tile; their durations do not add up to elapsed time.
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
    /// The request line and headers sent for one hop.
    ///
    /// Emitted per hop, so a redirect chain reports each leg separately; the headers differ
    /// between legs, since credentials and conditional headers are added for a single send
    /// and a method downgrade drops the body.
    ///
    /// These are the headers this crate set. The HTTP client adds `host`, `accept-encoding`
    /// and its configured user agent below this layer, so this is not a byte-exact capture
    /// of what left the socket.
    RequestSent {
        /// Target of this hop
        url: Url,
        /// HTTP method for this hop
        method: Method,
        /// Headers this stack set for this hop
        headers: HeaderMap,
    },

    /// The leading bytes of the response body.
    ///
    /// Only emitted when an observer asks for a copy via
    /// [`NetObserver::body_capture_limit`], which also sets the byte limit; nothing is copied
    /// otherwise. The bytes are teed as the consumer reads the body, so the consumer never
    /// waits for the capture, and the event lands when the body ends, fails, or is dropped.
    ///
    /// [`NetObserver::body_capture_limit`]: crate::net::observer::NetObserver::body_capture_limit
    BodyPreview {
        /// URL the body belongs to
        url: Url,
        /// Up to the observer's requested limit, as received: not decoded, not necessarily
        /// valid UTF-8.
        body: Vec<u8>,
        /// Whether the body continued past what was captured
        truncated: bool,
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
    /// Response headers were received for a hop.
    ///
    /// Emitted per hop, like the other per-connection events: the first one marks
    /// time-to-first-byte, and a redirect chain reports one for every hop it waited on
    /// (each paired with the [`NetEvent::Redirected`] that followed it).
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
    /// The request failed. Emitted once for any request that ends in an error, whatever
    /// went wrong and wherever it went wrong - a refused connection, a rejected policy
    /// check, a body that died mid-stream.
    ///
    /// The events that name a specific cause - [`NetEvent::Blocked`],
    /// [`NetEvent::TlsFailed`] - are emitted first and carry the detail; this one is the
    /// terminal event, so an observer can tell a dead request from a slow one without
    /// matching every cause it might have.
    ///
    /// A cancelled request is not a failure: it reports [`NetEvent::Cancelled`] and
    /// nothing else. Every request therefore ends in exactly one of [`NetEvent::Finished`],
    /// `Failed`, or [`NetEvent::Cancelled`].
    Failed {
        /// URL that failed to load
        url: Url,
        /// Error that caused the failure
        error: anyhow::Error,
    },
    /// TLS handshake failed for this hop. The request fails with the same error as
    /// [`NetError::Tls`](crate::net::types::NetError::Tls), and [`NetEvent::Failed`]
    /// follows as the terminal event.
    TlsFailed {
        /// URL of the hop
        url: Url,
        /// The error
        error: TlsError,
    },
    /// A request hop was refused by policy and never sent. [`NetEvent::Failed`] follows as
    /// the terminal event.
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
    /// The HTTP cache was used for this hop: a stored response was served, one was confirmed by
    /// a `304`, a response was written, or an unsafe method dropped what was stored.
    /// See [`cache`](crate::net::cache).
    Cache {
        /// The hop the cache acted on
        url: Url,
        /// What it did
        outcome: CacheOutcome,
    },
    /// Resource fetching was cancelled
    Cancelled {
        /// URL whose fetch was cancelled
        url: Url,
        /// Short static description of why the fetch was cancelled
        reason: &'static str,
    },
}

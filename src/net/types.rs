//! Core types for fetch requests, responses, errors, and priorities.

use crate::net::mixed_content::{is_origin_potentially_trustworthy, MixedContentPolicy};
use crate::net::referrer::{self, ReferrerPolicy};
use crate::net::request_ref::RequestReference;
use crate::net::shared_body::SharedBody;
use crate::net::utils::{normalize_url, short_hash, BytesAsyncReader};
use crate::types::{PeekBuf, RequestId};
use bytes::Bytes;
use http::{header, HeaderMap, Method};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, ReadBuf};
use url::{Origin, Url};

/// Priority of the scheduled request. Documents usually have high priority, while images have low.
/// Currently, the scheduler uses a round-robin system to load resources
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub enum Priority {
    /// Fetched before all lower priorities (e.g. primary documents)
    High,
    /// Default priority for most resources
    #[default]
    Normal,
    /// Fetched after normal-priority resources (e.g. images)
    Low,
    /// Only fetched when nothing else is pending (e.g. prefetches)
    Idle,
}

impl Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Priority::High => "High",
            Priority::Normal => "Normal",
            Priority::Low => "Low",
            Priority::Idle => "Idle",
        };
        f.write_str(s)
    }
}

/// Broad category of the resource being fetched.
///
/// Callers that need finer-grained classification can extend this at the
/// application layer; the net crate only uses these values for logging and
/// to pass them back through [`crate::net::fetcher_context::FetcherContext::observer_for`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum ResourceKind {
    /// Top-level or primary resource (e.g. a document, feed, or binary download)
    #[default]
    Primary,
    /// Secondary asset loaded on behalf of a primary resource (e.g. image, font, script)
    Asset,
    /// Other or unspecified resource kind
    Other,
}

/// Who or what triggered the fetch.
///
/// Used for logging and passed back through [`crate::net::fetcher_context::FetcherContext::observer_for`];
/// the net crate does not alter scheduling based on this value.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum Initiator {
    /// Triggered by a user action (e.g. address bar, link click, button)
    #[default]
    User,
    /// Triggered programmatically by the application
    Application,
    /// Other or unspecified initiator
    Other,
}

/// Metadata returned by the FetchResult
#[derive(Clone, Debug)]
pub struct FetchResultMeta {
    /// Final URL after redirects
    pub final_url: Url,
    /// HTTP status code
    pub status: u16,
    /// HTTP status reason phrase
    pub status_text: String,
    /// Response headers
    pub headers: HeaderMap,
    /// Length of the content (if known from headers)
    pub content_length: Option<u64>,
    /// Content-Type header (if any)
    pub content_type: Option<String>,
    /// True if the response has a body (e.g. HEAD requests do not)
    pub has_body: bool,
}

/// Why a request hop was refused. The refused hop is never sent.
///
/// Carried by [`NetError::Blocked`] and [`NetEvent::Blocked`](crate::net::events::NetEvent::Blocked)
/// so callers can distinguish a deliberate refusal from a transport failure without matching on
/// error strings.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum BlockReason {
    /// An insecure sub-resource was requested by a secure document.
    /// See [`mixed_content`](crate::net::mixed_content).
    MixedContent,
    /// Rejected by [`FetcherContext::is_url_allowed`](crate::net::fetcher_context::FetcherContext::is_url_allowed).
    UrlPolicy,
    /// The URL scheme is not `http` or `https`.
    UnsupportedScheme,
}

impl Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BlockReason::MixedContent => "mixed content",
            BlockReason::UrlPolicy => "blocked by URL policy",
            BlockReason::UnsupportedScheme => "unsupported URL scheme",
        };
        f.write_str(s)
    }
}

/// Network-level errors.
#[derive(Debug, thiserror::Error, Clone)]
pub enum NetError {
    /// Request hop refused by policy. Applies to the initial URL and to every redirect target.
    #[error("net error: blocked: {reason}: {url}")]
    Blocked {
        /// Why the request was refused
        reason: BlockReason,
        /// URL that was refused. On a redirect chain this is the hop that was blocked,
        /// not the URL originally requested.
        url: Url,
    },

    /// Error reported by the underlying HTTP client
    #[error("net error: reqwest: {0}")]
    Reqwest(#[from] Arc<reqwest::Error>),

    /// Redirect could not be followed (e.g. too many redirects, invalid target)
    #[error("net error: redirect: {0}")]
    Redirect(Arc<anyhow::Error>),

    /// I/O error while transferring data
    #[error("net error: I/O: {0}")]
    Io(#[from] Arc<std::io::Error>),

    /// Request was cancelled before it completed; the string describes why
    #[error("net error: cancelled: {0}")]
    Cancelled(String),

    /// Error while reading the response body
    #[error(transparent)]
    Read(Arc<anyhow::Error>),

    /// Any other error not covered by the variants above
    #[error(transparent)]
    Other(Arc<anyhow::Error>),

    /// Request did not complete within the configured time limit
    #[error("net error: timeout: {0}")]
    Timeout(String),
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(Arc::new(e))
    }
}

impl NetError {
    /// Wrap this error in an `io::Error`, carrying the typed error as the source so the other
    /// side of an `AsyncRead` boundary can recover the original `NetError` (see
    /// `stream_to_bytes`) instead of a stringified copy.
    pub fn to_io(&self) -> std::io::Error {
        std::io::Error::other(self.clone())
    }

    /// Wraps an [`anyhow::Error`] as a [`NetError::Read`]
    pub fn from_anyhow(e: anyhow::Error) -> Self {
        Self::Read(Arc::new(e))
    }
}

/// Marker for types that must be [`Send`] on native targets. On wasm32 the crate runs
/// single-threaded and its fetch-backed streams wrap `!Send` JS types, so the bound is empty.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}
/// Marker for types that must be [`Send`] on native targets. On wasm32 the crate runs
/// single-threaded and its fetch-backed streams wrap `!Send` JS types, so the bound is empty.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// Boxed async reader backing [`BodyStream`]: `Send` on native targets, plain on wasm32
/// (see [`MaybeSend`]).
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + 'static>>;
/// Boxed async reader backing [`BodyStream`]: `Send` on native targets, plain on wasm32
/// (see [`MaybeSend`]).
#[cfg(target_arch = "wasm32")]
pub type BoxedAsyncRead = Pin<Box<dyn AsyncRead + 'static>>;

/// A BodyStream is an async reader that can be used to read the body of a response.
pub struct BodyStream {
    /// Inner reader
    inner: BoxedAsyncRead,
    /// Content length (if known)
    pub len: Option<u64>,
    /// True when the stream is seekable (most often not, unless it's backed by a memory buffer)
    pub is_seekable: bool,
    /// Can be cloned to create a new independent stream starting at the beginning
    pub clonable: bool,
}

impl Debug for BodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyStream")
            .field("len", &self.len)
            .field("is_seekable", &self.is_seekable)
            .field("clonable", &self.clonable)
            .finish()
    }
}

impl BodyStream {
    /// Creates a non-seekable, non-clonable stream from the given reader and optional length
    pub fn new(inner: BoxedAsyncRead, len: Option<u64>) -> Self {
        Self {
            inner,
            len,
            is_seekable: false,
            clonable: false,
        }
    }

    /// Converts a series of bytes into a body stream
    pub fn from_bytes(bytes: Bytes) -> Self {
        let len = bytes.len() as u64;
        let reader = Box::pin(BytesAsyncReader {
            data: bytes,
            pos: 0,
        });
        Self {
            inner: reader,
            len: Some(len),
            is_seekable: true, // It's a buffer so we can seek it
            clonable: true,    // It's a buffer so we can clone it
        }
    }
}

impl AsyncRead for BodyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_read(cx, buf)
    }
}

/// Opens a fresh reader over the body contents, once per send attempt: a 307/308 redirect
/// replays the body by calling it again, which a one-shot reader could not survive.
#[cfg(not(target_arch = "wasm32"))]
pub type BodyStreamFactory =
    Arc<dyn Fn() -> std::io::Result<BoxedAsyncRead> + Send + Sync + 'static>;

/// Body sent with a non-GET request (POST, PUT, PATCH, …).
///
/// Either buffered bytes or a stream opened at send time (see [`RequestBody::stream`] and
/// [`RequestBody::file`]). The `content_type` field is automatically injected as a
/// `Content-Type` header when the request headers do not already contain one. The caller is
/// responsible for encoding the body correctly (JSON, form-encoding, multipart, etc.).
#[derive(Clone, Default)]
pub struct RequestBody {
    payload: Payload,
    /// Optional `Content-Type` value to inject (e.g. `"application/json"`).
    /// Ignored if the request headers already set `Content-Type`.
    pub content_type: Option<String>,
}

#[derive(Clone)]
enum Payload {
    Bytes(Bytes),
    #[cfg(not(target_arch = "wasm32"))]
    Stream {
        open: BodyStreamFactory,
        len: Option<u64>,
    },
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Bytes(Bytes::new())
    }
}

impl Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("RequestBody");
        match &self.payload {
            Payload::Bytes(b) => d.field("bytes", &b.len()),
            #[cfg(not(target_arch = "wasm32"))]
            Payload::Stream { len, .. } => d.field("stream", len),
        };
        d.field("content_type", &self.content_type).finish()
    }
}

impl RequestBody {
    /// Plain byte body with no automatic `Content-Type`.
    pub fn bytes(b: impl Into<Bytes>) -> Self {
        Self {
            payload: Payload::Bytes(b.into()),
            content_type: None,
        }
    }

    /// `application/json` body.
    pub fn json(b: impl Into<Bytes>) -> Self {
        Self {
            content_type: Some("application/json".into()),
            ..Self::bytes(b)
        }
    }

    /// `application/x-www-form-urlencoded` body.
    pub fn form(b: impl Into<Bytes>) -> Self {
        Self {
            content_type: Some("application/x-www-form-urlencoded".into()),
            ..Self::bytes(b)
        }
    }

    /// `text/plain; charset=utf-8` body.
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            content_type: Some("text/plain; charset=utf-8".into()),
            ..Self::bytes(s.into().into_bytes())
        }
    }

    /// Body streamed from a reader opened at send time, without buffering it in memory.
    ///
    /// With `len` set, `Content-Length` is sent; without it the transfer is chunked. The
    /// fetcher's `req_timeout` covers the upload, so large bodies may need a higher value.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn stream(
        open: impl Fn() -> std::io::Result<BoxedAsyncRead> + Send + Sync + 'static,
        len: Option<u64>,
    ) -> Self {
        Self {
            payload: Payload::Stream {
                open: Arc::new(open),
                len,
            },
            content_type: None,
        }
    }

    /// Body streamed from a file on disk, opened at send time.
    ///
    /// `Content-Length` is taken from its current size, so the file must not change until
    /// the request completes.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn file(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let len = std::fs::metadata(&path)?.len();
        Ok(Self::stream(
            move || {
                let f = std::fs::File::open(&path)?;
                Ok(Box::pin(tokio::fs::File::from_std(f)) as BoxedAsyncRead)
            },
            Some(len),
        ))
    }

    /// The buffered bytes, or `None` when the body is streamed.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.payload {
            Payload::Bytes(b) => Some(b),
            #[cfg(not(target_arch = "wasm32"))]
            Payload::Stream { .. } => None,
        }
    }

    /// Number of body bytes, or `None` for a stream without a declared length.
    pub fn len(&self) -> Option<u64> {
        match &self.payload {
            Payload::Bytes(b) => Some(b.len() as u64),
            #[cfg(not(target_arch = "wasm32"))]
            Payload::Stream { len, .. } => *len,
        }
    }

    /// Returns true when the body is known to contain no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// Build the reqwest body for one hop. The returned length, when present, must be sent
    /// as an explicit `Content-Length`: a wrapped stream is unsized as far as reqwest knows.
    pub(crate) fn to_reqwest_body(&self) -> std::io::Result<(reqwest::Body, Option<u64>)> {
        match &self.payload {
            Payload::Bytes(b) => Ok((reqwest::Body::from(b.clone()), None)),
            #[cfg(not(target_arch = "wasm32"))]
            Payload::Stream { open, len } => {
                let reader = open()?;
                let stream = tokio_util::io::ReaderStream::new(reader);
                Ok((reqwest::Body::wrap_stream(stream), *len))
            }
        }
    }
}

/// A fetch request defines what needs to be fetched, how and where to send the result to
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// Reference to what initiated this request (navigation, document, prefetch, background task)
    pub reference: RequestReference,
    /// Unique ID of this request (for logging and tracking)
    pub req_id: RequestId,
    /// Priority of this request
    pub priority: Priority,
    /// Who initiated this request
    pub initiator: Initiator,
    /// What kind of resource is being fetched
    pub kind: ResourceKind,
    /// Whether to stream the response body or buffer it fully before returning
    pub streaming: bool,
    /// Auto decode the request (if for instance, gzipped), or pass directly through to the caller
    pub auto_decode: bool,
    /// Maximum amount of (buffered) bytes we can fetch
    pub max_bytes: Option<usize>,
    /// HTTP Method used
    pub method: Method,
    /// Target Url
    pub url: Url,
    /// Origin of the document that initiated this request, used for mixed content checks.
    ///
    /// `None` means "no document context", which disables mixed content blocking for this
    /// request entirely — set it whenever a request is made on behalf of a page.
    /// See [`mixed_content`](crate::net::mixed_content).
    pub origin: Option<Origin>,
    /// Overrides [`FetcherConfig::mixed_content`](crate::net::fetcher::FetcherConfig::mixed_content)
    /// for this one request; `None` uses the fetcher-wide setting. Requires `origin`.
    pub mixed_content: Option<MixedContentPolicy>,
    /// URL of the document that initiated this request, used to compute the `Referer` header.
    ///
    /// `None` sends no `Referer` at all. Any `Referer` set by hand in `headers` is overwritten
    /// when this is set. See [`referrer`](mod@crate::net::referrer).
    pub referrer: Option<Url>,
    /// How much of `referrer` to reveal. Ignored when `referrer` is `None`.
    pub referrer_policy: ReferrerPolicy,
    /// HTTP Headers (unified).
    pub headers: HeaderMap,
    /// Optional request body (for POST, PUT, PATCH, DELETE, etc.).
    /// `None` for GET and HEAD requests.
    pub body: Option<RequestBody>,
}

impl FetchRequest {
    /// Gives a FetchRequestBuilder
    pub fn builder(method: Method, url: Url) -> FetchRequestBuilder {
        FetchRequestBuilder::new(method, url)
    }

    /// Generates a key for coalescing in-flight requests based on the request's method, URL, and headers.
    pub fn generate_request_key(&self) -> Option<String> {
        match self.method {
            Method::GET | Method::HEAD => {}
            _ => return None,
        }

        let url = normalize_url(&self.url);
        let h = &self.headers;

        let range = h
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let accept = h
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let accept_enc = h
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let accept_lang = h
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let auth_hash = h
            .get(header::AUTHORIZATION)
            .map(|v| format!("{:x}", short_hash(v.as_bytes())))
            .unwrap_or_default();
        let cookie_hash = h
            .get(header::COOKIE)
            .map(|v| format!("{:x}", short_hash(v.as_bytes())))
            .unwrap_or_default();

        // Requests are only interchangeable if they reach the same mixed content verdict —
        // otherwise a permitted fetch would be handed to a subscriber that should have been
        // blocked.
        //
        // This must NOT be narrowed by inspecting `self.url`: enforcement is per-hop, and a
        // trustworthy https URL can 302 onto plain http. Bucketing an https request as
        // "mixed content cannot apply" would let a leader with no origin follow that redirect
        // and hand the http body to a secure-origin follower that asked to be blocked.
        let mixed_content = if !self
            .origin
            .as_ref()
            .is_some_and(is_origin_potentially_trustworthy)
        {
            // No secure document to protect, so every hop of this request resolves to Allow
            // whatever the policy says. All such requests share one bucket.
            "n"
        } else {
            // The fetcher-wide default is constant across one fetcher, so the per-request
            // policy is all that can distinguish two verdicts here. The fetcher resolves
            // `None` to the effective policy before keying; it only survives for requests
            // keyed outside the scheduler.
            match self.mixed_content {
                None => "default",
                Some(MixedContentPolicy::Allow) => "allow",
                Some(MixedContentPolicy::Upgrade) => "upgrade",
                Some(MixedContentPolicy::Block) => "block",
            }
        };

        // Servers vary on `Referer` — hotlink protection is the common case — so requests that
        // would send different values must not share a response.
        //
        // Keyed on the *inputs* rather than the value computed for `self.url`: the header is
        // recomputed at every hop, so two requests that agree on the first hop can still diverge
        // after a redirect.
        let referrer = match self.referrer.as_ref() {
            Some(r) if !referrer::never_sends(r, self.referrer_policy) => {
                // Under an origin-only policy the path can never be revealed on any hop, so
                // every page on one origin sends byte-identical values and can share a bucket.
                // The rest must split on the full URL.
                let source = match self.referrer_policy {
                    ReferrerPolicy::Origin | ReferrerPolicy::StrictOrigin => {
                        r.origin().ascii_serialization()
                    }
                    _ => r.as_str().to_string(),
                };
                // An explicit token rather than `{:?}`, so renaming a variant cannot silently
                // change how requests bucket.
                let policy = match self.referrer_policy {
                    ReferrerPolicy::NoReferrer => "no-referrer",
                    ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
                    ReferrerPolicy::SameOrigin => "same-origin",
                    ReferrerPolicy::Origin => "origin",
                    ReferrerPolicy::StrictOrigin => "strict-origin",
                    ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
                    ReferrerPolicy::StrictOriginWhenCrossOrigin => {
                        "strict-origin-when-cross-origin"
                    }
                    ReferrerPolicy::UnsafeUrl => "unsafe-url",
                };
                format!("{:x}:{}", short_hash(source.as_bytes()), policy)
            }
            // No referrer of our own to send. A hand-set `Referer` still goes out verbatim on the
            // first hop, and it varies the response just as a computed one would, so it has to
            // vary the key too.
            _ => match self.headers.get(header::REFERER) {
                Some(manual) => format!("h{:x}", short_hash(manual.as_bytes())),
                None => "n".to_string(),
            },
        };

        Some(format!(
            "M={};U={};R={};A={};AL={};AE={};Auth={};C={};MC={};Ref={}",
            self.method,
            url,
            range,
            accept,
            accept_lang,
            accept_enc,
            auth_hash,
            cookie_hash,
            mixed_content,
            referrer
        ))
    }
}

/// Builder for [`FetchRequest`], created via [`FetchRequest::builder`].
///
/// All settings are optional; `build()` produces a buffered, decoding request
/// with [`Priority::Normal`] unless configured otherwise.
pub struct FetchRequestBuilder {
    reference: RequestReference,
    req_id: RequestId,
    priority: Priority,
    initiator: Initiator,
    kind: ResourceKind,
    streaming: bool,
    auto_decode: bool,
    max_bytes: Option<usize>,
    method: Method,
    headers: HeaderMap,
    url: Url,
    origin: Option<Origin>,
    mixed_content: Option<MixedContentPolicy>,
    referrer: Option<Url>,
    referrer_policy: ReferrerPolicy,
    body: Option<RequestBody>,
}

impl FetchRequestBuilder {
    /// Create a new FetchRequestBuilder
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            url,
            method,
            headers: HeaderMap::default(),
            reference: RequestReference::default(),
            req_id: RequestId::default(),
            priority: Priority::default(),
            initiator: Initiator::default(),
            kind: ResourceKind::default(),
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            origin: None,
            mixed_content: None,
            referrer: None,
            referrer_policy: ReferrerPolicy::default(),
            body: None,
        }
    }

    /// Sets a reference for the request
    pub fn with_reference(mut self, reference: RequestReference) -> Self {
        self.reference = reference;
        self
    }

    /// Sets an ID for the request
    pub fn with_req_id(mut self, req_id: RequestId) -> Self {
        self.req_id = req_id;
        self
    }

    /// Sets the priority of the request
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Sets initiator of the request
    pub fn with_initiator(mut self, initiator: Initiator) -> Self {
        self.initiator = initiator;
        self
    }

    /// Sets the kind property of the request
    pub fn with_kind(mut self, kind: ResourceKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets whether to stream the response body instead of buffering it (default: buffered)
    pub fn with_streaming(mut self, streaming: bool) -> Self {
        self.streaming = streaming;
        self
    }

    /// Sets whether to transparently decode compressed responses (default: true).
    ///
    /// With decoding on, [`with_max_bytes`](Self::with_max_bytes) caps the decompressed
    /// size; set `false` to cap bytes as they arrive on the wire.
    pub fn with_auto_decode(mut self, auto_decode: bool) -> Self {
        self.auto_decode = auto_decode;
        self
    }

    /// Sets the maximum number of body bytes to buffer (default: unlimited)
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    /// Sets the request body (for POST, PUT, PATCH, etc.)
    pub fn with_body(mut self, body: RequestBody) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets the URL for the request
    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }

    /// Sets the origin of the document initiating the request, enabling mixed content checks.
    ///
    /// Typically `document_url.origin()`. Leaving this unset disables mixed content blocking
    /// for the request — see [`mixed_content`](crate::net::mixed_content).
    pub fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Overrides the fetcher-wide mixed content policy. Use [`MixedContentPolicy::Allow`] for
    /// optionally-blockable resources; requires [`with_origin`](Self::with_origin).
    pub fn with_mixed_content(mut self, policy: MixedContentPolicy) -> Self {
        self.mixed_content = Some(policy);
        self
    }

    /// Sets the URL of the initiating document, enabling the `Referer` header.
    /// Unset sends no referrer. See [`referrer`](mod@crate::net::referrer).
    pub fn with_referrer(mut self, referrer: Url) -> Self {
        self.referrer = Some(referrer);
        self
    }

    /// Sets how much of the referrer to reveal. Requires [`with_referrer`](Self::with_referrer).
    pub fn with_referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = policy;
        self
    }

    /// Sets the HTTP method of the request
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets the headers for the request
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Builds the [`FetchRequest`]
    pub fn build(self) -> FetchRequest {
        FetchRequest {
            reference: self.reference,
            req_id: self.req_id,
            priority: self.priority,
            initiator: self.initiator,
            kind: self.kind,
            streaming: self.streaming,
            auto_decode: self.auto_decode,
            max_bytes: self.max_bytes,
            headers: self.headers,
            method: self.method,
            url: self.url,
            origin: self.origin,
            mixed_content: self.mixed_content,
            referrer: self.referrer,
            referrer_policy: self.referrer_policy,
            body: self.body,
        }
    }
}

/// FetchResult defines the resource response. Either a stream or buffered response are possible
#[derive(Clone)]
pub enum FetchResult {
    /// Streamed response body
    Stream {
        /// Response metadata (status, headers, final URL)
        meta: FetchResultMeta,
        /// First bytes of the body, for content-type sniffing
        peek_buf: PeekBuf,
        /// Shared body that fans the stream out to all subscribers
        shared: Arc<SharedBody>,
    },
    /// Buffered response body
    Buffered {
        /// Response metadata (status, headers, final URL)
        meta: FetchResultMeta,
        /// Complete response body
        body: Bytes,
    },
    /// Network error occurred
    Error(NetError),
}

impl FetchResult {
    /// Returns true when the result is an error
    pub fn is_error(&self) -> bool {
        matches!(self, FetchResult::Error(_))
    }

    /// Return the metadata if available
    pub fn meta(&self) -> Option<&FetchResultMeta> {
        match self {
            FetchResult::Stream { meta, .. } => Some(meta),
            FetchResult::Buffered { meta, .. } => Some(meta),
            FetchResult::Error(_) => None,
        }
    }
}

impl Debug for FetchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchResult::Stream { meta, .. } => f
                .debug_struct("FetchResult::Stream")
                .field("meta", meta)
                .finish(),
            FetchResult::Buffered { meta, body } => f
                .debug_struct("FetchResult::Buffered")
                .field("meta", meta)
                .field("body_len", &body.len())
                .finish(),
            FetchResult::Error(e) => f.debug_tuple("FetchResult::Error").field(e).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cow_utils::CowUtils;
    use tokio::io::AsyncReadExt;

    #[tokio::test(flavor = "current_thread")]
    async fn bodystream_from_bytes_reads_all() {
        let data = Bytes::from_static(b"hello world");
        let mut s = BodyStream::from_bytes(data.clone());
        assert_eq!(s.len, Some(11));
        assert!(s.is_seekable);
        assert!(s.clonable);

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out[..], &data[..]);

        let n = s.read(&mut [0u8; 8]).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn stream_body_reports_len_and_no_bytes() {
        let sized = RequestBody::stream(|| Ok(Box::pin(&b""[..]) as BoxedAsyncRead), Some(3));
        assert_eq!(sized.len(), Some(3));
        assert!(sized.as_bytes().is_none());
        assert!(!sized.is_empty());

        let unsized_body = RequestBody::stream(|| Ok(Box::pin(&b""[..]) as BoxedAsyncRead), None);
        assert_eq!(unsized_body.len(), None);
        assert!(!unsized_body.is_empty());

        let buffered = RequestBody::bytes(&b"abc"[..]);
        assert_eq!(buffered.len(), Some(3));
        assert_eq!(buffered.as_bytes().map(|b| b.len()), Some(3));
    }

    #[test]
    fn builder_decodes_by_default() {
        let fr =
            FetchRequest::builder(Method::GET, Url::parse("https://example.org").unwrap()).build();
        assert!(fr.auto_decode);
    }

    #[test]
    fn fetch_request_generate_get_and_headers() {
        let mut fr = FetchRequest::builder(
            Method::default(),
            Url::parse("https://example.org/a/b#frag").unwrap(),
        )
        .build();
        fr.headers
            .insert(header::RANGE, "bytes=0-99".parse().unwrap());
        fr.headers
            .insert(header::ACCEPT, "text/html".parse().unwrap());
        fr.headers
            .insert(header::ACCEPT_LANGUAGE, "en-US".parse().unwrap());
        fr.headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        fr.headers
            .insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        fr.headers
            .insert(header::COOKIE, "a=1; b=2".parse().unwrap());

        let key = fr.generate_request_key().expect("GET should produce a key");

        let url_norm = normalize_url(&fr.url);
        let auth_hash = format!("{:x}", short_hash(b"Bearer abc"));
        let cookie_hash = format!("{:x}", short_hash(b"a=1; b=2"));
        let expected = format!(
            // MC=n: no secure initiating origin. Ref=n: no referrer set, so none is ever sent.
            "M={};U={};R={};A={};AL={};AE={};Auth={};C={};MC=n;Ref=n",
            fr.method, url_norm, "bytes=0-99", "text/html", "en-US", "gzip", auth_hash, cookie_hash
        );

        assert_eq!(key, expected);
        assert!(key.starts_with("M=GET;U=https://example.org/a/b"));
        assert!(!key.contains("#frag"));
    }

    /// Two documents fetching the same insecure URL must not coalesce when only one of them is
    /// a secure context — otherwise the insecure document's allowed fetch would be handed to the
    /// secure one, silently defeating mixed content blocking.
    #[test]
    fn coalescing_key_separates_secure_from_insecure_initiators() {
        let target = Url::parse("http://cdn.example.org/a.js").unwrap();
        let key_for = |origin: Option<&str>| {
            let mut b = FetchRequest::builder(Method::GET, target.clone());
            if let Some(o) = origin {
                b = b.with_origin(Url::parse(o).unwrap().origin());
            }
            b.build().generate_request_key().unwrap()
        };

        let secure = key_for(Some("https://a.example.com"));
        let insecure = key_for(Some("http://b.example.com"));
        let none = key_for(None);

        assert_ne!(secure, insecure);
        // No origin means no document to protect, so it shares the insecure verdict.
        assert_eq!(insecure, none);
        // Two different secure origins reach the same verdict and should still coalesce,
        // otherwise every document would get its own connection for shared assets.
        assert_eq!(secure, key_for(Some("https://c.example.com")));
    }

    /// A permitted image and a blocked script can target the same insecure URL from the same
    /// page. They must not coalesce, or the script would inherit the image's fetched body.
    #[test]
    fn coalescing_key_separates_per_request_policy_overrides() {
        let target = Url::parse("http://cdn.example.org/a.js").unwrap();
        let origin = Url::parse("https://example.com").unwrap().origin();
        let key_for = |policy: Option<MixedContentPolicy>| {
            let mut b =
                FetchRequest::builder(Method::GET, target.clone()).with_origin(origin.clone());
            if let Some(p) = policy {
                b = b.with_mixed_content(p);
            }
            b.build().generate_request_key().unwrap()
        };

        let keys = [
            key_for(None),
            key_for(Some(MixedContentPolicy::Allow)),
            key_for(Some(MixedContentPolicy::Upgrade)),
            key_for(Some(MixedContentPolicy::Block)),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "each policy reaches a different verdict");
            }
        }
    }

    /// Regression: an `https` target must NOT be treated as "mixed content cannot apply".
    ///
    /// Enforcement is per-hop, so an https URL that 302s onto plain http is still a mixed
    /// content decision. Bucketing on the initial URL's scheme let a leader with no origin
    /// follow that redirect and hand the http body to a secure-origin follower that had asked
    /// to be blocked — defeating the feature entirely.
    #[test]
    fn coalescing_key_does_not_trust_an_https_initial_url() {
        let target = Url::parse("https://redirector.example.org/r").unwrap();
        let key = |origin: Option<&str>| {
            let mut b = FetchRequest::builder(Method::GET, target.clone());
            if let Some(o) = origin {
                b = b.with_origin(Url::parse(o).unwrap().origin());
            }
            b.build().generate_request_key().unwrap()
        };

        assert_ne!(
            key(Some("https://example.com")),
            key(None),
            "a secure-origin request must not share a bucket with an unprotected one, \
             however trustworthy the initial URL looks"
        );
    }

    /// Two documents fetching the same URL send different `Referer` values, and servers vary on
    /// it (hotlink protection). They must not share one response.
    #[test]
    fn coalescing_key_separates_different_referrers() {
        let target = Url::parse("https://cdn.example.org/a.js").unwrap();
        let key = |referrer: Option<&str>, policy: ReferrerPolicy| {
            let mut b =
                FetchRequest::builder(Method::GET, target.clone()).with_referrer_policy(policy);
            if let Some(r) = referrer {
                b = b.with_referrer(Url::parse(r).unwrap());
            }
            b.build().generate_request_key().unwrap()
        };
        let default = ReferrerPolicy::default();

        assert_ne!(
            key(Some("https://a.example.com/x"), default),
            key(Some("https://b.example.com/y"), default)
        );
        // Same source, different policy — different amounts of it get revealed.
        assert_ne!(
            key(Some("https://a.example.com/x"), default),
            key(Some("https://a.example.com/x"), ReferrerPolicy::UnsafeUrl)
        );
        // Identical inputs coalesce, which is the common case: one page, many sub-resources.
        assert_eq!(
            key(Some("https://a.example.com/x"), default),
            key(Some("https://a.example.com/x"), default)
        );
        // Anything that never sends a header shares one bucket, whatever the source.
        assert_eq!(key(None, default), key(None, ReferrerPolicy::UnsafeUrl));
        assert_eq!(
            key(None, default),
            key(Some("https://a.example.com/x"), ReferrerPolicy::NoReferrer)
        );
    }

    /// The key must not be derived from the value computed for the request's own URL.
    ///
    /// Two pages on one origin agree on what to send cross-origin (the bare origin), then differ
    /// the moment a redirect lands back home and the full path is revealed. Keying on the hop-0
    /// value would coalesce them and send one page's path on the other's behalf.
    #[test]
    fn coalescing_key_is_not_derived_from_the_first_hop_value() {
        let target = Url::parse("https://other.example.org/r").unwrap();
        let key = |referrer: &str| {
            FetchRequest::builder(Method::GET, target.clone())
                .with_referrer(Url::parse(referrer).unwrap())
                .build()
                .generate_request_key()
                .unwrap()
        };

        let (a, b) = ("https://example.com/page-a", "https://example.com/page-b");
        // Both send the bare origin to this cross-origin target, so hop 0 is identical...
        let policy = ReferrerPolicy::default();
        let hop0 = |r: &str| {
            referrer::determine(&Url::parse(r).unwrap(), policy, &target).map(|u| u.to_string())
        };
        assert_eq!(hop0(a), hop0(b));
        // ...but the keys must still differ, because a redirect home would diverge.
        assert_ne!(key(a), key(b));
    }

    /// A hand-set `Referer` goes out verbatim, so it varies the response just as a computed one
    /// would and must vary the key too.
    #[test]
    fn coalescing_key_accounts_for_a_hand_set_referer_header() {
        let target = Url::parse("https://cdn.example.org/a.js").unwrap();
        let key = |manual: Option<&str>| {
            let mut req = FetchRequest::builder(Method::GET, target.clone()).build();
            if let Some(value) = manual {
                req.headers.insert(header::REFERER, value.parse().unwrap());
            }
            req.generate_request_key().unwrap()
        };

        assert_ne!(key(Some("https://a.example.com/x")), key(None));
        assert_ne!(
            key(Some("https://a.example.com/x")),
            key(Some("https://b.example.com/y"))
        );
        assert_eq!(
            key(Some("https://a.example.com/x")),
            key(Some("https://a.example.com/x"))
        );
    }

    #[test]
    fn fetch_request_generate_post_is_none() {
        let mut fr = FetchRequest::builder(
            Method::default(),
            Url::parse("https://example.org/").unwrap(),
        )
        .build();
        fr.method = Method::POST;
        assert!(fr.generate_request_key().is_none());
    }

    #[test]
    fn priority_display_is_stable() {
        assert_eq!(format!("{}", Priority::High), "High");
        assert_eq!(format!("{}", Priority::Normal), "Normal");
        assert_eq!(format!("{}", Priority::Low), "Low");
        assert_eq!(format!("{}", Priority::Idle), "Idle");
    }

    #[test]
    fn neterror_helpers_work() {
        let io = NetError::Timeout("oops".into()).to_io();
        assert_eq!(io.kind(), std::io::ErrorKind::Other);
        assert!(io.to_string().cow_to_ascii_lowercase().contains("timeout"));

        let ne = NetError::from_anyhow(anyhow::anyhow!("boom"));
        assert!(matches!(ne, NetError::Read(_)));
    }

    #[test]
    fn net_error_redirect_formats_with_redirect_prefix() {
        let e = NetError::Redirect(Arc::new(anyhow::anyhow!("too many redirects")));
        assert!(e.to_string().contains("redirect"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn body_stream_new_creates_non_seekable_stream() {
        use tokio::io::AsyncReadExt;
        let mut s = BodyStream::new(Box::pin(tokio::io::empty()), Some(0));
        assert_eq!(s.len, Some(0));
        assert!(!s.is_seekable);
        assert!(!s.clonable);
        let n = s.read(&mut [0u8; 4]).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn fetch_result_meta_returns_none_for_error() {
        let e = FetchResult::Error(NetError::Cancelled("x".into()));
        assert!(e.meta().is_none());
        assert!(e.is_error());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_result_meta_returns_some_for_stream_and_buffered() {
        use crate::net::shared_body::SharedBody;
        use crate::types::PeekBuf;
        use http::HeaderMap;

        let meta = FetchResultMeta {
            final_url: Url::parse("http://example.com/").unwrap(),
            status: 200,
            status_text: "OK".into(),
            headers: HeaderMap::new(),
            content_length: None,
            content_type: None,
            has_body: false,
        };

        let buffered = FetchResult::Buffered {
            meta: meta.clone(),
            body: bytes::Bytes::new(),
        };
        assert_eq!(buffered.meta().unwrap().status, 200);
        assert!(!buffered.is_error());
        assert!(format!("{:?}", buffered).contains("Buffered"));

        let stream = FetchResult::Stream {
            meta: meta.clone(),
            peek_buf: PeekBuf::empty(),
            shared: Arc::new(SharedBody::new(1)),
        };
        assert_eq!(stream.meta().unwrap().status, 200);
        assert!(format!("{:?}", stream).contains("Stream"));
    }

    #[test]
    fn fetch_request_builder_builds_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert("ACCEPT", "text/html".parse().unwrap());
        headers.insert("CONTENT_TYPE", "application/json".parse().unwrap());

        let reference = RequestReference::default();
        let req_id = RequestId::new();
        let priority = Priority::High;
        let initiator = Initiator::Application;
        let kind = ResourceKind::Asset;
        let body = RequestBody::json(r#"{"key": "value"}"#);

        let request =
            FetchRequest::builder(Method::POST, Url::parse("https://example.com/api").unwrap())
                .with_reference(reference)
                .with_req_id(req_id)
                .with_priority(priority)
                .with_initiator(initiator)
                .with_kind(kind)
                .with_headers(headers)
                .with_streaming(true)
                .with_auto_decode(true)
                .with_max_bytes(1024)
                .with_body(body)
                .build();

        assert_eq!(request.reference, reference);
        assert_eq!(request.req_id, req_id);
        assert_eq!(request.priority, priority);
        assert_eq!(request.initiator, initiator);
        assert_eq!(request.kind, kind);
        assert!(request.streaming);
        assert!(request.auto_decode);
        assert_eq!(request.max_bytes, Some(1024));
        assert_eq!(
            request.body.as_ref().unwrap().content_type,
            Some("application/json".into())
        );

        assert_eq!(request.url.as_str(), "https://example.com/api");
        assert_eq!(request.method, Method::POST);
        assert!(request.headers.contains_key("ACCEPT"));
        assert!(request.headers.contains_key("CONTENT_TYPE"));
    }
}

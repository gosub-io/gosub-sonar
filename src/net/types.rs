//! Core types for fetch requests, responses, errors, and priorities.

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
use tokio_util::sync::CancellationToken;
use url::Url;

/// Priority of the scheduled request. Documents usually have high priority, while images have low.
/// Currently, the scheduler uses a round-robin system to load resources
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub enum Priority {
    #[default]
    High,
    Normal,
    Low,
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

/// A fetch key data is a key that is used to find out if two requests want to fetch the same resource.
/// If this is true, the requests are bundled so only once the resource will be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchKeyData {
    /// URL fetched
    pub url: Url,
    /// HTTP method used (GET, POST etc.)
    pub method: Method,
    /// HTTP headers
    pub headers: HeaderMap,
}

impl Default for FetchKeyData {
    fn default() -> Self {
        let url = Url::parse("https:://example.net").unwrap();

        Self {
            url: url,
            method: Method::default(),
            headers: HeaderMap::default(),
        }
    }
}

impl Hash for FetchKeyData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if let Some(key) = self.generate() {
            key.hash(state);
        }
    }
}

impl Display for FetchKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl FetchKeyData {
    /// Creates a new fetch key data with the given URL, method GET and no headers
    pub fn new(url: Url) -> Self {
        Self {
            url,
            method: Method::GET,
            headers: HeaderMap::new(),
        }
    }

    /// Generates a key for coalescing in-flight requests based on the request's method, URL, and headers.
    pub fn generate(&self) -> Option<String> {
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

        Some(format!(
            "M={};U={};R={};A={};AL={};AE={};Auth={};C={}",
            self.method, url, range, accept, accept_lang, accept_enc, auth_hash, cookie_hash
        ))
    }
}

/// Network-level errors.
#[derive(Debug, thiserror::Error, Clone)]
pub enum NetError {
    #[error("net error: reqwest: {0}")]
    Reqwest(#[from] Arc<reqwest::Error>),

    #[error("net error: redirect: {0}")]
    Redirect(Arc<anyhow::Error>),

    #[error("net error: I/O: {0}")]
    Io(#[from] Arc<std::io::Error>),

    #[error("net error: cancelled: {0}")]
    Cancelled(String),

    #[error(transparent)]
    Read(Arc<anyhow::Error>),

    #[error(transparent)]
    Other(Arc<anyhow::Error>),

    #[error("net error: timeout: {0}")]
    Timeout(String),
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(Arc::new(e))
    }
}

impl NetError {
    pub fn to_io(&self) -> std::io::Error {
        std::io::Error::other(format!("{self}"))
    }

    pub fn from_anyhow(e: anyhow::Error) -> Self {
        Self::Read(Arc::new(e))
    }
}

/// A BodyStream is an async reader that can be used to read the body of a response.
pub struct BodyStream {
    /// Inner reader
    inner: Pin<Box<dyn AsyncRead + Send + 'static>>,
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
    pub fn new(inner: Pin<Box<dyn AsyncRead + Send + 'static>>, len: Option<u64>) -> Self {
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

#[derive(Clone)]
pub struct FetchHandle {
    /// Unique ID of this request (for logging and tracking)
    pub req_id: RequestId,
    /// Key data identifying the resource to fetch
    pub key: FetchKeyData,
    /// Cancellation token
    pub cancel: CancellationToken,
}

impl Debug for FetchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchHandle")
            .field("req_id", &self.req_id)
            .field("key", &self.key)
            .field("cancel", &self.cancel)
            .finish()
    }
}

/// Body sent with a non-GET request (POST, PUT, PATCH, …).
///
/// The `content_type` field is automatically injected as a `Content-Type` header when the
/// request headers do not already contain one. The caller is responsible for encoding the body
/// correctly (JSON, form-encoding, multipart, etc.).
#[derive(Debug, Clone, Default)]
pub struct RequestBody {
    /// Raw bytes to send.
    pub bytes: Bytes,
    /// Optional `Content-Type` value to inject (e.g. `"application/json"`).
    /// Ignored if the request headers already set `Content-Type`.
    pub content_type: Option<String>,
}

impl RequestBody {
    /// Plain byte body with no automatic `Content-Type`.
    pub fn bytes(b: impl Into<Bytes>) -> Self {
        Self {
            bytes: b.into(),
            content_type: None,
        }
    }

    /// `application/json` body.
    pub fn json(b: impl Into<Bytes>) -> Self {
        Self {
            bytes: b.into(),
            content_type: Some("application/json".into()),
        }
    }

    /// `application/x-www-form-urlencoded` body.
    pub fn form(b: impl Into<Bytes>) -> Self {
        Self {
            bytes: b.into(),
            content_type: Some("application/x-www-form-urlencoded".into()),
        }
    }

    /// `text/plain; charset=utf-8` body.
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            bytes: Bytes::from(s.into().into_bytes()),
            content_type: Some("text/plain; charset=utf-8".into()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// A fetch request defines what needs to be fetched, how and where to send the result to
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// Reference to what initiated this request (navigation, document, prefetch, background task)
    pub reference: RequestReference,
    /// Unique ID of this request (for logging and tracking)
    pub req_id: RequestId,
    /// Key data identifying the resource to fetch (URL, method, headers)
    pub key_data: FetchKeyData,
    /// Priority of this request
    pub priority: Priority,
    /// Who initiated this request
    pub initiator: Initiator,
    /// What kind of resource is being fetched
    pub kind: ResourceKind,
    // whether to stream or buffer
    pub streaming: bool,
    /// Auto decode the request (if for instance, gzipped), or pass directly through to the caller
    pub auto_decode: bool,
    /// Maximum amount of (buffered) bytes we can fetch
    pub max_bytes: Option<usize>,
    /// Optional request body (for POST, PUT, PATCH, DELETE, etc.).
    /// `None` for GET and HEAD requests.
    pub body: Option<RequestBody>,
}

impl FetchRequest {
    pub fn builder() -> FetchRequestBuilder {
        FetchRequestBuilder::default()
    }
}

#[derive(Default)]
pub struct FetchRequestBuilder {
    reference: RequestReference,
    req_id: RequestId,
    key_data: FetchKeyData,
    priority: Priority,
    initiator: Initiator,
    kind: ResourceKind,
    streaming: bool,
    auto_decode: bool,
    max_bytes: Option<usize>,
    body: Option<RequestBody>,
}

impl FetchRequestBuilder {
    pub fn with_reference(mut self, refernece: RequestReference) -> Self {
        self.reference = refernece;
        self
    }

    pub fn with_req_id(mut self, req_id: RequestId) -> Self {
        self.req_id = req_id;
        self
    }

    pub fn with_key_data(mut self, key_data: FetchKeyData) -> Self {
        self.key_data = key_data;
        self
    }

    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_initiator(mut self, initiator: Initiator) -> Self {
        self.initiator = initiator;
        self
    }

    pub fn with_king(mut self, kind: ResourceKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_streaming(mut self, streaming: bool) -> Self {
        self.streaming = streaming;
        self
    }

    pub fn with_auto_decode(mut self, auto_decode: bool) -> Self {
        self.auto_decode = auto_decode;
        self
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    pub fn with_body(mut self, body: RequestBody) -> Self {
        self.body = Some(body);
        self
    }

    pub fn build(self) -> FetchRequest {
        FetchRequest {
            reference: self.reference,
            req_id: self.req_id,
            key_data: self.key_data,
            priority: self.priority,
            initiator: self.initiator,
            kind: self.kind,
            streaming: self.streaming,
            auto_decode: self.auto_decode,
            max_bytes: self.max_bytes,
            body: self.body,
        }
    }
}

/// FetchResult defines the resource response. Either a stream or buffered response are possible
#[derive(Clone)]
pub enum FetchResult {
    /// Streamed response body
    Stream {
        meta: FetchResultMeta,
        peek_buf: PeekBuf,
        shared: Arc<SharedBody>,
    },
    /// Buffered response body
    Buffered { meta: FetchResultMeta, body: Bytes },
    /// Network error occurred
    Error(NetError),
}

impl FetchResult {
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
    fn fetch_key_generate_get_and_headers() {
        let mut fk = FetchKeyData::new(Url::parse("https://example.org/a/b#frag").unwrap());
        fk.headers
            .insert(header::RANGE, "bytes=0-99".parse().unwrap());
        fk.headers
            .insert(header::ACCEPT, "text/html".parse().unwrap());
        fk.headers
            .insert(header::ACCEPT_LANGUAGE, "en-US".parse().unwrap());
        fk.headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        fk.headers
            .insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        fk.headers
            .insert(header::COOKIE, "a=1; b=2".parse().unwrap());

        let key = fk.generate().expect("GET should produce a key");

        let url_norm = normalize_url(&fk.url);
        let auth_hash = format!("{:x}", short_hash(b"Bearer abc"));
        let cookie_hash = format!("{:x}", short_hash(b"a=1; b=2"));
        let expected = format!(
            "M={};U={};R={};A={};AL={};AE={};Auth={};C={}",
            fk.method, url_norm, "bytes=0-99", "text/html", "en-US", "gzip", auth_hash, cookie_hash
        );

        assert_eq!(key, expected);
        assert!(key.starts_with("M=GET;U=https://example.org/a/b"));
        assert!(!key.contains("#frag"));
    }

    #[test]
    fn fetch_key_generate_post_is_none() {
        let mut fk = FetchKeyData::new(Url::parse("https://example.org/").unwrap());
        fk.method = Method::POST;
        assert!(fk.generate().is_none());
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

    #[test]
    fn fetch_key_data_display_shows_url() {
        let key = FetchKeyData::new(Url::parse("http://example.com/path").unwrap());
        assert_eq!(format!("{}", key), "http://example.com/path");
    }

    #[test]
    fn fetch_key_data_is_usable_as_hash_map_key() {
        use std::collections::HashMap;
        let key = FetchKeyData::new(Url::parse("http://example.com/").unwrap());
        let mut map = HashMap::new();
        map.insert(key.clone(), 42u32);
        assert_eq!(map.get(&key), Some(&42));
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
    fn fetch_handle_implements_debug() {
        let key = FetchKeyData::new(Url::parse("http://example.com/").unwrap());
        let req_id = crate::types::RequestId::new();
        let handle = FetchHandle {
            req_id,
            key,
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        assert!(format!("{:?}", handle).contains("FetchHandle"));
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
}

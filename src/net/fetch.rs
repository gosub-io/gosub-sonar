//! Low-level fetch functions used by the [`super::fetcher::Fetcher`].

use crate::net::events::NetEvent;
use crate::net::fetcher_context::FetcherContext;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::hsts::{self, HstsStore};
use crate::net::observer::NetObserver;
use crate::net::types::{FetchResultMeta, NetError};
use crate::types::PeekBuf;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use futures_util::{stream, StreamExt, TryStreamExt};
use http::{header, HeaderMap, Method};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Headers that must be stripped when following a redirect to a different origin (RFC 9110 §15.4).
const SENSITIVE_REDIRECT_HEADERS: &[header::HeaderName] = &[header::AUTHORIZATION, header::COOKIE];

/// Callback type for the URL allowlist check.
pub type UrlFilter = Box<dyn Fn(&Url) -> bool + Send + Sync>;

/// Callback type for per-URL cookie jar queries.
pub type CookieJarFn = Box<dyn Fn(&Url) -> Option<String> + Send + Sync>;

/// Callback type for reporting `Set-Cookie` values received on a response.
pub type CookieSinkFn = Box<dyn Fn(&Url, &[&str]) + Send + Sync>;

/// Network-level request policies threaded through the fetch stack.
///
/// Bundles the URL allowlist check and the cookie-jar query so both can be applied at
/// every redirect hop without passing separate generic parameters.
///
/// Construct with [`NetPolicy::default`] (no-op, allows everything) or
/// [`NetPolicy::from_context`] to wire up a [`FetcherContext`] implementation.
pub struct NetPolicy {
    /// Return `false` to block a URL. Called for the initial URL and each redirect target.
    pub url_allowed: UrlFilter,
    /// Return cookies for a request URL in `"name=value; name2=value2"` format, or `None`.
    /// Called on each hop after cross-origin cookie stripping, so the jar is always consulted
    /// for the correct origin.
    pub cookies_for: CookieJarFn,
    /// Called with the raw `Set-Cookie` values of each redirect (3xx) response, so cookies set
    /// mid-chain (e.g. a session cookie on a login 302) reach the jar before the next hop.
    /// The final response's cookies are reported by the fetcher, not here.
    pub on_cookies: CookieSinkFn,
    /// HSTS store consulted to upgrade each hop, and updated from each hop's response.
    /// `None` disables HSTS. Set via [`NetPolicy::with_hsts`].
    #[cfg(not(target_arch = "wasm32"))]
    pub hsts: Option<Arc<dyn HstsStore>>,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            url_allowed: Box::new(|_| true),
            cookies_for: Box::new(|_| None),
            on_cookies: Box::new(|_, _| {}),
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
        }
    }
}

impl NetPolicy {
    /// Build a policy that delegates to a [`FetcherContext`] implementation.
    pub fn from_context(ctx: &Arc<dyn FetcherContext>) -> Self {
        let ctx_url = ctx.clone();
        let ctx_cookies = ctx.clone();
        let ctx_sink = ctx.clone();
        Self {
            url_allowed: Box::new(move |url| ctx_url.is_url_allowed(url)),
            cookies_for: Box::new(move |url| ctx_cookies.cookies_for(url)),
            on_cookies: Box::new(move |url, values| ctx_sink.on_cookies_received(url, values)),
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
        }
    }

    /// Attaches the HSTS store this policy should consult and update. `None` disables HSTS.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_hsts(mut self, store: Option<Arc<dyn HstsStore>>) -> Self {
        self.hsts = store;
        self
    }
}

/// Bundled HTTP method, headers, and optional body passed through the fetch stack.
///
/// Using a struct instead of three separate parameters keeps function arities stable as
/// the set of per-request properties grows (e.g. adding trailers, priority hints, etc.).
pub struct RequestInit {
    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, …).
    pub method: Method,
    /// Request headers. The policy's cookie jar and any `Content-Type` derived from the body
    /// are injected before the request is sent.
    pub headers: HeaderMap,
    /// Optional body bytes. `None` for GET/HEAD.
    /// Automatically dropped when a 301, 302, or 303 redirect requires a method downgrade.
    pub body: Option<Bytes>,
}

impl Default for RequestInit {
    fn default() -> Self {
        Self::get(HeaderMap::new())
    }
}

impl RequestInit {
    /// Plain GET request with the given headers and no body.
    pub fn get(headers: HeaderMap) -> Self {
        Self {
            method: Method::GET,
            headers,
            body: None,
        }
    }

    /// POST request with the given headers and body bytes.
    pub fn post(headers: HeaderMap, body: impl Into<Bytes>) -> Self {
        Self {
            method: Method::POST,
            headers,
            body: Some(body.into()),
        }
    }

    /// Request with an explicit method, headers, and optional body.
    pub fn new(method: Method, headers: HeaderMap, body: Option<Bytes>) -> Self {
        Self {
            method,
            headers,
            body,
        }
    }
}

/// Peek buffer size (first bytes of body). Used for detecting mime type
const PEEK_MAX: usize = 5 * 1024;
/// Maximum number of redirects allowed
const MAX_REDIRECTS: usize = 20;
/// Ceiling on the body buffer pre-allocation. Content-Length is server-controlled, so we never
/// allocate more than this up front; larger honest bodies grow the buffer as bytes arrive.
const MAX_PREALLOC: usize = 1024 * 1024;

/// The top of a response (HTTP headers + first 5KB of the body, if any), plus a stream
/// for the remainder of the body.
pub struct ResponseTop {
    /// Metadata about the result
    pub meta: FetchResultMeta,
    /// Peek buffer of the first PEEK_MAX of data
    pub peek_buf: PeekBuf,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data)
    #[cfg(not(target_arch = "wasm32"))]
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data).
    /// Not `Send` on wasm32: reqwest's fetch-backed body stream wraps JS types.
    #[cfg(target_arch = "wasm32")]
    pub reader: Box<dyn AsyncRead + Unpin>,
}

/// This function will make a request to a given URL and returns the top of the response. These
/// are most likely the headers and the first 5 KB of body. This can be used to determine mime type
/// of the resource fetched. It will also return a stream reader that is able to read the remainder
/// of the body (minus the peek buffer).
pub async fn fetch_response_top(
    client: Arc<reqwest::Client>,
    url: Url,
    // Method, headers, and optional body for this request.
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ResponseTop, NetError> {
    let started = Instant::now();
    observer.on_event(NetEvent::Started { url: url.clone() });

    let resp = get_with_redirects(
        client.clone(),
        url.clone(),
        init,
        cancel.clone(),
        observer.clone(),
        policy,
    )
    .await?;

    // Response is received, setup our meta structure
    let mut meta = FetchResultMeta {
        final_url: resp.url().clone(),
        status: resp.status().as_u16(),
        status_text: resp.status().canonical_reason().unwrap_or("").to_string(),
        headers: resp.headers().clone(),
        content_length: resp.content_length(), // More often than not, this is None
        content_type: resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        has_body: true, // Don't know yet
    };

    // Peek the stream up to PEEK_MAX bytes
    let mut body_stream = resp
        .bytes_stream()
        .map_err(|e| NetError::Read(Arc::new(anyhow!(e))));
    let mut received_net: u64 = 0;
    let mut peek_buf_vec: Vec<u8> = Vec::with_capacity(PEEK_MAX);
    let mut excess: Option<Bytes> = None;

    let observer_clone = observer.clone();

    // We might need more fetches than one. Although it's unlikely unless you set PEEK_MAX to >8KB
    while peek_buf_vec.len() < PEEK_MAX {
        let next = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                observer_clone.on_event(NetEvent::Cancelled { url: url.clone(), reason: "peek stream cancelled" });
                return Err(NetError::Cancelled("peek stream cancelled".into()));
            }
            // Read bytes from stream
            n = body_stream.next() => n,
        };

        match next {
            // We received a chunk of data
            Some(Ok(chunk)) => {
                received_net += chunk.len() as u64;

                observer.on_event(NetEvent::Progress {
                    received_bytes: received_net,
                    elapsed: started.elapsed(),
                    expected_length: meta.content_length,
                });

                let need = PEEK_MAX.saturating_sub(peek_buf_vec.len());
                if chunk.len() <= need {
                    // Entire chunk fits in our peek_buf.
                    peek_buf_vec.extend_from_slice(&chunk);
                } else {
                    // Chunk does not fit. For instance: Peek Buf = 12Kb. We read 8Kb in the first
                    // read, and 8kb in the second. In this case we have read 16kb when we only need
                    // the first 12kb. We fill the peek buf until full, and keep the rest in the
                    // 'excess' buffer
                    peek_buf_vec.extend_from_slice(&chunk[..need]);
                    excess = Some(chunk.slice(need..));
                    break;
                }
            }
            Some(Err(e)) => {
                // Something failed
                observer.on_event(NetEvent::Failed {
                    url: url.clone(),
                    error: e.into(),
                });
                return Err(NetError::Read(Arc::new(anyhow!("peek read failed"))));
            }
            None => {
                // Stream ended successfully
                break;
            }
        }
    }

    // Save the length before we store the excess into a body stream
    let excess_len = excess.as_ref().map(|b| b.len() as u64).unwrap_or(0);

    // It's possible that we have read too much, and we have an exccess buffer, so we create
    // a new stream that starts at the end of the peek buffer WITH the excess buffer in front.
    //
    //  |--- Peek buffer ---|---- Excess buffer ----| ---- body stream ----|
    //                                              ^ stream starts here
    //                      ^  new body stream "rereads" the excess buffer and starts here
    // boxed() demands a `Send` stream; reqwest's wasm body stream is `!Send` (single thread).
    #[cfg(not(target_arch = "wasm32"))]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed()
    } else {
        body_stream.boxed()
    };
    #[cfg(target_arch = "wasm32")]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed_local()
    } else {
        body_stream.boxed_local()
    };

    // Update last remaining items in meta struct
    let peek_buf = PeekBuf::from_vec(peek_buf_vec);
    let has_body_by_len = meta.content_length.unwrap_or(0) > 0 || !peek_buf.is_empty();
    meta.has_body = has_body_by_len;

    // Wrap our body stream into a progress reader. This way it will emit net events to the observer
    // whenever it is read.
    let stream = body_stream.map_err(|e: NetError| e.to_io());
    let inner_reader = StreamReader::new(stream);

    // Update the progress counter to the point of the bytes read (note: this can cause a strange
    // decrease in bytes read in the progress events?)
    let already_delivered = received_net - excess_len;

    let progress_reader = ProgressReader::new(
        inner_reader,
        cancel.clone(),
        observer.clone(),
        url.clone(),
        started,
        meta.content_length,
        already_delivered,
    );

    Ok(ResponseTop {
        meta,
        peek_buf,
        reader: Box::new(progress_reader),
    })
}

/// Progres reader is a simple stream that will wrap another AsyncRead stream, and emit progress
/// events to the observer.
struct ProgressReader<R> {
    /// Actual reader
    inner: R,
    /// Cancellation token
    cancel: CancellationToken,
    // Observer to emit events to
    observer: Arc<dyn NetObserver + Send + Sync>,
    /// Url we are reading from. For event emission
    url: Url,
    /// When we started reading, since we already read the peek buffer from this stream
    started: Instant,
    /// Expected length of the resource, if known
    expected_length: Option<u64>,
    /// Number of bytes already received (from the peek buffer)
    received: u64,
    /// Whether we already emitted a cancelled event
    cancel_emitted: bool,
    /// Whether we already emitted a finished event (guards against duplicate EOF polls)
    finished_emitted: bool,
}

impl<R: AsyncRead + Unpin> ProgressReader<R> {
    fn new(
        inner: R,
        cancel: CancellationToken,
        observer: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        started: Instant,
        expected_length: Option<u64>,
        already_received: u64,
    ) -> Self {
        Self {
            inner,
            cancel,
            observer,
            url,
            started,
            expected_length,
            received: already_received,
            cancel_emitted: false,
            finished_emitted: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // When cancelled, we are directly done
        if self.cancel.is_cancelled() {
            // Maybe it's already cancelled? Then don't send another cancelled event
            if !self.cancel_emitted {
                self.observer.on_event(NetEvent::Cancelled {
                    url: self.url.clone(),
                    reason: "progress reader cancelled",
                });
                self.cancel_emitted = true;
            }

            let err = NetError::Cancelled("progress reader cancelled".into());
            return std::task::Poll::Ready(Err(err.to_io()));
        }

        // Pull new bytes from the reader
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let std::task::Poll::Ready(Ok(())) = &poll {
            let new_len = buf.filled().len();
            let read_bytes = (new_len - pre_len) as u64;

            // nothing read, then we have reached the end of the stream
            if read_bytes == 0 && !self.finished_emitted {
                self.finished_emitted = true;
                self.observer.on_event(NetEvent::Finished {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    url: self.url.clone(),
                });
            }
            if read_bytes > 0 {
                self.received += read_bytes;
                self.observer.on_event(NetEvent::Progress {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    expected_length: self.expected_length,
                });
            }
        }

        poll
    }
}

/// Spare capacity kept available for each `read_buf` so it never returns 0 for lack of room
/// (which the loop would misread as EOF).
const READ_CHUNK: usize = 16 * 1024;

/// Fetch a complete resource, returning the metadata and the full body as `Bytes`.
///
/// The body is assembled with a single copy per chunk: bytes are read straight from the
/// underlying stream into a pre-sized [`BytesMut`] (sized from `Content-Length` when known) and
/// then `freeze`d into an `Arc`-backed [`Bytes`]. Handing the result to the caller — and the
/// `Bytes::from`/`freeze` at the boundary — is zero-copy, so the only memcpy of the payload is the
/// unavoidable assembly into one contiguous buffer.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_response_complete(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    // We can cap the amount of bytes we want to read (None for unlimited)
    max_bytes: Option<usize>,
    // Maximum time allowed between reads
    read_idle_timeout: Duration,
    // Total time of read allowed (if any)
    total_body_timeout: Option<Duration>,
    policy: NetPolicy,
) -> Result<(FetchResultMeta, Bytes), NetError> {
    let started = Instant::now();

    let ResponseTop {
        meta,
        peek_buf,
        mut reader,
    } = fetch_response_top(client, url, init, cancel.clone(), observer.clone(), policy).await?;

    // Reject responses that already declare a body larger than max_bytes, before reading any of it.
    // The in-loop check below remains the backstop for servers that lie or use chunked encoding.
    if let (Some(max), Some(len)) = (max_bytes, meta.content_length) {
        if len as usize > max {
            return Err(NetError::Read(Arc::new(anyhow!(
                "content-length {} exceeds maximum size of {} bytes",
                len,
                max
            ))));
        }
    }

    // Pre-size from Content-Length when known to avoid reallocations as the body grows; otherwise
    // start from the peek length. The peek bytes have already been read off the stream, so seed the
    // buffer with them (a one-off copy of the small peek region, not the whole body). Content-Length
    // is untrusted, so the pre-allocation is clamped to MAX_PREALLOC (and max_bytes when set).
    let advertised = meta.content_length.map(|n| n as usize).unwrap_or(0);
    let ceiling = max_bytes.unwrap_or(MAX_PREALLOC).min(MAX_PREALLOC);
    let initial_cap = advertised.min(ceiling).max(peek_buf.len());
    let mut body_buf = BytesMut::with_capacity(initial_cap);
    body_buf.extend_from_slice(peek_buf.as_slice());

    loop {
        // Check if we hit the total body timeout
        if let Some(total) = total_body_timeout {
            if started.elapsed() > total {
                return Err(NetError::Timeout("total body timeout".into()));
            }
        }

        // Ensure there is spare capacity so `read_buf` reads directly into the buffer (single copy
        // from the stream) rather than returning 0 for lack of room.
        if body_buf.capacity() - body_buf.len() < READ_CHUNK {
            body_buf.reserve(READ_CHUNK);
        }

        let n = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                return Err(NetError::Cancelled("fetch_request_complete cancelled".into()));
            }
            // Read bytes, or timeout when not read something in time. `read_buf` reads directly into
            // the spare capacity of `body_buf`, so there is no intermediate scratch buffer.
            r = timeout(read_idle_timeout, reader.read_buf(&mut body_buf)) => {
                match r {
                    Err(_) => return Err(NetError::Timeout("fetch_request_complete timeout".into())),
                    Ok(Err(e)) => return Err(NetError::Io(Arc::new(e))),
                    Ok(Ok(n)) => n,
                }
            }
        };

        if n == 0 {
            // Stream ended normally
            break;
        }

        if let Some(max) = max_bytes {
            // Too many bytes are read. We throw an error (@TODO: should we do this? not just cap
            // the buffer and return that?
            if body_buf.len() > max {
                return Err(NetError::Read(Arc::new(anyhow!(
                    "fetch_request_complete exceeded maximum size of {} bytes",
                    max
                ))));
            }
        }
    }

    // `freeze` converts the `BytesMut` into an `Arc`-backed `Bytes` without copying.
    Ok((meta, body_buf.freeze()))
}

/// Perform a GET request, following redirects up to MAX_REDIRECTS times, while sending out net events.
///
/// Follow a chain of HTTP redirects, returning the first non-redirect response.
///
/// - `init.method` and `init.body` are preserved on 307/308; downgraded to GET (body dropped)
///   on 301/302/303, matching browser behaviour (RFC 7231 §6.4).
/// - `Authorization` and `Cookie` are stripped on cross-origin redirects (RFC 9110 §15.4);
///   the cookie jar is re-queried for the new origin.
/// - Only `http` and `https` targets are followed; other schemes are rejected.
/// - `policy.url_allowed` and `policy.cookies_for` are called at every hop.
/// - `Set-Cookie` values on 3xx responses are reported via `policy.on_cookies` and the jar is
///   re-queried for the next hop; the final response's cookies are the caller's responsibility.
async fn get_with_redirects(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<reqwest::Response, NetError> {
    let mut url = url;
    let mut current_method = init.method;
    let mut current_headers = init.headers;
    let mut current_body = init.body;

    for _ in 0..MAX_REDIRECTS {
        // Scheme allowlist — only http/https are safe to follow
        if !matches!(url.scheme(), "http" | "https") {
            return Err(NetError::Redirect(Arc::new(anyhow!(
                "unsupported URL scheme '{}': only http and https are allowed",
                url.scheme()
            ))));
        }

        // HSTS upgrade, before the policy check so the hook sees the URL that will actually be
        // requested, and before any connection is opened so the plaintext request never happens.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = policy.hsts {
            if hsts::should_upgrade(store.as_ref(), &url, chrono::Utc::now()) {
                url = hsts::upgrade(&url);
            }
        }

        // Policy check (SSRF / blocklist hook)
        if !(policy.url_allowed)(&url) {
            return Err(NetError::Redirect(Arc::new(anyhow!(
                "URL blocked by policy: {}",
                url
            ))));
        }

        // Inject cookies from the jar for this hop's origin.
        // Only applied when no Cookie header is already set; this naturally handles cross-origin
        // redirects: the cookie was stripped above, so the jar is re-queried for the new origin.
        if !current_headers.contains_key(header::COOKIE) {
            if let Some(cookie_str) = (policy.cookies_for)(&url) {
                if let Ok(val) = cookie_str.parse() {
                    current_headers.insert(header::COOKIE, val);
                }
            }
        }

        let mut req_builder = client
            .request(current_method.clone(), url.clone())
            .headers(current_headers.clone());
        if let Some(ref body) = current_body {
            req_builder = req_builder.body(body.clone());
        }
        let fut = req_builder.send();
        tokio::pin!(fut);

        let resp = tokio::select! {
            _ = cancel.cancelled() => {
                observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "cancelled net.get_with_redirects" });
                return Err(NetError::Cancelled("cancelled net.get_with_redirects".into()));
            }
            r = &mut fut => r.context("net.get_with_redirects request failed").map_err(|e| NetError::Read(Arc::new(e)))?
        };

        // Harvest HSTS from every hop, not just the final one: a 301 http->https is the usual way
        // a site first arms it, and that response is consumed below.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = policy.hsts {
            hsts::record(store.as_ref(), &url, resp.headers(), chrono::Utc::now());
        }

        if !resp.status().is_redirection() {
            return Ok(resp);
        }

        // 3xx — resolve the Location header
        let status = resp.status().as_u16();
        let from = resp.url().clone();

        // Report Set-Cookie values on this hop to the jar before following the redirect —
        // login flows commonly set the session cookie on a 302. Dropping our Cookie header
        // makes the next hop re-query the now-updated jar instead of resending a stale value.
        let set_cookies: Vec<&str> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if !set_cookies.is_empty() {
            (policy.on_cookies)(&from, &set_cookies);
            current_headers.remove(header::COOKIE);
        }

        let loc = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                NetError::Redirect(Arc::new(anyhow!(
                    "redirect status {} without Location header",
                    status
                )))
            })?;

        let to = from.join(loc).map_err(|e| {
            NetError::Redirect(Arc::new(anyhow!("invalid redirect URL '{}': {}", loc, e)))
        })?;

        // Method and body semantics per RFC 7231 §6.4
        match status {
            // 301/302: browsers always downgrade POST to GET (§6.4.2–3); we follow suit.
            // HEAD stays HEAD (no body involved); all other methods become GET.
            301 | 302 => {
                if current_method != Method::HEAD {
                    current_method = Method::GET;
                }
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 303 See Other: always GET, always drop body.
            303 => {
                current_method = Method::GET;
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 307/308: preserve method and body.
            307 | 308 => {}
            // Other 3xx: treat conservatively as 302.
            _ => {
                if current_method != Method::HEAD {
                    current_method = Method::GET;
                }
                current_body = None;
            }
        }

        // Strip credential headers when redirecting to a different origin (RFC 9110 §15.4).
        // Cookie will be re-applied from the jar at the top of the next loop iteration.
        if from.origin() != to.origin() {
            for h in SENSITIVE_REDIRECT_HEADERS {
                current_headers.remove(h);
            }
        }

        observer.on_event(NetEvent::Redirected {
            from,
            to: to.clone(),
            status,
        });

        url = to
    }

    Err(NetError::Redirect(Arc::new(anyhow!("too many redirects"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::test_support::{RouteConfig, TestServer};
    use cow_utils::CowUtils;
    use http::HeaderMap;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    struct TestObserver;
    impl NetObserver for TestObserver {
        fn on_event(&self, _: NetEvent) {}
    }

    fn observer() -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(TestObserver)
    }

    /// Deterministic, position-dependent byte pattern. Any truncation or mis-ordering during body
    /// assembly changes the bytes, so an exact compare catches it.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    fn client() -> Arc<reqwest::Client> {
        Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        )
    }

    /// A TLS `TestServer` plus a client pointed at it: the certificate is trusted explicitly and
    /// the domain resolved to the loopback listener, so no DNS or public CA is involved.
    async fn tls_server_and_client(
        routes: Vec<(&str, RouteConfig)>,
    ) -> (
        crate::net::test_support::TestServerHandle,
        Arc<reqwest::Client>,
    ) {
        let mut srv = TestServer::new().tls("hsts.test");
        for (path, cfg) in routes {
            srv = srv.route(path, cfg);
        }
        let srv = srv.start().await;

        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(cert)
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        (srv, Arc::new(client))
    }

    /// A real HTTPS response must arm the store. This is the one path the hermetic HTTP tests
    /// cannot reach: HSTS ignores plaintext responses and IP-literal hosts alike.
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_recorded_from_a_real_https_response() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                )],
                b"hello".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());

        let entry = crate::net::hsts::HstsStore::load(store.as_ref(), "hsts.test")
            .expect("an https response carrying the header must arm the store");
        assert!(entry.include_subdomains);
        assert!(!entry.is_expired(chrono::Utc::now()));
    }

    /// The header must be ignored unless it arrived over TLS, so the same response served over
    /// plain HTTP arms nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_not_recorded_over_plaintext() {
        let srv = TestServer::new()
            .route(
                "/",
                RouteConfig::ok_with_headers(
                    &[("Strict-Transport-Security", "max-age=31536000")],
                    b"hello".to_vec(),
                ),
            )
            .start()
            .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok());
        assert!(store.is_empty(), "plaintext must never arm HSTS");
    }

    /// max-age=0 over TLS disarms a host that was previously armed.
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_max_age_zero_disarms_over_tls() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[("Strict-Transport-Security", "max-age=0")],
                b"bye".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        crate::net::hsts::HstsStore::store(
            store.as_ref(),
            "hsts.test",
            crate::net::hsts::HstsEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                include_subdomains: false,
            },
        );

        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());
        assert!(store.is_empty(), "max-age=0 must remove the entry");
    }

    async fn server() -> crate::net::test_support::TestServerHandle {
        // 64 KiB pattern, chunked so the body arrives in many pieces with no Content-Length.
        let big = pattern(64 * 1024);
        let big_chunks: Vec<&[u8]> = big.chunks(5_000).collect();
        // Exactly one READ_CHUNK worth of body, chunked (no Content-Length).
        let exact = vec![b'Y'; super::READ_CHUNK];
        TestServer::new()
            .route("/big", RouteConfig::ok(vec![b'X'; 12 * 1024]))
            .route("/big-chunked", RouteConfig::chunked(big_chunks))
            .route("/exact-chunk", RouteConfig::chunked(vec![exact.as_slice()]))
            .route("/large-cl", RouteConfig::ok(pattern(64 * 1024)))
            .route("/redirect", RouteConfig::redirect_to("/big"))
            .route(
                "/slow",
                RouteConfig::stall_mid_body(super::PEEK_MAX, Duration::from_millis(2_000)),
            )
            .route("/drop", RouteConfig::drop_mid_body(100, 10_000))
            // Declares an absurd Content-Length, sends exactly the peek window, then drops. The
            // peek loop stops at PEEK_MAX without another read, so the fetch reaches the body
            // phase with the hostile Content-Length intact.
            .route(
                "/huge-cl",
                RouteConfig::drop_mid_body(super::PEEK_MAX, 1 << 45),
            )
            .route("/xl-cl", RouteConfig::ok(pattern(2 * 1024 * 1024)))
            .route(
                "/login",
                RouteConfig::redirect_with_cookie("/whoami", "session=abc123; Path=/"),
            )
            .route("/whoami", RouteConfig::echo_cookie_header())
            .route("/empty", RouteConfig::ok(b""))
            .route("/nohead", RouteConfig::no_location_redirect())
            .route("/loop", RouteConfig::redirect_self())
            .route("/hop1", RouteConfig::redirect_to("/hop2"))
            .route("/hop2", RouteConfig::redirect_to("/hop3"))
            .route("/hop3", RouteConfig::ok(b"final"))
            .route(
                "/chunked",
                RouteConfig::chunked(vec![b"hel", b"lo ", b"wor", b"ld"]),
            )
            .start()
            .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn top_returns_peek_and_reader_rest() {
        let srv = server().await;
        let ResponseTop {
            meta,
            peek_buf,
            mut reader,
        } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(peek_buf.len(), super::PEEK_MAX);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(peek_buf.len() + rest.len(), 12 * 1024);
        assert!(meta.has_body);
        assert_eq!(meta.status, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/redirect"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
        assert!(meta.has_body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_timeout_triggers_on_slow_body() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_millis(100),
            Some(Duration::from_secs(2)),
            NetPolicy::default(),
        )
        .await;

        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("timeout"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_peek_is_honored() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    /// Uses a chunked route (no Content-Length) so the in-loop size check is what fires; responses
    /// that declare an oversized Content-Length up front are rejected earlier, see
    /// `huge_content_length_rejected_before_body_read`.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_max_bytes_exceeded() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(100),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("exceeded"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_cancel_mid_body() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn progress_reader_cancel_returns_error() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let ResponseTop { mut reader, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        cancel.cancel();
        assert!(reader.read(&mut vec![0u8; 1024]).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_mid_body_produces_error() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/drop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_body_has_no_body_flag_and_empty_peek() {
        let srv = server().await;
        let ResponseTop { meta, peek_buf, .. } = super::fetch_response_top(
            client(),
            srv.url("/empty"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert!(peek_buf.is_empty());
        assert!(!meta.has_body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multi_hop_redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"final");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_redirect_chain() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        assert!(fut.await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_is_assembled_correctly() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_without_location_header_errors() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/nohead"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_loop_exceeds_max_redirects() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/loop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("redirect"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn url_filter_blocks_request() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy {
                url_allowed: Box::new(|_| false),
                ..NetPolicy::default()
            },
        )
        .await;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("blocked"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_headers_are_sent() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        // Just verify the request completes successfully with custom headers
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    // Body assembly / READ_CHUNK reservation path.

    /// A large body with no Content-Length (chunked) forces `initial_cap == 0`, so every byte of
    /// growth goes through the `reserve(READ_CHUNK)` guard across many loop iterations. Verifies
    /// the loop never mistakes a full buffer for EOF and assembles all 64 KiB in order.
    #[tokio::test(flavor = "current_thread")]
    async fn large_chunked_body_without_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 64 * 1024);
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// A chunked body of exactly `READ_CHUNK` bytes lands on the reservation boundary: after the
    /// data is read the spare capacity is fully consumed, and the next `read_buf` must reserve more
    /// before it can observe the real EOF. Guards against an off-by-one false EOF at the boundary.
    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_exactly_read_chunk_size_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/exact-chunk"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), super::READ_CHUNK);
        assert!(body.iter().all(|&b| b == b'Y'));
    }

    /// A body larger than READ_CHUNK *with* Content-Length exercises the pre-sized path (buffer
    /// seeded to the full length up front). The reservation guard should rarely fire, and the body
    /// must still come back byte-for-byte.
    #[tokio::test(flavor = "current_thread")]
    async fn large_body_with_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/large-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(64 * 1024));
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// `max_bytes` is checked with a strict `>`, so a body whose length equals the cap exactly must
    /// succeed. Boundary partner to `fetch_complete_max_bytes_exceeded`.
    #[tokio::test(flavor = "current_thread")]
    async fn max_bytes_equal_to_body_size_succeeds() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(12 * 1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
    }

    /// A response whose Content-Length already exceeds `max_bytes` is rejected right after the
    /// header/peek phase, before any body bytes beyond the peek are read.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_rejected_before_body_read() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("content-length"), "unexpected error: {msg}");
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    }

    /// With no `max_bytes`, a hostile Content-Length must not drive the buffer pre-allocation
    /// (it is clamped to MAX_PREALLOC). The connection then drops, so the fetch surfaces a read
    /// error instead of attempting a multi-terabyte allocation.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_does_not_preallocate() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    /// A body larger than MAX_PREALLOC still assembles correctly: the pre-allocation is clamped,
    /// and the read loop grows the buffer as real bytes arrive.
    #[tokio::test(flavor = "current_thread")]
    async fn body_larger_than_prealloc_cap_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/xl-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(2 * 1024 * 1024));
        assert_eq!(&body[..], pattern(2 * 1024 * 1024).as_slice());
    }

    /// A cookie set on an intermediate 302 must be reported via `on_cookies` before the next hop,
    /// and the next hop must carry the updated jar contents instead of a stale Cookie header.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_reaches_jar_and_next_hop() {
        let srv = server().await;

        type ReceivedCookies = Vec<(Url, Vec<String>)>;
        let jar: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let received: Arc<std::sync::Mutex<ReceivedCookies>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let jar_read = jar.clone();
        let jar_write = jar.clone();
        let received_sink = received.clone();
        let policy = NetPolicy {
            cookies_for: Box::new(move |_| jar_read.lock().unwrap().clone()),
            on_cookies: Box::new(move |url, values| {
                received_sink
                    .lock()
                    .unwrap()
                    .push((url.clone(), values.iter().map(|v| v.to_string()).collect()));
                // Store only the name=value part, as a real jar would.
                if let Some(v) = values.first() {
                    let nv = v.split(';').next().unwrap_or(v).trim().to_string();
                    *jar_write.lock().unwrap() = Some(nv);
                }
            }),
            ..NetPolicy::default()
        };

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        // The /whoami route echoes back the Cookie header the follow-up request carried.
        assert_eq!(&body[..], b"session=abc123");

        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.path(), "/login");
        assert_eq!(received[0].1, vec!["session=abc123; Path=/".to_string()]);
    }

    /// When a redirect hop sets cookies but no jar is wired up, the pre-existing Cookie header is
    /// dropped for subsequent hops rather than resending a value the server just replaced.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_drops_stale_cookie_header() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "stale=1".parse().unwrap());

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"");
    }
}

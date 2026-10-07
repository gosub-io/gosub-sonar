//! One-shot GET helpers for callers that don't need the full scheduler.
//!
//! These send the same [`DEFAULT_USER_AGENT`] the [`Fetcher`](crate::Fetcher) does unless
//! [`SimpleOptions::user_agent`] says otherwise. reqwest sets no `User-Agent` of its own, so
//! without it these requests would go out with the header absent entirely - which servers are
//! entitled to refuse, and some do (Wikimedia answers a header-less request with 403). A caller
//! reaching for the simple API is still the same client as one using the scheduler, and should
//! look like it.
//!
//! None of the [`Fetcher`](crate::Fetcher)'s policy applies here: no URL hook, HSTS, mixed
//! content, cookie jar or DNS policy, so there is no SSRF protection. Redirects are followed up
//! to 10 hops, across hosts, but never from `https` down to `http`. A `file:` URL reads any
//! regular file the process can read. Bodies are capped at 10 MiB unless
//! [`SimpleOptions::max_body`] says otherwise.

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{header, HeaderMap};
use std::time::Duration;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
use crate::http::response::Response;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::fetcher::DEFAULT_USER_AGENT;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::proxy::ProxyConfig;
#[cfg(not(target_arch = "wasm32"))]
use cookie::Cookie;
#[cfg(not(target_arch = "wasm32"))]
use cow_utils::CowUtils;
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;

/// Maximum body size accepted by the simple API (10 MiB).
const MAX_SIMPLE_BODY: u64 = 10 * 1024 * 1024;

/// Most redirect hops followed.
#[cfg(not(target_arch = "wasm32"))]
const MAX_SIMPLE_REDIRECTS: usize = 10;

/// Whether a redirect from `previous` (every hop so far) to `next` is followed.
#[cfg(not(target_arch = "wasm32"))]
fn allow_redirect(previous: &[Url], next: &Url) -> Result<(), &'static str> {
    if previous.len() >= MAX_SIMPLE_REDIRECTS {
        return Err("too many redirects");
    }
    match next.scheme() {
        "https" => Ok(()),
        "http" if previous.iter().any(|u| u.scheme() == "https") => {
            Err("redirect from https to http refused")
        }
        "http" => Ok(()),
        _ => Err("redirect to an unsupported scheme"),
    }
}

/// What to send with a one-shot request, for the `_with` variants of the simple helpers.
///
/// [`SimpleOptions::default`] is exactly what [`simple_get`], [`sync_get`] and [`sync_fetch`]
/// do, so the plain helpers are these with the defaults.
///
/// ```no_run
/// use gosub_sonar::SimpleOptions;
///
/// let opts = SimpleOptions::default()
///     .with_user_agent("MyBrowser/1.0")
///     .with_cookies("session=abc; theme=dark");
/// ```
///
/// Each call builds its own client, so there is no connection reuse and no cookie jar carried
/// between calls. Cookies are what you pass in and, for [`sync_fetch`], what comes back in
/// [`Response::cookies`]; nothing is remembered. Use [`Fetcher`](crate::Fetcher) for a real
/// jar, pooled connections, or per-hop cookie handling across redirects.
#[derive(Debug, Clone)]
pub struct SimpleOptions {
    /// Headers sent with the request. Empty by default.
    pub headers: HeaderMap,

    /// `User-Agent` for the request. `None` sends [`DEFAULT_USER_AGENT`], as the
    /// [`Fetcher`](crate::Fetcher) does. On wasm32 `None` leaves it to the browser. Ignored if
    /// [`headers`](SimpleOptions::headers) already carries a `User-Agent`, so a hand-written one
    /// always wins, as with [`cookies`](SimpleOptions::cookies).
    pub user_agent: Option<String>,

    /// Cookies to send, in `Cookie` header format: `"name=value; name2=value2"`. Ignored if
    /// [`headers`](SimpleOptions::headers) already carries a `Cookie` header, so a hand-written
    /// one always wins. An unusable value fails the call rather than being dropped.
    pub cookies: Option<String>,

    /// Timeout for the TCP and TLS handshake. Ignored on wasm32, where the browser's `fetch()`
    /// owns timeouts.
    pub connect_timeout: Duration,

    /// Deadline for the whole request, headers and body together. Ignored on wasm32.
    pub timeout: Duration,

    /// Cap on the response body, and on a `file:` read. Defaults to 10 MiB. Checked against
    /// `Content-Length` and again while streaming, so a lying header cannot get past it.
    pub max_body: u64,

    /// Which proxy the request goes through. Defaults to [`ProxyConfig::System`], which reads
    /// `HTTP_PROXY` and friends from the environment - see [`proxy`](mod@crate::net::proxy).
    ///
    /// Native-only: on wasm32 the browser's `fetch()` uses the user's own proxy settings.
    #[cfg(not(target_arch = "wasm32"))]
    pub proxy: ProxyConfig,
}

impl Default for SimpleOptions {
    fn default() -> Self {
        Self {
            headers: HeaderMap::new(),
            user_agent: None,
            cookies: None,
            connect_timeout: Duration::from_secs(10),
            timeout: Duration::from_secs(30),
            max_body: MAX_SIMPLE_BODY,
            #[cfg(not(target_arch = "wasm32"))]
            proxy: ProxyConfig::default(),
        }
    }
}

impl SimpleOptions {
    /// Send these headers with the request, replacing any set earlier.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Send this `User-Agent`.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Send these cookies, in `Cookie` header format - see [`SimpleOptions::cookies`].
    #[must_use]
    pub fn with_cookies(mut self, cookies: impl Into<String>) -> Self {
        self.cookies = Some(cookies.into());
        self
    }

    /// Set the connect and total-request timeouts.
    #[must_use]
    pub fn with_timeouts(mut self, connect: Duration, total: Duration) -> Self {
        self.connect_timeout = connect;
        self.timeout = total;
        self
    }

    /// Cap the response body at `max_body` bytes.
    #[must_use]
    pub fn with_max_body(mut self, max_body: u64) -> Self {
        self.max_body = max_body;
        self
    }

    /// Route the request through `proxy` - see [`SimpleOptions::proxy`].
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = proxy;
        self
    }

    /// The headers actually sent: [`headers`](SimpleOptions::headers) plus a `User-Agent` and a
    /// `Cookie` header built from [`user_agent`](SimpleOptions::user_agent) and
    /// [`cookies`](SimpleOptions::cookies), each unless one was set by hand.
    fn effective_headers(&self) -> Result<HeaderMap> {
        let mut headers = self.headers.clone();
        if !headers.contains_key(header::USER_AGENT) {
            #[cfg(not(target_arch = "wasm32"))]
            let user_agent = Some(self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT));
            #[cfg(target_arch = "wasm32")]
            let user_agent = self.user_agent.as_deref();
            if let Some(user_agent) = user_agent {
                let value = user_agent
                    .parse()
                    .with_context(|| format!("unusable User-Agent header value {user_agent:?}"))?;
                headers.insert(header::USER_AGENT, value);
            }
        }
        if let Some(ref cookies) = self.cookies {
            if !headers.contains_key(header::COOKIE) {
                let value = cookies
                    .parse()
                    .with_context(|| format!("unusable Cookie header value {cookies:?}"))?;
                headers.insert(header::COOKIE, value);
            }
        }
        Ok(headers)
    }

    /// The one-shot client for this request.
    fn build_client(&self) -> Result<reqwest::Client> {
        // The user agent travels in the default headers rather than through
        // `ClientBuilder::user_agent`, which would overwrite one the caller set in `headers`.
        let b = reqwest::Client::builder().default_headers(self.effective_headers()?);
        // The browser's fetch() owns TLS, timeouts, redirects and proxying; reqwest's wasm
        // backend has headers and nothing else.
        #[cfg(not(target_arch = "wasm32"))]
        let b = self.proxy.apply(
            b.use_rustls_tls()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout)
                .redirect(reqwest::redirect::Policy::custom(
                    |attempt| match allow_redirect(attempt.previous(), attempt.url()) {
                        Ok(()) => attempt.follow(),
                        Err(why) => attempt.error(why),
                    },
                )),
        )?;
        Ok(b.build()?)
    }
}

/// Fail for anything but a regular file: a FIFO or device has no end to read to.
#[cfg(not(target_arch = "wasm32"))]
fn require_regular_file(meta: &std::fs::Metadata) -> Result<()> {
    if meta.is_file() {
        Ok(())
    } else {
        anyhow::bail!("not a regular file")
    }
}

/// Perform a simple one-shot GET request and return the body as bytes.
/// Handles http, https, and file:// URLs.
/// Use this for standalone callers (renderer, tools) that don't need the full
/// priority-scheduler Fetcher.
///
/// The body is capped at 10 MiB. See the [module docs](self) for what is not checked.
///
/// Use [`simple_get_with`] to send headers, a `User-Agent`, or cookies.
pub async fn simple_get(url: &Url) -> Result<Bytes> {
    simple_get_with(url, &SimpleOptions::default()).await
}

/// [`simple_get`] with explicit request options - see [`SimpleOptions`].
///
/// For a `file:` URL only [`SimpleOptions::max_body`] applies; the rest mean nothing off the
/// network and are ignored.
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use gosub_sonar::{simple_get_with, SimpleOptions};
/// use url::Url;
///
/// let opts = SimpleOptions::default()
///     .with_user_agent("MyBrowser/1.0")
///     .with_cookies("session=abc");
/// let bytes = simple_get_with(&Url::parse("https://example.org")?, &opts).await?;
/// # Ok(())
/// # }
/// ```
pub async fn simple_get_with(url: &Url, opts: &SimpleOptions) -> Result<Bytes> {
    let max_body = opts.max_body;
    match url.scheme() {
        // wasm32 has no filesystem; file:// URLs fall through to the unsupported-scheme error.
        #[cfg(not(target_arch = "wasm32"))]
        "file" => {
            use tokio::io::AsyncReadExt as _;
            let path = url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL: {url}"))?;
            // Checked on the opened handle and read with a hard cap, so there is no window
            // between the check and the read.
            let file = tokio::fs::File::open(&path).await?;
            require_regular_file(&file.metadata().await?)?;
            let mut body = Vec::new();
            file.take(max_body + 1).read_to_end(&mut body).await?;
            if body.len() as u64 > max_body {
                anyhow::bail!("file too large (exceeds {} bytes)", max_body);
            }
            Ok(Bytes::from(body))
        }
        "http" | "https" => {
            let client = opts.build_client()?;
            let resp = client.get(url.as_str()).send().await?;
            let status = resp.status();
            if !status.is_success() {
                anyhow::bail!("HTTP {status} fetching {url}");
            }
            if let Some(len) = resp.content_length() {
                if len > max_body {
                    anyhow::bail!("response too large ({len} bytes, limit {max_body} bytes)");
                }
            }
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                body.extend_from_slice(&chunk);
                if body.len() as u64 > max_body {
                    anyhow::bail!("response body exceeds {max_body} bytes");
                }
            }
            Ok(Bytes::from(body))
        }
        scheme => anyhow::bail!("Unsupported URL scheme: {scheme}"),
    }
}

/// Perform a one-shot synchronous GET and return the body as bytes.
///
/// Like [`simple_get`] but sync and safe to call from any context (including inside a Tokio
/// runtime). Errors on non-2xx status codes.
///
/// Native-only: blocking a thread is impossible on wasm32.
///
/// Use [`sync_get_with`] to send headers, a `User-Agent`, or cookies.
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_get(url: &Url) -> Result<Bytes> {
    sync_get_with(url, &SimpleOptions::default())
}

/// [`sync_get`] with explicit request options - see [`SimpleOptions`].
///
/// Native-only: blocking a thread is impossible on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_get_with(url: &Url, opts: &SimpleOptions) -> Result<Bytes> {
    let url = url.clone();
    let opts = opts.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(simple_get_with(&url, &opts))
    })
    .join()
    .map_err(|_| anyhow::anyhow!("sync_get: HTTP thread panicked"))?
}

/// Perform a one-shot synchronous GET, returning the full response (status, headers, body).
///
/// Safe to call from **any** context — including from within a Tokio async runtime.
/// The request always runs on a dedicated OS thread with its own Tokio runtime, so it
/// never conflicts with an already-active runtime on the calling thread.
///
/// Use this for engine-internal code that must issue an HTTP request synchronously
/// (e.g. the HTML parser loading an external stylesheet mid-parse).
///
/// Native-only: blocking a thread is impossible on wasm32.
///
/// Use [`sync_fetch_with`] to send headers, a `User-Agent`, or cookies. Cookies set by the
/// response come back in [`Response::cookies`] either way.
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_fetch(url: &Url) -> Result<Response> {
    sync_fetch_with(url, &SimpleOptions::default())
}

/// [`sync_fetch`] with explicit request options - see [`SimpleOptions`].
///
/// Native-only: blocking a thread is impossible on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_fetch_with(url: &Url, opts: &SimpleOptions) -> Result<Response> {
    let url = url.clone();
    let opts = opts.clone();
    std::thread::spawn(move || do_sync_fetch(url, opts))
        .join()
        .map_err(|_| anyhow::anyhow!("sync_fetch: HTTP thread panicked"))?
}

#[cfg(not(target_arch = "wasm32"))]
fn do_sync_fetch(url: Url, opts: SimpleOptions) -> Result<Response> {
    use std::io::Read as _;

    let max_body = opts.max_body;

    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid file URL: {}", url))?;
        // Blocking is fine: this runs on its own thread.
        let file = std::fs::File::open(&path)?;
        require_regular_file(&file.metadata()?)?;
        let mut body = Vec::new();
        file.take(max_body + 1).read_to_end(&mut body)?;
        if body.len() as u64 > max_body {
            anyhow::bail!("File too large (> {} bytes)", max_body);
        }
        return Ok(Response::from(body));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;

    rt.block_on(async move {
        let client = opts.build_client()?;
        let resp = client.get(url.as_str()).send().await?;

        let status = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();
        let version = match resp.version() {
            reqwest::Version::HTTP_10 => "HTTP/1.0",
            reqwest::Version::HTTP_11 => "HTTP/1.1",
            reqwest::Version::HTTP_2 => "HTTP/2",
            reqwest::Version::HTTP_3 => "HTTP/3",
            _ => "HTTP/1.1",
        }
        .to_string();

        if let Some(cl) = resp.headers().get("content-length") {
            if let Ok(size) = cl.to_str().unwrap_or("").parse::<u64>() {
                if size > max_body {
                    anyhow::bail!("Response body exceeds maximum size of {} bytes", max_body);
                }
            }
        }

        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().cow_to_lowercase().into_owned(), v.to_string()))
            })
            .collect();

        let cookies: HashMap<String, String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| {
                let s = v.to_str().ok()?;
                Cookie::parse(s.to_owned())
                    .ok()
                    .map(|c| (c.name().to_owned(), c.value().to_owned()))
            })
            .collect();

        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
            if body.len() as u64 > max_body {
                anyhow::bail!("Response body exceeds maximum size of {} bytes", max_body);
            }
        }

        Ok(Response {
            status,
            status_text,
            version,
            headers,
            cookies,
            body,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::net::test_support::{RouteConfig, TestServer};
    use url::Url;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn redirects_are_limited_and_never_downgrade() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(allow_redirect(&[u("http://a.test/")], &u("http://b.test/")).is_ok());
        assert!(allow_redirect(&[u("http://a.test/")], &u("https://b.test/")).is_ok());
        assert!(allow_redirect(&[u("https://a.test/")], &u("http://b.test/")).is_err());
        assert!(allow_redirect(
            &[u("https://a.test/"), u("http://b.test/")],
            &u("http://c.test/")
        )
        .is_err());
        assert!(allow_redirect(&[u("http://a.test/")], &u("ftp://b.test/")).is_err());
        let ten = vec![u("http://a.test/"); MAX_SIMPLE_REDIRECTS];
        assert!(allow_redirect(&ten, &u("http://b.test/")).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn simple_get_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let url = Url::from_directory_path(dir.path()).unwrap();
        assert!(simple_get(&url).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_reads_file_url() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"file content").unwrap();
        let url = Url::from_file_path(f.path()).unwrap();
        let bytes = simple_get(&url).await.unwrap();
        assert_eq!(&bytes[..], b"file content");
    }

    #[test]
    fn sync_get_fetches_from_http_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                );
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        let bytes = sync_get(&url).unwrap();
        assert_eq!(&bytes[..], b"hello");
    }

    /// reqwest sets no `User-Agent` of its own, so a builder that does not ask for one sends the
    /// header absent entirely - and servers are entitled to refuse that (Wikimedia answers a
    /// header-less request with 403). Capture the raw request and assert the header is there.
    #[test]
    fn sync_fetch_sends_a_user_agent() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                );
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        let _ = sync_fetch(&url).unwrap();

        let request = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("no request captured");
        let sent = request
            .lines()
            .find_map(|line| {
                line.strip_prefix("user-agent: ")
                    .or_else(|| line.strip_prefix("User-Agent: "))
            })
            .map(str::trim);
        assert_eq!(sent, Some(DEFAULT_USER_AGENT), "request was:\n{request}");
    }

    #[test]
    fn sync_fetch_returns_full_response() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                );
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        let resp = sync_fetch(&url).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body[..], b"hello");
        assert!(resp.headers.contains_key("content-type"));
    }

    #[test]
    fn effective_headers_adds_a_cookie_header() {
        let opts = SimpleOptions::default().with_cookies("a=1; b=2");
        let headers = opts.effective_headers().unwrap();
        assert_eq!(headers.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    /// A `Cookie` header set by hand is the caller being explicit; `cookies` must not clobber it.
    #[test]
    fn effective_headers_keeps_a_hand_written_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "explicit=1".parse().unwrap());
        let opts = SimpleOptions::default()
            .with_headers(headers)
            .with_cookies("ignored=2");
        assert_eq!(
            opts.effective_headers()
                .unwrap()
                .get(header::COOKIE)
                .unwrap(),
            "explicit=1"
        );
    }

    /// A `User-Agent` set by hand is the caller being explicit; neither `user_agent` nor the
    /// default may replace it.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sync_fetch_keeps_a_hand_written_user_agent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let srv = rt.block_on(async {
            TestServer::new()
                .route("/ua", RouteConfig::echo_request_header("User-Agent"))
                .start()
                .await
        });

        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, "Explicit/1.0".parse().unwrap());
        let resp = sync_fetch_with(
            &srv.url("/ua"),
            &SimpleOptions::default().with_headers(headers.clone()),
        )
        .unwrap();
        assert_eq!(&resp.body[..], b"Explicit/1.0");

        let opts = SimpleOptions::default()
            .with_headers(headers)
            .with_user_agent("Ignored/2.0");
        let resp = sync_fetch_with(&srv.url("/ua"), &opts).unwrap();
        assert_eq!(&resp.body[..], b"Explicit/1.0");
    }

    #[test]
    fn effective_headers_reports_an_unusable_cookie_value() {
        let err = SimpleOptions::default()
            .with_cookies("bad\nvalue")
            .effective_headers()
            .unwrap_err();
        assert!(
            err.to_string().contains("Cookie"),
            "error should name the header, got: {err}"
        );
    }

    #[test]
    fn defaults_match_the_plain_helpers() {
        let opts = SimpleOptions::default();
        assert!(opts.headers.is_empty());
        assert!(opts.user_agent.is_none());
        assert!(opts.cookies.is_none());
        assert_eq!(opts.connect_timeout, Duration::from_secs(10));
        assert_eq!(opts.timeout, Duration::from_secs(30));
        assert_eq!(opts.max_body, MAX_SIMPLE_BODY);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_with_sends_custom_headers() {
        let srv = TestServer::new()
            .route("/h", RouteConfig::echo_request_header("X-Custom"))
            .start()
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("X-Custom", "from-caller".parse().unwrap());
        let opts = SimpleOptions::default().with_headers(headers);

        let body = simple_get_with(&srv.url("/h"), &opts).await.unwrap();
        assert_eq!(&body[..], b"from-caller");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_with_sends_user_agent() {
        let srv = TestServer::new()
            .route("/ua", RouteConfig::echo_request_header("User-Agent"))
            .start()
            .await;

        let opts = SimpleOptions::default().with_user_agent("MyBrowser/1.0");
        let body = simple_get_with(&srv.url("/ua"), &opts).await.unwrap();
        assert_eq!(&body[..], b"MyBrowser/1.0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_with_sends_cookies() {
        let srv = TestServer::new()
            .route("/c", RouteConfig::echo_cookie_header())
            .start()
            .await;

        let opts = SimpleOptions::default().with_cookies("session=abc; theme=dark");
        let body = simple_get_with(&srv.url("/c"), &opts).await.unwrap();
        assert_eq!(&body[..], b"session=abc; theme=dark");
    }

    /// The plain helpers must keep behaving exactly as before: no cookies, no caller headers.
    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_still_sends_no_cookies() {
        let srv = TestServer::new()
            .route("/c", RouteConfig::echo_cookie_header())
            .start()
            .await;

        let body = simple_get(&srv.url("/c")).await.unwrap();
        assert!(body.is_empty(), "expected no Cookie header, got {body:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_with_enforces_the_body_cap() {
        let srv = TestServer::new()
            .route("/big", RouteConfig::ok(vec![b'x'; 4096]))
            .start()
            .await;

        let opts = SimpleOptions::default().with_max_body(1024);
        let err = simple_get_with(&srv.url("/big"), &opts).await.unwrap_err();
        assert!(
            err.to_string().contains("1024"),
            "error should name the cap, got: {err}"
        );

        // The same response is fine under the default cap.
        assert_eq!(simple_get(&srv.url("/big")).await.unwrap().len(), 4096);
    }

    #[test]
    fn sync_get_with_sends_cookies() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let srv = rt.block_on(async {
            TestServer::new()
                .route("/c", RouteConfig::echo_cookie_header())
                .start()
                .await
        });

        let opts = SimpleOptions::default().with_cookies("sid=42");
        let body = sync_get_with(&srv.url("/c"), &opts).unwrap();
        assert_eq!(&body[..], b"sid=42");
    }

    #[test]
    fn sync_fetch_with_sends_headers_and_user_agent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let srv = rt.block_on(async {
            TestServer::new()
                .route("/ua", RouteConfig::echo_request_header("User-Agent"))
                .route("/h", RouteConfig::echo_request_header("X-Custom"))
                .start()
                .await
        });

        let opts = SimpleOptions::default().with_user_agent("MyBrowser/1.0");
        let resp = sync_fetch_with(&srv.url("/ua"), &opts).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body[..], b"MyBrowser/1.0");

        let mut headers = HeaderMap::new();
        headers.insert("X-Custom", "from-caller".parse().unwrap());
        let resp = sync_fetch_with(
            &srv.url("/h"),
            &SimpleOptions::default().with_headers(headers),
        )
        .unwrap();
        assert_eq!(&resp.body[..], b"from-caller");
    }

    /// `sync_fetch` reads `Set-Cookie` off the response; pair it with `with_cookies` and the
    /// caller can carry a session across two one-shot calls by hand.
    #[test]
    fn sync_fetch_with_returns_response_cookies() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let srv = rt.block_on(async {
            TestServer::new()
                .route(
                    "/set",
                    RouteConfig::ok_with_headers(&[("Set-Cookie", "sid=99; Path=/")], b"ok"),
                )
                .start()
                .await
        });

        let resp = sync_fetch_with(&srv.url("/set"), &SimpleOptions::default()).unwrap();
        assert_eq!(resp.cookies.get("sid").map(String::as_str), Some("99"));
    }
}

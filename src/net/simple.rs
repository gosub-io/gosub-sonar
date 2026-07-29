//! One-shot GET helpers for callers that don't need the full scheduler.

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{header, HeaderMap};
use std::time::Duration;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
use crate::http::response::Response;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::proxy::ProxyConfig;
#[cfg(not(target_arch = "wasm32"))]
use cookie::Cookie;
#[cfg(not(target_arch = "wasm32"))]
use cow_utils::CowUtils;
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;

/// Maximum body size accepted by the simple API by default (10 MiB).
const MAX_SIMPLE_BODY: u64 = 10 * 1024 * 1024;

/// What to send with a one-shot request, for the `_with` variants of the simple helpers.
///
/// [`SimpleOptions::default`] reproduces exactly what [`simple_get`], [`sync_get`], and
/// [`sync_fetch`] have always done, so the plain helpers are just these with the defaults.
///
/// ```no_run
/// use gosub_sonar::SimpleOptions;
///
/// let opts = SimpleOptions::default()
///     .with_user_agent("MyBrowser/1.0")
///     .with_cookies("session=abc; theme=dark");
/// ```
///
/// This is a one-shot API: each call builds its own client, so there is no connection reuse
/// and no cookie jar carried between calls. Cookies are what you pass in and, for
/// [`sync_fetch`], what comes back in [`Response::cookies`]; nothing is remembered. Reach for
/// [`Fetcher`](crate::net::fetcher::Fetcher) and its
/// [`FetcherContext`](crate::net::fetcher_context::FetcherContext) when you want a real jar,
/// pooled connections, or per-hop cookie handling across redirects.
#[derive(Debug, Clone)]
pub struct SimpleOptions {
    /// Headers sent with the request. Empty by default.
    pub headers: HeaderMap,

    /// `User-Agent` header for the request. `None` falls back to reqwest's built-in default
    /// (`reqwest/VERSION`).
    pub user_agent: Option<String>,

    /// Cookies to send, in `Cookie` header format: `"name=value; name2=value2"`. Ignored if
    /// [`headers`](SimpleOptions::headers) already carries a `Cookie` header, so a hand-written
    /// one always wins. An unusable value is reported by the call, not silently dropped.
    pub cookies: Option<String>,

    /// Timeout for the TCP + TLS handshake. Ignored on wasm32, where the browser's `fetch()`
    /// owns timeouts.
    pub connect_timeout: Duration,

    /// Deadline for the whole request, headers and body together. Ignored on wasm32.
    pub timeout: Duration,

    /// Hard cap on the response body, and on the size of a `file://` read. Defaults to 10 MiB.
    /// Enforced both from `Content-Length` and while streaming, so a lying header cannot get
    /// past it.
    pub max_body: u64,

    /// Which proxy the request goes through. Defaults to [`ProxyConfig::System`], which reads
    /// `HTTP_PROXY` and friends from the environment — see [`proxy`](mod@crate::net::proxy).
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

    /// Send these cookies, in `Cookie` header format — see [`SimpleOptions::cookies`].
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

    /// Route the request through `proxy` — see [`SimpleOptions::proxy`].
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = proxy;
        self
    }

    /// The headers actually sent: [`headers`](SimpleOptions::headers) plus a `Cookie` header
    /// built from [`cookies`](SimpleOptions::cookies), unless one was set by hand.
    fn effective_headers(&self) -> Result<HeaderMap> {
        let mut headers = self.headers.clone();
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

    /// Build the one-shot client for this request.
    fn build_client(&self) -> Result<reqwest::Client> {
        let mut b = reqwest::Client::builder().default_headers(self.effective_headers()?);
        if let Some(ref ua) = self.user_agent {
            b = b.user_agent(ua);
        }
        // The browser's fetch() owns TLS, timeouts, and proxying; those knobs do not exist in
        // reqwest's wasm backend, but headers and User-Agent do.
        #[cfg(not(target_arch = "wasm32"))]
        {
            b = b
                .use_rustls_tls()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout);
            b = self.proxy.apply(b)?;
        }
        Ok(b.build()?)
    }
}

/// Perform a simple one-shot GET request and return the body as bytes.
/// Handles http, https, and file:// URLs.
/// Use this for standalone callers (renderer, tools) that don't need the full
/// priority-scheduler Fetcher.
///
/// The body is capped at 10 MiB. No SSRF protection is applied;
/// callers are responsible for validating the URL before passing it here.
///
/// Use [`simple_get_with`] to send headers, a `User-Agent`, or cookies.
pub async fn simple_get(url: &Url) -> Result<Bytes> {
    simple_get_with(url, &SimpleOptions::default()).await
}

/// [`simple_get`] with explicit request options.
///
/// `opts` covers headers, `User-Agent`, cookies, timeouts, the body cap, and the proxy. For a
/// `file://` URL only [`SimpleOptions::max_body`] applies; the rest are meaningless off-network
/// and are ignored.
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
            use std::io::Read as _;
            let path = url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL: {url}"))?;
            // Open and read in one step with a hard byte cap to eliminate the TOCTOU
            // window that a separate metadata() + read() would create.
            let mut body = Vec::new();
            std::fs::File::open(&path)?
                .take(max_body + 1)
                .read_to_end(&mut body)?;
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

/// [`sync_get`] with explicit request options — see [`SimpleOptions`].
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

/// [`sync_fetch`] with explicit request options — see [`SimpleOptions`].
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
        let mut body = Vec::new();
        std::fs::File::open(&path)?
            .take(max_body + 1)
            .read_to_end(&mut body)?;
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
    use crate::net::test_support::{RouteConfig, TestServer};
    use url::Url;

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

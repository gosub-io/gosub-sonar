//! In-process mock HTTP server for tests.
//!
//! Provides a fluent [`TestServer`] builder with configurable per-route behaviours:
//! immediate responses, delays, mid-body stalls, connection drops, and redirect variants.
//! Hit counts per path are tracked so coalescing and retry logic can be asserted.
//!
//! # Example
//! ```ignore
//! let server = TestServer::new()
//!     .route("/ok",   RouteConfig::ok(b"hello"))
//!     .route("/slow", RouteConfig::stall_mid_body(0, Duration::from_secs(5)))
//!     .route("/drop", RouteConfig::drop_mid_body(64, 4096))
//!     .start().await;
//!
//! let url = server.url("/ok");
//! assert_eq!(server.hit_count("/ok"), 0);
//! // … make request …
//! assert_eq!(server.hit_count("/ok"), 1);
//! ```

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Behaviour for a single route.
#[derive(Clone)]
pub enum RouteConfig {
    /// Respond with 200 and `body` immediately.
    Ok(Vec<u8>),
    /// Respond with `code` and `body` immediately.
    Status(u16, Vec<u8>),
    /// Wait `delay` before sending 200 + `body` (simulates a slow server).
    Delay(Duration, Vec<u8>),
    /// Send headers and `initial` body bytes immediately, then stall for `stall` before
    /// closing. Use to trigger read-idle-timeout errors.
    StallMidBody { initial: usize, stall: Duration },
    /// Declare `total` bytes in Content-Length but only send `prefix` bytes then drop the
    /// connection. Use to trigger unexpected-EOF / IO errors.
    DropMidBody { prefix: usize, total: usize },
    /// 302 redirect to another `path` on this server.
    RedirectTo(String),
    /// 302 redirect to the same path on every request — creates an infinite redirect loop.
    RedirectSelf,
    /// 302 without a Location header (malformed redirect).
    NoLocationRedirect,
    /// 302 redirect to `target` that also carries a `Set-Cookie: cookie` header.
    /// Use to verify that cookies set on intermediate redirect hops reach the jar.
    RedirectWithCookie { target: String, cookie: String },
    /// Respond 200 with the request's `Cookie` header value as the body (empty if absent).
    /// Use to verify which cookies a request actually carried.
    EchoCookieHeader,
    /// Accept the TCP connection but never send any data.
    /// Use to trigger `req_timeout` (the client's request timeout).
    HangAfterConnect,
    /// HTTP/1.1 chunked transfer encoding with the given chunks.
    /// Use to test that the body is correctly assembled across multiple chunks.
    Chunked(Vec<Vec<u8>>),
    /// Like `Chunked`, but sleeps `delay` before each chunk: headers arrive immediately, the
    /// body dribbles in. Use when a test must subscribe to a stream before the body completes.
    ChunkedWithDelay {
        chunks: Vec<Vec<u8>>,
        delay: Duration,
    },
    /// Gzip-compress `body` and respond with `Content-Encoding: gzip`.
    /// Use to verify that `auto_decode: true` decompresses and `auto_decode: false` returns raw bytes.
    GzipOk(Vec<u8>),
    /// Read `Content-Length` bytes from the request body and echo them back as a 200 response.
    /// Use to verify that POST/PUT bodies are transmitted correctly.
    EchoBody,
}

impl RouteConfig {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::Ok(body.into())
    }
    pub fn status(code: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Status(code, body.into())
    }
    pub fn delay(d: Duration, body: impl Into<Vec<u8>>) -> Self {
        Self::Delay(d, body.into())
    }
    pub fn stall_mid_body(initial: usize, stall: Duration) -> Self {
        Self::StallMidBody { initial, stall }
    }
    pub fn drop_mid_body(prefix: usize, total: usize) -> Self {
        Self::DropMidBody { prefix, total }
    }
    pub fn redirect_to(path: impl Into<String>) -> Self {
        Self::RedirectTo(path.into())
    }
    pub fn gzip_ok(body: impl Into<Vec<u8>>) -> Self {
        Self::GzipOk(body.into())
    }
    pub fn echo_body() -> Self {
        Self::EchoBody
    }
    pub fn redirect_self() -> Self {
        Self::RedirectSelf
    }
    pub fn no_location_redirect() -> Self {
        Self::NoLocationRedirect
    }
    pub fn redirect_with_cookie(target: impl Into<String>, cookie: impl Into<String>) -> Self {
        Self::RedirectWithCookie {
            target: target.into(),
            cookie: cookie.into(),
        }
    }
    pub fn echo_cookie_header() -> Self {
        Self::EchoCookieHeader
    }
    pub fn hang_after_connect() -> Self {
        Self::HangAfterConnect
    }
    pub fn chunked(chunks: Vec<&[u8]>) -> Self {
        Self::Chunked(chunks.into_iter().map(|c| c.to_vec()).collect())
    }
    pub fn chunked_with_delay(chunks: Vec<&[u8]>, delay: Duration) -> Self {
        Self::ChunkedWithDelay {
            chunks: chunks.into_iter().map(|c| c.to_vec()).collect(),
            delay,
        }
    }
}

async fn send_response(stream: &mut tokio::net::TcpStream, code: u16, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        reason(code),
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

/// Fluent builder for an in-process mock HTTP server.
pub struct TestServer {
    routes: HashMap<String, RouteConfig>,
    default: RouteConfig,
}

impl Default for TestServer {
    fn default() -> Self {
        Self::new()
    }
}

impl TestServer {
    /// Create a server whose unmatched routes return `200 hello`.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            default: RouteConfig::Ok(b"hello".to_vec()),
        }
    }

    /// Add a route. A later call with the same path overrides the earlier one.
    pub fn route(mut self, path: &str, config: RouteConfig) -> Self {
        self.routes.insert(path.to_string(), config);
        self
    }

    /// Override the fallback behaviour for unregistered paths.
    pub fn default_route(mut self, config: RouteConfig) -> Self {
        self.default = config;
        self
    }

    /// Bind a random port, start accepting connections, and return a [`TestServerHandle`].
    pub async fn start(self) -> TestServerHandle {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Arc<DashMap<String, AtomicUsize>> = Arc::new(DashMap::new());
        let shutdown = CancellationToken::new();

        let routes = Arc::new(self.routes);
        let default = Arc::new(self.default);
        let hits_srv = hits.clone();
        let shutdown_srv = shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_srv.cancelled() => break,
                    result = listener.accept() => {
                        let Ok((mut stream, _)) = result else { break };
                        let routes = routes.clone();
                        let default = default.clone();
                        let hits = hits_srv.clone();

                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            let n = stream.read(&mut buf).await.unwrap_or(0);
                            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                            let raw_path = req
                                .lines()
                                .next()
                                .and_then(|l| l.split_whitespace().nth(1))
                                .unwrap_or("/");
                            // Strip query string so routes are matched and counted by path only.
                            let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();

                            hits.entry(path.clone())
                                .or_insert_with(|| AtomicUsize::new(0))
                                .fetch_add(1, Ordering::Relaxed);

                            let cfg =
                                routes.get(&path).cloned().unwrap_or_else(|| (*default).clone());

                            match cfg {
                                RouteConfig::Ok(body) => {
                                    send_response(&mut stream, 200, &body).await;
                                }
                                RouteConfig::Status(code, body) => {
                                    send_response(&mut stream, code, &body).await;
                                }
                                RouteConfig::Delay(d, body) => {
                                    tokio::time::sleep(d).await;
                                    send_response(&mut stream, 200, &body).await;
                                }
                                RouteConfig::StallMidBody { initial, stall } => {
                                    // Declare more bytes than we send so the client waits.
                                    let declared = initial + 8192;
                                    let hdr = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        declared
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                    if initial > 0 {
                                        let _ = stream.write_all(&vec![b'X'; initial]).await;
                                        let _ = stream.flush().await;
                                    }
                                    tokio::time::sleep(stall).await;
                                    // stream drops → connection closes
                                }
                                RouteConfig::DropMidBody { prefix, total } => {
                                    let hdr = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        total
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                    if prefix > 0 {
                                        let _ = stream.write_all(&vec![b'X'; prefix]).await;
                                        let _ = stream.flush().await;
                                    }
                                    // stream drops → premature EOF
                                }
                                RouteConfig::RedirectTo(target) => {
                                    let hdr = format!(
                                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                        port, target
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                }
                                RouteConfig::RedirectSelf => {
                                    let hdr = format!(
                                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                        port, path
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                }
                                RouteConfig::NoLocationRedirect => {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    ).await;
                                }
                                RouteConfig::RedirectWithCookie { target, cookie } => {
                                    let hdr = format!(
                                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}{}\r\nSet-Cookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                        port, target, cookie
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                }
                                RouteConfig::EchoCookieHeader => {
                                    let cookie = req
                                        .lines()
                                        .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                                        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                                        .unwrap_or_default();
                                    send_response(&mut stream, 200, cookie.as_bytes()).await;
                                }
                                RouteConfig::HangAfterConnect => {
                                    // Hold the connection open without sending anything.
                                    // The client's req_timeout will fire.
                                    tokio::time::sleep(Duration::from_secs(3600)).await;
                                }
                                RouteConfig::Chunked(chunks) => {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                    ).await;
                                    for chunk in &chunks {
                                        let _ = stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await;
                                        let _ = stream.write_all(chunk).await;
                                        let _ = stream.write_all(b"\r\n").await;
                                    }
                                    let _ = stream.write_all(b"0\r\n\r\n").await;
                                }
                                RouteConfig::ChunkedWithDelay { chunks, delay } => {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                                    ).await;
                                    let _ = stream.flush().await;
                                    for chunk in &chunks {
                                        tokio::time::sleep(delay).await;
                                        let _ = stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await;
                                        let _ = stream.write_all(chunk).await;
                                        let _ = stream.write_all(b"\r\n").await;
                                        let _ = stream.flush().await;
                                    }
                                    let _ = stream.write_all(b"0\r\n\r\n").await;
                                }
                                RouteConfig::EchoBody => {
                                    // Parse Content-Length from the request headers we already read.
                                    let content_length: usize = req
                                        .lines()
                                        .find(|l| {
                                            l.to_ascii_lowercase().starts_with("content-length:")
                                        })
                                        .and_then(|l| l.split_once(':').map(|(_, v)| v))
                                        .and_then(|v| v.trim().parse().ok())
                                        .unwrap_or(0);

                                    // The body follows the blank line (\r\n\r\n) at the end of headers.
                                    let header_end = buf[..n]
                                        .windows(4)
                                        .position(|w| w == b"\r\n\r\n")
                                        .map(|p| p + 4)
                                        .unwrap_or(n);
                                    let mut body = buf[header_end..n].to_vec();

                                    // Read any remaining body bytes (handles requests > 4 KB).
                                    while body.len() < content_length {
                                        let mut extra = [0u8; 4096];
                                        let k = stream.read(&mut extra).await.unwrap_or(0);
                                        if k == 0 {
                                            break;
                                        }
                                        body.extend_from_slice(&extra[..k]);
                                    }
                                    body.truncate(content_length);
                                    send_response(&mut stream, 200, &body).await;
                                }
                                RouteConfig::GzipOk(body) => {
                                    use flate2::{write::GzEncoder, Compression};
                                    use std::io::Write as _;
                                    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                                    enc.write_all(&body).unwrap();
                                    let compressed = enc.finish().unwrap();
                                    let hdr = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        compressed.len()
                                    );
                                    let _ = stream.write_all(hdr.as_bytes()).await;
                                    let _ = stream.write_all(&compressed).await;
                                }
                            }
                        });
                    }
                }
            }
        });

        TestServerHandle {
            port,
            hits,
            shutdown,
        }
    }
}

/// Handle to a running [`TestServer`]. Cancels the server when dropped.
pub struct TestServerHandle {
    port: u16,
    hits: Arc<DashMap<String, AtomicUsize>>,
    shutdown: CancellationToken,
}

impl TestServerHandle {
    /// URL for `path` on this server (e.g. `server.url("/items/1")`).
    pub fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}{}", self.port, path)).unwrap()
    }

    /// Base URL (`/`) of this server.
    pub fn base_url(&self) -> Url {
        self.url("/")
    }

    /// Number of times `path` has been requested since the server started.
    pub fn hit_count(&self, path: &str) -> usize {
        self.hits
            .get(path)
            .map(|e| e.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

impl Drop for TestServerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

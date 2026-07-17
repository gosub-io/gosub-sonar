//! In-process mock HTTP server for tests.
//!
//! Provides a fluent [`TestServer`](crate::net::test_support::TestServer) builder with
//! configurable per-route behaviours:
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

// This is a test utility: panicking on setup failure is the desired behavior, and the crate-wide
// unwrap/expect/panic denial only exempts cfg(test), not the `test-support` feature build.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    /// Respond with 200, `body`, and extra `(name, value)` response headers.
    OkWithHeaders(Vec<(String, String)>, Vec<u8>),
    /// Respond with `code` and `body` immediately.
    Status(u16, Vec<u8>),
    /// Wait `delay` before sending 200 + `body` (simulates a slow server).
    Delay(Duration, Vec<u8>),
    /// Send headers and `initial` body bytes immediately, then stall for `stall` before
    /// closing. Use to trigger read-idle-timeout errors.
    StallMidBody {
        /// Number of body bytes to send before stalling
        initial: usize,
        /// How long to stall before closing the connection
        stall: Duration,
    },
    /// Declare `total` bytes in Content-Length but only send `prefix` bytes then drop the
    /// connection. Use to trigger unexpected-EOF / IO errors.
    DropMidBody {
        /// Number of body bytes actually sent
        prefix: usize,
        /// Byte count declared in the Content-Length header
        total: usize,
    },
    /// 302 redirect to another `path` on this server.
    RedirectTo(String),
    /// 302 redirect to the same path on every request — creates an infinite redirect loop.
    RedirectSelf,
    /// 302 without a Location header (malformed redirect).
    NoLocationRedirect,
    /// 302 redirect to `target` that also carries a `Set-Cookie: cookie` header.
    /// Use to verify that cookies set on intermediate redirect hops reach the jar.
    RedirectWithCookie {
        /// Path to redirect to
        target: String,
        /// Value sent in the `Set-Cookie` header
        cookie: String,
    },
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
        /// Body chunks to send, in order
        chunks: Vec<Vec<u8>>,
        /// Sleep before each chunk
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
    /// Shorthand for [`RouteConfig::Ok`]
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self::Ok(body.into())
    }
    /// Shorthand for [`RouteConfig::OkWithHeaders`]
    pub fn ok_with_headers(headers: &[(&str, &str)], body: impl Into<Vec<u8>>) -> Self {
        Self::OkWithHeaders(
            headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body.into(),
        )
    }
    /// Shorthand for [`RouteConfig::Status`]
    pub fn status(code: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Status(code, body.into())
    }
    /// Shorthand for [`RouteConfig::Delay`]
    pub fn delay(d: Duration, body: impl Into<Vec<u8>>) -> Self {
        Self::Delay(d, body.into())
    }
    /// Shorthand for [`RouteConfig::StallMidBody`]
    pub fn stall_mid_body(initial: usize, stall: Duration) -> Self {
        Self::StallMidBody { initial, stall }
    }
    /// Shorthand for [`RouteConfig::DropMidBody`]
    pub fn drop_mid_body(prefix: usize, total: usize) -> Self {
        Self::DropMidBody { prefix, total }
    }
    /// Shorthand for [`RouteConfig::RedirectTo`]
    pub fn redirect_to(path: impl Into<String>) -> Self {
        Self::RedirectTo(path.into())
    }
    /// Shorthand for [`RouteConfig::GzipOk`]
    pub fn gzip_ok(body: impl Into<Vec<u8>>) -> Self {
        Self::GzipOk(body.into())
    }
    /// Shorthand for [`RouteConfig::EchoBody`]
    pub fn echo_body() -> Self {
        Self::EchoBody
    }
    /// Shorthand for [`RouteConfig::RedirectSelf`]
    pub fn redirect_self() -> Self {
        Self::RedirectSelf
    }
    /// Shorthand for [`RouteConfig::NoLocationRedirect`]
    pub fn no_location_redirect() -> Self {
        Self::NoLocationRedirect
    }
    /// Shorthand for [`RouteConfig::RedirectWithCookie`]
    pub fn redirect_with_cookie(target: impl Into<String>, cookie: impl Into<String>) -> Self {
        Self::RedirectWithCookie {
            target: target.into(),
            cookie: cookie.into(),
        }
    }
    /// Shorthand for [`RouteConfig::EchoCookieHeader`]
    pub fn echo_cookie_header() -> Self {
        Self::EchoCookieHeader
    }
    /// Shorthand for [`RouteConfig::HangAfterConnect`]
    pub fn hang_after_connect() -> Self {
        Self::HangAfterConnect
    }
    /// Shorthand for [`RouteConfig::Chunked`]
    pub fn chunked(chunks: Vec<&[u8]>) -> Self {
        Self::Chunked(chunks.into_iter().map(|c| c.to_vec()).collect())
    }
    /// Shorthand for [`RouteConfig::ChunkedWithDelay`]
    pub fn chunked_with_delay(chunks: Vec<&[u8]>, delay: Duration) -> Self {
        Self::ChunkedWithDelay {
            chunks: chunks.into_iter().map(|c| c.to_vec()).collect(),
            delay,
        }
    }
}

async fn send_response<S: AsyncWrite + Unpin>(stream: &mut S, code: u16, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        reason(code),
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

/// Serve one connection. Generic over the stream so the same routing logic drives both the plain
/// TCP listener and a TLS-wrapped one.
///
/// `base` is this server's own scheme://host:port, used for absolute redirect targets.
async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    routes: Arc<HashMap<String, RouteConfig>>,
    default: Arc<RouteConfig>,
    hits: Arc<DashMap<String, AtomicUsize>>,
    base: Arc<String>,
) {
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

    let cfg = routes
        .get(&path)
        .cloned()
        .unwrap_or_else(|| (*default).clone());

    match cfg {
        RouteConfig::Ok(body) => {
            send_response(&mut stream, 200, &body).await;
        }
        RouteConfig::OkWithHeaders(headers, body) => {
            let extra: String = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect();
            let hdr = format!(
                "HTTP/1.1 200 OK\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                extra,
                body.len()
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
            let _ = stream.write_all(&body).await;
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
                "HTTP/1.1 302 Found\r\nLocation: {}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                base, target
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
        }
        RouteConfig::RedirectSelf => {
            let hdr = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                base, path
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
        }
        RouteConfig::NoLocationRedirect => {
            let _ = stream
                .write_all(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
        RouteConfig::RedirectWithCookie { target, cookie } => {
            let hdr = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}{}\r\nSet-Cookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                base, target, cookie
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
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            for chunk in &chunks {
                let _ = stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await;
                let _ = stream.write_all(chunk).await;
                let _ = stream.write_all(b"\r\n").await;
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        }
        RouteConfig::ChunkedWithDelay { chunks, delay } => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.flush().await;
            for chunk in &chunks {
                tokio::time::sleep(delay).await;
                let _ = stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await;
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
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
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
}

/// Fluent builder for an in-process mock HTTP server.
pub struct TestServer {
    routes: HashMap<String, RouteConfig>,
    default: RouteConfig,
    tls_domain: Option<String>,
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
            tls_domain: None,
        }
    }

    /// Serve HTTPS with a self-signed certificate for `domain` instead of plain HTTP.
    ///
    /// The server still listens on 127.0.0.1; `domain` is only the name in the certificate and in
    /// [`TestServerHandle::url`]. Point a client at it with [`TestServerHandle::socket_addr`] and
    /// [`TestServerHandle::cert_pem`].
    pub fn tls(mut self, domain: &str) -> Self {
        self.tls_domain = Some(domain.to_string());
        self
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
        let addr = listener.local_addr().unwrap();
        let hits: Arc<DashMap<String, AtomicUsize>> = Arc::new(DashMap::new());
        let shutdown = CancellationToken::new();

        let tls = self.tls_domain.as_ref().map(|domain| {
            let ck = rcgen::generate_simple_self_signed(vec![domain.clone()]).unwrap();
            let cert_pem = ck.cert.pem().into_bytes();
            let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
                rcgen::KeyPair::serialize_der(&ck.signing_key),
            )
            .unwrap();
            let server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![ck.cert.der().clone()], key)
                .unwrap();
            (
                domain.clone(),
                cert_pem,
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
            )
        });

        let base = Arc::new(match &tls {
            Some((domain, _, _)) => format!("https://{}:{}", domain, addr.port()),
            None => format!("http://127.0.0.1:{}", addr.port()),
        });

        let routes = Arc::new(self.routes);
        let default = Arc::new(self.default);
        let hits_srv = hits.clone();
        let shutdown_srv = shutdown.clone();
        let acceptor = tls.as_ref().map(|(_, _, a)| a.clone());
        let base_srv = base.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_srv.cancelled() => break,
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { break };
                        let routes = routes.clone();
                        let default = default.clone();
                        let hits = hits_srv.clone();
                        let base = base_srv.clone();
                        let acceptor = acceptor.clone();

                        tokio::spawn(async move {
                            match acceptor {
                                // The client observes a failed handshake; nothing to do here.
                                Some(acceptor) => {
                                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                                        handle_conn(tls_stream, routes, default, hits, base).await
                                    }
                                }
                                None => handle_conn(stream, routes, default, hits, base).await,
                            }
                        });
                    }
                }
            }
        });

        TestServerHandle {
            addr,
            hits,
            shutdown,
            tls: tls.map(|(domain, cert_pem, _)| TlsInfo { domain, cert_pem }),
        }
    }
}

/// The certificate and name of a TLS-enabled [`TestServer`].
struct TlsInfo {
    domain: String,
    cert_pem: Vec<u8>,
}

/// Handle to a running [`TestServer`]. Cancels the server when dropped.
pub struct TestServerHandle {
    addr: std::net::SocketAddr,
    hits: Arc<DashMap<String, AtomicUsize>>,
    shutdown: CancellationToken,
    tls: Option<TlsInfo>,
}

impl TestServerHandle {
    /// URL for `path` on this server (e.g. `server.url("/items/1")`).
    ///
    /// Under [`TestServer::tls`] this is `https://<domain>:<port>`, which does not resolve on its
    /// own — point the client at [`socket_addr`](Self::socket_addr).
    pub fn url(&self, path: &str) -> Url {
        let base = match &self.tls {
            Some(t) => format!("https://{}:{}", t.domain, self.addr.port()),
            None => format!("http://127.0.0.1:{}", self.addr.port()),
        };
        Url::parse(&format!("{base}{path}")).unwrap()
    }

    /// Base URL (`/`) of this server.
    pub fn base_url(&self) -> Url {
        self.url("/")
    }

    /// The address the server actually listens on, always on 127.0.0.1.
    ///
    /// Pair with `reqwest::ClientBuilder::resolve` to point a TLS server's domain here without
    /// involving DNS.
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// The server's self-signed certificate in PEM form, or `None` if TLS is not enabled.
    ///
    /// Pass to `reqwest::Certificate::from_pem` and `ClientBuilder::add_root_certificate` so the
    /// client trusts this server.
    pub fn cert_pem(&self) -> Option<&[u8]> {
        self.tls.as_ref().map(|t| t.cert_pem.as_slice())
    }

    /// The domain in the server's certificate, or `None` if TLS is not enabled.
    pub fn tls_domain(&self) -> Option<&str> {
        self.tls.as_ref().map(|t| t.domain.as_str())
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

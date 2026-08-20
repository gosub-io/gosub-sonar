#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Implementing `FetcherContext`: the host's hooks into the fetcher.
//!
//! - `observer_for` hands out a `NetObserver` per request; ours logs every `NetEvent`, the way
//!   a devtools network panel would.
//! - `cookies_for` / `on_cookies_received` wire up a cookie jar. A `/login` redirect sets a
//!   cookie which then shows up on the following hop.
//! - `is_url_allowed` blocks a URL before anything is sent.
//! - `on_ref_active` / `on_ref_done` track outstanding work per `RequestReference` (a tab id).
//!
//! Runs against the in-process mock server, so no network needed.
//!
//! Run with:
//! ```text
//! cargo run --example fetcher_context --features test-support
//! ```

use gosub_sonar::net::test_support::{RouteConfig, TestServer};
use gosub_sonar::{
    FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, Initiator, NetEvent,
    NetObserver, RequestId, RequestReference, ResourceKind,
};
use http::Method;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Prints events, prefixed with the request they belong to.
struct Logger {
    tag: String,
}

impl NetObserver for Logger {
    fn on_event(&self, ev: NetEvent) {
        let t = &self.tag;
        match ev {
            NetEvent::Started { url } => println!("[{t}] started   {url}"),
            NetEvent::Redirected { from, to, status } => {
                println!("[{t}] redirect  {status} {} -> {}", from.path(), to.path())
            }
            NetEvent::ResponseHeaders {
                status, headers, ..
            } => {
                println!("[{t}] headers   {status} ({} headers)", headers.len())
            }
            NetEvent::Progress { received_bytes, .. } => {
                println!("[{t}] progress  {received_bytes} bytes")
            }
            NetEvent::Finished {
                received_bytes,
                elapsed,
                ..
            } => println!("[{t}] finished  {received_bytes} bytes in {elapsed:?}"),
            NetEvent::Failed { error, .. } => println!("[{t}] failed    {error}"),
            NetEvent::Blocked { url, reason } => println!("[{t}] blocked   {reason} {url}"),
            NetEvent::Cancelled { reason, .. } => println!("[{t}] cancelled {reason}"),
            NetEvent::TlsFailed { error, .. } => println!("[{t}] tls       {error}"),
            NetEvent::CorsPreflight { url } => println!("[{t}] preflight {url}"),
            NetEvent::Warning { message, .. } => println!("[{t}] warning   {message}"),
            NetEvent::Io { message } => println!("[{t}] io        {message}"),
        }
    }
}

/// A context with a cookie jar, a URL blocklist and a per-tab work counter.
struct AppContext {
    /// host -> "name=value; name2=value2"
    cookies: Mutex<HashMap<String, Vec<String>>>,
    /// Paths we refuse to fetch.
    blocked_paths: Vec<&'static str>,
    /// Outstanding fetches per reference.
    active: Mutex<HashMap<RequestReference, usize>>,
}

impl FetcherContext for AppContext {
    fn observer_for(
        &self,
        reference: RequestReference,
        _req_id: RequestId,
        kind: ResourceKind,
        _initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(Logger {
            tag: format!("{reference:?}/{kind:?}"),
        })
    }

    fn on_ref_active(&self, reference: RequestReference) {
        *self.active.lock().entry(reference).or_default() += 1;
    }

    fn on_ref_done(&self, reference: RequestReference) {
        let mut active = self.active.lock();
        if let Some(n) = active.get_mut(&reference) {
            *n -= 1;
            if *n == 0 {
                println!("[{reference:?}] no more outstanding fetches");
            }
        }
    }

    // Called for the initial URL and for every redirect target.
    fn is_url_allowed(&self, url: &Url) -> bool {
        !self.blocked_paths.contains(&url.path())
    }

    // Called on every hop; the jar is keyed by host here, a real one would follow RFC 6265.
    fn cookies_for(&self, url: &Url) -> Option<String> {
        let jar = self.cookies.lock();
        let cookies = jar.get(url.host_str()?)?;
        if cookies.is_empty() {
            return None;
        }
        Some(cookies.join("; "))
    }

    // Called with the raw Set-Cookie values of a response (redirect hops included).
    fn on_cookies_received(&self, url: &Url, values: &[&str]) {
        let Some(host) = url.host_str() else { return };
        let mut jar = self.cookies.lock();
        let entry = jar.entry(host.to_string()).or_default();
        for v in values {
            // keep only name=value, drop attributes
            let nv = v.split(';').next().unwrap_or(v).trim().to_string();
            println!("  jar: {host} <- {nv}");
            entry.push(nv);
        }
    }
}

async fn fetch(fetcher: &Fetcher, url: Url, reference: RequestReference) -> FetchResult {
    let req = FetchRequest::builder(Method::GET, url)
        .with_reference(reference)
        .with_kind(ResourceKind::Primary)
        .build();
    fetcher.fetch(req).await
}

fn show(result: FetchResult) {
    match result {
        FetchResult::Buffered { meta, body } => {
            println!(
                "  => {} {:?}\n",
                meta.status,
                String::from_utf8_lossy(&body)
            )
        }
        FetchResult::Stream { meta, .. } => println!("  => {} (stream)\n", meta.status),
        FetchResult::Error(e) => println!("  => {e}\n"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let srv = TestServer::new()
        // /login sets a session cookie and redirects to /whoami, which echoes the Cookie header
        .route(
            "/login",
            RouteConfig::redirect_with_cookie("/whoami", "session=abc123; Path=/"),
        )
        .route("/whoami", RouteConfig::echo_cookie_header())
        .route("/admin", RouteConfig::ok(b"secret".to_vec()))
        .route("/to-admin", RouteConfig::redirect_to("/admin"))
        .start()
        .await;

    let ctx = Arc::new(AppContext {
        cookies: Mutex::new(HashMap::new()),
        blocked_paths: vec!["/admin"],
        active: Mutex::new(HashMap::new()),
    });
    let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), ctx.clone())?);
    let shutdown = CancellationToken::new();
    let run = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move { run.run(cancel).await });

    let tab = RequestReference::Tagged(1);

    println!("--- 1. login: cookie set on the 302 is sent on the next hop");
    show(fetch(&fetcher, srv.url("/login"), tab).await);

    println!("--- 2. same host again: the jar supplies the cookie");
    show(fetch(&fetcher, srv.url("/whoami"), tab).await);

    println!("--- 3. blocked by is_url_allowed, directly");
    show(fetch(&fetcher, srv.url("/admin"), tab).await);

    println!("--- 4. blocked by is_url_allowed, as a redirect target");
    show(fetch(&fetcher, srv.url("/to-admin"), tab).await);

    shutdown.cancel();
    Ok(())
}

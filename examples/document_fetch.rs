#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Fetching like a page does: origin, referrer, fetch metadata, CORS and mixed content.
//!
//! A browser engine sets `FetchRequest::origin` to the document's origin plus a referrer,
//! destination and mode, and the fetcher takes care of the headers and checks that follow from
//! that on every hop: `Referer` (per referrer policy), `Origin`, `Sec-Fetch-*`, CORS (with
//! preflight) and mixed content. This example makes a few such requests against the mock server
//! and prints what arrived on the wire, or why the request was refused.
//!
//! The mock server listens on 127.0.0.1; `http://localhost:<port>` is the same server under a
//! different origin, which is all cross-origin needs.
//!
//! Run with:
//! ```text
//! cargo run --example document_fetch --features test-support
//! ```

use gosub_sonar::net::test_support::{CorsRouteOptions, RouteConfig, TestServer};
use gosub_sonar::{
    FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, Initiator, NetEvent,
    NetObserver, ReferrerPolicy, RequestCredentials, RequestDestination, RequestId, RequestMode,
    RequestReference, ResourceKind,
};
use http::{HeaderMap, HeaderValue, Method};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Prints the events that show a policy at work; ignores the rest.
struct PolicyLog;

impl NetObserver for PolicyLog {
    fn on_event(&self, ev: NetEvent) {
        match ev {
            NetEvent::Blocked { reason, url } => println!("    blocked: {reason} ({url})"),
            NetEvent::CorsPreflight { url } => println!("    preflight sent to {url}"),
            NetEvent::Redirected { status, to, .. } => println!("    {status} -> {to}"),
            _ => {}
        }
    }
}

struct Ctx;
impl FetcherContext for Ctx {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(PolicyLog)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

/// A request as a document at `page` would make it.
fn from_page(page: &Url, method: Method, url: Url) -> FetchRequest {
    FetchRequest::builder(method, url)
        .with_origin(page.origin())
        .with_referrer(page.clone())
        .with_destination(RequestDestination::Image)
        .with_mode(RequestMode::NoCors)
        .build()
}

async fn show(label: &str, fetcher: &Fetcher, req: FetchRequest) {
    println!("{label}");
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            println!(
                "    {} {:?} (tainting: {:?})\n",
                meta.status,
                String::from_utf8_lossy(&body),
                meta.tainting
            )
        }
        FetchResult::Stream { meta, .. } => println!("    {} (stream)\n", meta.status),
        FetchResult::Error(e) => println!("    {e}\n"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let srv = TestServer::new()
        // routes that answer with one request header, so we can see what was sent
        .route("/referer", RouteConfig::echo_request_header("Referer"))
        .route("/site", RouteConfig::echo_request_header("Sec-Fetch-Site"))
        .route("/dest", RouteConfig::echo_request_header("Sec-Fetch-Dest"))
        .route("/origin", RouteConfig::echo_request_header("Origin"))
        // a CORS-enabled route: answers preflights and sends Access-Control-Allow-Origin: *
        .route(
            "/api",
            RouteConfig::cors(CorsRouteOptions {
                allow_headers: Some("x-custom".into()),
                ..CorsRouteOptions::default()
            }),
        )
        .start()
        .await;

    let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), Arc::new(Ctx))?);
    let shutdown = CancellationToken::new();
    let run = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move { run.run(cancel).await });

    // The "page" that makes the requests: same origin as the server, and a cross-origin one.
    let same = srv.url("/page.html");
    let cross = Url::parse(&format!(
        "http://localhost:{}/page.html",
        srv.socket_addr().port()
    ))?;

    println!("== same-origin page {same}\n");
    show(
        "Referer: full URL within the same origin",
        &fetcher,
        from_page(&same, Method::GET, srv.url("/referer")),
    )
    .await;
    show(
        "Sec-Fetch-Site",
        &fetcher,
        from_page(&same, Method::GET, srv.url("/site")),
    )
    .await;
    show(
        "Sec-Fetch-Dest (from FetchRequest::destination)",
        &fetcher,
        from_page(&same, Method::GET, srv.url("/dest")),
    )
    .await;

    println!("== cross-origin page {cross}\n");
    show(
        "Referer: strict-origin-when-cross-origin sends only the origin",
        &fetcher,
        from_page(&cross, Method::GET, srv.url("/referer")),
    )
    .await;
    show(
        "Referer with ReferrerPolicy::NoReferrer",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/referer"))
            .with_origin(cross.origin())
            .with_referrer(cross.clone())
            .with_referrer_policy(ReferrerPolicy::NoReferrer)
            .build(),
    )
    .await;
    show(
        "Sec-Fetch-Site",
        &fetcher,
        from_page(&cross, Method::GET, srv.url("/site")),
    )
    .await;
    show(
        "Origin header on a POST",
        &fetcher,
        from_page(&cross, Method::POST, srv.url("/origin")),
    )
    .await;
    show(
        "mode: cors to a route without CORS headers -> refused, response never reaches the page",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/site"))
            .with_origin(cross.origin())
            .with_mode(RequestMode::Cors)
            .build(),
    )
    .await;
    let mut headers = HeaderMap::new();
    headers.insert("x-custom", HeaderValue::from_static("1"));
    show(
        "mode: cors with a custom header to a CORS route -> preflight, then the request",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/api"))
            .with_origin(cross.origin())
            .with_mode(RequestMode::Cors)
            // Allow-Origin: * only works without credentials, so leave the cookies at home
            .with_credentials(RequestCredentials::Omit)
            .with_headers(headers)
            .build(),
    )
    .await;

    println!("== secure page https://secure.example/\n");
    let secure = Url::parse("https://secure.example/page.html")?;
    show(
        "mixed content: http:// image from an https:// page -> blocked before connecting",
        &fetcher,
        from_page(
            &secure,
            Method::GET,
            Url::parse("http://example.com/logo.png")?,
        ),
    )
    .await;

    shutdown.cancel();
    Ok(())
}

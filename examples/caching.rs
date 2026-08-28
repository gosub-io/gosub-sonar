#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The HTTP cache: hits, revalidation, and the per-request cache modes.
//!
//! Every route below is served by the mock server and counts the requests it receives, so the
//! hit count says whether a fetch reached it at all. In order:
//!
//! 1. A response with `max-age=600` is fetched twice. The second fetch is answered from the
//!    cache, and the server never hears about it.
//! 2. A response that is already stale but carries an `ETag` is fetched twice. The second fetch
//!    revalidates, the server answers `304`, and the stored body comes back as a 200.
//! 3. The same fresh URL as (1) is fetched with `CacheMode::Reload` (a refresh button), then
//!    normally again, to show the reloaded response took the stored one's place.
//! 4. A URL that was never fetched is asked for with `CacheMode::OnlyIfCached`, which fails
//!    instead of reaching the network.
//!
//! Run with:
//! ```text
//! cargo run --example caching --features test-support
//! ```

use gosub_sonar::net::test_support::{CacheRouteOptions, RouteConfig, TestServer};
use gosub_sonar::{
    CacheMode, FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, HttpCache,
    InMemoryHttpCache, Initiator, NetEvent, NetObserver, RequestId, RequestReference, ResourceKind,
};
use http::Method;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Prints what the cache did with each hop.
struct CacheLog;

impl NetObserver for CacheLog {
    fn on_event(&self, ev: NetEvent) {
        if let NetEvent::Cache { url, outcome } = ev {
            println!("    cache {outcome}: {}", url.path());
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
        Arc::new(CacheLog)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

async fn show(label: &str, fetcher: &Fetcher, req: FetchRequest) {
    println!("{label}");
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => println!(
            "    {} {} — {:?}",
            meta.status,
            if meta.from_cache {
                "(cached)"
            } else {
                "(network)"
            },
            String::from_utf8_lossy(&body[..body.len().min(40)])
        ),
        FetchResult::Error(err) => println!("    error: {err}"),
        other => println!("    {other:?}"),
    }
}

#[tokio::main]
async fn main() {
    let srv = TestServer::new()
        // Fresh for ten minutes, with a body that says which request produced it.
        .route(
            "/fresh",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
        )
        // Stale immediately, but revalidatable.
        .route(
            "/validated",
            RouteConfig::Cacheable(
                CacheRouteOptions::max_age(0, b"the stored body".to_vec()).with_etag("\"v1\""),
            ),
        )
        .start()
        .await;

    let cache = Arc::new(InMemoryHttpCache::new());
    let cfg = FetcherConfig {
        cache: Some(cache.clone() as Arc<dyn HttpCache>),
        ..FetcherConfig::default()
    };
    let fetcher = Arc::new(Fetcher::new(cfg, Arc::new(Ctx)).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });

    let get = |path: &str| FetchRequest::builder(Method::GET, srv.url(path));

    show(
        "1a. first fetch of a cacheable response",
        &fetcher,
        get("/fresh").build(),
    )
    .await;
    show(
        "1b. and again, while it is fresh",
        &fetcher,
        get("/fresh").build(),
    )
    .await;
    println!(
        "    the server saw {} request(s)\n",
        srv.hit_count("/fresh")
    );

    show(
        "2a. first fetch of a stale-but-validatable response",
        &fetcher,
        get("/validated").build(),
    )
    .await;
    show(
        "2b. and again: revalidated with If-None-Match",
        &fetcher,
        get("/validated").build(),
    )
    .await;
    println!(
        "    the server saw {} request(s), one of which was a 304\n",
        srv.hit_count("/validated")
    );

    show(
        "3a. a reload goes back to the server even though the entry is fresh",
        &fetcher,
        get("/fresh").with_cache_mode(CacheMode::Reload).build(),
    )
    .await;
    show(
        "3b. and the reloaded response is what the cache now holds",
        &fetcher,
        get("/fresh").build(),
    )
    .await;
    println!(
        "    the server saw {} request(s)\n",
        srv.hit_count("/fresh")
    );

    show(
        "4. only-if-cached, for a URL that was never fetched",
        &fetcher,
        get("/never-fetched")
            .with_cache_mode(CacheMode::OnlyIfCached)
            .build(),
    )
    .await;

    println!(
        "\ncache holds {} entries, {} bytes",
        cache.len(),
        cache.byte_len()
    );
    shutdown.cancel();
}

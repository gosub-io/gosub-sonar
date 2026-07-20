//! End-to-end tests driving the crate through its public API only, as a downstream consumer
//! would: `use gosub_sonar::…`, an externally implemented [`FetcherContext`], and the
//! `test-support` mock server. Requires `--features test-support`.

use gosub_sonar::net::test_support::{RouteConfig, TestServer};
use gosub_sonar::{
    simple_get, FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, Initiator,
    NetObserver, NullContext, NullEmitter, RequestBody, RequestId, RequestReference, ResourceKind,
    SharedBody,
};
use http::Method;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

fn spawn_fetcher(ctx: Arc<dyn FetcherContext>) -> (Arc<Fetcher>, CancellationToken) {
    let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), ctx).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });
    (fetcher, shutdown)
}

#[tokio::test]
async fn buffered_get_roundtrip() {
    let srv = TestServer::new()
        .route("/ok", RouteConfig::ok(b"hello"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/ok")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(meta.status, 200);
            assert_eq!(&body[..], b"hello");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

#[tokio::test]
async fn streaming_get_roundtrip() {
    let srv = TestServer::new()
        .route("/ok", RouteConfig::ok(b"streamed hello"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/ok"))
        .with_streaming(true)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Stream {
            meta,
            peek_buf,
            shared,
        } => {
            assert_eq!(meta.status, 200);
            let mut reader = SharedBody::combined_reader(peek_buf, shared);
            let mut body = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut body)
                .await
                .unwrap();
            assert_eq!(&body[..], b"streamed hello");
        }
        other => panic!("expected Stream, got {other:?}"),
    }
    shutdown.cancel();
}

#[tokio::test]
async fn post_body_is_echoed() {
    let srv = TestServer::new()
        .route("/echo", RouteConfig::echo_body())
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::POST, srv.url("/echo"))
        .with_body(RequestBody::text("integration payload"))
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(meta.status, 200);
            assert_eq!(&body[..], b"integration payload");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

#[tokio::test]
async fn simple_get_roundtrip() {
    let srv = TestServer::new()
        .route("/ok", RouteConfig::ok(b"simple"))
        .start()
        .await;
    let bytes = simple_get(&srv.url("/ok")).await.unwrap();
    assert_eq!(&bytes[..], b"simple");
}

/// Implements only the required methods plus a cookie jar.
struct CookieContext;

impl FetcherContext for CookieContext {
    fn observer_for(
        &self,
        _reference: RequestReference,
        _req_id: RequestId,
        _kind: ResourceKind,
        _initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
    fn cookies_for(&self, _url: &Url) -> Option<String> {
        Some("session=e2e".into())
    }
}

#[tokio::test]
async fn external_context_supplies_cookies() {
    let srv = TestServer::new()
        .route("/cookie", RouteConfig::echo_cookie_header())
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(CookieContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/cookie")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => assert_eq!(&body[..], b"session=e2e"),
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// A context that blocks everything.
struct BlockAllContext;

impl FetcherContext for BlockAllContext {
    fn observer_for(
        &self,
        _reference: RequestReference,
        _req_id: RequestId,
        _kind: ResourceKind,
        _initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
    fn is_url_allowed(&self, _url: &Url) -> bool {
        false
    }
}

#[tokio::test]
async fn external_context_can_block_urls() {
    let srv = TestServer::new()
        .route("/ok", RouteConfig::ok(b"unreachable"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(BlockAllContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/ok")).build();
    let res = fetcher.fetch(req).await;
    assert!(res.is_error(), "blocked URL must not fetch, got {res:?}");
    assert_eq!(
        srv.hit_count("/ok"),
        0,
        "the request must never reach the server"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn identical_concurrent_requests_coalesce() {
    let srv = TestServer::new()
        .route(
            "/slow",
            RouteConfig::delay(std::time::Duration::from_millis(200), b"shared"),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = || FetchRequest::builder(Method::GET, srv.url("/slow")).build();
    let (a, b) = tokio::join!(fetcher.fetch(req()), fetcher.fetch(req()));

    for res in [a, b] {
        match res {
            FetchResult::Buffered { body, .. } => assert_eq!(&body[..], b"shared"),
            other => panic!("expected Buffered, got {other:?}"),
        }
    }
    assert_eq!(
        srv.hit_count("/slow"),
        1,
        "identical in-flight GETs must share one fetch"
    );
    shutdown.cancel();
}

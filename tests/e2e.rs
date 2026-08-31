//! End-to-end tests driving the crate through its public API only, as a downstream consumer
//! would: `use gosub_sonar::…`, an externally implemented [`FetcherContext`], and the
//! `test-support` mock server. Requires `--features test-support`.

use gosub_sonar::net::test_support::{
    CorsRouteOptions, RecordingObserver, RouteConfig, TestServer, TestServerHandle,
};
use gosub_sonar::{
    simple_get, BlockReason, CorsError, FetchRequest, FetchResult, Fetcher, FetcherConfig,
    FetcherContext, Initiator, NetError, NetObserver, NullContext, NullEmitter, RequestBody,
    RequestCredentials, RequestDestination, RequestId, RequestMode, RequestReference, ResourceKind,
    ResponseTainting, SharedBody, DEFAULT_USER_AGENT,
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

/// The destination and mode set on a request must reach the server as `Sec-Fetch-*` headers
/// when going through the full scheduler.
#[tokio::test]
async fn fetch_metadata_reaches_the_server() {
    let srv = TestServer::new()
        .route("/dest", RouteConfig::echo_request_header("sec-fetch-dest"))
        .route("/mode", RouteConfig::echo_request_header("sec-fetch-mode"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    for (path, expected) in [("/dest", "script"), ("/mode", "cors")] {
        let req = FetchRequest::builder(Method::GET, srv.url(path))
            .with_destination(RequestDestination::Script)
            .with_mode(RequestMode::Cors)
            .build();
        match fetcher.fetch(req).await {
            FetchResult::Buffered { body, .. } => {
                assert_eq!(String::from_utf8_lossy(&body), expected, "{path}")
            }
            other => panic!("expected Buffered, got {other:?}"),
        }
    }
    shutdown.cancel();
}

/// Without an explicit override, requests must identify themselves as `gosub-sonar/<version>`.
#[tokio::test]
async fn default_user_agent_reaches_the_server() {
    let srv = TestServer::new()
        .route("/ua", RouteConfig::echo_request_header("user-agent"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/ua")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => {
            assert_eq!(String::from_utf8_lossy(&body), DEFAULT_USER_AGENT)
        }
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

/// Unwrap a blocked result down to its [`CorsError`], panicking with context otherwise.
fn cors_block_reason(res: FetchResult) -> CorsError {
    match res {
        FetchResult::Error(NetError::Blocked {
            reason: BlockReason::Cors(err),
            ..
        }) => err,
        other => panic!("expected a CORS block, got {other:?}"),
    }
}

/// A cross-origin CORS request against a server that never grants anything must be refused,
/// and the target must still have been contacted exactly once (the CORS check inspects the
/// response — it is not a client-side guess).
#[tokio::test]
async fn cors_without_allow_origin_is_blocked() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::ok(b"secret"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::MissingAllowOrigin
    );
    assert_eq!(away.hit_count("/data"), 1);
    shutdown.cancel();
}

/// `Access-Control-Allow-Origin: *` admits a credential-less request; the response comes back
/// cors-tainted, with the readable-header view filtered down to the safelist + exposed names.
#[tokio::test]
async fn cors_wildcard_admits_credentialless_request() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route(
            "/data",
            RouteConfig::cors(CorsRouteOptions {
                expose_headers: Some("X-Request-Id".into()),
                extra_headers: vec![
                    ("X-Request-Id".to_string(), "42".to_string()),
                    ("X-Secret".to_string(), "s".to_string()),
                ],
                ..Default::default()
            }),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .with_credentials(RequestCredentials::Omit)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(&body[..], b"cors ok");
            assert_eq!(meta.tainting, ResponseTainting::Cors);
            let readable = meta.readable_headers(false);
            assert!(readable.get("x-request-id").is_some(), "exposed header");
            assert!(readable.get("x-secret").is_none(), "unexposed header");
            // The full map is untouched — filtering is the embedder's call.
            assert!(meta.headers.get("x-secret").is_some());
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// The same wildcard grant must NOT admit a credentialed request (the spec requires an exact
/// origin echo plus `Access-Control-Allow-Credentials: true` for those).
#[tokio::test]
async fn cors_wildcard_rejects_credentialed_request() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::cors(CorsRouteOptions::default()))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    // RequestCredentials::Include is the default.
    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::WildcardWithCredentials
    );
    shutdown.cancel();
}

/// A credentialed request is admitted when the server echoes the exact origin and opts in
/// with `Access-Control-Allow-Credentials: true`.
#[tokio::test]
async fn cors_exact_origin_admits_credentialed_request() {
    let home = TestServer::new().start().await;
    let origin = home.base_url().origin().ascii_serialization();
    let away = TestServer::new()
        .route(
            "/data",
            RouteConfig::cors(CorsRouteOptions {
                allow_origin: origin,
                allow_credentials: true,
                ..Default::default()
            }),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, .. } => assert_eq!(meta.tainting, ResponseTainting::Cors),
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// A non-safelisted method triggers exactly one `OPTIONS` preflight; the grant is cached for
/// `Access-Control-Max-Age`, so a second request goes straight through.
#[tokio::test]
async fn preflight_runs_once_then_is_cached() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route(
            "/data",
            RouteConfig::cors(CorsRouteOptions {
                allow_methods: Some("PUT".into()),
                max_age: Some(600),
                ..Default::default()
            }),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    for _ in 0..2 {
        let req = FetchRequest::builder(Method::PUT, away.url("/data"))
            .with_origin(home.base_url().origin())
            .with_mode(RequestMode::Cors)
            .with_credentials(RequestCredentials::Omit)
            .with_body(RequestBody::text("payload"))
            .build();
        match fetcher.fetch(req).await {
            FetchResult::Buffered { .. } => {}
            other => panic!("expected Buffered, got {other:?}"),
        }
    }
    assert_eq!(
        away.hit_count("OPTIONS /data"),
        1,
        "second request must be served from the preflight cache"
    );
    assert_eq!(away.hit_count("/data"), 2);
    shutdown.cancel();
}

/// Hands the same recording observer to every request, so a test can assert on the events
/// the fetch stack emitted.
struct RecordingCtx(Arc<RecordingObserver>);

impl FetcherContext for RecordingCtx {
    fn observer_for(
        &self,
        _reference: RequestReference,
        _req_id: RequestId,
        _kind: ResourceKind,
        _initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        self.0.clone()
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

/// The `OPTIONS` round-trip is reported as a completed pair, so its cost is attributable
/// rather than hiding in the gap before the response. A hop served from the grant cache
/// sends no `OPTIONS` and so reports nothing at all.
#[tokio::test]
async fn preflight_reports_its_round_trip() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route(
            "/data",
            RouteConfig::cors(CorsRouteOptions {
                allow_methods: Some("PUT".into()),
                max_age: Some(600),
                ..Default::default()
            }),
        )
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    for _ in 0..2 {
        let req = FetchRequest::builder(Method::PUT, away.url("/data"))
            .with_origin(home.base_url().origin())
            .with_mode(RequestMode::Cors)
            .with_credentials(RequestCredentials::Omit)
            .with_body(RequestBody::text("payload"))
            .build();
        match fetcher.fetch(req).await {
            FetchResult::Buffered { .. } => {}
            other => panic!("expected Buffered, got {other:?}"),
        }
    }

    let preflights = obs.cors_preflights();
    assert_eq!(
        preflights.len(),
        1,
        "the cached second request must report no preflight, got {preflights:?}"
    );
    assert_eq!(preflights[0].0, away.url("/data").to_string());
    assert!(preflights[0].1, "the preflight got a response");
    shutdown.cancel();
}

/// A rejected preflight still cost a round-trip, so it is reported as completed - the
/// refusal is carried separately by `Blocked`.
#[tokio::test]
async fn rejected_preflight_still_reports_its_cost() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::cors(CorsRouteOptions::default()))
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    let req = FetchRequest::builder(Method::DELETE, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .with_credentials(RequestCredentials::Omit)
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::PreflightMethodRejected
    );

    assert_eq!(
        obs.cors_preflights(),
        vec![(away.url("/data").to_string(), true)]
    );
    shutdown.cancel();
}

/// A preflight that does not grant the method blocks the request before it is ever sent.
#[tokio::test]
async fn preflight_denial_blocks_the_request() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route(
            "/data",
            // No allow_methods: the preflight response grants nothing beyond safelisted ones.
            RouteConfig::cors(CorsRouteOptions::default()),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::DELETE, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .with_credentials(RequestCredentials::Omit)
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::PreflightMethodRejected
    );
    assert_eq!(away.hit_count("OPTIONS /data"), 1);
    assert_eq!(
        away.hit_count("/data"),
        0,
        "the denied request must never reach the server"
    );
    shutdown.cancel();
}

/// Same-origin mode refuses a cross-origin target without contacting it.
#[tokio::test]
async fn same_origin_mode_refuses_cross_origin_target() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::ok(b"other"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::SameOrigin)
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::SameOriginMode
    );
    assert_eq!(away.hit_count("/data"), 0);
    shutdown.cancel();
}

/// A cross-origin no-cors load (how markup fetches images and scripts) succeeds without any
/// server opt-in, but comes back opaque: the embedder can render it, scripts read nothing.
#[tokio::test]
async fn no_cors_cross_origin_is_opaque() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/img", RouteConfig::ok(b"pixels"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    // RequestMode::NoCors is the default.
    let req = FetchRequest::builder(Method::GET, away.url("/img"))
        .with_origin(home.base_url().origin())
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(&body[..], b"pixels", "the embedder still gets the bytes");
            assert_eq!(meta.tainting, ResponseTainting::Opaque);
            assert!(meta.readable_headers(true).is_empty());
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// A cross-origin no-cors request cannot smuggle a method markup could never produce.
#[tokio::test]
async fn no_cors_cross_origin_rejects_unsafe_method() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::ok(b"x"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::DELETE, away.url("/data"))
        .with_origin(home.base_url().origin())
        .build();
    assert_eq!(
        cors_block_reason(fetcher.fetch(req).await),
        CorsError::UnsafeMethodForNoCors
    );
    assert_eq!(away.hit_count("/data"), 0);
    shutdown.cancel();
}

/// A same-origin request in cors mode needs no server opt-in and stays basic.
#[tokio::test]
async fn same_origin_cors_request_stays_basic() {
    let home = TestServer::new()
        .route("/data", RouteConfig::ok(b"mine"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, home.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, .. } => assert_eq!(meta.tainting, ResponseTainting::Basic),
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// The CORS check runs on every hop: a redirect response that fails to grant the origin kills
/// the chain even when the final target would have granted it.
#[tokio::test]
async fn cors_check_applies_to_redirect_hops() {
    let home = TestServer::new().start().await;

    // Grants on the redirect hop AND on the target: the chain succeeds.
    let away_ok = TestServer::new()
        .route("/data", RouteConfig::cors(CorsRouteOptions::default()))
        .start()
        .await;
    let hop_target = away_ok.url("/data").to_string();
    let away_granting_hop = TestServer::new()
        .route(
            "/hop",
            RouteConfig::redirect_absolute_with_headers(
                &[("Access-Control-Allow-Origin", "*")],
                hop_target.clone(),
            ),
        )
        .start()
        .await;
    // No grant on the redirect hop itself: the chain must die there.
    let away_bare_hop = TestServer::new()
        .route("/hop", RouteConfig::redirect_absolute(&hop_target))
        .start()
        .await;

    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));
    let req = |srv: &TestServerHandle| {
        FetchRequest::builder(Method::GET, srv.url("/hop"))
            .with_origin(home.base_url().origin())
            .with_mode(RequestMode::Cors)
            .with_credentials(RequestCredentials::Omit)
            .build()
    };

    match fetcher.fetch(req(&away_granting_hop)).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(&body[..], b"cors ok");
            assert_eq!(meta.tainting, ResponseTainting::Cors);
        }
        other => panic!("expected Buffered, got {other:?}"),
    }

    assert_eq!(
        cors_block_reason(fetcher.fetch(req(&away_bare_hop)).await),
        CorsError::MissingAllowOrigin
    );
    assert_eq!(
        away_ok.hit_count("/data"),
        1,
        "the second chain must die on the ungranted hop"
    );
    shutdown.cancel();
}

/// `RequestCredentials::Omit` keeps the jar's cookies off the wire even same-origin;
/// the default (`Include`) sends them. Headers set by hand are unaffected.
#[tokio::test]
async fn omit_credentials_keeps_jar_cookies_off_the_wire() {
    let srv = TestServer::new()
        .route("/cookie", RouteConfig::echo_cookie_header())
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(CookieContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/cookie"))
        .with_credentials(RequestCredentials::Omit)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => assert_eq!(&body[..], b""),
        other => panic!("expected Buffered, got {other:?}"),
    }

    let req = FetchRequest::builder(Method::GET, srv.url("/cookie")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => assert_eq!(&body[..], b"session=e2e"),
        other => panic!("expected Buffered, got {other:?}"),
    }
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

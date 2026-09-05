//! End-to-end tests driving the crate through its public API only, as a downstream consumer
//! would: `use gosub_sonar::…`, an externally implemented [`FetcherContext`], and the
//! `test-support` mock server. Requires `--features test-support`.

use gosub_sonar::net::test_support::{
    CacheRouteOptions, CorsRouteOptions, RecordingObserver, RouteConfig, TestServer,
    TestServerHandle,
};
use gosub_sonar::{
    simple_get, AuthChallenge, AuthScheme, AuthTarget, BlockReason, CacheMode, CorsError,
    CredentialStore, Credentials, FetchRequest, FetchResult, Fetcher, FetcherConfig,
    FetcherContext, HttpCache, InMemoryCredentialStore, InMemoryHttpCache, Initiator, NetError,
    NetObserver, NullContext, NullEmitter, ProtectionSpace, RequestBody, RequestCredentials,
    RequestDestination, RequestId, RequestMode, RequestReference, ResourceKind, ResponseTainting,
    SharedBody, DEFAULT_USER_AGENT,
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

/// The header set a request actually carried, as `name: value` lines read off the wire by the
/// mock server, lowercased and sorted.
async fn headers_on_the_wire(fetcher: &Arc<Fetcher>, req: FetchRequest) -> Vec<String> {
    let body = match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => body,
        other => panic!("expected Buffered, got {other:?}"),
    };
    let mut lines: Vec<String> = String::from_utf8_lossy(&body)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (name, value) = l.split_once(':').expect("header line");
            format!("{}: {}", name.trim().to_ascii_lowercase(), value.trim())
        })
        .collect();
    lines.sort();
    lines
}

/// The header set `NetEvent::RequestSent` reported for the last hop, in the same shape.
fn headers_reported(obs: &RecordingObserver) -> Vec<String> {
    let (_, _, headers) = obs
        .requests_sent()
        .pop()
        .expect("a request was reported sent");
    let mut lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name.as_str(), value.to_str().unwrap()))
        .collect();
    lines.sort();
    lines
}

/// The point of the whole exercise: what an observer is told was sent is what was sent.
///
/// Every header this crate can write, it writes -- so nothing is left for the HTTP client to
/// default in after the report has been emitted. `host` is the documented exception, added by
/// the connection from the URL that is reported alongside the headers.
#[tokio::test]
async fn the_reported_headers_are_the_headers_on_the_wire() {
    let srv = TestServer::new()
        .default_route(RouteConfig::echo_request_headers())
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    let req = FetchRequest::builder(Method::GET, srv.url("/headers"))
        .with_destination(RequestDestination::Document)
        .build();
    let on_the_wire = headers_on_the_wire(&fetcher, req).await;

    let mut expected = headers_reported(&obs);
    expected.push(format!("host: {}", srv.socket_addr()));
    expected.sort();

    assert_eq!(on_the_wire, expected);
    shutdown.cancel();
}

/// The same guarantee for a request with a body, where `content-length` is the header the
/// connection would otherwise have computed for itself, below anything that could report it.
#[tokio::test]
async fn a_body_s_content_length_is_reported_and_sent() {
    let srv = TestServer::new()
        .default_route(RouteConfig::echo_request_headers())
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    let req = FetchRequest::builder(Method::POST, srv.url("/submit"))
        .with_body(RequestBody::json(r#"{"a":1}"#))
        .build();
    let on_the_wire = headers_on_the_wire(&fetcher, req).await;

    let reported = headers_reported(&obs);
    assert!(
        reported.iter().any(|l| l == "content-length: 7"),
        "the body's length is reported: {reported:?}"
    );

    let mut expected = reported;
    expected.push(format!("host: {}", srv.socket_addr()));
    expected.sort();

    assert_eq!(on_the_wire, expected);
    shutdown.cancel();
}

/// `Accept` is composed from the destination rather than left to the client, which would send
/// a bare `*/*` for everything -- and send it after the report was emitted.
#[tokio::test]
async fn accept_is_shaped_by_the_destination() {
    let srv = TestServer::new()
        .default_route(RouteConfig::echo_request_header("accept"))
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let cases = [
        (
            RequestDestination::Document,
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        (
            RequestDestination::Image,
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        ),
        (RequestDestination::Style, "text/css,*/*;q=0.1"),
        (RequestDestination::Script, "*/*"),
    ];
    for (destination, expected) in cases {
        let req = FetchRequest::builder(Method::GET, srv.url("/accept"))
            .with_destination(destination)
            .build();
        match fetcher.fetch(req).await {
            FetchResult::Buffered { body, .. } => {
                assert_eq!(String::from_utf8_lossy(&body), expected, "{destination:?}")
            }
            other => panic!("expected Buffered, got {other:?}"),
        }
    }
    shutdown.cancel();
}

/// Every hop reports its response headers, so a redirect chain accounts for each round-trip
/// it waited on rather than only the one that produced the body.
#[tokio::test]
async fn response_headers_are_reported_per_hop() {
    let srv = TestServer::new()
        .route("/start", RouteConfig::RedirectTo("/end".into()))
        .route("/end", RouteConfig::ok(b"arrived"))
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    let req = FetchRequest::builder(Method::GET, srv.url("/start")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { body, .. } => assert_eq!(&body[..], b"arrived"),
        other => panic!("expected Buffered, got {other:?}"),
    }

    assert_eq!(
        obs.response_headers(),
        vec![
            (srv.url("/start").to_string(), 302),
            (srv.url("/end").to_string(), 200),
        ]
    );
    shutdown.cancel();
}

/// A request refused by policy reports the reason *and* a terminal `Failed`, so an observer
/// can tell a dead request from a slow one without matching every possible cause.
#[tokio::test]
async fn a_refused_request_reports_a_terminal_failure() {
    let home = TestServer::new().start().await;
    let away = TestServer::new()
        .route("/data", RouteConfig::ok(b"nope"))
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    // cors mode against a route that sends no Access-Control-Allow-Origin.
    let req = FetchRequest::builder(Method::GET, away.url("/data"))
        .with_origin(home.base_url().origin())
        .with_mode(RequestMode::Cors)
        .with_credentials(RequestCredentials::Omit)
        .build();
    assert!(fetcher.fetch(req).await.is_error());

    assert!(
        obs.blocked_reason().is_some(),
        "the cause is still reported"
    );
    assert_eq!(
        obs.failures().len(),
        1,
        "exactly one terminal failure, got {:?}",
        obs.failures()
    );
    shutdown.cancel();
}

/// A cancelled request is not a failure: it reports `Cancelled` and nothing else.
#[tokio::test]
async fn a_cancelled_request_is_not_reported_as_failed() {
    let srv = TestServer::new()
        .route("/slow", RouteConfig::ok(b"never read"))
        .start()
        .await;
    let obs = Arc::new(RecordingObserver::default());
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(RecordingCtx(obs.clone())));

    let cancel = CancellationToken::new();
    cancel.cancel();
    let req = FetchRequest::builder(Method::GET, srv.url("/slow")).build();
    assert!(fetcher.fetch_with_cancel(req, cancel).await.is_error());

    assert!(
        obs.failures().is_empty(),
        "cancellation must not report a failure, got {:?}",
        obs.failures()
    );
    shutdown.cancel();
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

/// base64("e2e:hunter2") — what the `/protected` routes below accept.
const E2E_AUTH: &str = "Basic ZTJlOmh1bnRlcjI=";

/// Answers `Basic` challenges with one fixed password and records what it was asked.
struct AuthContext {
    seen: std::sync::Mutex<Vec<AuthChallenge>>,
    password: String,
}

impl AuthContext {
    fn new(password: &str) -> Self {
        Self {
            seen: std::sync::Mutex::new(Vec::new()),
            password: password.to_string(),
        }
    }
}

impl FetcherContext for AuthContext {
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
    fn on_auth_challenge(&self, challenge: &AuthChallenge) -> Option<Credentials> {
        self.seen.lock().unwrap().push(challenge.clone());
        match challenge.scheme {
            AuthScheme::Basic => Some(Credentials::basic("e2e", self.password.clone())),
            // Nothing here can compute a Digest response.
            _ => None,
        }
    }
}

fn protected_server(challenge: &str) -> TestServer {
    TestServer::new().route(
        "/protected",
        RouteConfig::require_auth(challenge, E2E_AUTH, b"top secret".to_vec()),
    )
}

/// Issue #7: a 401 is answered and retried instead of being the result of the fetch.
#[tokio::test]
async fn a_401_is_answered_from_the_context_hook() {
    let srv = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let ctx = Arc::new(AuthContext::new("hunter2"));
    let (fetcher, shutdown) = spawn_fetcher(ctx.clone());

    let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(meta.status, 200);
            assert_eq!(&body[..], b"top secret");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    assert_eq!(srv.hit_count("/protected"), 2);

    let seen = ctx.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, AuthTarget::Server);
    assert_eq!(seen[0].realm.as_deref(), Some("Members Only"));
    assert_eq!(seen[0].url, srv.url("/protected"));
    shutdown.cancel();
}

/// A context that answers no challenge gets the 401 back, `WWW-Authenticate` intact.
#[tokio::test]
async fn a_401_without_an_answer_is_still_delivered() {
    let srv = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let (fetcher, shutdown) = spawn_fetcher(Arc::new(NullContext));

    let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, .. } => {
            assert_eq!(meta.status, 401);
            assert_eq!(
                meta.headers
                    .get(http::header::WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok()),
                Some(r#"Basic realm="Members Only""#)
            );
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    assert_eq!(srv.hit_count("/protected"), 1);
    shutdown.cancel();
}

/// A challenge the embedder cannot answer falls through to the next one the server offered.
#[tokio::test]
async fn the_first_answerable_challenge_wins() {
    let srv = protected_server(r#"Digest realm="d", nonce="n", Basic realm="Members Only""#)
        .start()
        .await;
    let ctx = Arc::new(AuthContext::new("hunter2"));
    let (fetcher, shutdown) = spawn_fetcher(ctx.clone());

    let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, .. } => assert_eq!(meta.status, 200),
        other => panic!("expected Buffered, got {other:?}"),
    }

    let seen = ctx.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].scheme, AuthScheme::Digest);
    assert_eq!(seen[0].param("nonce"), Some("n"));
    assert_eq!(seen[1].scheme, AuthScheme::Basic);
    shutdown.cancel();
}

/// A wrong password is retried a bounded number of times and then handed back as the 401.
#[tokio::test]
async fn a_refused_password_is_not_retried_forever() {
    let srv = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let ctx = Arc::new(AuthContext::new("wrong"));
    let (fetcher, shutdown) = spawn_fetcher(ctx.clone());

    let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, .. } => assert_eq!(meta.status, 401),
        other => panic!("expected Buffered, got {other:?}"),
    }
    assert_eq!(
        srv.hit_count("/protected"),
        1 + gosub_sonar::MAX_AUTH_ATTEMPTS as usize
    );
    assert_eq!(
        ctx.seen.lock().unwrap().len(),
        gosub_sonar::MAX_AUTH_ATTEMPTS as usize
    );
    shutdown.cancel();
}

/// The credential store can be pre-seeded. An asynchronous password dialog uses that: return
/// `None` from the hook, ask the user, put the answer in the store, fetch again.
#[tokio::test]
async fn a_pre_seeded_credential_store_answers_without_the_hook() {
    let srv = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let store = Arc::new(InMemoryCredentialStore::new());
    store.store(
        ProtectionSpace {
            target: AuthTarget::Server,
            scheme: AuthScheme::Basic,
            origin: Some(srv.url("/protected").origin().ascii_serialization()),
            realm: "Members Only".into(),
        },
        Credentials::basic("e2e", "hunter2"),
    );

    let cfg = FetcherConfig {
        credentials: Some(store.clone()),
        ..FetcherConfig::default()
    };
    // This context refuses every challenge; the store answers before it is consulted.
    let fetcher = Arc::new(Fetcher::new(cfg, Arc::new(NullContext)).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });

    let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            assert_eq!(meta.status, 200);
            assert_eq!(&body[..], b"top secret");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    shutdown.cancel();
}

/// Credentials for one origin's realm are not offered to another origin's, even when the realm
/// name matches.
#[tokio::test]
async fn credentials_do_not_cross_origins() {
    let one = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let two = protected_server(r#"Basic realm="Members Only""#)
        .start()
        .await;
    let store = Arc::new(InMemoryCredentialStore::new());
    let cfg = FetcherConfig {
        credentials: Some(store.clone()),
        ..FetcherConfig::default()
    };
    let ctx = Arc::new(AuthContext::new("hunter2"));
    let fetcher = Arc::new(Fetcher::new(cfg, ctx.clone()).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });

    for srv in [&one, &two] {
        let req = FetchRequest::builder(Method::GET, srv.url("/protected")).build();
        match fetcher.fetch(req).await {
            FetchResult::Buffered { meta, .. } => assert_eq!(meta.status, 200),
            other => panic!("expected Buffered, got {other:?}"),
        }
    }

    // One entry per origin, and the hook was asked once for each.
    assert_eq!(store.len(), 2);
    assert_eq!(ctx.seen.lock().unwrap().len(), 2);
    shutdown.cancel();
}

/// A fetcher with an explicit cache (or none), plus the cache itself.
fn spawn_with_cache(cache: Option<Arc<InMemoryHttpCache>>) -> (Arc<Fetcher>, CancellationToken) {
    let cfg = FetcherConfig {
        cache: cache.map(|c| c as Arc<dyn HttpCache>),
        ..FetcherConfig::default()
    };
    let fetcher = Arc::new(Fetcher::new(cfg, Arc::new(NullContext)).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });
    (fetcher, shutdown)
}

fn buffered(result: FetchResult) -> (gosub_sonar::FetchResultMeta, bytes::Bytes) {
    match result {
        FetchResult::Buffered { meta, body } => (meta, body),
        other => panic!("expected Buffered, got {other:?}"),
    }
}

/// Issue #1: a second fetch of a fresh resource does not reach the server.
#[tokio::test]
async fn a_fresh_response_is_served_from_the_cache() {
    let srv = TestServer::new()
        .route(
            "/cached",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
        )
        .start()
        .await;
    let cache = Arc::new(InMemoryHttpCache::new());
    let (fetcher, shutdown) = spawn_with_cache(Some(cache.clone()));

    let req = FetchRequest::builder(Method::GET, srv.url("/cached")).build();
    let (meta, body) = buffered(fetcher.fetch(req).await);
    assert_eq!(meta.status, 200);
    assert!(!meta.from_cache);
    assert_eq!(&body[..], b"hit-1");

    let req = FetchRequest::builder(Method::GET, srv.url("/cached")).build();
    let (meta, body) = buffered(fetcher.fetch(req).await);
    assert!(meta.from_cache);
    assert_eq!(&body[..], b"hit-1");
    assert_eq!(srv.hit_count("/cached"), 1);
    assert_eq!(cache.len(), 1);
    shutdown.cancel();
}

/// A `304` is invisible to the caller: the stored body comes back as a 200.
#[tokio::test]
async fn a_revalidated_response_comes_back_as_a_200() {
    let srv = TestServer::new()
        .route(
            "/etag",
            RouteConfig::Cacheable(
                CacheRouteOptions::max_age(0, b"stored body".to_vec()).with_etag("\"v1\""),
            ),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_with_cache(Some(Arc::new(InMemoryHttpCache::new())));

    for expected_from_cache in [false, true] {
        let req = FetchRequest::builder(Method::GET, srv.url("/etag")).build();
        let (meta, body) = buffered(fetcher.fetch(req).await);
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"stored body");
        assert_eq!(meta.from_cache, expected_from_cache);
    }
    // Asked twice, transferred once.
    assert_eq!(srv.hit_count("/etag"), 2);
    shutdown.cancel();
}

/// `CacheMode::Reload` is what a refresh button does: back to the server, and the answer
/// replaces what was stored.
#[tokio::test]
async fn a_reload_ignores_a_fresh_entry() {
    let srv = TestServer::new()
        .route(
            "/reload",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_with_cache(Some(Arc::new(InMemoryHttpCache::new())));

    let req = FetchRequest::builder(Method::GET, srv.url("/reload")).build();
    assert_eq!(&buffered(fetcher.fetch(req).await).1[..], b"hit-1");

    let req = FetchRequest::builder(Method::GET, srv.url("/reload"))
        .with_cache_mode(CacheMode::Reload)
        .build();
    let (meta, body) = buffered(fetcher.fetch(req).await);
    assert!(!meta.from_cache);
    assert_eq!(&body[..], b"hit-2");

    // And the reloaded response is what the next normal fetch gets.
    let req = FetchRequest::builder(Method::GET, srv.url("/reload")).build();
    let (meta, body) = buffered(fetcher.fetch(req).await);
    assert!(meta.from_cache);
    assert_eq!(&body[..], b"hit-2");
    assert_eq!(srv.hit_count("/reload"), 2);
    shutdown.cancel();
}

/// `CacheMode::NoStore` neither reads nor writes, for a private session.
#[tokio::test]
async fn no_store_leaves_no_trace() {
    let srv = TestServer::new()
        .route(
            "/private",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, b"secret".to_vec())),
        )
        .start()
        .await;
    let cache = Arc::new(InMemoryHttpCache::new());
    let (fetcher, shutdown) = spawn_with_cache(Some(cache.clone()));

    for _ in 0..2 {
        let req = FetchRequest::builder(Method::GET, srv.url("/private"))
            .with_cache_mode(CacheMode::NoStore)
            .build();
        let (meta, _) = buffered(fetcher.fetch(req).await);
        assert!(!meta.from_cache);
    }
    assert_eq!(srv.hit_count("/private"), 2);
    assert!(cache.is_empty());
    shutdown.cancel();
}

/// `only-if-cached` refuses rather than reaching the network.
#[tokio::test]
async fn only_if_cached_without_an_entry_fails() {
    let srv = TestServer::new()
        .route(
            "/absent",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, b"x".to_vec())),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_with_cache(Some(Arc::new(InMemoryHttpCache::new())));

    let req = FetchRequest::builder(Method::GET, srv.url("/absent"))
        .with_cache_mode(CacheMode::OnlyIfCached)
        .build();
    match fetcher.fetch(req).await {
        FetchResult::Error(NetError::Blocked { reason, .. }) => {
            assert_eq!(reason, BlockReason::NotCached)
        }
        other => panic!("expected a NotCached block, got {other:?}"),
    }
    assert_eq!(srv.hit_count("/absent"), 0);
    shutdown.cancel();
}

/// A fetcher configured without a cache behaves exactly as it did before caching existed.
#[tokio::test]
async fn a_fetcher_without_a_cache_always_goes_to_the_server() {
    let srv = TestServer::new()
        .route(
            "/uncached",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
        )
        .start()
        .await;
    let (fetcher, shutdown) = spawn_with_cache(None);

    for expected in [&b"hit-1"[..], &b"hit-2"[..]] {
        let req = FetchRequest::builder(Method::GET, srv.url("/uncached")).build();
        let (meta, body) = buffered(fetcher.fetch(req).await);
        assert!(!meta.from_cache);
        assert_eq!(&body[..], expected);
    }
    assert_eq!(srv.hit_count("/uncached"), 2);
    shutdown.cancel();
}

/// Clearing the store empties the fetcher's cache: what a "clear browsing data" button does.
#[tokio::test]
async fn clearing_the_store_drops_what_was_cached() {
    let srv = TestServer::new()
        .route(
            "/clearable",
            RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
        )
        .start()
        .await;
    let cache = Arc::new(InMemoryHttpCache::new());
    let (fetcher, shutdown) = spawn_with_cache(Some(cache.clone()));

    let req = FetchRequest::builder(Method::GET, srv.url("/clearable")).build();
    assert_eq!(&buffered(fetcher.fetch(req).await).1[..], b"hit-1");
    assert_eq!(cache.len(), 1);

    cache.clear();

    let req = FetchRequest::builder(Method::GET, srv.url("/clearable")).build();
    let (meta, body) = buffered(fetcher.fetch(req).await);
    assert!(!meta.from_cache);
    assert_eq!(&body[..], b"hit-2");
    shutdown.cancel();
}

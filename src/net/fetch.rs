//! Low-level fetch functions used by the [`super::fetcher::Fetcher`].

use crate::net::auth::{
    self, AuthChallenge, AuthTarget, CredentialStore, Credentials, ProtectionSpace,
    MAX_AUTH_ATTEMPTS,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::cache::{self, CacheDecision, CacheKey, HttpCache};
use crate::net::cache::{CacheEntry, CacheMode, CacheOutcome};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::cors::CorsPreflightCache;
use crate::net::cors::{self, CorsError, ResponseTainting};
use crate::net::events::NetEvent;
use crate::net::fetch_metadata::{self, RequestDestination, RequestMode, SecFetchSite};
use crate::net::fetcher_context::FetcherContext;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::hsts::{self, HstsStore};
use crate::net::mixed_content::{self, MixedContentAction, MixedContentPolicy};
use crate::net::observer::NetObserver;
use crate::net::referrer::{self, ReferrerPolicy};
use crate::net::types::{BlockReason, FetchResultMeta, NetError, RequestBody, RequestCredentials};
use crate::net::utils::BytesAsyncReader;
use crate::types::PeekBuf;
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use futures_util::{stream, StreamExt, TryStreamExt};
use http::{header, HeaderMap, Method};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;
use url::{Origin, Url};

/// Headers that must be stripped when following a redirect to a different origin (RFC 9110 §15.4).
///
/// `Referer` and `Origin` are included so hand-set values cannot leak to a third-party host.
/// When the caller supplies a referrer or an initiating origin instead, the values are
/// recomputed for each hop anyway, so removing them here costs nothing.
const SENSITIVE_REDIRECT_HEADERS: &[header::HeaderName] = &[
    header::AUTHORIZATION,
    header::COOKIE,
    header::REFERER,
    header::ORIGIN,
];

/// `Referrer-Policy` is not in `http`'s well-known header set, so name it once here rather than
/// repeating a string literal at the use site.
static REFERRER_POLICY: header::HeaderName = header::HeaderName::from_static("referrer-policy");

/// Emit the block event and build the matching error, so the two can never drift apart.
pub(crate) fn blocked(
    observer: &Arc<dyn NetObserver + Send + Sync>,
    url: Url,
    reason: BlockReason,
) -> NetError {
    observer.on_event(NetEvent::Blocked {
        url: url.clone(),
        reason,
    });
    NetError::Blocked { reason, url }
}

/// What [`hop_checks`] decided about one hop.
pub(crate) enum HopCheck {
    /// Send the request to this URL, which may be an upgraded form of the one checked.
    Proceed(Url),
    /// Refuse the request.
    Reject(BlockReason),
}

/// Apply the pre-dispatch checks to a single hop: scheme allowlist, mixed content, then the
/// embedder's URL allowlist.
///
/// Both the scheduler's pre-dispatch check and the per-hop redirect loop call this, so the two
/// cannot reach different conclusions about the same URL. Order matters: a mixed content upgrade
/// rewrites the URL, and `url_allowed` must vet the URL that will actually be sent — an embedder
/// that rejects `http://` should not see a request the upgrade would have made `https://`.
pub(crate) fn hop_checks(
    url: &Url,
    mixed_content: MixedContentPolicy,
    origin: Option<&Origin>,
    url_allowed: &dyn Fn(&Url) -> bool,
) -> HopCheck {
    if !matches!(url.scheme(), "http" | "https") {
        return HopCheck::Reject(BlockReason::UnsupportedScheme);
    }

    let target = match mixed_content::evaluate(mixed_content, origin, url) {
        MixedContentAction::Allow => url.clone(),
        MixedContentAction::Upgrade(upgraded) => upgraded,
        MixedContentAction::Block => return HopCheck::Reject(BlockReason::MixedContent),
    };

    if !url_allowed(&target) {
        return HopCheck::Reject(BlockReason::UrlPolicy);
    }

    HopCheck::Proceed(target)
}

/// Callback type for the URL allowlist check.
pub type UrlFilter = Box<dyn Fn(&Url) -> bool + Send + Sync>;

/// Callback type for per-URL cookie jar queries.
pub type CookieJarFn = Box<dyn Fn(&Url) -> Option<String> + Send + Sync>;

/// Callback type for reporting `Set-Cookie` values received on a response.
pub type CookieSinkFn = Box<dyn Fn(&Url, &[&str]) + Send + Sync>;

/// Callback type for reporting the HTTP version of a response.
pub type ProtocolSinkFn = Box<dyn Fn(&Url, http::Version) + Send + Sync>;

/// Callback type for answering an authentication challenge.
pub type AuthChallengeFn = Box<dyn Fn(&AuthChallenge) -> Option<Credentials> + Send + Sync>;

/// Network-level request policies threaded through the fetch stack.
///
/// Bundles the URL allowlist check and the cookie-jar query so both can be applied at
/// every redirect hop without passing separate generic parameters.
///
/// Construct with [`NetPolicy::default`] (no-op, allows everything) or
/// [`NetPolicy::from_context`] to wire up a [`FetcherContext`] implementation.
pub struct NetPolicy {
    /// Return `false` to block a URL. Called for the initial URL and each redirect target.
    pub url_allowed: UrlFilter,
    /// Return cookies for a request URL in `"name=value; name2=value2"` format, or `None`.
    /// Called on each hop after cross-origin cookie stripping, so the jar is always consulted
    /// for the correct origin.
    pub cookies_for: CookieJarFn,
    /// Called with the raw `Set-Cookie` values of each redirect (3xx) response, so cookies set
    /// mid-chain (e.g. a session cookie on a login 302) reach the jar before the next hop.
    /// The final response's cookies are reported by the fetcher, not here.
    pub on_cookies: CookieSinkFn,
    /// Called with the URL and HTTP version of every response in the chain, redirects included.
    /// The fetcher uses this to pick the h1 or h2 per-origin connection limit. Not called on
    /// wasm32 (the browser's `fetch()` doesn't expose the version). Set via
    /// [`NetPolicy::with_protocol_sink`].
    pub on_protocol: ProtocolSinkFn,
    /// HSTS store consulted to upgrade each hop, and updated from each hop's response.
    /// `None` disables HSTS. Set via [`NetPolicy::with_hsts`].
    #[cfg(not(target_arch = "wasm32"))]
    pub hsts: Option<Arc<dyn HstsStore>>,
    /// Cache of CORS preflight grants. `None` still preflights when the spec requires it,
    /// asking the server every time. Set via [`NetPolicy::with_cors_preflight_cache`].
    #[cfg(not(target_arch = "wasm32"))]
    pub cors_preflight: Option<Arc<dyn CorsPreflightCache>>,
    /// Called for each challenge of a `401`/`407` response until one yields credentials to retry
    /// the hop with. The default answers no challenge, leaving the response for the caller.
    /// See [`auth`](mod@crate::net::auth).
    pub on_auth_challenge: AuthChallengeFn,
    /// Credentials remembered per protection space, consulted before `on_auth_challenge` and
    /// updated from its answers. `None` still authenticates, asking the hook every time.
    /// Set via [`NetPolicy::with_credential_store`].
    pub credentials: Option<Arc<dyn CredentialStore>>,
    /// Store of cached responses, consulted before every hop and written to after it.
    /// `None` disables caching. Set via [`NetPolicy::with_cache`].
    /// See [`cache`](mod@crate::net::cache).
    #[cfg(not(target_arch = "wasm32"))]
    pub cache: Option<Arc<dyn HttpCache>>,
    /// The user agent configured on the HTTP client, purely so that
    /// [`NetEvent::RequestSent`] can report it.
    ///
    /// It exists because the client will not say. A default header set on the client is
    /// merged when a request is *executed*, not when it is built, and is never exposed for
    /// reading -- so a request assembled here carries no user agent even though one is about
    /// to be sent. Telling the policy what was configured is the only way an observer can be
    /// shown the truth.
    ///
    /// `None` reports no user agent rather than inventing one, which is the honest answer
    /// for a client this crate did not build. Set via [`NetPolicy::with_user_agent`].
    pub user_agent: Option<http::HeaderValue>,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            url_allowed: Box::new(|_| true),
            cookies_for: Box::new(|_| None),
            on_cookies: Box::new(|_, _| {}),
            on_protocol: Box::new(|_, _| {}),
            user_agent: None,
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
            #[cfg(not(target_arch = "wasm32"))]
            cors_preflight: None,
            on_auth_challenge: Box::new(|_| None),
            credentials: None,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
        }
    }
}

impl NetPolicy {
    /// Build a policy that delegates to a [`FetcherContext`] implementation.
    pub fn from_context(ctx: &Arc<dyn FetcherContext>) -> Self {
        let ctx_url = ctx.clone();
        let ctx_cookies = ctx.clone();
        let ctx_sink = ctx.clone();
        let ctx_auth = ctx.clone();
        Self {
            url_allowed: Box::new(move |url| ctx_url.is_url_allowed(url)),
            cookies_for: Box::new(move |url| ctx_cookies.cookies_for(url)),
            on_cookies: Box::new(move |url, values| ctx_sink.on_cookies_received(url, values)),
            on_protocol: Box::new(|_, _| {}),
            // Filled in by the fetcher, which is what knows how its client was built.
            user_agent: None,
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
            #[cfg(not(target_arch = "wasm32"))]
            cors_preflight: None,
            on_auth_challenge: Box::new(move |challenge| ctx_auth.on_auth_challenge(challenge)),
            credentials: None,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
        }
    }

    /// Tell the policy which user agent the client was built with, so
    /// [`NetEvent::RequestSent`] can report it. A value that is not a valid header is
    /// dropped rather than reported wrongly.
    pub fn with_user_agent(mut self, user_agent: Option<&str>) -> Self {
        self.user_agent = user_agent.and_then(|ua| http::HeaderValue::from_str(ua).ok());
        self
    }

    /// Attaches a callback that receives the URL and HTTP version of every response.
    pub fn with_protocol_sink(mut self, sink: ProtocolSinkFn) -> Self {
        self.on_protocol = sink;
        self
    }

    /// Attaches the HSTS store this policy should consult and update. `None` disables HSTS.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_hsts(mut self, store: Option<Arc<dyn HstsStore>>) -> Self {
        self.hsts = store;
        self
    }

    /// Attaches the CORS preflight cache this policy should consult and update.
    /// `None` still preflights when required, without caching the grants.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_cors_preflight_cache(mut self, cache: Arc<dyn CorsPreflightCache>) -> Self {
        self.cors_preflight = Some(cache);
        self
    }

    /// Drops the CORS preflight cache: preflights still run when required, but no grant is
    /// remembered between them.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clear_preflight_cache(mut self) -> Self {
        self.cors_preflight = None;
        self
    }

    /// Attaches the credential store consulted for authentication challenges, and updated when
    /// credentials from [`NetPolicy::on_auth_challenge`] turn out to work. `None` asks the hook
    /// for every challenge.
    pub fn with_credential_store(mut self, store: Option<Arc<dyn CredentialStore>>) -> Self {
        self.credentials = store;
        self
    }

    /// Replaces the callback answering authentication challenges.
    pub fn with_auth_challenge_fn(mut self, hook: AuthChallengeFn) -> Self {
        self.on_auth_challenge = hook;
        self
    }

    /// Attaches the store of cached responses. `None` disables caching.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_cache(mut self, cache: Option<Arc<dyn HttpCache>>) -> Self {
        self.cache = cache;
        self
    }
}

/// Bundled HTTP method, headers, and optional body passed through the fetch stack.
///
/// Using a struct instead of three separate parameters keeps function arities stable as
/// the set of per-request properties grows (e.g. adding trailers, priority hints, etc.).
pub struct RequestInit {
    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, …).
    pub method: Method,
    /// Request headers. The policy's cookie jar and any `Content-Type` derived from the body
    /// are injected before the request is sent.
    pub headers: HeaderMap,
    /// Optional body. `None` for GET/HEAD.
    /// Automatically dropped when a 301, 302, or 303 redirect requires a method downgrade.
    pub body: Option<RequestBody>,
    /// Origin of the document that initiated this request. `None` disables mixed content
    /// checks; see [`mixed_content`](mod@crate::net::mixed_content).
    pub origin: Option<Origin>,
    /// How to treat an insecure hop requested by a secure `origin`. Applied to the initial URL
    /// and re-applied to every redirect target.
    pub mixed_content: MixedContentPolicy,
    /// URL of the initiating document, used to compute `Referer`. `None` sends no referrer.
    pub referrer: Option<Url>,
    /// How much of `referrer` to reveal. Ignored when `referrer` is `None`.
    pub referrer_policy: ReferrerPolicy,
    /// What the resource will be used as, sent in `Sec-Fetch-Dest`.
    /// See [`fetch_metadata`](mod@crate::net::fetch_metadata).
    pub destination: RequestDestination,
    /// The request's mode, sent in `Sec-Fetch-Mode` and selecting the CORS regime.
    /// See [`cors`](mod@crate::net::cors).
    pub mode: RequestMode,
    /// Whether the request stems from a user action. Sends `Sec-Fetch-User: ?1` when the mode
    /// is [`RequestMode::Navigate`]; ignored for other modes.
    pub user_activated: bool,
    /// Whether cookies from the policy's jar ride along, and how strict the credentialed CORS
    /// rules are. See [`RequestCredentials`].
    pub credentials: RequestCredentials,
    /// How this request uses the HTTP cache. Inert without [`NetPolicy::cache`].
    /// See [`cache`](mod@crate::net::cache).
    pub cache_mode: CacheMode,
    /// Whether the HTTP client decompresses the body. A cache entry records it, since a decoded
    /// body is not the bytes a raw caller asked for.
    pub auto_decode: bool,
}

impl Default for RequestInit {
    fn default() -> Self {
        Self::get(HeaderMap::new())
    }
}

impl RequestInit {
    /// Plain GET request with the given headers and no body.
    pub fn get(headers: HeaderMap) -> Self {
        Self::new(Method::GET, headers, None)
    }

    /// POST request with the given headers and body bytes.
    pub fn post(headers: HeaderMap, body: impl Into<Bytes>) -> Self {
        Self::new(Method::POST, headers, Some(RequestBody::bytes(body.into())))
    }

    /// Request with an explicit method, headers, and optional body.
    ///
    /// Mixed content checks are off until an origin is supplied — see
    /// [`with_mixed_content`](Self::with_mixed_content).
    pub fn new(method: Method, headers: HeaderMap, body: Option<RequestBody>) -> Self {
        Self {
            method,
            headers,
            body,
            origin: None,
            mixed_content: MixedContentPolicy::default(),
            referrer: None,
            referrer_policy: ReferrerPolicy::default(),
            destination: RequestDestination::default(),
            mode: RequestMode::default(),
            user_activated: false,
            credentials: RequestCredentials::default(),
            cache_mode: CacheMode::default(),
            auto_decode: true,
        }
    }

    /// Attach the initiating document's URL and the policy controlling how much of it is sent
    /// in the `Referer` header. `None` sends no referrer.
    pub fn with_referrer(mut self, referrer: Option<Url>, policy: ReferrerPolicy) -> Self {
        self.referrer = referrer;
        self.referrer_policy = policy;
        self
    }

    /// Attach the request's destination and mode for the `Sec-Fetch-*` headers, and whether it
    /// stems from a user action (`Sec-Fetch-User`, navigations only).
    /// See [`fetch_metadata`](mod@crate::net::fetch_metadata).
    pub fn with_fetch_metadata(
        mut self,
        destination: RequestDestination,
        mode: RequestMode,
        user_activated: bool,
    ) -> Self {
        self.destination = destination;
        self.mode = mode;
        self.user_activated = user_activated;
        self
    }

    /// Attach the initiating document's origin and the policy to apply to insecure hops.
    ///
    /// With `origin` set to `None` the policy has no effect: mixed content is defined relative
    /// to a document, and without one there is nothing to protect.
    pub fn with_mixed_content(
        mut self,
        origin: Option<Origin>,
        policy: MixedContentPolicy,
    ) -> Self {
        self.origin = origin;
        self.mixed_content = policy;
        self
    }

    /// Attach the request's credentials mode (default: [`RequestCredentials::Include`]).
    pub fn with_credentials(mut self, credentials: RequestCredentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Attach how this request uses the cache, and whether the client decodes the body. The two
    /// together decide which stored responses may answer it.
    /// See [`cache`](mod@crate::net::cache).
    pub fn with_cache(mut self, mode: CacheMode, auto_decode: bool) -> Self {
        self.cache_mode = mode;
        self.auto_decode = auto_decode;
        self
    }
}

/// Peek buffer size (first bytes of body). Used for detecting mime type
const PEEK_MAX: usize = 5 * 1024;
/// Maximum number of redirects allowed
const MAX_REDIRECTS: usize = 20;
/// Ceiling on the body buffer pre-allocation. Content-Length is server-controlled, so we never
/// allocate more than this up front; larger honest bodies grow the buffer as bytes arrive.
const MAX_PREALLOC: usize = 1024 * 1024;

/// The top of a response (HTTP headers + first 5KB of the body, if any), plus a stream
/// for the remainder of the body.
pub struct ResponseTop {
    /// Metadata about the result
    pub meta: FetchResultMeta,
    /// Peek buffer of the first PEEK_MAX of data
    pub peek_buf: PeekBuf,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data)
    #[cfg(not(target_arch = "wasm32"))]
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data).
    /// Not `Send` on wasm32: reqwest's fetch-backed body stream wraps JS types.
    #[cfg(target_arch = "wasm32")]
    pub reader: Box<dyn AsyncRead + Unpin>,
}

/// This function will make a request to a given URL and returns the top of the response. These
/// are most likely the headers and the first 5 KB of body. This can be used to determine mime type
/// of the resource fetched. It will also return a stream reader that is able to read the remainder
/// of the body (minus the peek buffer).
pub async fn fetch_response_top(
    client: Arc<reqwest::Client>,
    url: Url,
    // Method, headers, and optional body for this request.
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ResponseTop, NetError> {
    let result =
        fetch_response_top_inner(client, url.clone(), init, cancel, observer.clone(), policy).await;

    // One terminal event per failed request, whatever went wrong and wherever it went
    // wrong. The events that name a specific cause - `Blocked`, `TlsFailed` - are emitted
    // on the way here and stay; without this an observer would see `Started` and then
    // silence, unable to tell a dead request from a slow one.
    //
    // Cancellation is not a failure and already reported itself as `Cancelled`.
    if let Err(ref e) = result {
        if !matches!(e, NetError::Cancelled(_)) {
            observer.on_event(NetEvent::Failed {
                url,
                error: anyhow::Error::new(e.clone()),
            });
        }
    }

    result
}

/// The body of [`fetch_response_top`], split out so every error exit funnels through the
/// one place that reports the failure.
async fn fetch_response_top_inner(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ResponseTop, NetError> {
    let started = Instant::now();
    observer.on_event(NetEvent::Started { url: url.clone() });

    // Bind this request's observer for the duration of the HTTP exchange. Work that
    // happens below the request layer - DNS resolution inside the connection pool - has no
    // other way to reach it.
    let outcome = crate::net::observer::CURRENT_OBSERVER
        .scope(
            observer.clone(),
            get_with_redirects(
                client.clone(),
                url.clone(),
                init,
                cancel.clone(),
                observer.clone(),
                policy,
            ),
        )
        .await?;
    let ChainOutcome {
        response,
        url: final_url,
        tainting,
        #[cfg(not(target_arch = "wasm32"))]
        store,
    } = outcome;

    // A stored response has no stream to read: the body is already here, so it is split into the
    // peek window and a reader over the remainder, and handed back in the same shape as a
    // response off the wire.
    let resp = match response {
        HopResponse::Cached(entry) => {
            let peek_len = entry.body.len().min(PEEK_MAX);
            let meta = FetchResultMeta {
                tainting,
                final_url: final_url.clone(),
                status: entry.status,
                status_text: http::StatusCode::from_u16(entry.status)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .unwrap_or("")
                    .to_string(),
                headers: entry.headers.clone(),
                content_length: Some(entry.body.len() as u64),
                content_type: entry
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                has_body: !entry.body.is_empty(),
                from_cache: true,
            };
            let rest = BytesAsyncReader {
                data: entry.body.slice(peek_len..),
                pos: 0,
            };
            let reader = ProgressReader::new(
                rest,
                cancel.clone(),
                observer.clone(),
                final_url,
                started,
                meta.content_length,
                peek_len as u64,
            );
            // A cache hit reports a preview too. No tee here: the entry is already whole in
            // memory, so it is cut to the budget directly.
            if let Some(limit) = observer.body_capture_limit(&meta.headers, meta.content_length) {
                let take = entry.body.len().min(limit);
                observer.on_event(NetEvent::BodyPreview {
                    url: meta.final_url.clone(),
                    body: entry.body[..take].to_vec(),
                    truncated: take < entry.body.len(),
                });
            }

            return Ok(ResponseTop {
                meta,
                peek_buf: PeekBuf::from_vec(entry.body[..peek_len].to_vec()),
                reader: Box::new(reader),
            });
        }
        HopResponse::Network(resp) => resp,
    };

    // Response is received, setup our meta structure
    let mut meta = FetchResultMeta {
        tainting,
        final_url,
        status: resp.status().as_u16(),
        status_text: resp.status().canonical_reason().unwrap_or("").to_string(),
        headers: resp.headers().clone(),
        content_length: resp.content_length(), // More often than not, this is None
        content_type: resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        has_body: true, // Don't know yet
        from_cache: false,
    };

    // Peek the stream up to PEEK_MAX bytes
    let mut body_stream = resp
        .bytes_stream()
        .map_err(|e| NetError::Read(Arc::new(anyhow!(e))));
    let mut received_net: u64 = 0;
    let mut peek_buf_vec: Vec<u8> = Vec::with_capacity(PEEK_MAX);
    let mut excess: Option<Bytes> = None;

    let observer_clone = observer.clone();

    // We might need more fetches than one. Although it's unlikely unless you set PEEK_MAX to >8KB
    while peek_buf_vec.len() < PEEK_MAX {
        let next = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                observer_clone.on_event(NetEvent::Cancelled { url: url.clone(), reason: "peek stream cancelled" });
                return Err(NetError::Cancelled("peek stream cancelled".into()));
            }
            // Read bytes from stream
            n = body_stream.next() => n,
        };

        match next {
            // We received a chunk of data
            Some(Ok(chunk)) => {
                received_net += chunk.len() as u64;

                observer.on_event(NetEvent::Progress {
                    received_bytes: received_net,
                    elapsed: started.elapsed(),
                    expected_length: meta.content_length,
                });

                let need = PEEK_MAX.saturating_sub(peek_buf_vec.len());
                if chunk.len() <= need {
                    // Entire chunk fits in our peek_buf.
                    peek_buf_vec.extend_from_slice(&chunk);
                } else {
                    // Chunk does not fit. For instance: Peek Buf = 12Kb. We read 8Kb in the first
                    // read, and 8kb in the second. In this case we have read 16kb when we only need
                    // the first 12kb. We fill the peek buf until full, and keep the rest in the
                    // 'excess' buffer
                    peek_buf_vec.extend_from_slice(&chunk[..need]);
                    excess = Some(chunk.slice(need..));
                    break;
                }
            }
            Some(Err(e)) => {
                // Reported by the caller, along with every other failure path. The error
                // is returned as it came rather than flattened into a generic one, so what
                // reaches the observer still names the cause.
                return Err(e);
            }
            None => {
                // Stream ended successfully
                break;
            }
        }
    }

    // Save the length before we store the excess into a body stream
    let excess_len = excess.as_ref().map(|b| b.len() as u64).unwrap_or(0);

    // It's possible that we have read too much, and we have an exccess buffer, so we create
    // a new stream that starts at the end of the peek buffer WITH the excess buffer in front.
    //
    //  |--- Peek buffer ---|---- Excess buffer ----| ---- body stream ----|
    //                                              ^ stream starts here
    //                      ^  new body stream "rereads" the excess buffer and starts here
    // boxed() demands a `Send` stream; reqwest's wasm body stream is `!Send` (single thread).
    #[cfg(not(target_arch = "wasm32"))]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed()
    } else {
        body_stream.boxed()
    };
    #[cfg(target_arch = "wasm32")]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed_local()
    } else {
        body_stream.boxed_local()
    };

    // Capture only when the observer asked for one, up to the limit it gave. It sees the
    // headers first, so an oversized or unwanted response is refused before anything is
    // copied.
    //
    // The peek window is handed over separately and read first, so it is seeded into the
    // capture as the body's opening bytes; the wrapper copies the remainder as the consumer
    // pulls it.
    #[cfg(not(target_arch = "wasm32"))]
    let body_stream = match observer.body_capture_limit(&meta.headers, meta.content_length) {
        Some(limit) => crate::net::body_capture::CapturingBody::new(
            body_stream,
            observer.clone(),
            meta.final_url.clone(),
            limit,
            &peek_buf_vec,
        )
        .boxed(),
        None => body_stream,
    };
    #[cfg(target_arch = "wasm32")]
    let body_stream = match observer.body_capture_limit(&meta.headers, meta.content_length) {
        Some(limit) => crate::net::body_capture::CapturingBody::new(
            body_stream,
            observer.clone(),
            meta.final_url.clone(),
            limit,
            &peek_buf_vec,
        )
        .boxed_local(),
        None => body_stream,
    };

    // Update last remaining items in meta struct
    let peek_buf = PeekBuf::from_vec(peek_buf_vec);
    let has_body_by_len = meta.content_length.unwrap_or(0) > 0 || !peek_buf.is_empty();
    meta.has_body = has_body_by_len;

    // Wrap our body stream into a progress reader. This way it will emit net events to the observer
    // whenever it is read.
    let stream = body_stream.map_err(|e: NetError| e.to_io());
    let inner_reader = StreamReader::new(stream);

    // Update the progress counter to the point of the bytes read (note: this can cause a strange
    // decrease in bytes read in the progress events?)
    let already_delivered = received_net - excess_len;

    let progress_reader = ProgressReader::new(
        inner_reader,
        cancel.clone(),
        observer.clone(),
        url.clone(),
        started,
        meta.content_length,
        already_delivered,
    );
    // A response the cache accepted is copied as the caller reads it, and written when the body
    // is complete. A body already known to be too large is not collected at all.
    #[cfg(not(target_arch = "wasm32"))]
    let progress_reader = progress_reader.with_cache(store.and_then(|store| {
        let too_large = meta
            .content_length
            .is_some_and(|len| len as usize > store.max_bytes());
        (!too_large).then(|| CacheCollector::new(store, peek_buf.as_slice()))
    }));

    Ok(ResponseTop {
        meta,
        peek_buf,
        reader: Box::new(progress_reader),
    })
}

/// Copies a body on its way to the caller so it can be written to the cache when the stream ends.
///
/// Only a complete body is stored. A fetch that is cancelled, fails, or is dropped mid-stream
/// drops the collector instead, and one that grows past the cache's ceiling drops the pending
/// write and stops copying.
#[cfg(not(target_arch = "wasm32"))]
struct CacheCollector {
    /// The write to perform on EOF. Taken away when the body turns out to be too large.
    store: Option<PendingStore>,
    /// Body bytes so far, starting with the peek window the caller already read.
    body: BytesMut,
    /// Ceiling from [`HttpCache::max_entry_bytes`].
    limit: usize,
}

#[cfg(not(target_arch = "wasm32"))]
impl CacheCollector {
    /// Collector for `store`, seeded with the bytes read before the reader was built.
    fn new(store: PendingStore, prefix: &[u8]) -> Self {
        let limit = store.max_bytes();
        let mut body = BytesMut::with_capacity(prefix.len());
        body.extend_from_slice(prefix);
        let mut collector = Self {
            store: Some(store),
            body,
            limit,
        };
        collector.enforce_limit();
        collector
    }

    /// Record bytes handed to the caller.
    fn feed(&mut self, chunk: &[u8]) {
        if self.store.is_none() {
            return;
        }
        self.body.extend_from_slice(chunk);
        self.enforce_limit();
    }

    /// Give up on a body the cache would refuse anyway, and stop holding it in memory.
    fn enforce_limit(&mut self) {
        if self.body.len() > self.limit {
            self.store = None;
            self.body = BytesMut::new();
        }
    }

    /// Write the complete body to the cache.
    fn commit(&mut self, observer: &Arc<dyn NetObserver + Send + Sync>) {
        if let Some(store) = self.store.take() {
            store.commit(std::mem::take(&mut self.body).freeze(), observer);
        }
    }
}

/// Progres reader is a simple stream that will wrap another AsyncRead stream, and emit progress
/// events to the observer.
struct ProgressReader<R> {
    /// Actual reader
    inner: R,
    /// Cancellation token
    cancel: CancellationToken,
    // Observer to emit events to
    observer: Arc<dyn NetObserver + Send + Sync>,
    /// Url we are reading from. For event emission
    url: Url,
    /// When we started reading, since we already read the peek buffer from this stream
    started: Instant,
    /// Expected length of the resource, if known
    expected_length: Option<u64>,
    /// Number of bytes already received (from the peek buffer)
    received: u64,
    /// When the body last actually moved. A reader can sit unread for a long time before it
    /// is dropped, and reporting `started.elapsed()` then would describe the wait rather than
    /// the transfer.
    last_activity: Instant,
    /// Whether we already emitted a cancelled event
    cancel_emitted: bool,
    /// Whether we already emitted a finished event (guards against duplicate EOF polls)
    finished_emitted: bool,
    /// Whether we already emitted a failed event (a reader may be polled again after an error)
    failed_emitted: bool,
    /// Copies the body for the HTTP cache, when this response is one that may be stored.
    #[cfg(not(target_arch = "wasm32"))]
    cache: Option<CacheCollector>,
}

impl<R: AsyncRead + Unpin> ProgressReader<R> {
    fn new(
        inner: R,
        cancel: CancellationToken,
        observer: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        started: Instant,
        expected_length: Option<u64>,
        already_received: u64,
    ) -> Self {
        Self {
            inner,
            cancel,
            observer,
            url,
            started,
            expected_length,
            received: already_received,
            last_activity: Instant::now(),
            cancel_emitted: false,
            finished_emitted: false,
            failed_emitted: false,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
        }
    }

    /// Collect the body for the HTTP cache as it is read.
    #[cfg(not(target_arch = "wasm32"))]
    fn with_cache(mut self, collector: Option<CacheCollector>) -> Self {
        self.cache = collector;
        self
    }
}

impl<R> Drop for ProgressReader<R> {
    /// Report the end of a request whose reader is dropped without reaching end-of-stream.
    ///
    /// `Finished` is otherwise only emitted from a read that returns zero bytes, so a
    /// consumer that takes what it needs and drops the reader would end the request with no
    /// terminal event at all -- breaking this module's contract that every request reports
    /// exactly one of `Finished`, `Failed` or `Cancelled`, and leaving an observer with a
    /// request that never comes back.
    ///
    /// Which event depends on whether the body actually arrived. A consumer whose response
    /// fit in the peek window has the whole thing and is genuinely finished; one that
    /// abandoned a partly-read body is not, and saying `Finished` there would report a
    /// transfer that did not happen. Without a declared length there is no way to tell, so
    /// it is treated as abandoned rather than guessed complete.
    ///
    /// The elapsed time is measured to the last read that moved bytes, not to the drop. A
    /// reader can sit untouched for a long time before its owner lets go -- fifteen seconds
    /// is routine -- and `started.elapsed()` would report that wait as the transfer time,
    /// which is a plausible number and a false one.
    fn drop(&mut self) {
        if self.finished_emitted || self.cancel_emitted || self.failed_emitted {
            return;
        }
        let complete = self
            .expected_length
            .is_some_and(|expected| self.received >= expected);
        if complete {
            self.observer.on_event(NetEvent::Finished {
                received_bytes: self.received,
                elapsed: self.last_activity.saturating_duration_since(self.started),
                url: self.url.clone(),
            });
        } else {
            self.observer.on_event(NetEvent::Cancelled {
                url: self.url.clone(),
                reason: "body reader dropped before end of stream",
            });
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // When cancelled, we are directly done
        if self.cancel.is_cancelled() {
            // Maybe it's already cancelled? Then don't send another cancelled event
            if !self.cancel_emitted {
                self.observer.on_event(NetEvent::Cancelled {
                    url: self.url.clone(),
                    reason: "progress reader cancelled",
                });
                self.cancel_emitted = true;
            }

            let err = NetError::Cancelled("progress reader cancelled".into());
            return std::task::Poll::Ready(Err(err.to_io()));
        }

        // Pull new bytes from the reader
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let std::task::Poll::Ready(Ok(())) = &poll {
            let new_len = buf.filled().len();
            let read_bytes = (new_len - pre_len) as u64;

            // nothing read, then we have reached the end of the stream
            if read_bytes == 0 && !self.finished_emitted {
                self.finished_emitted = true;
                // The body is complete, so a response waiting to be cached can be written.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let observer = self.observer.clone();
                    if let Some(collector) = self.cache.as_mut() {
                        collector.commit(&observer);
                    }
                }
                self.observer.on_event(NetEvent::Finished {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    url: self.url.clone(),
                });
            }
            if read_bytes > 0 {
                self.last_activity = Instant::now();
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(collector) = self.cache.as_mut() {
                    let filled = buf.filled();
                    collector.feed(&filled[pre_len..new_len]);
                }
                self.received += read_bytes;
                self.observer.on_event(NetEvent::Progress {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    expected_length: self.expected_length,
                });
            }
        }

        // A body that dies mid-stream is past the point where `fetch_response_top` can
        // report it - the caller already has this reader - so the terminal event is emitted
        // here instead. Errors are reported once: a reader may be polled again afterwards.
        if let std::task::Poll::Ready(Err(e)) = &poll {
            if !self.failed_emitted && !self.cancel.is_cancelled() {
                self.failed_emitted = true;
                self.observer.on_event(NetEvent::Failed {
                    url: self.url.clone(),
                    error: anyhow!("body read failed: {e}"),
                });
            }
        }

        poll
    }
}

/// Spare capacity kept available for each `read_buf` so it never returns 0 for lack of room
/// (which the loop would misread as EOF).
const READ_CHUNK: usize = 16 * 1024;

/// Fetch a complete resource, returning the metadata and the full body as `Bytes`.
///
/// The body is assembled with a single copy per chunk: bytes are read straight from the
/// underlying stream into a pre-sized [`BytesMut`] (sized from `Content-Length` when known) and
/// then `freeze`d into an `Arc`-backed [`Bytes`]. Handing the result to the caller — and the
/// `Bytes::from`/`freeze` at the boundary — is zero-copy, so the only memcpy of the payload is the
/// unavoidable assembly into one contiguous buffer.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_response_complete(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    // We can cap the amount of bytes we want to read (None for unlimited)
    max_bytes: Option<usize>,
    // Maximum time allowed between reads
    read_idle_timeout: Duration,
    // Total time of read allowed (if any)
    total_body_timeout: Option<Duration>,
    policy: NetPolicy,
) -> Result<(FetchResultMeta, Bytes), NetError> {
    let started = Instant::now();

    let ResponseTop {
        meta,
        peek_buf,
        mut reader,
    } = fetch_response_top(client, url, init, cancel.clone(), observer.clone(), policy).await?;

    // Reject responses that already declare a body larger than max_bytes, before reading any of it.
    // The in-loop check below remains the backstop for servers that lie or use chunked encoding.
    if let (Some(max), Some(len)) = (max_bytes, meta.content_length) {
        if len as usize > max {
            return Err(NetError::Read(Arc::new(anyhow!(
                "content-length {} exceeds maximum size of {} bytes",
                len,
                max
            ))));
        }
    }

    // Pre-size from Content-Length when known to avoid reallocations as the body grows; otherwise
    // start from the peek length. The peek bytes have already been read off the stream, so seed the
    // buffer with them (a one-off copy of the small peek region, not the whole body). Content-Length
    // is untrusted, so the pre-allocation is clamped to MAX_PREALLOC (and max_bytes when set).
    let advertised = meta.content_length.map(|n| n as usize).unwrap_or(0);
    let ceiling = max_bytes.unwrap_or(MAX_PREALLOC).min(MAX_PREALLOC);
    let initial_cap = advertised.min(ceiling).max(peek_buf.len());
    let mut body_buf = BytesMut::with_capacity(initial_cap);
    body_buf.extend_from_slice(peek_buf.as_slice());

    loop {
        // Check if we hit the total body timeout
        if let Some(total) = total_body_timeout {
            if started.elapsed() > total {
                return Err(NetError::Timeout("total body timeout".into()));
            }
        }

        // Ensure there is spare capacity so `read_buf` reads directly into the buffer (single copy
        // from the stream) rather than returning 0 for lack of room.
        if body_buf.capacity() - body_buf.len() < READ_CHUNK {
            body_buf.reserve(READ_CHUNK);
        }

        let n = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                return Err(NetError::Cancelled("fetch_request_complete cancelled".into()));
            }
            // Read bytes, or timeout when not read something in time. `read_buf` reads directly into
            // the spare capacity of `body_buf`, so there is no intermediate scratch buffer.
            r = timeout(read_idle_timeout, reader.read_buf(&mut body_buf)) => {
                match r {
                    Err(_) => return Err(NetError::Timeout("fetch_request_complete timeout".into())),
                    Ok(Err(e)) => return Err(NetError::Io(Arc::new(e))),
                    Ok(Ok(n)) => n,
                }
            }
        };

        if n == 0 {
            // Stream ended normally
            break;
        }

        if let Some(max) = max_bytes {
            // Too many bytes are read. We throw an error (@TODO: should we do this? not just cap
            // the buffer and return that?
            if body_buf.len() > max {
                return Err(NetError::Read(Arc::new(anyhow!(
                    "fetch_request_complete exceeded maximum size of {} bytes",
                    max
                ))));
            }
        }
    }

    // `freeze` converts the `BytesMut` into an `Arc`-backed `Bytes` without copying.
    Ok((meta, body_buf.freeze()))
}

/// Map a failed `send()` to a `NetError`: TLS handshake failures become `NetError::Tls` (plus a
/// `NetEvent::TlsFailed`), everything else is wrapped in `Read` as before.
fn send_error(
    e: reqwest::Error,
    url: &Url,
    what: &str,
    observer: &Arc<dyn NetObserver + Send + Sync>,
) -> NetError {
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(tls) = crate::net::tls::classify(&e, url) {
        observer.on_event(NetEvent::TlsFailed {
            url: url.clone(),
            error: tls.clone(),
        });
        return NetError::Tls(tls);
    }
    #[cfg(target_arch = "wasm32")]
    let _ = (url, observer);
    NetError::Read(Arc::new(anyhow::Error::from(e).context(what.to_string())))
}

/// A hop's response: what the server sent, or what the cache had.
///
/// A stored response is not a `reqwest::Response` and cannot be made into one, so the redirect
/// loop and its consumers read both through this.
pub(crate) enum HopResponse {
    /// A response from the network.
    Network(reqwest::Response),
    /// A stored response, used as it was or confirmed by a `304`.
    Cached(Arc<CacheEntry>),
}

impl HopResponse {
    /// Status code of the response.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Network(resp) => resp.status().as_u16(),
            Self::Cached(entry) => entry.status,
        }
    }

    /// Response headers. A stored response carries the headers as they were stored: without
    /// `Set-Cookie`, and with the `304`'s updates already merged in.
    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Self::Network(resp) => resp.headers(),
            Self::Cached(entry) => &entry.headers,
        }
    }

    /// Whether this is a redirect the chain should follow.
    pub(crate) fn is_redirection(&self) -> bool {
        (300..400).contains(&self.status())
    }
}

/// A storable response whose body has not been read yet.
///
/// `get_with_redirects` decides whether a response may be cached from its headers, but the body
/// only arrives later, in whichever consumer reads it. This carries that decision until then;
/// dropping it (a cancelled fetch, a body over the cache's ceiling) stores nothing.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct PendingStore {
    cache: Arc<dyn HttpCache>,
    key: CacheKey,
    url: Url,
    status: u16,
    response_headers: HeaderMap,
    request_headers: HeaderMap,
    decoded: bool,
    requested_at: chrono::DateTime<chrono::Utc>,
    received_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PendingStore {
    /// Largest body the cache behind this will accept.
    pub(crate) fn max_bytes(&self) -> usize {
        self.cache.max_entry_bytes()
    }

    /// Write the response to the cache now that its body is complete.
    pub(crate) fn commit(self, body: Bytes, observer: &Arc<dyn NetObserver + Send + Sync>) {
        let entry = cache::entry_from_response(
            self.status,
            &self.response_headers,
            &self.request_headers,
            body,
            self.decoded,
            self.requested_at,
            self.received_at,
        );
        self.cache.put(self.key, Arc::new(entry));
        observer.on_event(NetEvent::Cache {
            url: self.url,
            outcome: CacheOutcome::Stored,
        });
    }
}

/// What a whole redirect chain came to.
pub(crate) struct ChainOutcome {
    /// The first response that was not a redirect.
    pub(crate) response: HopResponse,
    /// URL of the hop that produced it, i.e. the final URL of the chain.
    pub(crate) url: Url,
    /// Response tainting of the chain — see [`cors`](mod@crate::net::cors).
    pub(crate) tainting: ResponseTainting,
    /// Set when that response may be cached once its body has been read.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) store: Option<PendingStore>,
}

/// Find credentials for the first challenge that has any: the credential store first, then the
/// embedder's hook, walking the challenges in the order the server listed them.
///
/// Returns the protection space they belong to, so they can be stored or dropped depending on
/// what the server makes of them, the credentials, and the value for the credentials header.
fn credentials_for_challenges(
    policy: &NetPolicy,
    challenges: &[AuthChallenge],
) -> Option<(ProtectionSpace, Credentials, header::HeaderValue)> {
    for challenge in challenges {
        let space = challenge.protection_space();
        let known = policy
            .credentials
            .as_ref()
            .and_then(|store| store.credentials_for(&space));
        let credentials = match known.or_else(|| (policy.on_auth_challenge)(challenge)) {
            Some(credentials) => credentials,
            None => continue,
        };
        // Credentials that cannot be expressed as a header value are not an answer; try the next
        // challenge instead of re-sending the request unchanged.
        if let Some(value) = credentials.header_value() {
            return Some((space, credentials, value));
        }
    }
    None
}

/// Perform a GET request, following redirects up to MAX_REDIRECTS times, while sending out net events.
///
/// Follow a chain of HTTP redirects, returning the first non-redirect response.
///
/// - `init.method` and `init.body` are preserved on 307/308; downgraded to GET (body dropped)
///   on 301/302/303, matching browser behaviour (RFC 7231 §6.4).
/// - `Authorization` and `Cookie` are stripped on cross-origin redirects (RFC 9110 §15.4);
///   the cookie jar is re-queried for the new origin.
/// - Only `http` and `https` targets are followed; other schemes are rejected.
/// - Insecure hops requested by a secure `init.origin` are blocked or upgraded per
///   `init.mixed_content`, re-evaluated at every hop so a redirect cannot escape the check.
/// - `Referer` is recomputed from `init.referrer` and `init.referrer_policy` at every hop, since
///   the same-origin and downgrade determinations change as the chain moves. A `Referrer-Policy`
///   header on a 3xx response replaces the policy for the remaining hops.
/// - `Origin` and the `Sec-Fetch-*` headers are likewise recomputed at every hop from
///   `init.origin`, `init.destination`, and `init.mode`. `Sec-Fetch-Site` only degrades across
///   the chain, and `Origin` collapses to `null` once the chain redirects away from an origin
///   the request had already left — see [`fetch_metadata`](mod@crate::net::fetch_metadata).
/// - `policy.url_allowed` and `policy.cookies_for` are called at every hop.
/// - A `401`/`407` hop is re-sent with credentials from the credential store or
///   `policy.on_auth_challenge` (see [`auth`](mod@crate::net::auth)); only a response that is
///   not a challenge continues through the chain.
/// - `Set-Cookie` values on 3xx responses are reported via `policy.on_cookies` and the jar is
///   re-queried for the next hop; the final response's cookies are the caller's responsibility.
/// - CORS is enforced per hop when `init.origin` is set — the same-origin/no-cors mode rules
///   before sending, a preflight (with `policy.cors_preflight` as its cache) when the method or
///   headers need one, and the CORS check on every response of a cors-tainted chain. The chain's
///   final [`ResponseTainting`] is returned beside the response — see
///   [`cors`](mod@crate::net::cors).
async fn get_with_redirects(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ChainOutcome, NetError> {
    let mut url = url;
    let mut current_method = init.method;
    let mut current_headers = init.headers;
    let mut current_body = init.body;
    let origin = init.origin;
    // A redirect may replace this for the remaining hops (Fetch, HTTP-redirect fetch).
    let mut referrer_policy = init.referrer_policy;
    // `Sec-Fetch-Site` describes the whole chain, not the current hop: it starts at same-origin
    // and can only degrade, so a detour through a foreign site is still visible when the chain
    // lands back home.
    let mut site = SecFetchSite::SameOrigin;
    // The tainted origin flag (Fetch, HTTP-redirect fetch): once set, `Origin` is sent as the
    // literal `null` for every remaining hop.
    let mut origin_tainted = false;
    // Response tainting (Fetch §2.2.5): basic until the chain leaves the initiating origin,
    // then cors/opaque per the request mode — and it stays there even if a detour redirects
    // back home, which is why the CORS check below keys on this and not on the hop's URL.
    let mut tainting = ResponseTainting::Basic;
    // The credentialed CORS rules key on the request's credentials *mode*, not on whether
    // cookies were actually attached on a given hop. Only the native checks consult it — on
    // wasm32 the browser enforces the credentialed rules itself.
    #[cfg(not(target_arch = "wasm32"))]
    let credentials_include = init.credentials == RequestCredentials::Include;

    for _ in 0..MAX_REDIRECTS {
        // HSTS upgrade first: a stored policy forces `https` for a known host regardless of the
        // mixed-content setting. `hop_checks` then re-checks the scheme and mixed content on the
        // (possibly upgraded) URL and runs `url_allowed` last, so the policy hook always vets the
        // URL actually sent. All of this re-runs on every hop: an https document may be redirected
        // onto plain http, which the caller cannot see and so cannot check for itself.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = policy.hsts {
            if hsts::should_upgrade(store.as_ref(), &url, chrono::Utc::now()) {
                url = hsts::upgrade(&url);
            }
        }

        match hop_checks(&url, init.mixed_content, origin.as_ref(), &|u| {
            (policy.url_allowed)(u)
        }) {
            HopCheck::Reject(reason) => return Err(blocked(&observer, url, reason)),
            HopCheck::Proceed(target) => {
                if target != url {
                    observer.on_event(NetEvent::Warning {
                        url: url.clone(),
                        message: format!("upgraded insecure request to {target}"),
                    });
                    url = target;
                }
            }
        }

        // CORS regime for this hop (Fetch, main fetch). Only a request with a document context
        // is subject to it, and only once the chain has left the initiating origin — a tainted
        // chain counts as having left even when a detour lands back home. Navigations are not
        // CORS-checked, and a WebSocket server opts in via its own handshake instead.
        if let Some(ref o) = origin {
            let has_left_origin = origin_tainted || *o != url.origin();
            if has_left_origin {
                match init.mode {
                    RequestMode::SameOrigin => {
                        return Err(blocked(
                            &observer,
                            url,
                            BlockReason::Cors(CorsError::SameOriginMode),
                        ));
                    }
                    // A no-cors request may go cross-origin, but only in the shape markup can
                    // produce: safelisted method, no headers the fetcher does not own. The
                    // response becomes opaque.
                    RequestMode::NoCors => {
                        tainting = ResponseTainting::Opaque;
                        if !cors::is_cors_safelisted_method(&current_method) {
                            return Err(blocked(
                                &observer,
                                url,
                                BlockReason::Cors(CorsError::UnsafeMethodForNoCors),
                            ));
                        }
                        if !cors::unsafe_request_header_names(&current_headers).is_empty() {
                            return Err(blocked(
                                &observer,
                                url,
                                BlockReason::Cors(CorsError::UnsafeHeaderForNoCors),
                            ));
                        }
                    }
                    RequestMode::Cors => tainting = ResponseTainting::Cors,
                    RequestMode::Navigate | RequestMode::Websocket => {}
                }
            }
        }

        // Recomputed per hop; see the note on this function.
        if let Some(ref source) = init.referrer {
            match referrer::determine(source, referrer_policy, &url) {
                Some(value) => match value.as_str().parse() {
                    Ok(header_value) => {
                        current_headers.insert(header::REFERER, header_value);
                    }
                    // A URL that will not go into a header is not worth failing the request over.
                    Err(_) => {
                        current_headers.remove(header::REFERER);
                    }
                },
                // Drop any value from an earlier hop: this one is not allowed a referrer.
                None => {
                    current_headers.remove(header::REFERER);
                }
            }
        }

        // Origin and Sec-Fetch-* are likewise recomputed per hop.
        let hop_site = match origin {
            Some(ref o) => {
                site = site.min(fetch_metadata::classify_site(o, &url));
                site
            }
            // No initiating origin means the request was not triggered by web content.
            None => SecFetchSite::None,
        };
        fetch_metadata::apply_sec_fetch_headers(
            &mut current_headers,
            &url,
            init.destination,
            init.mode,
            hop_site,
            init.user_activated,
        );

        // Without an initiating origin there is nothing to compute; a hand-set `Origin`
        // header then goes out verbatim, like a hand-set `Referer`.
        if let Some(ref o) = origin {
            match fetch_metadata::origin_header_value(
                o,
                origin_tainted,
                &current_method,
                init.mode,
                referrer_policy,
                &url,
            )
            .and_then(|v| v.parse().ok())
            {
                Some(value) => {
                    current_headers.insert(header::ORIGIN, value);
                }
                None => {
                    current_headers.remove(header::ORIGIN);
                }
            }
        }

        // CORS preflight (Fetch §4.9): a cross-origin cors-mode request whose method or headers
        // markup could not produce must be approved by the server before it is sent. Running
        // this per hop is what modern browsers do after a redirect moves the target — the
        // grant is per (origin, URL), so a new URL needs its own, usually served from the
        // cache. The OPTIONS goes out credential-less and never follows redirects (the client
        // has redirects disabled; a 3xx fails the ok-status test).
        //
        // Native-only: on wasm32 the browser preflights itself and does not surface the
        // `Access-Control-*` response headers this validation would need.
        #[cfg(not(target_arch = "wasm32"))]
        if init.mode == RequestMode::Cors && tainting == ResponseTainting::Cors {
            if let Some(ref o) = origin {
                let unsafe_names = cors::unsafe_request_header_names(&current_headers);
                if !cors::is_cors_safelisted_method(&current_method) || !unsafe_names.is_empty() {
                    let serialized = cors::serialize_origin(o, origin_tainted);
                    let now = chrono::Utc::now();
                    let granted = policy
                        .cors_preflight
                        .as_ref()
                        .and_then(|c| c.get(&serialized, &url, credentials_include, now))
                        .is_some_and(|allows| {
                            allows
                                .permits(&current_method, &unsafe_names, credentials_include)
                                .is_ok()
                        });
                    if !granted {
                        let mut pf_headers =
                            cors::preflight_request_headers(&current_method, &unsafe_names);
                        if let Ok(v) = serialized.parse() {
                            pf_headers.insert(header::ORIGIN, v);
                        }
                        fetch_metadata::apply_sec_fetch_headers(
                            &mut pf_headers,
                            &url,
                            init.destination,
                            init.mode,
                            hop_site,
                            false,
                        );
                        observer.on_event(NetEvent::CorsPreflight { url: url.clone() });
                        let pf_started = Instant::now();
                        let fut = client
                            .request(Method::OPTIONS, url.clone())
                            .headers(pf_headers)
                            .send();
                        tokio::pin!(fut);
                        let pf_resp = tokio::select! {
                            _ = cancel.cancelled() => {
                                observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "cancelled during CORS preflight" });
                                return Err(NetError::Cancelled("cancelled during CORS preflight".into()));
                            }
                            r = &mut fut => r.map_err(|e| send_error(e, &url, "CORS preflight request failed", &observer))?
                        };
                        // Reported before validation: a preflight the server answered cost
                        // this round-trip whether or not the answer turns out to permit the
                        // request. A rejection is separately reported as `Blocked`.
                        observer.on_event(NetEvent::CorsPreflightDone {
                            url: url.clone(),
                            elapsed: pf_started.elapsed(),
                        });
                        let allows = cors::validate_preflight_response(
                            pf_resp.status().as_u16(),
                            pf_resp.headers(),
                            o,
                            origin_tainted,
                            credentials_include,
                        )
                        .and_then(|allows| {
                            allows
                                .permits(&current_method, &unsafe_names, credentials_include)
                                .map(|()| allows)
                        })
                        .map_err(|e| blocked(&observer, url.clone(), BlockReason::Cors(e)))?;
                        if let Some(cache) = policy.cors_preflight.as_ref() {
                            cache.put(&serialized, &url, credentials_include, allows, now);
                        }
                    }
                }
            }
        }

        // Cookies from the jar and an answer to an authentication challenge are both
        // credentials, so the request's credentials mode gates them together.
        // Cookies are only injected when no Cookie header is already set; this naturally handles
        // cross-origin redirects: the cookie was stripped above, so the jar is re-queried for the
        // new origin.
        let attach_credentials = match init.credentials {
            RequestCredentials::Include => true,
            RequestCredentials::Omit => false,
            // Without a document origin to compare against, "same-origin" has no meaning and
            // the request is first-party tooling; it keeps its cookies.
            RequestCredentials::SameOrigin => origin
                .as_ref()
                .is_none_or(|o| !origin_tainted && *o == url.origin()),
        };
        if attach_credentials && !current_headers.contains_key(header::COOKIE) {
            if let Some(cookie_str) = (policy.cookies_for)(&url) {
                if let Ok(val) = cookie_str.parse() {
                    current_headers.insert(header::COOKIE, val);
                }
            }
        }

        // The HTTP cache (RFC 9111), consulted per hop with the headers this hop will actually
        // send, so `Vary` selects on the cookies and the negotiation headers as sent. A fresh
        // stored response ends the hop without a request; a stale one that can be revalidated
        // adds its conditional headers to the send below. See [`cache`](mod@crate::net::cache).
        #[cfg(not(target_arch = "wasm32"))]
        let (cache_hit, revalidating, conditional) = match policy.cache {
            Some(ref cache) => {
                let key = CacheKey::new(&current_method, &url);
                let stored = cache.get(&key);
                match cache::decide(
                    &stored,
                    &current_headers,
                    init.auto_decode,
                    init.cache_mode,
                    chrono::Utc::now(),
                ) {
                    CacheDecision::Use(entry) => (Some(entry), None, HeaderMap::new()),
                    CacheDecision::Revalidate(entry, conditional) => {
                        (None, Some(entry), conditional)
                    }
                    CacheDecision::Send => (None, None, HeaderMap::new()),
                    // `only-if-cached`, with nothing stored to answer it.
                    CacheDecision::NotCached => {
                        return Err(blocked(&observer, url, BlockReason::NotCached))
                    }
                }
            }
            None => (None, None, HeaderMap::new()),
        };
        // No cache on wasm32, so every hop goes out as it is.
        #[cfg(target_arch = "wasm32")]
        let (cache_hit, conditional): (Option<Arc<CacheEntry>>, HeaderMap) =
            (None, HeaderMap::new());

        // Authentication (RFC 9110 §11): a 401 or 407 is re-sent with credentials whenever they
        // can be found for one of its challenges, at most `MAX_AUTH_ATTEMPTS` times. Only a
        // response that is not a challenge leaves this loop. See
        // [`auth`](mod@crate::net::auth).
        let mut auth_header: Option<(header::HeaderName, header::HeaderValue)> = None;
        let mut auth_attempt = 0u32;
        // Credentials the server has not accepted yet. Stored once a response arrives that is
        // not another challenge, dropped when it is.
        let mut unproven: Option<(ProtectionSpace, Credentials)> = None;

        // Timestamps of the exchange that produced the response below, for the age of a cache
        // entry made from it (RFC 9111 §4.2.3). A retried hop overwrites them, so they always
        // describe the send that was kept.
        #[cfg(not(target_arch = "wasm32"))]
        let mut requested_at = chrono::Utc::now();
        #[cfg(not(target_arch = "wasm32"))]
        let mut received_at = requested_at;

        let hop = match cache_hit {
            Some(entry) => {
                observer.on_event(NetEvent::Cache {
                    url: url.clone(),
                    outcome: CacheOutcome::Hit,
                });
                HopResponse::Cached(entry)
            }
            None => loop {
                // The credentials and conditional headers are added for the send only, so a redirect
                // from this hop starts from the caller's headers again.
                let mut hop_headers = current_headers.clone();
                if let Some((ref name, ref value)) = auth_header {
                    hop_headers.insert(name.clone(), value.clone());
                }
                for (name, value) in conditional.iter() {
                    hop_headers.insert(name.clone(), value.clone());
                }
                let mut req_builder = client
                    .request(current_method.clone(), url.clone())
                    .headers(hop_headers);
                if let Some(ref body) = current_body {
                    // Built fresh per send so a streamed body can be replayed on 307/308 and for an
                    // authenticated retry of this hop.
                    let (hop_body, explicit_len) = body.to_reqwest_body()?;
                    if let Some(len) = explicit_len {
                        if !current_headers.contains_key(header::CONTENT_LENGTH) {
                            req_builder = req_builder.header(header::CONTENT_LENGTH, len);
                        }
                    }
                    req_builder = req_builder.body(hop_body);
                }
                // Built rather than sent straight away, so the request line reported is the
                // one the client actually assembled. `build()` has by then applied the
                // client's own defaults -- its user agent, its configured default headers --
                // on top of what this stack set. Reporting the headers we handed over would
                // describe what was asked for, which is not the same thing, and the gap
                // between the two is exactly what a developer opens a network panel to find.
                //
                // Reported here rather than beside `Started`: the headers are only final for
                // this hop at this point. Credentials and conditional headers are added just
                // above, and a redirect starts over from the caller's set, so an earlier
                // event would describe a request that was never sent.
                //
                // A few headers are still added below this layer by the connection itself --
                // `host` or `:authority`, and transfer framing. Those never reach a
                // `reqwest::Request`, and are not guessed at here.
                let request = req_builder.build().map_err(|e| {
                    send_error(
                        e,
                        &url,
                        "net.get_with_redirects request build failed",
                        &observer,
                    )
                })?;
                let mut reported = request.headers().clone();
                // Only when the assembled request does not already carry one: a header set
                // per-request wins over the client default, and reporting the default over
                // the top of it would be a lie in the one direction that matters.
                if let Some(ref ua) = policy.user_agent {
                    reported
                        .entry(http::header::USER_AGENT)
                        .or_insert(ua.clone());
                }
                observer.on_event(NetEvent::RequestSent {
                    url: url.clone(),
                    method: request.method().clone(),
                    headers: reported,
                });

                let fut = client.execute(request);
                tokio::pin!(fut);
                #[cfg(not(target_arch = "wasm32"))]
                {
                    requested_at = chrono::Utc::now();
                }

                let resp = tokio::select! {
                    _ = cancel.cancelled() => {
                        observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "cancelled net.get_with_redirects" });
                        return Err(NetError::Cancelled("cancelled net.get_with_redirects".into()));
                    }
                    r = &mut fut => r.map_err(|e| send_error(e, &url, "net.get_with_redirects request failed", &observer))?
                };
                #[cfg(not(target_arch = "wasm32"))]
                {
                    received_at = chrono::Utc::now();
                }

                // Report the HTTP version of every hop, not just the final response, so the fetcher's
                // per-origin limits also learn about intermediate origins. reqwest's wasm Response has
                // no version().
                #[cfg(not(target_arch = "wasm32"))]
                (policy.on_protocol)(resp.url(), resp.version());

                // Per hop, like the other events in this loop: the first one marks
                // time-to-first-byte for the request, and a redirect chain reports each hop
                // it waited on. A hop served from the cache received no headers over the
                // wire and reports `Cache` instead.
                observer.on_event(NetEvent::ResponseHeaders {
                    url: resp.url().clone(),
                    status: resp.status().as_u16(),
                    headers: resp.headers().clone(),
                });

                // Harvest HSTS from every hop, not just the final one: a 301 http->https is the usual way
                // a site first arms it, and that response is consumed below.
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(ref store) = policy.hsts {
                    hsts::record(store.as_ref(), &url, resp.headers(), chrono::Utc::now());
                }

                // The CORS check (Fetch §4.10.3) runs on *every* response of a cors-tainted chain —
                // redirects included, and also a final same-origin hop reached through a cross-origin
                // detour. Native-only: on wasm32 the browser has already enforced this.
                #[cfg(not(target_arch = "wasm32"))]
                if tainting == ResponseTainting::Cors {
                    if let Some(ref o) = origin {
                        if let Err(e) =
                            cors::cors_check(o, origin_tainted, credentials_include, resp.headers())
                        {
                            return Err(blocked(&observer, url, BlockReason::Cors(e)));
                        }
                    }
                }

                // A `304` answers a revalidation: the stored body stands, with the headers the
                // response carried written over the stored ones (RFC 9111 §4.3.4).
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(ref entry) = revalidating {
                    if resp.status().as_u16() == 304 {
                        let updated = Arc::new(entry.updated_by_304(
                            resp.headers(),
                            requested_at,
                            received_at,
                        ));
                        if let Some(ref cache) = policy.cache {
                            cache.put(CacheKey::new(&current_method, &url), updated.clone());
                        }
                        observer.on_event(NetEvent::Cache {
                            url: url.clone(),
                            outcome: CacheOutcome::Validated,
                        });
                        break HopResponse::Cached(updated);
                    }
                }

                // After the checks above: a response CORS refuses is blocked even when it asks for
                // credentials.
                let Some(target) = AuthTarget::for_status(resp.status().as_u16()) else {
                    // Only a password is remembered. A `Raw` answer was computed for the challenge
                    // it answered (a Digest nonce, a Negotiate token), and replaying it would only
                    // draw another challenge.
                    if let (Some(store), Some((space, credentials))) =
                        (policy.credentials.as_ref(), unproven.take())
                    {
                        if matches!(credentials, Credentials::Basic { .. }) {
                            store.store(space, credentials);
                        }
                    }
                    break HopResponse::Network(resp);
                };

                let may_answer = match target {
                    // Server credentials follow the request's credentials mode, and are only
                    // attached to a chain the CORS regime left untainted. `Authorization` is not a
                    // CORS-safelisted header, so adding it to a cors request would need a preflight
                    // of its own, and adding it to a no-cors one would be a header markup cannot
                    // produce. Navigations and requests without a document origin stay basic, and
                    // those are the ones a browser shows its password dialog for.
                    AuthTarget::Server => attach_credentials && tainting == ResponseTainting::Basic,
                    // A proxy challenge is about the hop to the proxy. `Proxy-Authorization` never
                    // reaches the origin server, so neither CORS nor the credentials mode has a say.
                    // On wasm32 the browser owns the proxy connection and forbids the header.
                    AuthTarget::Proxy => cfg!(not(target_arch = "wasm32")),
                };
                let challenges = auth::parse_challenges(resp.headers(), target, &url, auth_attempt);
                let answer = if may_answer && auth_attempt < MAX_AUTH_ATTEMPTS {
                    // What was sent last time has just been rejected: drop it so the store stops
                    // handing back a password the server no longer takes.
                    if let (Some(store), Some((space, _))) =
                        (policy.credentials.as_ref(), unproven.take())
                    {
                        store.forget(&space);
                    }
                    credentials_for_challenges(&policy, &challenges)
                } else {
                    None
                };

                observer.on_event(NetEvent::AuthRequired {
                    url: url.clone(),
                    target,
                    challenges,
                    retried: answer.is_some(),
                });

                let Some((space, credentials, value)) = answer else {
                    break HopResponse::Network(resp);
                };
                auth_header = Some((target.credentials_header(), value));
                unproven = Some((space, credentials));
                auth_attempt += 1;
            },
        };

        // A method that changed the resource makes what is stored for it wrong, including for
        // the `Location` it points at (RFC 9111 §4.4). Only a successful one: a rejected POST
        // changed nothing.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref cache) = policy.cache {
            if cache::invalidates(&current_method) && hop.status() < 400 {
                let mut targets = vec![url.clone()];
                for name in [header::LOCATION, header::CONTENT_LOCATION] {
                    let target = hop
                        .headers()
                        .get(&name)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| url.join(v).ok());
                    // Only same-origin: a response cannot invalidate another site's entries.
                    if let Some(target) = target.filter(|t| t.origin() == url.origin()) {
                        targets.push(target);
                    }
                }
                for target in targets {
                    // Entries are keyed by method, so both of the cacheable ones go.
                    for method in [Method::GET, Method::HEAD] {
                        cache.invalidate(&CacheKey::new(&method, &target));
                    }
                }
                observer.on_event(NetEvent::Cache {
                    url: url.clone(),
                    outcome: CacheOutcome::Invalidated,
                });
            }
        }

        // Whether this response may be stored. The body is not here yet: a redirect has none
        // worth keeping and is stored right away, while the final response's write waits for the
        // reader of its body.
        #[cfg(not(target_arch = "wasm32"))]
        let pending_store = match (&hop, policy.cache.as_ref()) {
            // `no-store` is both directions: the lookup above skipped the cache, and nothing
            // about this exchange is written to it either.
            (HopResponse::Network(resp), Some(cache))
                if init.cache_mode != CacheMode::NoStore
                    && cache::is_storable(
                        &current_method,
                        &current_headers,
                        resp.status().as_u16(),
                        resp.headers(),
                    ) =>
            {
                Some(PendingStore {
                    cache: cache.clone(),
                    key: CacheKey::new(&current_method, &url),
                    url: url.clone(),
                    status: resp.status().as_u16(),
                    response_headers: resp.headers().clone(),
                    request_headers: current_headers.clone(),
                    decoded: init.auto_decode,
                    requested_at,
                    received_at,
                })
            }
            _ => None,
        };

        if !hop.is_redirection() {
            return Ok(ChainOutcome {
                response: hop,
                url: url.clone(),
                tainting,
                #[cfg(not(target_arch = "wasm32"))]
                store: pending_store,
            });
        }

        // A redirect is stored now: the caller never sees its body, and a stored `301` lets the
        // next fetch skip the hop entirely.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(store) = pending_store {
            store.commit(Bytes::new(), &observer);
        }

        // 3xx — resolve the Location header
        let status = hop.status();
        let from = match hop {
            HopResponse::Network(ref resp) => resp.url().clone(),
            HopResponse::Cached(_) => url.clone(),
        };

        // A redirect may tighten (or loosen) the policy for the rest of the chain. Read every
        // field line, not just the first: a server may split the list across lines, and the
        // last token we understand wins across all of them.
        if let Some(updated) = hop
            .headers()
            .get_all(&REFERRER_POLICY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(ReferrerPolicy::parse_header)
            .next_back()
        {
            referrer_policy = updated;
        }

        // Report Set-Cookie values on this hop to the jar before following the redirect —
        // login flows commonly set the session cookie on a 302. Dropping our Cookie header
        // makes the next hop re-query the now-updated jar instead of resending a stale value.
        let set_cookies: Vec<&str> = hop
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if !set_cookies.is_empty() {
            (policy.on_cookies)(&from, &set_cookies);
            current_headers.remove(header::COOKIE);
        }

        let loc = hop
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                NetError::Redirect(Arc::new(anyhow!(
                    "redirect status {} without Location header",
                    status
                )))
            })?;

        let to = from.join(loc).map_err(|e| {
            NetError::Redirect(Arc::new(anyhow!("invalid redirect URL '{}': {}", loc, e)))
        })?;

        // A `Location` with embedded `user:password` is refused for a cors-mode request, and
        // for any request when it points at another origin (Fetch §4.4 steps 9–10): following
        // it would replay attacker-chosen credentials against the new target.
        if (!to.username().is_empty() || to.password().is_some())
            && (init.mode == RequestMode::Cors || from.origin() != to.origin())
        {
            return Err(blocked(
                &observer,
                to,
                BlockReason::Cors(CorsError::CredentialedRedirect),
            ));
        }

        // Method and body semantics per RFC 7231 §6.4
        match status {
            // 301/302: browsers always downgrade POST to GET (§6.4.2–3); we follow suit.
            // HEAD stays HEAD (no body involved); all other methods become GET.
            301 | 302 => {
                if current_method != Method::HEAD {
                    current_method = Method::GET;
                }
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 303 See Other: always GET, always drop body.
            303 => {
                current_method = Method::GET;
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 307/308: preserve method and body.
            307 | 308 => {}
            // Other 3xx: treat conservatively as 302.
            _ => {
                if current_method != Method::HEAD {
                    current_method = Method::GET;
                }
                current_body = None;
            }
        }

        // Strip credential headers when redirecting to a different origin (RFC 9110 §15.4).
        // Cookie will be re-applied from the jar at the top of the next loop iteration.
        if from.origin() != to.origin() {
            for h in SENSITIVE_REDIRECT_HEADERS {
                current_headers.remove(h);
            }
        }

        // A cross-origin redirect from a hop the request's own origin had already left taints
        // the Origin header for the rest of the chain (Fetch, HTTP-redirect fetch). The first
        // cross-origin hop still sends the real origin, which CORS depends on.
        if let Some(ref o) = origin {
            if to.origin() != from.origin() && *o != from.origin() {
                origin_tainted = true;
            }
        }

        observer.on_event(NetEvent::Redirected {
            from,
            to: to.clone(),
            status,
        });

        url = to
    }

    Err(NetError::Redirect(Arc::new(anyhow!("too many redirects"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::auth::{AuthScheme, InMemoryCredentialStore};
    use crate::net::referrer::ReferrerPolicy;
    use crate::net::test_support::{CacheRouteOptions, RecordingObserver, RouteConfig, TestServer};
    use cow_utils::CowUtils;
    use http::HeaderMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    struct TestObserver;
    impl NetObserver for TestObserver {
        fn on_event(&self, _: NetEvent) {}
    }

    fn observer() -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(TestObserver)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_request_line_is_reported_with_the_headers_that_were_sent() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("x-marker", "present".parse().unwrap());
        let rec = Arc::new(RecordingObserver::new());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(headers),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1, "one hop, one request line");
        let (method, url, headers) = &sent[0];
        assert_eq!(method, http::Method::GET);
        assert_eq!(url, &srv.url("/"));
        // The caller's headers are included in the report.
        assert_eq!(headers.get("x-marker").unwrap(), "present");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_shorter_than_the_budget_is_captured_whole() {
        let body = pattern(64);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].0, body,
            "the capture is the body, byte for byte"
        );
        assert!(!previews[0].1, "a body that fits is not truncated");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_larger_than_the_peek_window_is_captured_past_it() {
        // Well past the peek window, so the capture cannot be just the buffered peek.
        let body = pattern(PEEK_MAX * 4);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        // The tee fills as the consumer pulls, so the body has to be read.
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert!(
            previews[0].0.len() > PEEK_MAX,
            "the capture reaches past the peek window (got {})",
            previews[0].0.len()
        );
        assert_eq!(
            previews[0].0, body,
            "and it is the whole body, byte for byte"
        );
        assert!(!previews[0].1, "and not truncated");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_over_the_budget_stops_at_it_and_says_so() {
        let body = pattern(PEEK_MAX * 3);
        let limit = PEEK_MAX + 512; // deliberately not a window multiple
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        // The recorder has no limit of its own; this wrapper imposes the budget and passes
        // the events through.
        struct Capped(Arc<RecordingObserver>, usize);
        impl NetObserver for Capped {
            fn on_event(&self, ev: NetEvent) {
                self.0.on_event(ev);
            }
            fn body_capture_limit(&self, _: &HeaderMap, _: Option<u64>) -> Option<usize> {
                Some(self.1)
            }
        }

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            Arc::new(Capped(rec.clone(), limit)),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].0.len(), limit, "stops exactly at the budget");
        assert_eq!(
            previews[0].0,
            body[..limit],
            "and it is the start of the body"
        );
        assert!(
            previews[0].1,
            "a body that continued is reported as truncated"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refusing_a_capture_leaves_the_body_intact() {
        // The default `body_capture_limit` is None, which keeps the tee off the path.
        let body = pattern(PEEK_MAX * 2);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        assert_eq!(drain(top).await, body, "the body arrives whole");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_reported_headers_include_the_client_s_user_agent() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        // Set on the *client*, where reqwest merges it at execute time and never exposes it
        // for reading. The policy is told separately, which is the only route to reporting it.
        let client = Arc::new(
            reqwest::Client::builder()
                .user_agent("probe-agent/1.0")
                .build()
                .unwrap(),
        );

        fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default().with_user_agent(Some("probe-agent/1.0")),
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0]
                .2
                .get(http::header::USER_AGENT)
                .map(|v| v.to_str().unwrap()),
            Some("probe-agent/1.0")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn headers_this_crate_adds_are_reported_too() {
        // The question a network panel exists to answer: not "what did the caller ask for"
        // but "what went out". Cookies, Referer, Origin and the Sec-Fetch-* set are all
        // computed here, after the caller's map is handed over, and must show up.
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());
        let target = srv.url("/");

        let policy = NetPolicy {
            cookies_for: Box::new(|_| Some("session=abc123".to_string())),
            ..NetPolicy::default()
        };

        fetch_response_top(
            client(),
            target.clone(),
            RequestInit::get(HeaderMap::new())
                .with_referrer(Some(target.clone()), ReferrerPolicy::UnsafeUrl)
                .with_fetch_metadata(RequestDestination::Image, RequestMode::NoCors, false),
            CancellationToken::new(),
            rec.clone(),
            policy,
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1);
        let headers = &sent[0].2;

        // The caller set none of these.
        assert_eq!(
            headers.get(header::COOKIE).map(|v| v.to_str().unwrap()),
            Some("session=abc123"),
            "a cookie from the jar is reported"
        );
        assert!(
            headers.contains_key(header::REFERER),
            "a computed Referer is reported"
        );
        assert!(
            headers.contains_key("sec-fetch-dest") && headers.contains_key("sec-fetch-mode"),
            "computed fetch metadata is reported"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_user_agent_is_invented_when_the_policy_was_not_told_one() {
        // A client this crate did not build. Reporting a guess would be worse than reporting
        // nothing, so the header is simply absent.
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        assert!(!rec.requests_sent()[0]
            .2
            .contains_key(http::header::USER_AGENT));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_per_request_user_agent_wins_over_the_client_default() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "per-request/2.0".parse().unwrap());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(headers),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default().with_user_agent(Some("client-default/1.0")),
        )
        .await
        .expect("fetch");

        assert_eq!(
            rec.requests_sent()[0]
                .2
                .get(http::header::USER_AGENT)
                .map(|v| v.to_str().unwrap()),
            Some("per-request/2.0"),
            "the header on the request is what is sent, so it is what is reported"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abandoning_a_partly_read_body_reports_a_cancellation() {
        // Not "finished": the transfer did not happen, and reporting a completion with the
        // handful of bytes that did arrive would describe a request nobody made.
        let body = pattern(PEEK_MAX * 2);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let ResponseTop { mut reader, .. } = top;
        let mut sip = [0u8; 128];
        let _ = reader.read(&mut sip).await.unwrap();
        drop(reader);

        assert_eq!(
            rec.finished().len(),
            0,
            "an abandoned body is not a completed one"
        );
        assert_eq!(
            rec.cancellations(),
            vec!["body reader dropped before end of stream"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_that_arrived_whole_reports_finished_when_dropped_unread() {
        // The common case behind this: a response small enough to fit the peek window. Its
        // consumer has the entire body without ever touching the reader, so dropping it is
        // not an abandonment -- and the time reported must be the transfer, not however long
        // the owner sat on the reader afterwards.
        let body = pattern(64);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let ResponseTop { reader, .. } = top;
        let idle = Duration::from_millis(300);
        tokio::time::sleep(idle).await;
        drop(reader);

        let finished = rec.finished();
        assert_eq!(finished.len(), 1);
        assert_eq!(
            finished[0].0,
            body.len() as u64,
            "the whole body is accounted for"
        );
        assert!(
            finished[0].1 < idle,
            "the idle wait before the drop is not reported as transfer time (got {:?})",
            finished[0].1
        );
        assert!(rec.cancellations().is_empty());
    }

    /// Read a response to the end and return the whole body, peek window included. The
    /// capture only fills as the consumer pulls.
    async fn drain(top: ResponseTop) -> Vec<u8> {
        let ResponseTop {
            peek_buf,
            mut reader,
            ..
        } = top;
        let mut body = peek_buf.into_bytes().to_vec();
        reader.read_to_end(&mut body).await.unwrap();
        body
    }

    /// Deterministic, position-dependent byte pattern. Any truncation or mis-ordering during body
    /// assembly changes the bytes, so an exact compare catches it.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    fn client() -> Arc<reqwest::Client> {
        Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        )
    }

    /// A TLS `TestServer` plus a client that trusts its certificate and resolves its domain to
    /// the loopback listener. No DNS or public CA involved.
    async fn tls_server_and_client(
        routes: Vec<(&str, RouteConfig)>,
    ) -> (
        crate::net::test_support::TestServerHandle,
        Arc<reqwest::Client>,
    ) {
        let mut srv = TestServer::new().tls("hsts.test");
        for (path, cfg) in routes {
            srv = srv.route(path, cfg);
        }
        let srv = srv.start().await;

        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Not `add_root_certificate`: that leaves reqwest on the platform verifier and
            // passes this CA as an *extra* root, which on Windows and macOS still defers to
            // the OS trust store and rejects a CA generated in-process. `tls_certs_only`
            // replaces the roots outright, so verification is pure rustls WebPKI.
            .tls_certs_only([cert])
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        (srv, Arc::new(client))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn untrusted_certificate_is_a_tls_error() {
        let srv = TestServer::new()
            .tls("tls.test")
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        // client that doesn't trust the self-signed cert
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        let rec = Arc::new(RecordingObserver::new());

        let err = fetch_response_top(
            Arc::new(client),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        let tls = match err {
            Ok(_) => panic!("expected an error"),
            Err(NetError::Tls(tls)) => tls,
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
        };
        assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::UnknownIssuer);
        assert_eq!(tls.host, "tls.test");
        assert!(tls.certificate.is_none());
        assert_eq!(rec.tls_errors(), vec![tls]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn certificate_for_another_host_is_a_tls_error() {
        let srv = TestServer::new()
            .tls("tls.test")
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        // trust the cert, but connect with a name it wasn't issued for
        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .tls_certs_only([cert])
            .resolve("other.test", srv.socket_addr())
            .build()
            .unwrap();
        let url = Url::parse(&format!("https://other.test:{}/", srv.socket_addr().port())).unwrap();

        let err = fetch_response_top(
            Arc::new(client),
            url,
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;

        match err {
            Err(NetError::Tls(tls)) => {
                assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::HostnameMismatch);
                assert_eq!(tls.host, "other.test");
            }
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    // Fetch from a TLS server with a certificate that is valid between the given dates. The
    // cert is trusted, so validity is the only thing that can fail.
    async fn tls_error_for_validity(
        not_before: crate::net::test_support::Ymd,
        not_after: crate::net::test_support::Ymd,
    ) -> crate::net::tls::TlsError {
        let srv = TestServer::new()
            .tls("tls.test")
            .tls_validity(not_before, not_after)
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .tls_certs_only([cert])
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        match fetch_response_top(
            Arc::new(client),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        {
            Err(NetError::Tls(tls)) => tls,
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_certificate_is_a_tls_error() {
        let tls = tls_error_for_validity((2000, 1, 1), (2001, 1, 1)).await;
        assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::Expired, "{tls}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn not_yet_valid_certificate_is_a_tls_error() {
        let tls = tls_error_for_validity((3000, 1, 1), (3001, 1, 1)).await;
        assert_eq!(
            tls.kind,
            crate::net::tls::TlsErrorKind::NotYetValid,
            "{tls}"
        );
    }

    /// The plain mock server cannot cover this: HSTS ignores plaintext responses and IP-literal
    /// hosts, so only a TLS server with a domain name can arm a store.
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_recorded_from_a_real_https_response() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                )],
                b"hello".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());

        let entry = crate::net::hsts::HstsStore::load(store.as_ref(), "hsts.test")
            .expect("an https response carrying the header must arm the store");
        assert!(entry.include_subdomains);
        assert!(!entry.is_expired(chrono::Utc::now()));
    }

    /// The same header over plain HTTP must arm nothing (§8.1).
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_not_recorded_over_plaintext() {
        let srv = TestServer::new()
            .route(
                "/",
                RouteConfig::ok_with_headers(
                    &[("Strict-Transport-Security", "max-age=31536000")],
                    b"hello".to_vec(),
                ),
            )
            .start()
            .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok());
        assert!(store.is_empty(), "plaintext must never arm HSTS");
    }

    /// max-age=0 disarms a previously armed host (§6.1.1).
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_max_age_zero_disarms_over_tls() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[("Strict-Transport-Security", "max-age=0")],
                b"bye".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        crate::net::hsts::HstsStore::store(
            store.as_ref(),
            "hsts.test",
            crate::net::hsts::HstsEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                include_subdomains: false,
            },
        );

        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());
        assert!(store.is_empty(), "max-age=0 must remove the entry");
    }

    async fn server() -> crate::net::test_support::TestServerHandle {
        // 64 KiB pattern, chunked so the body arrives in many pieces with no Content-Length.
        let big = pattern(64 * 1024);
        let big_chunks: Vec<&[u8]> = big.chunks(5_000).collect();
        // Exactly one READ_CHUNK worth of body, chunked (no Content-Length).
        let exact = vec![b'Y'; super::READ_CHUNK];
        TestServer::new()
            .route("/big", RouteConfig::ok(vec![b'X'; 12 * 1024]))
            .route("/big-chunked", RouteConfig::chunked(big_chunks))
            .route("/exact-chunk", RouteConfig::chunked(vec![exact.as_slice()]))
            .route("/large-cl", RouteConfig::ok(pattern(64 * 1024)))
            .route("/redirect", RouteConfig::redirect_to("/big"))
            .route(
                "/slow",
                RouteConfig::stall_mid_body(super::PEEK_MAX, Duration::from_millis(2_000)),
            )
            .route("/drop", RouteConfig::drop_mid_body(100, 10_000))
            // Declares an absurd Content-Length, sends exactly the peek window, then drops. The
            // peek loop stops at PEEK_MAX without another read, so the fetch reaches the body
            // phase with the hostile Content-Length intact.
            .route(
                "/huge-cl",
                RouteConfig::drop_mid_body(super::PEEK_MAX, 1 << 45),
            )
            .route("/xl-cl", RouteConfig::ok(pattern(2 * 1024 * 1024)))
            .route(
                "/login",
                RouteConfig::redirect_with_cookie("/whoami", "session=abc123; Path=/"),
            )
            .route("/whoami", RouteConfig::echo_cookie_header())
            .route("/empty", RouteConfig::ok(b""))
            .route("/nohead", RouteConfig::no_location_redirect())
            .route("/loop", RouteConfig::redirect_self())
            .route("/hop1", RouteConfig::redirect_to("/hop2"))
            .route("/hop2", RouteConfig::redirect_to("/hop3"))
            .route("/hop3", RouteConfig::ok(b"final"))
            .route(
                "/chunked",
                RouteConfig::chunked(vec![b"hel", b"lo ", b"wor", b"ld"]),
            )
            .start()
            .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn top_returns_peek_and_reader_rest() {
        let srv = server().await;
        let ResponseTop {
            meta,
            peek_buf,
            mut reader,
        } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(peek_buf.len(), super::PEEK_MAX);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(peek_buf.len() + rest.len(), 12 * 1024);
        assert!(meta.has_body);
        assert_eq!(meta.status, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/redirect"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
        assert!(meta.has_body);
    }

    /// The open-count proves a 307 replays the body by opening a fresh reader.
    #[tokio::test(flavor = "current_thread")]
    async fn stream_body_is_uploaded_and_replayed_on_307() {
        use crate::net::types::BoxedAsyncRead;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let srv = TestServer::new()
            .route("/hop", RouteConfig::redirect_307("/echo"))
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        const PAYLOAD: &[u8] = b"streamed payload";
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = opened.clone();
        let body = RequestBody::stream(
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(Box::pin(PAYLOAD) as BoxedAsyncRead)
            },
            Some(PAYLOAD.len() as u64),
        );

        let (meta, echoed) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&echoed[..], PAYLOAD);
        assert_eq!(
            opened.load(Ordering::SeqCst),
            2,
            "307 must replay the body by opening a fresh reader"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_body_streams_from_disk() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"file payload").unwrap();
        let body = RequestBody::file(tmp.path()).unwrap();

        let (meta, echoed) = super::fetch_response_complete(
            client(),
            srv.url("/echo"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&echoed[..], b"file payload");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_body_open_failure_fails_the_request() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        let body = RequestBody::stream(|| Err(std::io::Error::other("source is gone")), None);

        let res = super::fetch_response_complete(
            client(),
            srv.url("/echo"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await;

        assert!(
            matches!(res, Err(NetError::Io(_))),
            "factory failure must surface as NetError::Io, got {res:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_timeout_triggers_on_slow_body() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_millis(100),
            Some(Duration::from_secs(2)),
            NetPolicy::default(),
        )
        .await;

        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("timeout"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_peek_is_honored() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    /// Uses a chunked route (no Content-Length) so the in-loop size check is what fires; responses
    /// that declare an oversized Content-Length up front are rejected earlier, see
    /// `huge_content_length_rejected_before_body_read`.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_max_bytes_exceeded() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(100),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("exceeded"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_cancel_mid_body() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn progress_reader_cancel_returns_error() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let ResponseTop { mut reader, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        cancel.cancel();
        assert!(reader.read(&mut vec![0u8; 1024]).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_mid_body_produces_error() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/drop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_body_has_no_body_flag_and_empty_peek() {
        let srv = server().await;
        let ResponseTop { meta, peek_buf, .. } = super::fetch_response_top(
            client(),
            srv.url("/empty"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert!(peek_buf.is_empty());
        assert!(!meta.has_body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multi_hop_redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"final");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_redirect_chain() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        assert!(fut.await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_is_assembled_correctly() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_without_location_header_errors() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/nohead"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_loop_exceeds_max_redirects() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/loop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("redirect"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn url_filter_blocks_request() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy {
                url_allowed: Box::new(|_| false),
                ..NetPolicy::default()
            },
        )
        .await;
        assert!(matches!(
            res.err(),
            Some(NetError::Blocked {
                reason: BlockReason::UrlPolicy,
                ..
            })
        ));
    }

    /// A secure document must not reach a plain-http sub-resource. No server is needed — the
    /// block happens before any connection is attempted.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_blocks_insecure_subresource() {
        let res = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.example.com/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(matches!(
            res.err(),
            Some(NetError::Blocked {
                reason: BlockReason::MixedContent,
                ..
            })
        ));
    }

    /// The test server binds to loopback, which is potentially trustworthy — the same request
    /// must go through. Guards against over-blocking, not under-blocking.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_allows_loopback_subresource() {
        let srv = server().await;
        assert!(srv.url("/big").host_str().unwrap().contains("127.0.0.1"));
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    /// An insecure document has nothing to downgrade, so the check must not fire for it.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_ignores_insecure_initiator() {
        let srv = server().await;
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("http://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    /// The case an embedder cannot check for itself: the initial URL is fine, and the *redirect
    /// target* is the insecure hop. Enforcement has to live inside the redirect loop to catch it.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_blocks_insecure_redirect_target() {
        // Loopback is trustworthy, so redirect off-box to get a genuinely insecure hop.
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute("http://insecure.example.com/a.js"),
            )
            .start()
            .await;

        let res = super::fetch_response_top(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;

        match res.err() {
            Some(NetError::Blocked { reason, url }) => {
                assert_eq!(reason, BlockReason::MixedContent);
                // The blocked hop is reported, not the URL originally requested.
                assert_eq!(url.as_str(), "http://insecure.example.com/a.js");
            }
            other => panic!("expected a mixed content block, got {other:?}"),
        }
    }

    /// Under `Upgrade` the same redirect is rewritten to https instead of blocked.
    ///
    /// Asserting only "did not block" would be worthless here: an `Upgrade` silently degraded to
    /// `Allow` would send plain http to a host that does not resolve and fail identically. The
    /// emitted warning naming the https URL is the only evidence the rewrite actually happened.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_upgrades_insecure_redirect_target() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute("http://insecure.invalid/a.js"),
            )
            .start()
            .await;

        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Upgrade,
            ),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        assert_eq!(
            rec.warnings(),
            vec!["upgraded insecure request to https://insecure.invalid/a.js"],
            "the hop must be rewritten to https"
        );
        assert!(
            !matches!(res.as_ref().err(), Some(NetError::Blocked { .. })),
            "upgrade must rewrite the hop, not block it"
        );
        assert_eq!(rec.blocked_reason(), None);
    }

    /// Fetch `path` on `srv` with the given referrer and return the `Referer` the server saw.
    async fn referer_seen_by_server(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        referrer: Option<&str>,
        policy: ReferrerPolicy,
    ) -> String {
        let (_, body) = super::fetch_response_complete(
            client(),
            srv.url(path),
            RequestInit::get(HeaderMap::new())
                .with_referrer(referrer.map(|r| Url::parse(r).unwrap()), policy),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            None,
            NetPolicy::default(),
        )
        .await
        .unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    /// The default policy sends the bare origin to a cross-origin target.
    #[tokio::test(flavor = "current_thread")]
    async fn referer_header_is_sent() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        // The server is on loopback (trustworthy), so this is not a downgrade; cross-origin
        // under the default policy means the bare origin.
        assert_eq!(
            referer_seen_by_server(
                &srv,
                "/echo",
                Some("https://example.com/page?q=1#frag"),
                ReferrerPolicy::default(),
            )
            .await,
            "https://example.com/"
        );
    }

    /// No referrer configured must mean no header at all, not an empty one — the echo route
    /// reports `<absent>` only when the header is genuinely missing.
    #[tokio::test(flavor = "current_thread")]
    async fn no_referrer_sends_no_header() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        assert_eq!(
            referer_seen_by_server(&srv, "/echo", None, ReferrerPolicy::default()).await,
            "<absent>"
        );
        assert_eq!(
            referer_seen_by_server(
                &srv,
                "/echo",
                Some("https://example.com/page"),
                ReferrerPolicy::NoReferrer,
            )
            .await,
            "<absent>"
        );
    }

    /// The header is recomputed per hop: leaving the referrer's origin reveals only that origin,
    /// then a redirect landing back home may reveal the full path.
    ///
    /// Two servers are required. One server cannot express "cross-origin then same-origin", so
    /// both hops would compute the same value and the test would pass even if the header were
    /// computed once up front.
    #[tokio::test(flavor = "current_thread")]
    async fn referer_is_recomputed_after_a_redirect() {
        let home = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;
        // A different port is a different origin, and loopback keeps it out of downgrade rules.
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/echo").as_str()),
            )
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        let doc = format!("{}page?q=1", home.base_url());
        let policy = ReferrerPolicy::default();

        // Leaving home is cross-origin, so only the bare origin is revealed.
        assert_eq!(
            referer_seen_by_server(&away, "/echo", Some(&doc), policy).await,
            home.base_url().as_str()
        );

        // Redirected back home it is same-origin, so the full path is revealed. Computing the
        // header once up front would still be sending the bare origin here.
        assert_eq!(
            referer_seen_by_server(&away, "/hop", Some(&doc), policy).await,
            doc
        );
    }

    /// A `Referrer-Policy` header on a redirect replaces the policy for the remaining hops.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_referrer_policy_header_applies_to_later_hops() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_with_referrer_policy("/echo", "no-referrer"),
            )
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        // Same-origin with the server, so without the header the full URL would be sent.
        let doc = format!("{}page?q=1", srv.base_url());
        let seen =
            referer_seen_by_server(&srv, "/hop", Some(&doc), ReferrerPolicy::default()).await;

        assert_eq!(
            seen, "<absent>",
            "the redirect's no-referrer policy must suppress the header on the next hop"
        );
    }

    /// Fetch `path` on `srv` with `init` and return the response body as text. Pair with
    /// [`RouteConfig::echo_request_header`] to see a header exactly as the server received it.
    async fn header_seen_by_server(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
    ) -> String {
        let (_, body) = super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            None,
            NetPolicy::default(),
        )
        .await
        .unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    /// Even a bare request carries fetch metadata: empty destination, no-cors mode, and a
    /// site of `none` when no initiating origin is set. `Sec-Fetch-User` must be absent,
    /// not `?0`.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_headers_are_sent_by_default() {
        let srv = TestServer::new()
            .route("/dest", RouteConfig::echo_request_header("sec-fetch-dest"))
            .route("/mode", RouteConfig::echo_request_header("sec-fetch-mode"))
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .route("/user", RouteConfig::echo_request_header("sec-fetch-user"))
            .start()
            .await;

        let cases = [
            ("/dest", "empty"),
            ("/mode", "no-cors"),
            ("/site", "none"),
            ("/user", "<absent>"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                header_seen_by_server(&srv, path, RequestInit::get(HeaderMap::new())).await,
                expected,
                "{path}"
            );
        }
    }

    /// `Sec-Fetch-Site` reports the target's relation to the initiating origin. The server is
    /// on loopback, so its own origin is same-origin, the same host on another port is
    /// same-site, and a foreign host is cross-site.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_site_reflects_the_initiating_origin() {
        let srv = TestServer::new()
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .start()
            .await;

        let mut other_port = srv.base_url();
        other_port.set_port(Some(1)).unwrap();

        let cases = [
            (srv.base_url(), "same-origin"),
            (other_port, "same-site"),
            (Url::parse("https://example.com").unwrap(), "cross-site"),
        ];
        for (initiator, expected) in cases {
            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(Some(initiator.origin()), MixedContentPolicy::default());
            assert_eq!(
                header_seen_by_server(&srv, "/site", init).await,
                expected,
                "{initiator}"
            );
        }
    }

    /// The site relation covers the whole redirect chain: a detour through a foreign origin
    /// degrades the value for good, even when the chain lands back on the initiator's own
    /// origin.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_site_degrades_across_redirects() {
        let home = TestServer::new()
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .start()
            .await;
        // Both servers are on 127.0.0.1, so the detour through `away` (another port) is a
        // same-site hop; loopback cannot express a cross-site one.
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/site").as_str()),
            )
            .start()
            .await;

        let init = RequestInit::get(HeaderMap::new()).with_mixed_content(
            Some(home.base_url().origin()),
            MixedContentPolicy::default(),
        );
        assert_eq!(
            header_seen_by_server(&away, "/hop", init).await,
            "same-site",
            "the foreign hop must cap the value even though the final hop is same-origin"
        );
    }

    /// `Sec-Fetch-User: ?1` is only sent on user-activated navigations; everything else
    /// omits the header.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_user_marks_user_navigations() {
        let srv = TestServer::new()
            .route("/user", RouteConfig::echo_request_header("sec-fetch-user"))
            .start()
            .await;

        let cases = [
            (RequestMode::Navigate, true, "?1"),
            (RequestMode::Navigate, false, "<absent>"),
            (RequestMode::NoCors, true, "<absent>"),
        ];
        for (mode, activated, expected) in cases {
            let init = RequestInit::get(HeaderMap::new()).with_fetch_metadata(
                RequestDestination::Document,
                mode,
                activated,
            );
            assert_eq!(
                header_seen_by_server(&srv, "/user", init).await,
                expected,
                "{mode:?} activated={activated}"
            );
        }
    }

    /// A POST carries an `Origin` header; a plain no-cors GET does not, even with an
    /// initiating origin configured.
    #[tokio::test(flavor = "current_thread")]
    async fn origin_header_is_sent_for_post_but_not_plain_get() {
        let srv = TestServer::new()
            .route("/origin", RouteConfig::echo_request_header("origin"))
            .start()
            .await;
        let initiator = srv.base_url().origin();

        let post = RequestInit::post(HeaderMap::new(), b"x".to_vec())
            .with_mixed_content(Some(initiator.clone()), MixedContentPolicy::default());
        assert_eq!(
            header_seen_by_server(&srv, "/origin", post).await,
            initiator.ascii_serialization()
        );

        let get = RequestInit::get(HeaderMap::new())
            .with_mixed_content(Some(initiator), MixedContentPolicy::default());
        assert_eq!(
            header_seen_by_server(&srv, "/origin", get).await,
            "<absent>"
        );
    }

    /// After a tainting cross-origin redirect the final server sees the literal `null`,
    /// not the initiator and not a missing header.
    #[tokio::test(flavor = "current_thread")]
    async fn origin_header_becomes_null_after_a_cross_origin_redirect() {
        let home = TestServer::new()
            .route("/origin", RouteConfig::echo_request_header("origin"))
            .start()
            .await;
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/origin").as_str()),
            )
            .start()
            .await;

        // Websocket mode: cors-like, so the cross-origin GET carries an Origin header at all,
        // but exempt from CORS response checks — the mock routes here grant nothing, and this
        // test is about the Origin *value*, not enforcement. The chain is home → away → home:
        // away redirecting elsewhere is the tainting hop.
        let init = RequestInit::get(HeaderMap::new())
            .with_fetch_metadata(RequestDestination::Empty, RequestMode::Websocket, false)
            .with_mixed_content(
                Some(home.base_url().origin()),
                MixedContentPolicy::default(),
            );
        assert_eq!(header_seen_by_server(&away, "/hop", init).await, "null");
    }

    /// A block must be observable, not just returned. Devtools has no other way to report why a
    /// resource never loaded, and nothing else in the test suite asserts the event is emitted.
    #[tokio::test(flavor = "current_thread")]
    async fn blocking_emits_a_blocked_event() {
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.example.com/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::MixedContent));
    }

    /// The URL allowlist rejection must be observable too — same helper, same guarantee.
    #[tokio::test(flavor = "current_thread")]
    async fn url_filter_block_emits_a_blocked_event() {
        let srv = server().await;
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy {
                url_allowed: Box::new(|_| false),
                ..NetPolicy::default()
            },
        )
        .await;

        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::UrlPolicy));
    }

    /// Regression: `url_allowed` must see the post-upgrade URL. An embedder that rejects plain
    /// http would otherwise kill a request the upgrade would have made https — and the two check
    /// sites (scheduler pre-flight and redirect loop) must agree on that.
    #[tokio::test(flavor = "current_thread")]
    async fn url_allowlist_vets_the_upgraded_url() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();

        let _ = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.invalid/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Upgrade,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy {
                url_allowed: Box::new(move |u| {
                    seen_cb.lock().unwrap().push(u.to_string());
                    true
                }),
                ..NetPolicy::default()
            },
        )
        .await;

        assert_eq!(
            *seen.lock().unwrap(),
            vec!["https://insecure.invalid/a.js"],
            "the allowlist must be shown the upgraded URL, never the http original"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_headers_are_sent() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        // Just verify the request completes successfully with custom headers
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    // Body assembly / READ_CHUNK reservation path.

    /// A large body with no Content-Length (chunked) forces `initial_cap == 0`, so every byte of
    /// growth goes through the `reserve(READ_CHUNK)` guard across many loop iterations. Verifies
    /// the loop never mistakes a full buffer for EOF and assembles all 64 KiB in order.
    #[tokio::test(flavor = "current_thread")]
    async fn large_chunked_body_without_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 64 * 1024);
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// A chunked body of exactly `READ_CHUNK` bytes lands on the reservation boundary: after the
    /// data is read the spare capacity is fully consumed, and the next `read_buf` must reserve more
    /// before it can observe the real EOF. Guards against an off-by-one false EOF at the boundary.
    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_exactly_read_chunk_size_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/exact-chunk"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), super::READ_CHUNK);
        assert!(body.iter().all(|&b| b == b'Y'));
    }

    /// A body larger than READ_CHUNK *with* Content-Length exercises the pre-sized path (buffer
    /// seeded to the full length up front). The reservation guard should rarely fire, and the body
    /// must still come back byte-for-byte.
    #[tokio::test(flavor = "current_thread")]
    async fn large_body_with_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/large-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(64 * 1024));
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// `max_bytes` is checked with a strict `>`, so a body whose length equals the cap exactly must
    /// succeed. Boundary partner to `fetch_complete_max_bytes_exceeded`.
    #[tokio::test(flavor = "current_thread")]
    async fn max_bytes_equal_to_body_size_succeeds() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(12 * 1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
    }

    /// A response whose Content-Length already exceeds `max_bytes` is rejected right after the
    /// header/peek phase, before any body bytes beyond the peek are read.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_rejected_before_body_read() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("content-length"), "unexpected error: {msg}");
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    }

    /// With no `max_bytes`, a hostile Content-Length must not drive the buffer pre-allocation
    /// (it is clamped to MAX_PREALLOC). The connection then drops, so the fetch surfaces a read
    /// error instead of attempting a multi-terabyte allocation.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_does_not_preallocate() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    /// A body larger than MAX_PREALLOC still assembles correctly: the pre-allocation is clamped,
    /// and the read loop grows the buffer as real bytes arrive.
    #[tokio::test(flavor = "current_thread")]
    async fn body_larger_than_prealloc_cap_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/xl-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(2 * 1024 * 1024));
        assert_eq!(&body[..], pattern(2 * 1024 * 1024).as_slice());
    }

    /// A cookie set on an intermediate 302 must be reported via `on_cookies` before the next hop,
    /// and the next hop must carry the updated jar contents instead of a stale Cookie header.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_reaches_jar_and_next_hop() {
        let srv = server().await;

        type ReceivedCookies = Vec<(Url, Vec<String>)>;
        let jar: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let received: Arc<std::sync::Mutex<ReceivedCookies>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let jar_read = jar.clone();
        let jar_write = jar.clone();
        let received_sink = received.clone();
        let policy = NetPolicy {
            cookies_for: Box::new(move |_| jar_read.lock().unwrap().clone()),
            on_cookies: Box::new(move |url, values| {
                received_sink
                    .lock()
                    .unwrap()
                    .push((url.clone(), values.iter().map(|v| v.to_string()).collect()));
                // Store only the name=value part, as a real jar would.
                if let Some(v) = values.first() {
                    let nv = v.split(';').next().unwrap_or(v).trim().to_string();
                    *jar_write.lock().unwrap() = Some(nv);
                }
            }),
            ..NetPolicy::default()
        };

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        // The /whoami route echoes back the Cookie header the follow-up request carried.
        assert_eq!(&body[..], b"session=abc123");

        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.path(), "/login");
        assert_eq!(received[0].1, vec!["session=abc123; Path=/".to_string()]);
    }

    /// `on_protocol` is called for every hop (the 302 and the final 200), with that hop's URL.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_reports_protocol_of_every_hop() {
        let srv = server().await;
        let seen: Arc<std::sync::Mutex<Vec<(String, http::Version)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_protocol_sink(Box::new(move |url, version| {
            sink.lock().unwrap().push((url.path().to_string(), version));
        }));

        let (meta, _) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);

        let seen = seen.lock().unwrap();
        // test server is plain http, so 1.1 on both hops
        assert_eq!(
            *seen,
            vec![
                ("/login".to_string(), http::Version::HTTP_11),
                ("/whoami".to_string(), http::Version::HTTP_11),
            ]
        );
    }

    /// When a redirect hop sets cookies but no jar is wired up, the pre-existing Cookie header is
    /// dropped for subsequent hops rather than resending a value the server just replaced.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_drops_stale_cookie_header() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "stale=1".parse().unwrap());

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"");
    }

    /// base64("user:pass"), the credentials the auth routes below accept.
    const GOOD_AUTH: &str = "Basic dXNlcjpwYXNz";

    async fn auth_server() -> crate::net::test_support::TestServerHandle {
        TestServer::new()
            .route(
                "/protected",
                RouteConfig::require_auth(
                    r#"Basic realm="Secure Area""#,
                    GOOD_AUTH,
                    b"secret".to_vec(),
                ),
            )
            .route(
                "/via-proxy",
                RouteConfig::require_proxy_auth(r#"Basic realm="corp""#, GOOD_AUTH, b"ok".to_vec()),
            )
            .start()
            .await
    }

    /// Run one fetch against the auth server with the given request and policy.
    async fn auth_fetch(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
        policy: NetPolicy,
        observer: Arc<dyn NetObserver + Send + Sync>,
    ) -> Result<(FetchResultMeta, Bytes), NetError> {
        super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer,
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
    }

    /// A policy whose hook answers every challenge with the given credentials, counting calls.
    fn answering_policy(credentials: Credentials) -> (NetPolicy, Arc<Mutex<Vec<AuthChallenge>>>) {
        let seen: Arc<Mutex<Vec<AuthChallenge>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_auth_challenge_fn(Box::new(move |challenge| {
            sink.lock().unwrap().push(challenge.clone());
            Some(credentials.clone())
        }));
        (policy, seen)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_basic_challenge_is_answered_and_the_hop_retried() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        // The 401 and the authenticated retry.
        assert_eq!(srv.hit_count("/protected"), 2);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].scheme, AuthScheme::Basic);
        assert_eq!(seen[0].realm.as_deref(), Some("Secure Area"));
        assert_eq!(seen[0].target, AuthTarget::Server);
        assert_eq!(seen[0].attempt, 0);

        let events = rec.auth_required();
        assert_eq!(events.len(), 1);
        assert!(events[0].1, "the challenge was answered");
        assert_eq!(events[0].0.len(), 1);
    }

    /// Without credentials the 401 itself is the response.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unanswered_challenge_is_returned_to_the_caller() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            NetPolicy::default(),
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);

        // The challenge still reaches the observer, so an embedder that can only answer
        // asynchronously can prompt and re-submit.
        let events = rec.auth_required();
        assert_eq!(events.len(), 1);
        assert!(!events[0].1);
        assert_eq!(events[0].0[0].realm.as_deref(), Some("Secure Area"));
    }

    /// Credentials the hook supplied are remembered once they work, so the second request answers
    /// the challenge without asking again.
    #[tokio::test(flavor = "current_thread")]
    async fn accepted_credentials_are_remembered_in_the_store() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());

        for expected_calls in [1, 1] {
            let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
            let policy = policy.with_credential_store(Some(store.clone()));
            let (meta, _) = auth_fetch(
                &srv,
                "/protected",
                RequestInit::get(HeaderMap::new()),
                policy,
                observer(),
            )
            .await
            .unwrap();
            assert_eq!(meta.status, 200);
            // The hook answers the first request; the second is served from the store, which is
            // why each fresh hook here sees at most one call.
            assert!(seen.lock().unwrap().len() <= expected_calls);
        }

        assert_eq!(store.len(), 1);
        let space = ProtectionSpace {
            target: AuthTarget::Server,
            scheme: AuthScheme::Basic,
            origin: Some(srv.url("/protected").origin().ascii_serialization()),
            realm: "Secure Area".into(),
        };
        assert_eq!(
            store.credentials_for(&space),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// Stored credentials the server rejects are dropped, and the hook is asked for better ones.
    #[tokio::test(flavor = "current_thread")]
    async fn rejected_stored_credentials_are_forgotten_and_replaced() {
        let srv = auth_server().await;
        let space = ProtectionSpace {
            target: AuthTarget::Server,
            scheme: AuthScheme::Basic,
            origin: Some(srv.url("/protected").origin().ascii_serialization()),
            realm: "Secure Area".into(),
        };
        let store = Arc::new(InMemoryCredentialStore::new());
        store.store(space.clone(), Credentials::basic("user", "stale"));

        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
        let policy = policy.with_credential_store(Some(store.clone()));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        // Unauthenticated, stale password, good password.
        assert_eq!(srv.hit_count("/protected"), 3);

        // The hook was only consulted after the stored password had been rejected.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].attempt, 1);
        assert_eq!(
            store.credentials_for(&space),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// An embedder that keeps handing back credentials the server refuses must not loop forever.
    #[tokio::test(flavor = "current_thread")]
    async fn the_retry_gives_up_after_max_attempts() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "wrong"));

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        // The unauthenticated request plus MAX_AUTH_ATTEMPTS answers to it.
        assert_eq!(srv.hit_count("/protected"), 1 + MAX_AUTH_ATTEMPTS as usize);
        assert_eq!(seen.lock().unwrap().len(), MAX_AUTH_ATTEMPTS as usize);

        let events = rec.auth_required();
        assert_eq!(events.len(), 1 + MAX_AUTH_ATTEMPTS as usize);
        assert!(
            !events.last().unwrap().1,
            "the last challenge was given up on"
        );
    }

    /// A `407` is answered with `Proxy-Authorization`, and its protection space is not tied to
    /// the origin the request was going to.
    #[tokio::test(flavor = "current_thread")]
    async fn a_proxy_challenge_is_answered_with_proxy_authorization() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
        let policy = policy.with_credential_store(Some(store.clone()));

        let (meta, body) = auth_fetch(
            &srv,
            "/via-proxy",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"ok");
        assert_eq!(srv.hit_count("/via-proxy"), 2);
        assert_eq!(seen.lock().unwrap()[0].target, AuthTarget::Proxy);
        assert_eq!(
            store.credentials_for(&ProtectionSpace {
                target: AuthTarget::Proxy,
                scheme: AuthScheme::Basic,
                origin: None,
                realm: "corp".into(),
            }),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// `RequestCredentials::Omit` means no credentials of any kind, so the challenge is not even
    /// offered to the embedder.
    #[tokio::test(flavor = "current_thread")]
    async fn a_credential_less_request_is_never_authenticated() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()).with_credentials(RequestCredentials::Omit),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);
        assert!(seen.lock().unwrap().is_empty());
        // Still reported, so the caller can see why the request came back a 401.
        assert_eq!(rec.auth_required().len(), 1);
    }

    /// `Authorization` is not CORS-safelisted, so a cors-tainted chain is left alone instead of
    /// getting credentials added behind the preflight's back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cors_request_is_not_authenticated() {
        let srv = auth_server().await;
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let init = RequestInit::get(HeaderMap::new())
            .with_mixed_content(
                Some(Url::parse("http://other.test/").unwrap().origin()),
                MixedContentPolicy::Allow,
            )
            .with_fetch_metadata(RequestDestination::Empty, RequestMode::NoCors, false);

        let (meta, _) = auth_fetch(&srv, "/protected", init, policy, observer())
            .await
            .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);
        assert!(seen.lock().unwrap().is_empty());
    }

    /// The retry rebuilds the request, body included.
    #[tokio::test(flavor = "current_thread")]
    async fn a_challenged_post_is_replayed_with_its_body() {
        let srv = auth_server().await;
        let (policy, _) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::post(HeaderMap::new(), Bytes::from_static(b"payload")),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        assert_eq!(srv.hit_count("/protected"), 2);
    }

    /// A `Raw` answer is used but not remembered; the hook recomputes it for the next challenge.
    #[tokio::test(flavor = "current_thread")]
    async fn a_computed_answer_is_used_but_not_stored() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, seen) = answering_policy(Credentials::Raw(GOOD_AUTH.into()));
        let policy = policy.with_credential_store(Some(store.clone()));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(store.is_empty(), "a computed answer is not replayable");
    }

    /// Credentials that cannot become a header value are not an answer, so the next challenge
    /// gets a turn: here the `Basic` one the server also offered.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unusable_answer_falls_through_to_the_next_challenge() {
        let srv = TestServer::new()
            .route(
                "/protected",
                RouteConfig::require_auth(
                    r#"Digest realm="d", nonce="n", Basic realm="Secure Area""#,
                    GOOD_AUTH,
                    b"secret".to_vec(),
                ),
            )
            .start()
            .await;

        let seen: Arc<Mutex<Vec<AuthChallenge>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_auth_challenge_fn(Box::new(move |challenge| {
            sink.lock().unwrap().push(challenge.clone());
            match challenge.scheme {
                // A colon in the user-id makes these unrepresentable.
                AuthScheme::Digest => Some(Credentials::basic("bad:name", "x")),
                _ => Some(Credentials::basic("user", "pass")),
            }
        }));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "both challenges were offered");
        assert_eq!(seen[0].scheme, AuthScheme::Digest);
        assert_eq!(seen[1].scheme, AuthScheme::Basic);
    }

    /// A policy with a fresh in-memory cache, plus the cache itself.
    fn caching_policy() -> (NetPolicy, Arc<crate::net::cache::InMemoryHttpCache>) {
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());
        (NetPolicy::default().with_cache(Some(cache.clone())), cache)
    }

    /// Fetch `path` through the policy, returning the metadata and body.
    async fn cache_fetch(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
        policy: NetPolicy,
        observer: Arc<dyn NetObserver + Send + Sync>,
    ) -> (FetchResultMeta, Bytes) {
        super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer,
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap()
    }

    /// A fresh stored response answers the next fetch without a request going out.
    #[tokio::test(flavor = "current_thread")]
    async fn a_fresh_response_is_served_from_the_cache() {
        let srv = TestServer::new()
            .route(
                "/fresh",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(60, b"v1".to_vec()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (meta, body) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, observer()).await;
        assert_eq!(meta.status, 200);
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(cache.len(), 1);

        let (policy, _) = (NetPolicy::default().with_cache(Some(cache.clone())), ());
        let rec = Arc::new(RecordingObserver::new());
        let (meta, body) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, rec.clone()).await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-1", "the stored body, not a second request");
        assert_eq!(srv.hit_count("/fresh"), 1, "the server was not asked again");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Hit]);
    }

    /// A stale entry is revalidated, and a `304` reuses the stored body.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_response_is_revalidated_and_a_304_reuses_the_body() {
        let srv = TestServer::new()
            .route(
                "/stale",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(0, b"original".to_vec()).with_etag("\"v1\""),
                ),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (_, body) =
            cache_fetch(&srv, "/stale", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"original");
        assert_eq!(cache.len(), 1);

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) =
            cache_fetch(&srv, "/stale", RequestInit::default(), policy, rec.clone()).await;

        // The server was asked, answered 304, and the stored body came back.
        assert_eq!(srv.hit_count("/stale"), 2);
        assert_eq!(meta.status, 200, "the 304 is not what the caller sees");
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"original");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Validated]);
    }

    /// A stale entry the server cannot confirm is refetched, and the fresh response takes its
    /// place instead of piling up beside it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_entry_without_a_validator_is_refetched_and_replaced() {
        let srv = TestServer::new()
            .route(
                "/changing",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(0, Vec::new()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        let (_, body) = cache_fetch(
            &srv,
            "/changing",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(cache.len(), 1);

        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/changing",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/changing"), 2);
        assert_eq!(cache.len(), 1, "replaced, not piled up");
    }

    /// `no-store` keeps a response out of the cache; `Cache-Control` with nothing to go on keeps
    /// it out too.
    #[tokio::test(flavor = "current_thread")]
    async fn responses_that_may_not_be_stored_are_not_stored() {
        let srv = TestServer::new()
            .route(
                "/no-store",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(60, b"x".to_vec()).with_cache_control("no-store"),
                ),
            )
            .route("/plain", RouteConfig::ok(b"x"))
            .start()
            .await;
        let (policy, cache) = caching_policy();
        cache_fetch(
            &srv,
            "/no-store",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert!(cache.is_empty());

        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        cache_fetch(&srv, "/plain", RequestInit::default(), policy, observer()).await;
        assert!(
            cache.is_empty(),
            "no directives and no validator: nothing to store"
        );
    }

    /// A cacheable redirect is stored, so the next fetch skips the hop entirely.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cacheable_redirect_is_stored_and_reused() {
        let target = TestServer::new()
            .route("/target", RouteConfig::ok(b"arrived"))
            .start()
            .await;
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::RedirectAbsoluteWithHeaders {
                    headers: vec![("Cache-Control".into(), "max-age=600".into())],
                    target: target.url("/target").to_string(),
                },
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (_, body) = cache_fetch(&srv, "/hop", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"arrived");
        assert_eq!(srv.hit_count("/hop"), 1);
        assert_eq!(cache.len(), 1, "the redirect itself is the entry");

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (_, body) =
            cache_fetch(&srv, "/hop", RequestInit::default(), policy, rec.clone()).await;

        assert_eq!(&body[..], b"arrived");
        assert_eq!(srv.hit_count("/hop"), 1, "the redirect came from the cache");
        assert_eq!(
            target.hit_count("/target"),
            2,
            "the target itself is not cacheable"
        );
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Hit]);
    }

    /// An unsafe method drops what is stored for the URL it changed.
    #[tokio::test(flavor = "current_thread")]
    async fn a_post_invalidates_the_stored_response() {
        let srv = TestServer::new()
            .route(
                "/resource",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, b"v1".to_vec())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        cache_fetch(
            &srv,
            "/resource",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert_eq!(cache.len(), 1);

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        cache_fetch(
            &srv,
            "/resource",
            RequestInit::post(HeaderMap::new(), Bytes::from_static(b"update")),
            policy,
            rec.clone(),
        )
        .await;

        assert!(cache.is_empty(), "the stored response is now wrong");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Invalidated]);
    }

    /// The cache modes reach past the normal rules in both directions.
    #[tokio::test(flavor = "current_thread")]
    async fn cache_modes_bypass_and_force() {
        let srv = TestServer::new()
            .route(
                "/mode",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        let (_, body) =
            cache_fetch(&srv, "/mode", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"hit-1");

        // Reload ignores the fresh entry and stores what comes back.
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/mode",
            RequestInit::default().with_cache(CacheMode::Reload, true),
            policy,
            observer(),
        )
        .await;
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/mode"), 2);

        // Force-cache uses the stored response even when the request would normally revalidate.
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/mode",
            RequestInit::default().with_cache(CacheMode::ForceCache, true),
            policy,
            observer(),
        )
        .await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/mode"), 2);
    }

    /// `only-if-cached` fails rather than reaching the network.
    #[tokio::test(flavor = "current_thread")]
    async fn only_if_cached_without_an_entry_is_refused() {
        let srv = TestServer::new()
            .route("/nothing", RouteConfig::ok(b"x"))
            .start()
            .await;
        let (policy, _cache) = caching_policy();
        let rec = Arc::new(RecordingObserver::new());

        let err = super::fetch_response_complete(
            client(),
            srv.url("/nothing"),
            RequestInit::default().with_cache(CacheMode::OnlyIfCached, true),
            CancellationToken::new(),
            rec.clone(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await;

        match err {
            Err(NetError::Blocked { reason, .. }) => assert_eq!(reason, BlockReason::NotCached),
            other => panic!("expected a NotCached block, got {other:?}"),
        }
        assert_eq!(srv.hit_count("/nothing"), 0, "nothing went out");
        assert_eq!(rec.blocked_reason(), Some(BlockReason::NotCached));
    }

    /// `Vary` keeps one entry per set of request headers the response depends on.
    #[tokio::test(flavor = "current_thread")]
    async fn vary_stores_one_entry_per_variant() {
        let srv = TestServer::new()
            .route(
                "/varies",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(600, Vec::new())
                        .counting()
                        .with_vary("accept-language"),
                ),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let fetch = |policy: NetPolicy, language: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_LANGUAGE, language.parse().unwrap());
            (policy, RequestInit::get(headers))
        };

        let (policy, init) = fetch(policy, "nl");
        let (_, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert_eq!(&body[..], b"hit-1");

        // A different language is a different variant, so it goes to the server.
        let (policy, init) = fetch(NetPolicy::default().with_cache(Some(cache.clone())), "en");
        let (_, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(cache.len(), 2);

        // The first variant is still there.
        let (policy, init) = fetch(NetPolicy::default().with_cache(Some(cache.clone())), "nl");
        let (meta, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(srv.hit_count("/varies"), 2);
    }

    /// A body past the cache's ceiling is delivered as usual, and not stored.
    #[tokio::test(flavor = "current_thread")]
    async fn a_body_over_the_ceiling_is_not_stored() {
        let big = pattern(64 * 1024);
        let srv = TestServer::new()
            .route(
                "/big",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, big.clone())),
            )
            .start()
            .await;
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::with_limits(
            1024 * 1024,
            1024,
        ));
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));

        let (_, body) = cache_fetch(&srv, "/big", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], big.as_slice(), "the caller still gets it all");
        assert!(cache.is_empty());
    }

    /// The streaming path fills the cache too: the body is collected as the caller reads it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_streamed_body_is_stored_once_it_is_read_to_the_end() {
        let body = pattern(32 * 1024);
        let srv = TestServer::new()
            .route(
                "/stream",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, body.clone())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let ResponseTop {
            peek_buf,
            mut reader,
            ..
        } = super::fetch_response_top(
            client(),
            srv.url("/stream"),
            RequestInit::default(),
            CancellationToken::new(),
            observer(),
            policy,
        )
        .await
        .unwrap();

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        let mut received = peek_buf.as_slice().to_vec();
        received.extend_from_slice(&rest);
        assert_eq!(received, body);

        // Stored complete, peek window included.
        let stored = cache.get(&crate::net::cache::CacheKey::new(
            &Method::GET,
            &srv.url("/stream"),
        ));
        assert_eq!(stored.len(), 1);
        assert_eq!(&stored[0].body[..], body.as_slice());
    }

    /// A stream the caller abandons mid-body leaves nothing behind.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unfinished_body_is_not_stored() {
        let body = pattern(32 * 1024);
        let srv = TestServer::new()
            .route(
                "/partial",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, body.clone())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let ResponseTop { mut reader, .. } = super::fetch_response_top(
            client(),
            srv.url("/partial"),
            RequestInit::default(),
            CancellationToken::new(),
            observer(),
            policy,
        )
        .await
        .unwrap();

        // Read a little and drop the reader.
        let mut scratch = vec![0u8; 128];
        let _ = reader.read(&mut scratch).await.unwrap();
        drop(reader);

        assert!(cache.is_empty(), "an incomplete body is not a cache entry");
    }
}

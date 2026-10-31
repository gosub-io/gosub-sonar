//! The redirect chain behind `fetch_response_top`: each hop checked, sent and followed in
//! turn, with what the chain carries from one hop to the next in [`HopChain`].

use super::{
    blocked, credentials_for_challenges, hop_checks, location_text, modified, normalize_method,
    origin_peer, report_set_cookie, send_error, strip_url_credentials, trimmed_values, AuthSlot,
    ChainOutcome, HopCheck, HopResponse, NetPolicy, RequestInit, MAX_REDIRECTS, REFERRER_POLICY,
    SENSITIVE_REDIRECT_HEADERS,
};
#[cfg(not(target_arch = "wasm32"))]
use super::{
    ip_literal, order_hop_headers, over_accepted_override, without_forbidden, PendingStore,
    PreflightGrant, Revalidation, NO_CLIENT_DEADLINE,
};
use crate::net::auth::{self, AuthTarget, MAX_AUTH_ATTEMPTS};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::cache::{self, CacheDecision, CacheEntry, CacheKey, CacheMode, CacheOutcome};
use crate::net::cors::{self, CorsError, ResponseTainting};
use crate::net::events::NetEvent;
use crate::net::fetch_metadata::{self, RequestMode, SecFetchSite};
use crate::net::fetcher_context::CookieHop;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::hsts;
use crate::net::mixed_content::{self, MixedContentAction};
use crate::net::observer::NetObserver;
use crate::net::referrer::{self, ReferrerPolicy};
use crate::net::transport::TransportError;
use crate::net::types::{
    BlockReason, NetError, RequestBody, RequestChange, RequestCredentials, UpgradeReason,
};
use anyhow::anyhow;
#[cfg(not(target_arch = "wasm32"))]
use bytes::Bytes;
use http::{header, HeaderMap, Method};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use url::{Origin, Url};

/// What every hop of a chain is fetched with.
struct ChainEnv<'a> {
    client: &'a reqwest::Client,
    // Without the method, headers, body and revalidation: those went into the `HopChain`.
    init: &'a RequestInit,
    cancel: &'a CancellationToken,
    observer: &'a Arc<dyn NetObserver + Send + Sync>,
    policy: &'a NetPolicy,
    // The credentialed CORS rules key on the request's credentials *mode*, not on whether
    // cookies were actually attached on a given hop. Only the native checks consult it — on
    // wasm32 the browser enforces the credentialed rules itself.
    #[cfg(not(target_arch = "wasm32"))]
    credentials_include: bool,
    // Whether a hop may be answered stale and revalidated behind it: only for a request with a
    // client (Fetch, HTTP-network-or-cache fetch), one with an origin here, and only with
    // something to revalidate it.
    #[cfg(not(target_arch = "wasm32"))]
    background: bool,
    // The chain is a background revalidation.
    #[cfg(not(target_arch = "wasm32"))]
    resumed: bool,
}

/// What the stages before a hop's send worked out for it.
struct HopPlan {
    attach_credentials: bool,
    #[cfg(not(target_arch = "wasm32"))]
    cache: CacheLookup,
    #[cfg(not(target_arch = "wasm32"))]
    preflight: Option<PreflightGrant>,
    // Where a background revalidation of this hop would start, if it may have one.
    #[cfg(not(target_arch = "wasm32"))]
    revalidation: Option<Revalidation>,
}

/// The response a hop got, and when it was asked for and received, for the age of a cache entry
/// made from it (RFC 9111 §4.2.3).
struct HopExchange {
    response: HopResponse,
    #[cfg(not(target_arch = "wasm32"))]
    requested_at: chrono::DateTime<chrono::Utc>,
    #[cfg(not(target_arch = "wasm32"))]
    received_at: chrono::DateTime<chrono::Utc>,
}

/// The cache partition of a hop: one that carries a jar's cookies is cached for that jar alone.
#[cfg(not(target_arch = "wasm32"))]
fn cache_partition(policy: &NetPolicy, attach_credentials: bool) -> &str {
    if attach_credentials {
        policy.cache_partition.as_str()
    } else {
        ""
    }
}

/// The request as its redirect chain carries it from hop to hop: what a redirect changes, and
/// what each hop works out from the ones before it.
struct HopChain {
    url: Url,
    method: Method,
    headers: HeaderMap,
    body: Option<RequestBody>,
    // Where the chain has been: every hop's URL before the current one (Fetch, request's URL
    // list), for the cookie hook to judge `SameSite` across the chain.
    url_list: Vec<Url>,
    // The request's referrer as the chain has left it (Fetch, main fetch step 9): each hop
    // determines its `Referer` from what the hop before it sent, not from the document URL, so
    // a referrer once cut down to its origin stays cut down, and one once withheld stays
    // withheld, however the chain moves or what policy a redirect announces.
    referrer: Option<Url>,
    // A redirect may replace this for the remaining hops (Fetch, HTTP-redirect fetch).
    referrer_policy: ReferrerPolicy,
    // `Sec-Fetch-Site` describes the whole chain, not the current hop: it starts at same-origin
    // and can only degrade, so a detour through a foreign site is still visible when the chain
    // lands back home.
    site: SecFetchSite,
    // The tainted origin flag (Fetch, HTTP-redirect fetch): once set, `Origin` is sent as the
    // literal `null` for every remaining hop.
    origin_tainted: bool,
    // `RequestChange::OriginTainted` is reported once per chain, on the first `null` it causes.
    taint_reported: bool,
    // Whether the `Cookie` in `headers` came from the jar rather than from the caller.
    cookie_from_jar: bool,
    // Response tainting (Fetch §2.2.5): basic until the chain leaves the initiating origin,
    // then cors/opaque per the request mode — and it stays there even if a detour redirects
    // back home, which is why the CORS check keys on this and not on the hop's URL.
    tainting: ResponseTainting,
    // The redirects followed so far.
    redirects: usize,
    // Armed by the first redirect; `None` until then, and for good without a budget.
    redirect_deadline: Option<tokio::time::Instant>,
}

/// What the cache makes of a hop before it is sent.
#[cfg(not(target_arch = "wasm32"))]
struct CacheLookup {
    // A stored response that answers the hop without a request.
    hit: Option<Arc<CacheEntry>>,
    // `hit` is stale, and revalidated behind the hop.
    stale: bool,
    // The entry the conditional headers revalidate.
    revalidating: Option<Arc<CacheEntry>>,
    conditional: HeaderMap,
    // The mode as Fetch handles it: a caller's own condition turns `Default` into `NoStore`.
    mode: CacheMode,
}

impl HopChain {
    /// The chain before its first hop: the caller's request, or, for a background revalidation,
    /// the chain where the hop it revalidates left it.
    fn start(
        url: Url,
        init: &mut RequestInit,
        observer: &Arc<dyn NetObserver + Send + Sync>,
    ) -> Result<Self, NetError> {
        let method = normalize_method(std::mem::take(&mut init.method));
        let mut headers = trimmed_values(std::mem::take(&mut init.headers));
        // The message framing is the body's (RFC 9112 §6): a caller's `Content-Length` that does
        // not match it cuts the body short or leaves the server waiting for bytes that never come,
        // and a `Transfer-Encoding` would contradict the one the connection picks. Web content
        // may not set any forbidden request-header (Fetch §2.2.2): those are the user agent's,
        // and the CORS rules below take that for granted.
        let mut removed: Vec<header::HeaderName> = Vec::new();
        for name in headers.keys() {
            let forbidden = init.origin.is_some()
                && headers
                    .get_all(name)
                    .iter()
                    .any(|value| cors::is_forbidden_request_header_value(name, value));
            let framing = *name == header::CONTENT_LENGTH || *name == header::TRANSFER_ENCODING;
            if forbidden || framing {
                removed.push(name.clone());
            }
        }
        for name in &removed {
            headers.remove(name);
        }
        if !removed.is_empty() {
            modified(
                observer,
                &url,
                RequestChange::HeadersRemoved { headers: removed },
            );
        }
        // Set here rather than left to the client, which would add it while executing the request,
        // after `RequestSent` was reported. Exactly the codings `net::decode` undoes; a caller that
        // asked for raw bytes advertises nothing it cannot decode.
        //
        // A range counts bytes of the representation as it is sent, so a ranged request asks for
        // it unencoded (Fetch §4.6), appended to a value the caller set itself.
        if headers.contains_key(header::RANGE) {
            headers.append(
                header::ACCEPT_ENCODING,
                header::HeaderValue::from_static("identity"),
            );
        } else if !headers.contains_key(header::ACCEPT_ENCODING) {
            headers.insert(
                header::ACCEPT_ENCODING,
                header::HeaderValue::from_static(if init.auto_decode {
                    "gzip, br, deflate"
                } else {
                    "identity"
                }),
            );
        }
        // Web content may not send these (Fetch §2.2.1). A request without an origin is the
        // embedder's own and may.
        if init.origin.is_some() && cors::is_forbidden_method(&method) {
            return Err(blocked(observer, url, BlockReason::ForbiddenMethod));
        }

        let mut chain = HopChain {
            url,
            method,
            headers,
            body: init.body.take(),
            url_list: Vec::new(),
            referrer: init.referrer.clone(),
            referrer_policy: init.referrer_policy,
            site: SecFetchSite::SameOrigin,
            origin_tainted: false,
            taint_reported: false,
            cookie_from_jar: false,
            tainting: ResponseTainting::Basic,
            redirects: 0,
            redirect_deadline: None,
        };
        // A background revalidation goes on from the hop it revalidates, as the redirect chain had
        // left it (Fetch revalidates with a clone of the request). Its URL, method and headers come
        // in as the request's own; the rest of the chain is taken up here.
        if let Some(from) = init.background_revalidation.take() {
            chain.url_list = from.url_list;
            chain.referrer = from.referrer;
            chain.referrer_policy = from.referrer_policy;
            chain.site = from.site;
            chain.origin_tainted = from.origin_tainted;
            chain.tainting = from.tainting;
            chain.redirects = from.redirects;
            // Already redirected: the budget runs from here, as it would from a redirect.
            if chain.redirects > 0 {
                chain.redirect_deadline = init
                    .redirect_timeout
                    .map(|budget| tokio::time::Instant::now() + budget);
            }
        }
        Ok(chain)
    }

    /// Where a background revalidation of this hop would start: the chain as it stands before
    /// the hop does anything.
    #[cfg(not(target_arch = "wasm32"))]
    fn revalidation(&self) -> Revalidation {
        Revalidation {
            url: self.url.clone(),
            method: self.method.clone(),
            headers: without_forbidden(&self.headers),
            url_list: self.url_list.clone(),
            referrer: self.referrer.clone(),
            referrer_policy: self.referrer_policy,
            site: self.site,
            origin_tainted: self.origin_tainted,
            tainting: self.tainting,
            redirects: self.redirects,
        }
    }

    /// HSTS upgrade first: a stored policy forces `https` for a known host regardless of the
    /// mixed-content setting. `hop_checks` then re-checks the scheme and mixed content on the
    /// (possibly upgraded) URL and runs `url_allowed` last, so the policy hook always vets the
    /// URL actually sent. All of this re-runs on every hop: an https document may be redirected
    /// onto plain http, which the caller cannot see and so cannot check for itself.
    ///
    /// Returns the URL as it stood before an HSTS rewrite, kept for the referrer: Fetch
    /// determines the referrer (main fetch step 9) before it applies HSTS (step 11), so an
    /// `https` document linking to `http://` is a downgrade for the referrer even when HSTS then
    /// sends the request over TLS.
    fn secure_url(&mut self, env: &ChainEnv<'_>) -> Result<Option<Url>, NetError> {
        #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
        let mut before_hsts: Option<Url> = None;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = env.policy.hsts {
            if hsts::should_upgrade(store.as_ref(), &self.url, chrono::Utc::now()) {
                before_hsts = Some(self.url.clone());
                let upgraded = hsts::upgrade(&self.url);
                env.observer.on_event(NetEvent::SecurityUpgraded {
                    from: self.url.clone(),
                    to: upgraded.clone(),
                    reason: UpgradeReason::Hsts,
                });
                self.url = upgraded;
            }
        }

        match hop_checks(
            &self.url,
            env.init.mixed_content,
            env.init.origin.as_ref(),
            env.init.destination,
            &env.policy.allowed_bad_ports,
            &|u| (env.policy.url_allowed)(u),
        ) {
            HopCheck::Reject(reason) => Err(blocked(env.observer, self.url.clone(), reason)),
            HopCheck::Proceed(target) => {
                if target != self.url {
                    env.observer.on_event(NetEvent::SecurityUpgraded {
                        from: self.url.clone(),
                        to: target.clone(),
                        reason: UpgradeReason::MixedContent,
                    });
                    self.url = target;
                }
                Ok(before_hsts)
            }
        }
    }

    /// The client connects to an IP literal without asking the resolver, so a policy in it
    /// would never see e.g. 169.254.169.254. Ask it here with the literal as the name; an Err
    /// refuses the hop like a refused name would. The returned addresses are unused.
    #[cfg(not(target_arch = "wasm32"))]
    async fn check_ip_literal(&self, env: &ChainEnv<'_>) -> Result<(), NetError> {
        let (Some(resolver), Some(literal)) =
            (env.policy.dns_resolver.as_ref(), ip_literal(&self.url))
        else {
            return Ok(());
        };
        let refused = tokio::select! {
            _ = env.cancel.cancelled() => {
                env.observer.on_event(NetEvent::Cancelled { url: self.url.clone(), reason: "all callers cancelled" });
                return Err(NetError::Cancelled("all callers cancelled".into()));
            }
            r = resolver.resolve(&literal) => r.err(),
        };
        match refused {
            Some(e) => Err(NetError::Transport(TransportError {
                kind: crate::net::transport::TransportErrorKind::Connect,
                message: format!("dns error: {e}"),
            })),
            None => Ok(()),
        }
    }

    /// CORS regime for this hop (Fetch, main fetch). Only a request with a document context is
    /// subject to it, and only once the chain has left the initiating origin — a tainted chain
    /// counts as having left even when a detour lands back home. Navigations are not
    /// CORS-checked, and a WebSocket server opts in via its own handshake instead.
    fn enter_cors_regime(&mut self, env: &ChainEnv<'_>) -> Result<(), NetError> {
        let Some(ref o) = env.init.origin else {
            return Ok(());
        };
        let has_left_origin = self.origin_tainted || *o != self.url.origin();
        if !has_left_origin {
            return Ok(());
        }
        let refused = match env.init.mode {
            RequestMode::SameOrigin => Some(CorsError::SameOriginMode),
            // A no-cors request may go cross-origin, but only in the shape markup can
            // produce: safelisted method, no headers the fetcher does not own. The
            // response becomes opaque.
            RequestMode::NoCors => {
                self.tainting = ResponseTainting::Opaque;
                if !cors::is_cors_safelisted_method(&self.method) {
                    Some(CorsError::UnsafeMethodForNoCors)
                } else if !cors::unsafe_request_header_names(&self.headers).is_empty() {
                    Some(CorsError::UnsafeHeaderForNoCors)
                } else {
                    None
                }
            }
            RequestMode::Cors => {
                self.tainting = ResponseTainting::Cors;
                None
            }
            RequestMode::Navigate | RequestMode::Websocket => None,
        };
        match refused {
            Some(e) => Err(blocked(
                env.observer,
                self.url.clone(),
                BlockReason::Cors(e),
            )),
            None => Ok(()),
        }
    }

    /// Recomputed per hop from what the last hop sent; see `referrer`. Judged against the URL
    /// before any HSTS rewrite, with only a mixed content upgrade applied, which Fetch makes
    /// first (main fetch step 6); see [`secure_url`](Self::secure_url).
    fn set_referrer(&mut self, env: &ChainEnv<'_>, before_hsts: Option<&Url>) {
        let Some(ref source) = env.init.referrer else {
            return;
        };
        let referrer_target = match before_hsts {
            Some(plain) => {
                match mixed_content::evaluate_for(
                    env.init.mixed_content,
                    env.init.origin.as_ref(),
                    plain,
                    env.init.destination,
                ) {
                    MixedContentAction::Upgrade(upgraded) => upgraded,
                    _ => plain.clone(),
                }
            }
            None => self.url.clone(),
        };
        let determined = self.referrer.as_ref().and_then(|current| {
            referrer::determine(current, self.referrer_policy, &referrer_target)
        });
        let sent = match determined {
            Some(value) => match value.as_str().parse() {
                Ok(header_value) => {
                    self.headers.insert(header::REFERER, header_value);
                    Some(value)
                }
                // A URL that will not go into a header is not worth failing the request over.
                Err(_) => {
                    self.headers.remove(header::REFERER);
                    None
                }
            },
            // Drop any value from an earlier hop: this one is not allowed a referrer.
            None => {
                self.headers.remove(header::REFERER);
                None
            }
        };
        self.referrer = sent.clone();
        // Measured against what would go out with no policy. A source that is never sent
        // (not http or https) has nothing to reduce.
        if let Some(full) = referrer::strip(source) {
            if sent.as_ref() != Some(&full) {
                modified(
                    env.observer,
                    &self.url,
                    RequestChange::ReferrerReduced {
                        from: full,
                        to: sent,
                        policy: self.referrer_policy,
                    },
                );
            }
        }
    }

    /// Origin and Sec-Fetch-* are likewise recomputed per hop. Returns the hop's
    /// `Sec-Fetch-Site`.
    fn set_fetch_metadata(&mut self, env: &ChainEnv<'_>) -> SecFetchSite {
        let hop_site = match env.init.origin {
            Some(ref o) => {
                self.site = self.site.min(fetch_metadata::classify_site(o, &self.url));
                self.site
            }
            // No initiating origin means the request was not triggered by web content.
            None => SecFetchSite::None,
        };
        fetch_metadata::apply_sec_fetch_headers(
            &mut self.headers,
            &self.url,
            env.init.destination,
            env.init.mode,
            hop_site,
            env.init.user_activated,
        );

        // Without an initiating origin there is nothing to compute; a hand-set `Origin`
        // header then goes out verbatim, like a hand-set `Referer`.
        if let Some(ref o) = env.init.origin {
            match fetch_metadata::origin_header_value(
                o,
                self.origin_tainted,
                &self.method,
                env.init.mode,
                self.referrer_policy,
                &self.url,
            ) {
                Some(value) => {
                    // `null` for an origin that has a serialisation is a change worth reporting.
                    // An opaque origin serialises to `null` anyway.
                    if value == "null" && matches!(o, Origin::Tuple(..)) {
                        if self.origin_tainted {
                            if !self.taint_reported {
                                self.taint_reported = true;
                                modified(env.observer, &self.url, RequestChange::OriginTainted);
                            }
                        } else {
                            modified(
                                env.observer,
                                &self.url,
                                RequestChange::OriginHidden {
                                    policy: self.referrer_policy,
                                },
                            );
                        }
                    }
                    match value.parse() {
                        Ok(value) => {
                            self.headers.insert(header::ORIGIN, value);
                        }
                        Err(_) => {
                            self.headers.remove(header::ORIGIN);
                        }
                    }
                }
                None => {
                    self.headers.remove(header::ORIGIN);
                }
            }
        }
        hop_site
    }

    /// CORS preflight (Fetch §4.9): a cross-origin cors-mode request whose method or headers
    /// markup could not produce must be approved by the server before it is sent. Running this
    /// per hop is what modern browsers do after a redirect moves the target — the grant is per
    /// (origin, URL), so a new URL needs its own, usually served from the cache. The OPTIONS
    /// goes out credential-less and never follows redirects (the client has redirects disabled;
    /// a 3xx fails the ok-status test).
    ///
    /// Native-only: on wasm32 the browser preflights itself and does not surface the
    /// `Access-Control-*` response headers this validation would need.
    #[cfg(not(target_arch = "wasm32"))]
    async fn preflight(
        &self,
        env: &ChainEnv<'_>,
        hop_site: SecFetchSite,
    ) -> Result<Option<PreflightGrant>, NetError> {
        if env.init.mode != RequestMode::Cors || self.tainting != ResponseTainting::Cors {
            return Ok(None);
        }
        let Some(ref o) = env.init.origin else {
            return Ok(None);
        };
        let unsafe_names = cors::unsafe_request_header_names(&self.headers);
        if cors::is_cors_safelisted_method(&self.method) && unsafe_names.is_empty() {
            return Ok(None);
        }
        let credentials_include = env.credentials_include;
        let serialized = cors::serialize_origin(o, self.origin_tainted);
        let now = chrono::Utc::now();
        // A grant made with credentials also covers the request without them
        // (Fetch, "method cache entry match"). It is judged by the credentialed
        // rules it was made under, where a `*` is a literal, not a wildcard.
        let granted = env.policy.cors_preflight.as_ref().is_some_and(|cache| {
            let fits = |credentialed: bool| {
                cache
                    .get(&serialized, &self.url, credentialed, now)
                    .is_some_and(|allows| {
                        allows
                            .permits(&self.method, &unsafe_names, credentialed)
                            .is_ok()
                    })
            };
            fits(credentials_include) || (!credentials_include && fits(true))
        });
        if !granted {
            let mut pf_headers = cors::preflight_request_headers(&self.method, &unsafe_names);
            if let Ok(v) = serialized.parse() {
                pf_headers.insert(header::ORIGIN, v);
            }
            // The preflight has the request's referrer (Fetch §4.8 step 1), as this
            // hop computed it above.
            if let Some(referer) = self.headers.get(header::REFERER) {
                pf_headers.insert(header::REFERER, referer.clone());
            }
            fetch_metadata::apply_sec_fetch_headers(
                &mut pf_headers,
                &self.url,
                env.init.destination,
                env.init.mode,
                hop_site,
                false,
            );
            env.observer.on_event(NetEvent::CorsPreflight {
                url: self.url.clone(),
            });
            let pf_started = Instant::now();
            let fut = env
                .client
                .request(Method::OPTIONS, self.url.clone())
                .headers(pf_headers)
                .send();
            tokio::pin!(fut);
            let pf_resp = tokio::select! {
                _ = env.cancel.cancelled() => {
                    env.observer.on_event(NetEvent::Cancelled { url: self.url.clone(), reason: "cancelled during CORS preflight" });
                    return Err(NetError::Cancelled("cancelled during CORS preflight".into()));
                }
                r = &mut fut => r.map_err(|e| send_error(e, &self.url, "CORS preflight request failed", env.observer, env.policy))?
            };
            // Reported before validation: a preflight the server answered cost
            // this round-trip whether or not the answer turns out to permit the
            // request. A rejection is separately reported as `Blocked`.
            env.observer.on_event(NetEvent::CorsPreflightDone {
                url: self.url.clone(),
                elapsed: pf_started.elapsed(),
            });
            let allows = cors::validate_preflight_response(
                pf_resp.status().as_u16(),
                pf_resp.headers(),
                o,
                self.origin_tainted,
                credentials_include,
            )
            .and_then(|allows| {
                allows
                    .permits(&self.method, &unsafe_names, credentials_include)
                    .map(|()| allows)
            })
            .map_err(|e| blocked(env.observer, self.url.clone(), BlockReason::Cors(e)))?;
            if let Some(cache) = env.policy.cors_preflight.as_ref() {
                cache.put(&serialized, &self.url, credentials_include, allows, now);
            }
        }
        Ok(env
            .policy
            .cors_preflight
            .as_ref()
            .map(|cache| PreflightGrant {
                cache: cache.clone(),
                origin: serialized,
                url: self.url.clone(),
                kept: false,
            }))
    }

    /// Whether this hop carries credentials, with the jar's cookies attached when it does.
    ///
    /// Cookies from the jar and an answer to an authentication challenge are both
    /// credentials, so the request's credentials mode gates them together.
    /// Cookies are only injected when no Cookie header is already set; this naturally handles
    /// cross-origin redirects: the cookie was stripped by the redirect, so the jar is
    /// re-queried for the new origin.
    fn attach_credentials(&mut self, env: &ChainEnv<'_>) -> bool {
        let attach = match env.init.credentials {
            RequestCredentials::Include => true,
            RequestCredentials::Omit => false,
            // Without a document origin to compare against, "same-origin" has no meaning and
            // the request is first-party tooling; it keeps its cookies.
            RequestCredentials::SameOrigin => env
                .init
                .origin
                .as_ref()
                .is_none_or(|o| !self.origin_tainted && *o == self.url.origin()),
        };
        if !attach && env.init.credentials == RequestCredentials::SameOrigin {
            modified(env.observer, &self.url, RequestChange::CredentialsWithheld);
        }
        if attach && !self.headers.contains_key(header::COOKIE) {
            if let Some(cookie_str) =
                (env.policy.cookies_for)(&CookieHop::new(&self.url, &self.method, &self.url_list))
            {
                if let Ok(mut val) = cookie_str.parse::<http::HeaderValue>() {
                    val.set_sensitive(true);
                    self.headers.insert(header::COOKIE, val);
                    self.cookie_from_jar = true;
                }
            }
        }
        attach
    }

    /// The HTTP cache (RFC 9111), consulted per hop with the headers this hop will actually
    /// send, so `Vary` selects on the cookies and the negotiation headers as sent. A fresh
    /// stored response ends the hop without a request; a stale one that can be revalidated
    /// adds its conditional headers to the send. See [`cache`](mod@crate::net::cache).
    ///
    /// A stale entry its `stale-while-revalidate` covers is used, and revalidated behind the
    /// hop, only where `background` allows. Anything else revalidates it first.
    #[cfg(not(target_arch = "wasm32"))]
    fn consult_cache(&self, env: &ChainEnv<'_>, partition: &str) -> Result<CacheLookup, NetError> {
        // Read here from the caller's headers, before any conditional header of the cache's own.
        let cache_mode = cache::effective_mode(env.init.cache_mode, &self.headers);
        let mut lookup = CacheLookup {
            hit: None,
            stale: false,
            revalidating: None,
            conditional: HeaderMap::new(),
            mode: cache_mode,
        };
        let Some(ref cache) = env.policy.cache else {
            return Ok(lookup);
        };
        let key = CacheKey::new(&self.method, &self.url).in_partition(partition);
        let stored = cache.get(&key);
        let decision = cache::decide(
            &stored,
            &self.headers,
            env.init.auto_decode,
            cache_mode,
            chrono::Utc::now(),
        );
        match if env.background {
            decision
        } else {
            decision.revalidated()
        } {
            CacheDecision::Use(entry) => lookup.hit = Some(entry),
            CacheDecision::UseStale(entry) => {
                lookup.hit = Some(entry);
                lookup.stale = true;
            }
            CacheDecision::Revalidate(entry, conditional) => {
                lookup.revalidating = Some(entry);
                lookup.conditional = conditional;
            }
            CacheDecision::Send => {}
            // `only-if-cached`, with nothing stored to answer it.
            CacheDecision::NotCached => {
                return Err(blocked(
                    env.observer,
                    self.url.clone(),
                    BlockReason::NotCached,
                ))
            }
        }
        Ok(lookup)
    }

    /// The hop answered from the cache, with no request sent.
    #[cfg(not(target_arch = "wasm32"))]
    fn answer_from_cache(
        &self,
        env: &ChainEnv<'_>,
        entry: Arc<CacheEntry>,
        plan: &mut HopPlan,
    ) -> Result<HopResponse, NetError> {
        // The CORS check applies to a response wherever it came from (Fetch §4.10.3).
        // The entry may have been stored by a same-origin fetch, which needed no
        // `Access-Control-Allow-Origin`; handing it to a cross-origin caller would read
        // it past the check the network path enforces. Blocked rather than re-sent,
        // as browsers do: a server whose allow-origin depends on `Origin` says
        // `Vary: Origin`, and then the entry is not a match in the first place.
        if self.tainting == ResponseTainting::Cors {
            if let Some(ref o) = env.init.origin {
                if let Err(e) = cors::cors_check(
                    o,
                    self.origin_tainted,
                    env.credentials_include,
                    &entry.headers,
                ) {
                    return Err(blocked(
                        env.observer,
                        self.url.clone(),
                        BlockReason::Cors(e),
                    ));
                }
            }
        }
        if let Some(grant) = plan.preflight.take() {
            grant.keep();
        }
        let outcome = if plan.cache.stale {
            CacheOutcome::Stale
        } else {
            CacheOutcome::Hit
        };
        env.observer.on_event(NetEvent::Cache {
            url: self.url.clone(),
            outcome,
        });
        // The stale entry answers this hop; the revalidation that refreshes it for the
        // next request runs on without it (Fetch: "in parallel").
        if plan.cache.stale {
            if let (Some(start), Some(from)) = (
                env.policy.revalidate_in_background.as_ref(),
                plan.revalidation.take(),
            ) {
                start(from);
            }
        }
        Ok(HopResponse::Cached(entry))
    }

    /// The hop sent over the network.
    ///
    /// Authentication (RFC 9110 §11): a 401 or 407 is re-sent with credentials whenever they
    /// can be found for one of its challenges, at most `MAX_AUTH_ATTEMPTS` times each. Only a
    /// response that is not a challenge is returned. See [`auth`](mod@crate::net::auth).
    ///
    /// The proxy and the origin server are asked separately, and a hop through an
    /// authenticating proxy to a protected server needs both answers at once
    /// (`Proxy-Authorization` and `Authorization`, RFC 9110 §11.6-11.7): each has its own
    /// header, attempt count and unaccepted credentials.
    async fn send(&self, env: &ChainEnv<'_>, plan: &mut HopPlan) -> Result<HopExchange, NetError> {
        let mut server_auth = AuthSlot::default();
        let mut proxy_auth = AuthSlot::default();
        // A site already logged in to gets its `Basic` credentials with the first send, as a
        // browser does, instead of after a `401` every time (RFC 7617 §2.2; Fetch's
        // authentication entry). Under the same conditions as answering a challenge, for this
        // hop's own URL: a redirect elsewhere is looked up for where it goes, and finds nothing
        // on another origin.
        if plan.attach_credentials
            && self.tainting == ResponseTainting::Basic
            && !self.headers.contains_key(header::AUTHORIZATION)
        {
            if let Some((_, credentials)) = env
                .policy
                .credentials
                .as_ref()
                .and_then(|store| store.upfront_for(&self.url))
            {
                server_auth.header = credentials.header_value();
            }
        }

        // A retried hop overwrites these, so they always describe the send that was kept.
        #[cfg(not(target_arch = "wasm32"))]
        let mut requested_at: chrono::DateTime<chrono::Utc>;
        #[cfg(not(target_arch = "wasm32"))]
        let mut received_at: chrono::DateTime<chrono::Utc>;

        let response = loop {
            let request = self.hop_request(env, plan, &server_auth, &proxy_auth)?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                requested_at = chrono::Utc::now();
            }
            let resp = self.await_response(env, request).await?;
            #[cfg(not(target_arch = "wasm32"))]
            {
                received_at = chrono::Utc::now();
            }
            self.received(env, plan, &resp)?;

            // A `304` answers a revalidation: the stored body stands, with the headers the
            // response carried written over the stored ones (RFC 9111 §4.3.4).
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(ref entry) = plan.cache.revalidating {
                // A `304` that names another version than the stored one confirms nothing
                // (RFC 9111 §4.3.4): updating from it would pin the old body under the new
                // tag, and every later revalidation would confirm it again. The entry goes,
                // and the hop is asked again without conditions, once.
                if resp.status().as_u16() == 304 && entry.contradicted_by(resp.headers()) {
                    if let Some(ref cache) = env.policy.cache {
                        cache.invalidate(&CacheKey::new(&self.method, &self.url));
                    }
                    plan.cache.revalidating = None;
                    plan.cache.conditional = HeaderMap::new();
                    continue;
                }
                if resp.status().as_u16() == 304 {
                    let mut updated = entry.updated_by_304(
                        resp.headers(),
                        requested_at,
                        received_at,
                        &self.headers,
                    );
                    // The connection that confirmed the entry is where it now comes from.
                    updated.peer_addr = origin_peer(&resp, &self.url, env.policy);
                    let updated = Arc::new(updated);
                    if let Some(ref cache) = env.policy.cache {
                        cache.put(
                            CacheKey::new(&self.method, &self.url)
                                .in_partition(cache_partition(env.policy, plan.attach_credentials)),
                            updated.clone(),
                        );
                    }
                    env.observer.on_event(NetEvent::Cache {
                        url: self.url.clone(),
                        outcome: CacheOutcome::Validated,
                    });
                    // The stored copy keeps no cookies, but the jar gets what the `304`
                    // set (RFC 6265 §3): a session rotated on a revalidation is not lost.
                    if plan.attach_credentials {
                        report_set_cookie(env.policy, &self.url, resp.headers());
                    }
                    break HopResponse::Cached(updated);
                }
            }

            // After the checks above: a response CORS refuses is blocked even when it asks for
            // credentials.
            let Some(target) = AuthTarget::for_status(resp.status().as_u16()) else {
                // Neither the proxy nor the server objected: whatever each was sent is
                // accepted.
                server_auth.accepted(env.policy, &self.url);
                proxy_auth.accepted(env.policy, &self.url);
                break HopResponse::Network(resp);
            };
            // A server challenge means the proxy let the request through, so the proxy
            // credentials sent with it are accepted.
            if target == AuthTarget::Server {
                proxy_auth.accepted(env.policy, &self.url);
            }
            let slot = match target {
                AuthTarget::Server => &mut server_auth,
                AuthTarget::Proxy => &mut proxy_auth,
            };

            // Only the proxy carrying a plain-http hop can send a 407 we see: over https
            // the proxy's 407 fails the CONNECT tunnel and comes back as a send error. So a
            // 407 *response* on an https or direct hop is the origin server's, and
            // answering it would leak the proxy credentials (or the password dialog) to
            // any server that sends the status. wasm32: the browser owns the proxy.
            #[cfg(not(target_arch = "wasm32"))]
            let proxy = (self.url.scheme() == "http")
                .then(|| env.policy.proxy_for.as_ref().and_then(|f| f(&self.url)))
                .flatten();
            #[cfg(target_arch = "wasm32")]
            let proxy: Option<Url> = None;
            let may_answer = match target {
                // Server credentials follow the request's credentials mode, and are only
                // attached to a chain the CORS regime left untainted. `Authorization` is not a
                // CORS-safelisted header, so adding it to a cors request would need a preflight
                // of its own, and adding it to a no-cors one would be a header markup cannot
                // produce. Navigations and requests without a document origin stay basic, and
                // those are the ones a browser shows its password dialog for.
                AuthTarget::Server => {
                    plan.attach_credentials && self.tainting == ResponseTainting::Basic
                }
                // `Proxy-Authorization` never reaches the origin, so CORS and the credentials
                // mode don't apply; only whether there is a proxy to answer.
                AuthTarget::Proxy => proxy.is_some(),
            };
            let challenges = auth::parse_challenges(
                resp.headers(),
                target,
                &self.url,
                slot.attempt,
                proxy.as_ref(),
            );
            let answer = if may_answer && slot.attempt < MAX_AUTH_ATTEMPTS {
                // What was sent to this party last time has just been rejected: drop it so
                // the store stops handing back a password it no longer takes.
                if let (Some(store), Some((space, _))) =
                    (env.policy.credentials.as_ref(), slot.unproven.take())
                {
                    store.forget(&space);
                }
                credentials_for_challenges(env.policy, &challenges)
            } else {
                None
            };

            env.observer.on_event(NetEvent::AuthRequired {
                url: self.url.clone(),
                target,
                challenges,
                retried: answer.is_some(),
            });

            let Some((space, credentials, value)) = answer else {
                break HopResponse::Network(resp);
            };
            slot.header = Some(value);
            slot.unproven = Some((space, credentials));
            slot.attempt += 1;
        };

        Ok(HopExchange {
            response,
            #[cfg(not(target_arch = "wasm32"))]
            requested_at,
            #[cfg(not(target_arch = "wasm32"))]
            received_at,
        })
    }

    /// The request for one send of the hop, reported as [`NetEvent::RequestSent`].
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    fn hop_request(
        &self,
        env: &ChainEnv<'_>,
        plan: &HopPlan,
        server_auth: &AuthSlot,
        proxy_auth: &AuthSlot,
    ) -> Result<reqwest::Request, NetError> {
        // The credentials and conditional headers are added for the send only, so a redirect
        // from this hop starts from the caller's headers again.
        let mut hop_headers = self.headers.clone();
        for (target, slot) in [
            (AuthTarget::Server, server_auth),
            (AuthTarget::Proxy, proxy_auth),
        ] {
            if let Some(ref value) = slot.header {
                hop_headers.insert(target.credentials_header(), value.clone());
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        for (name, value) in plan.cache.conditional.iter() {
            hop_headers.insert(name.clone(), value.clone());
        }
        // What the cache mode asks of every cache on the way, not just this one (Fetch,
        // HTTP-network-or-cache fetch): a forced revalidation says `max-age=0`, a reload
        // or a no-store request `no-cache`. Each only when the caller set none. Added for
        // the send, after the CORS decision, as Fetch does: neither header is
        // CORS-safelisted, and the mode alone must not cost a preflight.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let cache_control = match plan.cache.mode {
                // A background revalidation asks this cache alone.
                CacheMode::NoCache if env.resumed => None,
                CacheMode::NoCache => Some("max-age=0"),
                CacheMode::NoStore | CacheMode::Reload => {
                    if !hop_headers.contains_key(header::PRAGMA) {
                        hop_headers
                            .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
                    }
                    Some("no-cache")
                }
                _ => None,
            };
            if let Some(value) = cache_control {
                if !hop_headers.contains_key(header::CACHE_CONTROL) {
                    hop_headers.insert(
                        header::CACHE_CONTROL,
                        header::HeaderValue::from_static(value),
                    );
                }
            }
        }
        // Written here rather than left to the client, which would add it while
        // executing the request -- after this hop was reported. Only when nothing has
        // already answered a `407` for this hop, which is both the credential that was
        // actually accepted and what the client itself would defer to.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref proxy_authorization) = env.policy.proxy_authorization {
            if !hop_headers.contains_key(header::PROXY_AUTHORIZATION) {
                if let Some(mut value) = proxy_authorization(&self.url) {
                    value.set_sensitive(true);
                    hop_headers.insert(header::PROXY_AUTHORIZATION, value);
                }
            }
        }
        let mut req_builder = env
            .client
            .request(self.method.clone(), self.url.clone())
            .headers(hop_headers);
        // A per-request timeout replaces the client's for this request only, so it
        // can be set shorter or longer than the client-wide default. Redirects and
        // authenticated retries come back through here, so every hop gets a fresh one.
        if let Some(timeout) = env.init.timeout {
            req_builder = req_builder.timeout(timeout);
        }
        // A headers deadline takes over from the client's, which would also run over the
        // body: it is enforced in `await_response`, around the wait for the response.
        #[cfg(not(target_arch = "wasm32"))]
        if env.init.headers_timeout.is_some() {
            req_builder = req_builder.timeout(NO_CLIENT_DEADLINE);
        }
        if let Some(ref body) = self.body {
            // Built fresh per send so a streamed body can be replayed on 307/308 and for an
            // authenticated retry of this hop.
            let (hop_body, explicit_len) = body.to_reqwest_body()?;
            // Set here rather than left to the connection, which would otherwise
            // compute the same number while encoding the request -- below any layer
            // holding a header map, and so below anything that could report it. A
            // stream needs it regardless, being unsized as far as the client knows.
            if let Some(len) = explicit_len {
                req_builder = req_builder.header(header::CONTENT_LENGTH, len);
            }
            req_builder = req_builder.body(hop_body);
        } else if self.method == Method::POST || self.method == Method::PUT {
            // Fetch §4.6: a POST or PUT without a body says so, which strict servers
            // require (RFC 9110 §8.6) and the connection would not add.
            req_builder = req_builder.header(header::CONTENT_LENGTH, 0);
        }
        // Built rather than sent straight away, so what is reported is the request the
        // client assembled rather than the arguments it was handed.
        //
        // Reported here rather than beside `Started`: the headers are only final for
        // this hop at this point. Credentials and conditional headers are added just
        // above, and a redirect starts over from the caller's set, so an earlier
        // event would describe a request that was never sent.
        //
        // `build()` does not merge the client's own default headers -- those are
        // applied when the request executes, which is after this. For a client built
        // by `Fetcher` that costs nothing, because every header it would default is
        // written by this crate before the request is assembled. The user agent is the
        // exception, since it is configured on the client and cannot be read back, so
        // `NetPolicy::with_user_agent` carries the value and it is filled in below.
        //
        // What is left is added by the connection and determined by the protocol:
        // `host` (or `:authority` over HTTP/2), and `transfer-encoding: chunked` on
        // HTTP/1.1 for a body of unknown length. Neither reaches a `reqwest::Request`,
        // and neither is guessed at here.
        let request = req_builder.build().map_err(|e| {
            send_error(
                e,
                &self.url,
                "net.get_with_redirects request build failed",
                env.observer,
                env.policy,
            )
        })?;
        #[cfg(not(target_arch = "wasm32"))]
        let request = order_hop_headers(
            request,
            env.init.header_order.as_deref(),
            env.policy.user_agent.as_ref(),
            !(env.policy.speaks_h2)(&self.url),
        );
        let mut reported = request.headers().clone();
        // Only when the assembled request does not already carry one: a header set
        // per-request wins over the client default, and reporting the default over
        // the top of it would be a lie in the one direction that matters.
        if let Some(ref ua) = env.policy.user_agent {
            reported
                .entry(http::header::USER_AGENT)
                .or_insert(ua.clone());
        }
        env.observer.on_event(NetEvent::RequestSent {
            url: self.url.clone(),
            method: request.method().clone(),
            headers: reported,
        });
        Ok(request)
    }

    /// Sends `request` and waits for its response headers, for as long as neither the
    /// callers, the redirect budget nor the headers deadline give up on it.
    async fn await_response(
        &self,
        env: &ChainEnv<'_>,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, NetError> {
        let fut = env.client.execute(request);
        tokio::pin!(fut);
        let deadline = async {
            match self.redirect_deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(deadline);
        let headers_deadline = async {
            match env.init.headers_timeout {
                Some(timeout) => tokio::time::sleep(timeout).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(headers_deadline);

        tokio::select! {
            _ = env.cancel.cancelled() => {
                env.observer.on_event(NetEvent::Cancelled { url: self.url.clone(), reason: "all callers cancelled" });
                Err(NetError::Cancelled("all callers cancelled".into()))
            }
            _ = &mut deadline => {
                Err(NetError::Timeout(format!(
                    "redirect chain exceeded {:?} after {} redirects",
                    env.init.redirect_timeout.unwrap_or_default(),
                    self.redirects
                )))
            }
            _ = &mut headers_deadline => {
                Err(NetError::Transport(TransportError {
                    kind: crate::net::transport::TransportErrorKind::Timeout,
                    message: format!(
                        "net.get_with_redirects request failed: no response headers within {:?}",
                        env.init.headers_timeout.unwrap_or_default()
                    ),
                }))
            }
            r = &mut fut => r.map_err(|e| send_error(e, &self.url, "net.get_with_redirects request failed", env.observer, env.policy))
        }
    }

    /// What every response of the hop goes through, a challenge or a `304` included: the
    /// reports, the HSTS harvest and the CORS check.
    #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
    fn received(
        &self,
        env: &ChainEnv<'_>,
        plan: &mut HopPlan,
        resp: &reqwest::Response,
    ) -> Result<(), NetError> {
        // Report the HTTP version of every hop, not just the final response, so the fetcher's
        // per-origin limits also learn about intermediate origins. reqwest's wasm Response has
        // no version().
        #[cfg(not(target_arch = "wasm32"))]
        (env.policy.on_protocol)(resp.url(), resp.version());

        // Per hop, like the other events in this loop: the first one marks
        // time-to-first-byte for the request, and a redirect chain reports each hop
        // it waited on. A hop served from the cache received no headers over the
        // wire and reports `Cache` instead.
        env.observer.on_event(NetEvent::ResponseHeaders {
            url: resp.url().clone(),
            status: resp.status().as_u16(),
            headers: resp.headers().clone(),
        });

        // A `101` is a final response only to a WebSocket handshake (Fetch §4.7,
        // HTTP-network fetch) or a request that asked for an upgrade itself. Any other is
        // a protocol switch nothing here speaks, not a response to hand on.
        if resp.status() == http::StatusCode::SWITCHING_PROTOCOLS
            && env.init.mode != RequestMode::Websocket
            && !self.headers.contains_key(header::UPGRADE)
        {
            return Err(NetError::Other(Arc::new(anyhow!(
                "{}: 101 Switching Protocols to a request that asked for no upgrade",
                self.url
            ))));
        }

        // Harvest HSTS from every hop, not just the final one: a 301 http->https is the usual way
        // a site first arms it, and that response is consumed below.
        // RFC 6797 §8.1: not from a connection the user clicked through.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = env.policy.hsts {
            if !over_accepted_override(env.policy, resp) {
                hsts::record(
                    store.as_ref(),
                    &self.url,
                    resp.headers(),
                    chrono::Utc::now(),
                );
            }
        }

        // The CORS check (Fetch §4.10.3) runs on *every* response of a cors-tainted chain —
        // redirects included, and also a final same-origin hop reached through a cross-origin
        // detour. Native-only: on wasm32 the browser has already enforced this.
        #[cfg(not(target_arch = "wasm32"))]
        if self.tainting == ResponseTainting::Cors {
            if let Some(ref o) = env.init.origin {
                if let Err(e) = cors::cors_check(
                    o,
                    self.origin_tainted,
                    env.credentials_include,
                    resp.headers(),
                ) {
                    return Err(blocked(
                        env.observer,
                        self.url.clone(),
                        BlockReason::Cors(e),
                    ));
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(grant) = plan.preflight.take() {
            grant.keep();
        }
        Ok(())
    }

    /// Drops what `hop` shows to be wrong in the cache.
    #[cfg(not(target_arch = "wasm32"))]
    fn invalidate_cache(&self, env: &ChainEnv<'_>, hop: &HopResponse, partition: &str) {
        let Some(ref cache) = env.policy.cache else {
            return;
        };
        // A method that changed the resource makes what is stored for it wrong, including for
        // the `Location` it points at (RFC 9111 §4.4). Only a successful one: a rejected POST
        // changed nothing.
        if cache::invalidates(&self.method) && hop.status() < 400 {
            let mut targets = vec![self.url.clone()];
            for name in [header::LOCATION, header::CONTENT_LOCATION] {
                let target = hop
                    .headers()
                    .get(&name)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| self.url.join(v).ok());
                // Only same-origin: a response cannot invalidate another site's entries.
                if let Some(target) = target.filter(|t| t.origin() == self.url.origin()) {
                    targets.push(target);
                }
            }
            for target in targets {
                // Entries are keyed by method, so both of the cacheable ones go; in every
                // partition (see `HttpCache::invalidate`).
                for method in [Method::GET, Method::HEAD] {
                    cache.invalidate(&CacheKey::new(&method, &target));
                }
            }
            env.observer.on_event(NetEvent::Cache {
                url: self.url.clone(),
                outcome: CacheOutcome::Invalidated,
            });
        }

        // A `HEAD` that shows the resource changed makes the stored `GET` stale (RFC 9111
        // §4.3.5); it is dropped, in every partition, like a write would drop it.
        if let HopResponse::Network(resp) = hop {
            if self.method == Method::HEAD && resp.status().as_u16() == 200 {
                let get = CacheKey::new(&Method::GET, &self.url);
                let stored = cache.get(&get.clone().in_partition(partition));
                if stored.iter().any(|e| e.changed_per_head(resp.headers())) {
                    cache.invalidate(&get);
                    env.observer.on_event(NetEvent::Cache {
                        url: self.url.clone(),
                        outcome: CacheOutcome::Invalidated,
                    });
                }
            }
        }
    }

    /// Moves the chain on to where the redirect `hop` points, as the next hop will send it.
    fn follow_redirect(
        &mut self,
        env: &ChainEnv<'_>,
        hop: &HopResponse,
        attach_credentials: bool,
    ) -> Result<(), NetError> {
        // A redirect — resolve the Location header
        let status = hop.status();
        let from = match hop {
            HopResponse::Network(resp) => resp.url().clone(),
            HopResponse::Cached(_) => self.url.clone(),
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
            self.referrer_policy = updated;
        }

        // Report Set-Cookie values on this hop to the jar before following the redirect —
        // login flows commonly set the session cookie on a 302.
        let cookies_set = attach_credentials && report_set_cookie(env.policy, &from, hop.headers());
        // The jar's cookies answered for this hop's URL and method. The next hop asks again for
        // its own (Fetch appends `Cookie` per request): another path can match other cookies,
        // and a method changed to `GET` other `SameSite` ones. A caller's own `Cookie` stays,
        // unless the hop set cookies, which the jar now has, or the redirect leaves the origin.
        if self.cookie_from_jar || cookies_set {
            self.headers.remove(header::COOKIE);
            self.cookie_from_jar = false;
        }

        let loc = hop
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|v| location_text(v.as_bytes()))
            .ok_or_else(|| {
                NetError::Redirect(Arc::new(anyhow!(
                    "redirect status {} without Location header",
                    status
                )))
            })?;
        let loc = loc.as_str();

        let mut to = from.join(loc).map_err(|e| {
            NetError::Redirect(Arc::new(anyhow!("invalid redirect URL '{}': {}", loc, e)))
        })?;
        // A `Location` without a fragment keeps the request's (Fetch §2.2.6 location URL,
        // RFC 9110 §10.2.2): a redirect of `/a#top` to `/b` leads to `/b#top`. From `url`, the
        // request's current URL: the response's has no fragment.
        if to.fragment().is_none() {
            to.set_fragment(self.url.fragment());
        }

        // A `Location` with embedded `user:password` is refused for a cors-mode request, and
        // for any request when it points at another origin than the hop it came from: following
        // it would replay attacker-chosen credentials against the new target.
        //
        // Deliberately stricter than Fetch §4.5 steps 9-10, which only refuse a cors-mode
        // request whose Location's origin differs from the *request's* origin, or a chain whose
        // response tainting is already cors, and otherwise follow with the credentials kept.
        // Credentials in a redirect target are an attack pattern rather than something a site
        // relies on, and sonar strips them from what it follows anyway, so refusing more only
        // costs a redirect browsers would follow.
        if (!to.username().is_empty() || to.password().is_some())
            && (env.init.mode == RequestMode::Cors || from.origin() != to.origin())
        {
            return Err(blocked(
                env.observer,
                to,
                BlockReason::Cors(CorsError::CredentialedRedirect),
            ));
        }
        let location_credentials_removed = strip_url_credentials(&mut to);

        // Fetch §4.5 step 12: a 301 or 302 turns a `POST` into a `GET`, and a 303 every method
        // but `GET` and `HEAD`; the body goes with the method. Any other method, and every one
        // on a 307 or 308, goes on as it was, body included.
        let method_before = self.method.clone();
        let to_get = match status {
            301 | 302 => self.method == Method::POST,
            303 => self.method != Method::GET && self.method != Method::HEAD,
            _ => false,
        };
        if to_get {
            self.method = Method::GET;
            self.body = None;
            // The request-body-header names (Fetch §2.2.2), with the framing of the body gone.
            for name in [
                header::CONTENT_ENCODING,
                header::CONTENT_LANGUAGE,
                header::CONTENT_LOCATION,
                header::CONTENT_TYPE,
                header::CONTENT_LENGTH,
                header::TRANSFER_ENCODING,
            ] {
                self.headers.remove(name);
            }
        }

        // Strip credential headers when redirecting to a different origin (RFC 9110 §15.4).
        // Cookie will be re-applied from the jar at the start of the next hop.
        let mut stripped = Vec::new();
        if from.origin() != to.origin() {
            for h in SENSITIVE_REDIRECT_HEADERS {
                if self.headers.remove(h).is_none() {
                    continue;
                }
                // Only what the caller set and nothing puts back. Jar cookies are fetched again
                // for the new origin, and a computed `Referer` or `Origin` is recomputed.
                let reported = match *h {
                    header::COOKIE => !self.cookie_from_jar,
                    header::REFERER => env.init.referrer.is_none(),
                    header::ORIGIN => env.init.origin.is_none(),
                    _ => true,
                };
                if reported {
                    stripped.push(h.clone());
                }
            }
            self.cookie_from_jar = false;
        }

        // Fetch's redirect-taint, per hop: a redirect to another origin from a hop that was
        // itself not the request's origin taints the chain, and `Origin` reads `null` from
        // then on. The first cross-origin hop still sends the real origin, which CORS needs.
        if let Some(ref o) = env.init.origin {
            if to.origin() != from.origin() && *o != from.origin() {
                self.origin_tainted = true;
            }
        }

        env.observer.on_event(NetEvent::Redirected {
            from,
            to: to.clone(),
            status,
        });

        // After `Redirected`, so the stream first says where the chain goes, then how the hop changed.
        if location_credentials_removed {
            modified(env.observer, &to, RequestChange::UrlCredentialsRemoved);
        }
        if method_before != self.method {
            modified(
                env.observer,
                &to,
                RequestChange::MethodDowngraded {
                    from: method_before,
                    to: self.method.clone(),
                },
            );
        }
        if !stripped.is_empty() {
            modified(
                env.observer,
                &to,
                RequestChange::SensitiveHeadersStripped { headers: stripped },
            );
        }

        self.url_list.push(std::mem::replace(&mut self.url, to));
        self.redirects += 1;
        Ok(())
    }
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
/// - Credentials embedded in the URL (`user:password@`) are dropped, from the initial URL
///   and from every `Location`, so the client never turns them into an `Authorization`
///   header. A cross-origin or cors-mode `Location` with credentials is refused outright.
/// - Insecure hops requested by a secure `init.origin` are blocked or upgraded per
///   `init.mixed_content`, re-evaluated at every hop so a redirect cannot escape the check.
/// - `Referer` is recomputed at every hop, since the same-origin and downgrade determinations
///   change as the chain moves, from the referrer the previous hop sent (Fetch, main fetch step
///   9): `init.referrer` on the first hop, and what was left of it after that. A referrer once
///   reduced to its origin, or withheld, stays so for the rest of the chain. A
///   `Referrer-Policy` header on a 3xx response replaces the policy for the remaining hops, but
///   cannot bring back what an earlier hop already cut.
/// - `Origin` and the `Sec-Fetch-*` headers are likewise recomputed at every hop from
///   `init.origin`, `init.destination`, and `init.mode`. `Sec-Fetch-Site` only degrades across
///   the chain, and `Origin` collapses to `null` once the chain redirects away from an origin
///   the request had already left — see [`fetch_metadata`](mod@crate::net::fetch_metadata).
/// - Every upgrade to `https` is reported as [`NetEvent::SecurityUpgraded`], and every other
///   change a policy makes to a hop as [`NetEvent::RequestModified`].
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
pub(super) async fn get_with_redirects(
    client: Arc<reqwest::Client>,
    url: Url,
    mut init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ChainOutcome, NetError> {
    #[cfg(not(target_arch = "wasm32"))]
    let resumed = init.background_revalidation.is_some();
    let mut chain = HopChain::start(url, &mut init, &observer)?;
    let env = ChainEnv {
        client: &client,
        init: &init,
        cancel: &cancel,
        observer: &observer,
        policy: &policy,
        #[cfg(not(target_arch = "wasm32"))]
        credentials_include: init.credentials == RequestCredentials::Include,
        #[cfg(not(target_arch = "wasm32"))]
        background: init.origin.is_some()
            && policy.cache.is_some()
            && policy.revalidate_in_background.is_some(),
        #[cfg(not(target_arch = "wasm32"))]
        resumed,
    };

    // One request more than the limit: the chain may follow MAX_REDIRECTS redirects, and only a
    // redirect after those is an error (Fetch, HTTP-redirect fetch: a network error when the
    // count is already 20).
    while chain.redirects <= MAX_REDIRECTS {
        #[cfg(not(target_arch = "wasm32"))]
        let revalidation = env.background.then(|| chain.revalidation());
        let before_hsts = chain.secure_url(&env)?;
        #[cfg(not(target_arch = "wasm32"))]
        chain.check_ip_literal(&env).await?;
        chain.enter_cors_regime(&env)?;
        chain.set_referrer(&env, before_hsts.as_ref());
        #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
        let hop_site = chain.set_fetch_metadata(&env);
        #[cfg(not(target_arch = "wasm32"))]
        let preflight = chain.preflight(&env, hop_site).await?;
        let attach_credentials = chain.attach_credentials(&env);
        #[cfg(not(target_arch = "wasm32"))]
        let partition = cache_partition(&policy, attach_credentials);

        #[cfg(not(target_arch = "wasm32"))]
        let mut plan = HopPlan {
            attach_credentials,
            cache: chain.consult_cache(&env, partition)?,
            preflight,
            revalidation,
        };
        #[cfg(target_arch = "wasm32")]
        let mut plan = HopPlan { attach_credentials };

        #[cfg(not(target_arch = "wasm32"))]
        let exchange = match plan.cache.hit.take() {
            Some(entry) => {
                let response = chain.answer_from_cache(&env, entry, &mut plan)?;
                // Only a response from the network is stored, so these are not read.
                let now = chrono::Utc::now();
                HopExchange {
                    response,
                    requested_at: now,
                    received_at: now,
                }
            }
            None => chain.send(&env, &mut plan).await?,
        };
        // No cache on wasm32, so every hop goes out as it is.
        #[cfg(target_arch = "wasm32")]
        let exchange = chain.send(&env, &mut plan).await?;
        let hop = exchange.response;

        #[cfg(not(target_arch = "wasm32"))]
        chain.invalidate_cache(&env, &hop, partition);

        let peer_addr = match &hop {
            HopResponse::Network(resp) => origin_peer(resp, &chain.url, &policy),
            HopResponse::Cached(entry) => entry.peer_addr,
        };

        // Whether this response may be stored. The body is not here yet: a redirect has none
        // worth keeping and is stored right away, while the final response's write waits for the
        // reader of its body.
        #[cfg(not(target_arch = "wasm32"))]
        let pending_store = match (&hop, policy.cache.as_ref()) {
            // `no-store` is both directions: the lookup above skipped the cache, and nothing
            // about this exchange is written to it either.
            (HopResponse::Network(resp), Some(cache))
                if plan.cache.mode != CacheMode::NoStore
                    && cache::is_storable(
                        &chain.method,
                        &chain.headers,
                        resp.status().as_u16(),
                        resp.headers(),
                    ) =>
            {
                Some(PendingStore {
                    cache: cache.clone(),
                    key: CacheKey::new(&chain.method, &chain.url).in_partition(partition),
                    url: chain.url.clone(),
                    status: resp.status().as_u16(),
                    response_headers: resp.headers().clone(),
                    request_headers: chain.headers.clone(),
                    decoded: init.auto_decode,
                    requested_at: exchange.requested_at,
                    received_at: exchange.received_at,
                    peer_addr,
                })
            }
            _ => None,
        };

        // Fetch §4.5 steps 3-5, the location URL: a redirect without a `Location` is the
        // response, returned as it is, and one with more than one is a network error. The field
        // lines are counted, not split on commas: a URL may hold a comma.
        let locations = hop.headers().get_all(header::LOCATION).iter().count();
        if hop.is_redirection() && locations > 1 {
            return Err(NetError::Redirect(Arc::new(anyhow!(
                "redirect status {} with {} Location headers",
                hop.status(),
                locations
            ))));
        }
        if !hop.is_redirection() || locations == 0 {
            if attach_credentials {
                report_set_cookie(&policy, &chain.url, hop.headers());
            }
            return Ok(ChainOutcome {
                response: hop,
                url: chain.url,
                method: chain.method,
                tainting: chain.tainting,
                peer_addr,
                #[cfg(not(target_arch = "wasm32"))]
                store: pending_store,
            });
        }

        // The budget starts here rather than at the first request, so a request that is not
        // redirected is bounded by the request timeout alone.
        if chain.redirect_deadline.is_none() {
            chain.redirect_deadline = init
                .redirect_timeout
                .map(|budget| tokio::time::Instant::now() + budget);
        }

        // A redirect is stored now: the caller never sees its body, and a stored `301` lets the
        // next fetch skip the hop entirely.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(store) = pending_store {
            store.commit(Bytes::new(), &observer);
        }

        chain.follow_redirect(&env, &hop, attach_credentials)?;
    }

    Err(NetError::Redirect(Arc::new(anyhow!("too many redirects"))))
}

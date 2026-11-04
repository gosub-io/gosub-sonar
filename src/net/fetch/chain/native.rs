//! The redirect chain's native side: HSTS, the resolver check of IP literals, CORS preflights
//! and checks, the HTTP cache and proxies. On wasm32 the browser's `fetch()` does all of this
//! itself, and `wasm.rs` stands in with the same items doing nothing.

use super::HopChain;
use crate::net::cache::{self, CacheDecision, CacheEntry, CacheKey, CacheMode, CacheOutcome};
use crate::net::cors::{self, ResponseTainting};
use crate::net::events::NetEvent;
use crate::net::fetch::platform::{
    ip_literal, order_hop_headers, over_accepted_override, without_forbidden, PreflightGrant,
    NO_CLIENT_DEADLINE,
};
use crate::net::fetch::{
    blocked, origin_peer, report_set_cookie, send_error, HopResponse, NetPolicy, PendingStore,
    RequestInit, Revalidation,
};
use crate::net::fetch_metadata::{self, RequestMode, SecFetchSite};
use crate::net::hsts;
use crate::net::observer::NetObserver;
use crate::net::transport::TransportError;
use crate::net::types::{BlockReason, NetError, RequestCredentials, UpgradeReason};
use http::{header, HeaderMap, Method};
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

/// What every hop of a chain is fetched with.
pub(super) struct ChainEnv<'a> {
    pub(super) client: &'a reqwest::Client,
    // Without the method, headers, body and revalidation: those went into the `HopChain`.
    pub(super) init: &'a RequestInit,
    pub(super) cancel: &'a CancellationToken,
    pub(super) observer: &'a Arc<dyn NetObserver + Send + Sync>,
    pub(super) policy: &'a NetPolicy,
    // The credentialed CORS rules key on the request's credentials *mode*, not on whether
    // cookies were actually attached on a given hop. Only the native checks consult it — on
    // wasm32 the browser enforces the credentialed rules itself.
    credentials_include: bool,
    // Whether a hop may be answered stale and revalidated behind it: only for a request with a
    // client (Fetch, HTTP-network-or-cache fetch), one with an origin here, and only with
    // something to revalidate it.
    background: bool,
    // The chain is a background revalidation.
    resumed: bool,
}

impl<'a> ChainEnv<'a> {
    /// The env for a chain; `resumed` says whether it is a background revalidation.
    pub(super) fn new(
        client: &'a reqwest::Client,
        init: &'a RequestInit,
        cancel: &'a CancellationToken,
        observer: &'a Arc<dyn NetObserver + Send + Sync>,
        policy: &'a NetPolicy,
        resumed: bool,
    ) -> Self {
        ChainEnv {
            client,
            init,
            cancel,
            observer,
            policy,
            credentials_include: init.credentials == RequestCredentials::Include,
            background: init.origin.is_some()
                && policy.cache.store.is_some()
                && policy.cache.revalidate_in_background.is_some(),
            resumed,
        }
    }
}

/// What the stages before a hop's send worked out for it.
pub(super) struct HopPlan {
    pub(super) attach_credentials: bool,
    cache: CacheLookup,
    preflight: Option<PreflightGrant>,
    // Where a background revalidation of this hop would start, if it may have one.
    revalidation: Option<Revalidation>,
}

/// The response a hop got, and when it was asked for and received, for the age of a cache entry
/// made from it (RFC 9111 §4.2.3).
pub(super) struct HopExchange {
    pub(super) response: HopResponse,
    requested_at: chrono::DateTime<chrono::Utc>,
    received_at: chrono::DateTime<chrono::Utc>,
}

impl HopExchange {
    pub(super) fn new(response: HopResponse, timing: Timing) -> Self {
        HopExchange {
            response,
            requested_at: timing.requested_at,
            received_at: timing.received_at,
        }
    }
}

/// When one send of a hop was asked for and its response received.
pub(super) struct Timing {
    requested_at: chrono::DateTime<chrono::Utc>,
    received_at: chrono::DateTime<chrono::Utc>,
}

impl Timing {
    /// The send is asked for now.
    pub(super) fn requested() -> Self {
        let now = chrono::Utc::now();
        Timing {
            requested_at: now,
            received_at: now,
        }
    }

    /// Its response is received now.
    pub(super) fn received(&mut self) {
        self.received_at = chrono::Utc::now();
    }
}

/// The cache partition of a hop: one that carries a jar's cookies is cached for that jar alone.
fn cache_partition(policy: &NetPolicy, attach_credentials: bool) -> &str {
    if attach_credentials {
        policy.cookies.cache_partition.as_str()
    } else {
        ""
    }
}

/// What the cache makes of a hop before it is sent.
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
    /// Where a background revalidation of this hop would start: the chain as it stands before
    /// the hop does anything.
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

    /// Where a background revalidation of this hop would start, if the chain allows one.
    pub(super) fn revalidation_start(&self, env: &ChainEnv<'_>) -> Option<Revalidation> {
        env.background.then(|| self.revalidation())
    }

    /// The HSTS upgrade of the hop's URL. Returns the URL from before it, if it was upgraded.
    pub(super) fn apply_hsts(&mut self, env: &ChainEnv<'_>) -> Option<Url> {
        let mut before_hsts: Option<Url> = None;
        if let Some(ref store) = env.policy.transport.hsts {
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
        before_hsts
    }

    /// The client connects to an IP literal without asking the resolver, so a policy in it
    /// would never see e.g. 169.254.169.254. Ask it here with the literal as the name; an Err
    /// refuses the hop like a refused name would. The returned addresses are unused.
    pub(super) async fn check_ip_literal(&self, env: &ChainEnv<'_>) -> Result<(), NetError> {
        let (Some(resolver), Some(literal)) = (
            env.policy.transport.dns_resolver.as_ref(),
            ip_literal(&self.url),
        ) else {
            return Ok(());
        };
        let refused = tokio::select! {
            _ = env.cancel.cancelled() => {
                let reason = super::super::cancel_reason();
                env.observer.on_event(NetEvent::Cancelled { url: self.url.clone(), reason });
                return Err(NetError::Cancelled(reason.into()));
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

    /// CORS preflight (Fetch §4.9): a cross-origin cors-mode request whose method or headers
    /// markup could not produce must be approved by the server before it is sent. Running this
    /// per hop is what modern browsers do after a redirect moves the target — the grant is per
    /// (origin, URL), so a new URL needs its own, usually served from the cache. The OPTIONS
    /// goes out credential-less and never follows redirects (the client has redirects disabled;
    /// a 3xx fails the ok-status test).
    ///
    /// Native-only: on wasm32 the browser preflights itself and does not surface the
    /// `Access-Control-*` response headers this validation would need.
    pub(super) async fn preflight(
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
        let granted = env
            .policy
            .cache
            .cors_preflight
            .as_ref()
            .is_some_and(|cache| {
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
            if let Some(cache) = env.policy.cache.cors_preflight.as_ref() {
                cache.put(&serialized, &self.url, credentials_include, allows, now);
            }
        }
        Ok(env
            .policy
            .cache
            .cors_preflight
            .as_ref()
            .map(|cache| PreflightGrant {
                cache: cache.clone(),
                origin: serialized,
                url: self.url.clone(),
                kept: false,
            }))
    }

    /// The hop's plan, with what the cache makes of it.
    pub(super) fn plan(
        &self,
        env: &ChainEnv<'_>,
        attach_credentials: bool,
        preflight: Option<PreflightGrant>,
        revalidation: Option<Revalidation>,
    ) -> Result<HopPlan, NetError> {
        let partition = cache_partition(env.policy, attach_credentials);
        Ok(HopPlan {
            attach_credentials,
            cache: self.consult_cache(env, partition)?,
            preflight,
            revalidation,
        })
    }

    /// The hop answered from the cache, or sent.
    pub(super) async fn exchange(
        &self,
        env: &ChainEnv<'_>,
        plan: &mut HopPlan,
    ) -> Result<HopExchange, NetError> {
        match plan.cache.hit.take() {
            Some(entry) => {
                let response = self.answer_from_cache(env, entry, plan)?;
                // Only a response from the network is stored, so these are not read.
                let now = chrono::Utc::now();
                Ok(HopExchange {
                    response,
                    requested_at: now,
                    received_at: now,
                })
            }
            None => self.send(env, plan).await,
        }
    }

    /// The HTTP cache (RFC 9111), consulted per hop with the headers this hop will actually
    /// send, so `Vary` selects on the cookies and the negotiation headers as sent. A fresh
    /// stored response ends the hop without a request; a stale one that can be revalidated
    /// adds its conditional headers to the send. See [`cache`](mod@crate::net::cache).
    ///
    /// A stale entry its `stale-while-revalidate` covers is used, and revalidated behind the
    /// hop, only where `background` allows. Anything else revalidates it first.
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
        let Some(ref cache) = env.policy.cache.store else {
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
                env.policy.cache.revalidate_in_background.as_ref(),
                plan.revalidation.take(),
            ) {
                start(from);
            }
        }
        Ok(HopResponse::Cached(entry))
    }

    /// A `304` that answers the hop's revalidation: `Break` with the refreshed entry, or
    /// `Continue` to ask again without conditions. `None` for any other response.
    pub(super) fn revalidated(
        &self,
        env: &ChainEnv<'_>,
        plan: &mut HopPlan,
        resp: &reqwest::Response,
        timing: &Timing,
    ) -> Option<ControlFlow<HopResponse>> {
        if let Some(ref entry) = plan.cache.revalidating {
            // A `304` that names another version than the stored one confirms nothing
            // (RFC 9111 §4.3.4): updating from it would pin the old body under the new
            // tag, and every later revalidation would confirm it again. The entry goes,
            // and the hop is asked again without conditions, once.
            if resp.status().as_u16() == 304 && entry.contradicted_by(resp.headers()) {
                if let Some(ref cache) = env.policy.cache.store {
                    cache.invalidate(&CacheKey::new(&self.method, &self.url));
                }
                plan.cache.revalidating = None;
                plan.cache.conditional = HeaderMap::new();
                return Some(ControlFlow::Continue(()));
            }
            if resp.status().as_u16() == 304 {
                let mut updated = entry.updated_by_304(
                    resp.headers(),
                    timing.requested_at,
                    timing.received_at,
                    &self.headers,
                );
                // The connection that confirmed the entry is where it now comes from.
                updated.peer_addr = origin_peer(resp, &self.url, env.policy);
                let updated = Arc::new(updated);
                if let Some(ref cache) = env.policy.cache.store {
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
                return Some(ControlFlow::Break(HopResponse::Cached(updated)));
            }
        }
        None
    }

    /// The proxy that may answer a `407` for this hop.
    pub(super) fn challenge_proxy(&self, env: &ChainEnv<'_>) -> Option<Url> {
        (self.url.scheme() == "http")
            .then(|| {
                env.policy
                    .proxy
                    .proxy_for
                    .as_ref()
                    .and_then(|f| f(&self.url))
            })
            .flatten()
    }

    /// The headers a send gets from the cache and the proxy configuration.
    pub(super) fn add_send_headers(
        &self,
        env: &ChainEnv<'_>,
        plan: &HopPlan,
        hop_headers: &mut HeaderMap,
    ) {
        for (name, value) in plan.cache.conditional.iter() {
            hop_headers.insert(name.clone(), value.clone());
        }
        // What the cache mode asks of every cache on the way, not just this one (Fetch,
        // HTTP-network-or-cache fetch): a forced revalidation says `max-age=0`, a reload
        // or a no-store request `no-cache`. Each only when the caller set none. Added for
        // the send, after the CORS decision, as Fetch does: neither header is
        // CORS-safelisted, and the mode alone must not cost a preflight.
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
        if let Some(ref proxy_authorization) = env.policy.proxy.proxy_authorization {
            if !hop_headers.contains_key(header::PROXY_AUTHORIZATION) {
                if let Some(mut value) = proxy_authorization(&self.url) {
                    value.set_sensitive(true);
                    hop_headers.insert(header::PROXY_AUTHORIZATION, value);
                }
            }
        }
    }

    /// The headers in the order the request asked for, `host` and `user-agent` included.
    pub(super) fn order_headers(
        &self,
        env: &ChainEnv<'_>,
        request: reqwest::Request,
    ) -> reqwest::Request {
        order_hop_headers(
            request,
            env.init.header_order.as_deref(),
            env.policy.user_agent.as_ref(),
            !(env.policy.transport.speaks_h2)(&self.url),
        )
    }

    /// The checks on a response that need what the browser keeps to itself on wasm32: HSTS,
    /// CORS and the preflight grant.
    pub(super) fn check_response(
        &self,
        env: &ChainEnv<'_>,
        plan: &mut HopPlan,
        resp: &reqwest::Response,
    ) -> Result<(), NetError> {
        // Harvest HSTS from every hop, not just the final one: a 301 http->https is the usual way
        // a site first arms it, and that response is consumed below.
        // RFC 6797 §8.1: not from a connection the user clicked through.
        if let Some(ref store) = env.policy.transport.hsts {
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
        if let Some(grant) = plan.preflight.take() {
            grant.keep();
        }
        Ok(())
    }

    /// Drops what `hop` shows to be wrong in the cache.
    pub(super) fn invalidate_cache(&self, env: &ChainEnv<'_>, hop: &HopResponse, plan: &HopPlan) {
        let partition = cache_partition(env.policy, plan.attach_credentials);
        let Some(ref cache) = env.policy.cache.store else {
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

    /// What of this exchange the cache will store, if it may store it at all.
    pub(super) fn pending_store(
        &self,
        env: &ChainEnv<'_>,
        plan: &HopPlan,
        exchange: &HopExchange,
        peer_addr: Option<SocketAddr>,
    ) -> Option<PendingStore> {
        let partition = cache_partition(env.policy, plan.attach_credentials);
        match (&exchange.response, env.policy.cache.store.as_ref()) {
            // `no-store` is both directions: the lookup above skipped the cache, and nothing
            // about this exchange is written to it either.
            (HopResponse::Network(resp), Some(cache))
                if plan.cache.mode != CacheMode::NoStore
                    && cache::is_storable(
                        &self.method,
                        &self.headers,
                        resp.status().as_u16(),
                        resp.headers(),
                    ) =>
            {
                Some(PendingStore {
                    cache: cache.clone(),
                    key: CacheKey::new(&self.method, &self.url).in_partition(partition),
                    url: self.url.clone(),
                    status: resp.status().as_u16(),
                    response_headers: resp.headers().clone(),
                    request_headers: self.headers.clone(),
                    decoded: env.init.auto_decode,
                    requested_at: exchange.requested_at,
                    received_at: exchange.received_at,
                    peer_addr,
                })
            }
            _ => None,
        }
    }
}

/// Lets the client's own deadline run no longer than the headers deadline's: that one is
/// enforced in `await_response`.
pub(super) fn client_deadline(
    env: &ChainEnv<'_>,
    mut req_builder: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    if env.init.headers_timeout.is_some() {
        req_builder = req_builder.timeout(NO_CLIENT_DEADLINE);
    }
    req_builder
}

/// Reports the HTTP version of the hop's response.
pub(super) fn report_protocol(env: &ChainEnv<'_>, resp: &reqwest::Response) {
    (env.policy.transport.on_protocol)(resp.url(), resp.version());
}

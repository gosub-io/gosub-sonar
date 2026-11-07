//! The fetcher's native side: the proxies its client routes by, the HSTS upgrade before a
//! request is keyed, and the background revalidations it queues. On wasm32 the browser's
//! `fetch()` does all of this itself, and `wasm.rs` stands in with the same items.

use super::{Fetcher, FetcherConfig};
use crate::net::fetch::NetPolicy;
use crate::net::fetcher_context::FetcherContext;
use crate::net::hsts;
use crate::net::proxy::ProxyRoutes;
use crate::net::types::{FetchRequest, Priority};
use std::sync::Arc;
use tokio::sync::{oneshot, Notify};
use tokio_util::sync::CancellationToken;

/// What the client was built with that a request's policy has to agree with, taken when
/// it was built rather than looked up again per request, and where a request's policy leaves
/// the background revalidations it starts.
pub(super) struct ClientsBuilt {
    /// The proxies the client routes by; see [`ProxyRoutes`].
    proxy: ProxyRoutes,
    /// Background revalidations on their way to the run loop.
    revalidations: Revalidations,
}

impl ClientsBuilt {
    pub(super) fn new(cfg: &FetcherConfig) -> anyhow::Result<Self> {
        Ok(Self {
            proxy: ProxyRoutes::resolve(&cfg.proxy)?,
            revalidations: Revalidations::default(),
        })
    }
}

/// The background revalidations of stale responses that requests were answered with (see
/// [`cache`](mod@crate::net::cache)), handed from a request's policy to the run loop, which
/// queues them as requests of the fetcher's own.
#[derive(Default)]
struct Revalidations {
    /// Started and not yet queued.
    started: std::sync::Mutex<Vec<FetchRequest>>,
    /// Wakes the run loop for a revalidation started while it waits.
    ready: Notify,
}

impl Fetcher {
    /// Queue the background revalidations requests have started since the last look. Nobody
    /// waits for their result: what they bring back goes to the cache. Two for the same stored
    /// response share one fetch, as any two requests alike do, so it is revalidated once
    /// however many requests it answers meanwhile.
    pub(super) async fn queue_revalidations(&self) {
        let started = std::mem::take(
            &mut *self
                .built
                .revalidations
                .started
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for req in started {
            let (reply, _) = oneshot::channel();
            self.submit(req, CancellationToken::new(), reply).await;
        }
    }

    /// Waits until a request is submitted, a background revalidation is queued, or `shutdown`.
    pub(super) async fn wait_for_work(&self, shutdown: &CancellationToken) {
        tokio::select! {
            _ = self.wake.notified() => {},
            _ = self.built.revalidations.ready.notified() => {},
            _ = shutdown.cancelled() => {},
        }
    }

    /// Upgrades `req` to `https` when HSTS knows its host.
    pub(super) fn hsts_upgrade(&self, req: &mut FetchRequest) {
        if let Some(ref store) = self.cfg.hsts {
            if hsts::should_upgrade(store.as_ref(), &req.url, chrono::Utc::now()) {
                req.url = hsts::upgrade(&req.url);
            }
        }
    }
}

/// Whether a streamed fetch gets a deadline for its response headers alone.
pub(super) const HEADERS_DEADLINE: bool = true;

/// Build a reqwest client from `FetcherConfig`.
///
/// The client decodes no response bodies and adds no `Accept-Encoding`: both are the fetch's,
/// in `get_with_redirects` and [`decode`](crate::net::decode).
pub(super) fn build_client(
    cfg: &FetcherConfig,
    ctx: &Arc<dyn FetcherContext>,
    built: &ClientsBuilt,
) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        // `get_with_redirects` follows redirects itself so that the per-hop mixed content
        // check, HSTS upgrade, SSRF/URL policy, cookie jar, cross-origin header stripping,
        // and `NetEvent::Redirected` all apply at every hop. reqwest's own redirect following
        // must stay disabled or it swallows each 3xx internally and none of that runs — see
        // `fetcher_url_policy_is_applied_to_redirect_targets`.
        .redirect(reqwest::redirect::Policy::none())
        .connection_verbose(false)
        .http2_adaptive_window(true)
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.req_timeout)
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        .pool_idle_timeout(cfg.pool_idle_timeout)
        .tcp_keepalive(cfg.tcp_keepalive)
        // Bodies are decoded by `net::decode`, never by the client. Off explicitly too: a
        // crate that enables reqwest's decompression features would turn it on by default.
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd();
    // overrides need our own verifier, so we build the rustls config ourselves
    b = match &cfg.tls_overrides {
        // tls_info: responses carry their peer certificate, for the HSTS check
        Some(store) => b
            .tls_info(true)
            .tls_backend_preconfigured(crate::net::tls::client_config(
                store.clone(),
                ctx.clone(),
                cfg.hsts.clone(),
            )?),
        None => b.use_rustls_tls(),
    };
    if let Some(ref ua) = cfg.user_agent {
        b = b.user_agent(ua);
    }
    // Always installed, the system's resolver when none is configured, so that
    // `localhost` is answered with loopback rather than looked up.
    let resolver = cfg
        .dns_resolver
        .clone()
        .unwrap_or_else(|| Arc::new(crate::net::dns::SystemResolver));
    b = b.dns_resolver(Arc::new(crate::net::dns::ReqwestResolver(resolver)));
    // Observation only - forwards the request and returns the connector's own result
    // unchanged - so it is installed for every client rather than gated on config.
    b = b.connector_layer(crate::net::connect_timing::ConnectTimingLayer);
    b = built.proxy.apply(b)?;
    Ok(b.build()?)
}

/// `policy` with the proxy, DNS, HSTS, TLS override and cache hooks the fetcher's config sets.
pub(super) fn native_policy(
    policy: NetPolicy,
    req: &FetchRequest,
    cfg: &FetcherConfig,
    built: &Arc<ClientsBuilt>,
) -> NetPolicy {
    // Same reason as the user agent: the client would attach `Proxy-Authorization` itself,
    // while executing the request, and an observer would never see the header its own
    // configuration put there.
    let proxy = built.clone();
    let proxy_for = built.clone();
    let proxied = built.clone();
    let policy = policy
        .with_proxy_authorization(Box::new(move |url| proxy.proxy.proxy_authorization(url)))
        .with_proxy_for(Box::new(move |url| proxy_for.proxy.http_proxy(url)))
        .with_proxied(Box::new(move |url| proxied.proxy.routes_through_proxy(url)))
        .with_dns_resolver(cfg.dns_resolver.clone())
        .with_hsts(cfg.hsts.clone())
        .with_tls_overrides(cfg.tls_overrides.clone())
        .with_cache(cfg.cache.clone());
    let policy = match cfg.cache {
        Some(_) => policy.with_background_revalidation(revalidate_later(req, built)),
        None => policy,
    };
    match cfg.cors_preflight_cache.clone() {
        Some(cache) => policy.with_cors_preflight_cache(cache),
        None => policy,
    }
}

/// What starts the background revalidation of a stale response `req` was answered with: a
/// request of the fetcher's own, `req` again (Fetch: a clone of the request) from the hop that
/// was answered, as its redirect chain had left it, in
/// [`CacheMode::NoCache`](crate::net::cache::CacheMode::NoCache) and at [`Priority::Low`],
/// queued by the run loop. It reports to an observer of its own, under a request id of its
/// own, and the stored response it brings back answers the requests after it.
fn revalidate_later(
    req: &FetchRequest,
    built: &Arc<ClientsBuilt>,
) -> crate::net::fetch::BackgroundRevalidationFn {
    let req = req.clone();
    let built = built.clone();
    Box::new(move |from| {
        let mut revalidation = req.clone();
        revalidation.req_id = crate::types::RequestId::new();
        revalidation.url = from.url().clone();
        revalidation.method = from.method().clone();
        revalidation.headers = from.headers().clone();
        // A redirect to `GET` took the body; a hop that is answered from the cache has none.
        revalidation.body = None;
        revalidation.cache_mode = crate::net::cache::CacheMode::NoCache;
        revalidation.background_revalidation = Some(from);
        revalidation.priority = Priority::Low;
        // Read to its end, so the cache gets the whole response.
        revalidation.streaming = false;
        let revalidations = &built.revalidations;
        revalidations
            .started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(revalidation);
        revalidations.ready.notify_one();
    })
}

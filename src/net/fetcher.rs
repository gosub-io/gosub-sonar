//! Priority-scheduled fetcher with request coalescing and per-origin concurrency limits.

use crate::net::fetch::{
    blocked, fetch_response_complete, fetch_response_top, preflight, NetPolicy, Preflight,
    RequestInit, ResponseTop,
};
use crate::net::fetcher_context::FetcherContext;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::hsts::{self, HstsStore, InMemoryHstsStore};
use crate::net::mixed_content::MixedContentPolicy;
use crate::net::observer::NetObserver;
use crate::net::shared_body::{ReaderOptions, SharedBody};
use crate::net::types::{FetchRequest, FetchResult, NetError, Priority};
use crate::net::utils::{short_url, spawn_named, Waiter};
use dashmap::{DashMap, Entry};
use http::header;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::sync::{oneshot, Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;

const SHARED_MAX_CAPACITY: usize = 32;

/// Configuration for the priority-scheduled [`Fetcher`].
///
/// All timeouts apply per individual request, not to the fetcher as a whole.
/// The default values are conservative browser-like settings suitable for
/// general-purpose use; tune them for your environment.
#[derive(Clone)]
pub struct FetcherConfig {
    /// Maximum number of concurrent HTTP connections across all origins.
    pub global_slots: usize,
    /// Maximum concurrent connections **per origin** for HTTP/1.x.
    /// HTTP/1 pipelines poorly, so browsers cap this at 6.
    pub h1_per_origin: usize,
    /// Maximum concurrent streams **per origin** for HTTP/2 (multiplexed).
    pub h2_per_origin: usize,
    /// Timeout for the TCP + TLS handshake.  Applies before any bytes are sent.
    pub connect_timeout: Duration,
    /// Timeout from sending the first request byte until the response headers arrive.
    pub req_timeout: Duration,
    /// Maximum silence between consecutive body chunks before the read is aborted.
    pub read_idle_timeout: Duration,
    /// Wall-clock deadline for receiving the entire response body after headers.
    /// `None` disables the deadline (useful for very large downloads).
    pub total_body_timeout: Option<Duration>,

    /// Maximum idle connections kept in the pool **per host**.
    /// Without a cap, reqwest keeps every connection ever opened until it idles out.
    pub pool_max_idle_per_host: usize,
    /// How long an idle connection stays in the pool before being closed.
    /// `None` keeps idle connections around indefinitely.
    pub pool_idle_timeout: Option<Duration>,
    /// Interval for TCP keepalive probes on pooled connections, so dead peers
    /// (e.g. behind a NAT that dropped the mapping) are detected instead of
    /// failing the next request. `None` disables keepalive.
    pub tcp_keepalive: Option<Duration>,

    /// `User-Agent` header sent with every request made by this fetcher.
    ///
    /// Set this to identify your application to servers and CDNs.
    /// `None` falls back to reqwest's built-in default (`reqwest/VERSION`).
    /// For a browser engine use something like `"Mozilla/5.0 (compatible; MyBrowser/1.0)"`.
    pub user_agent: Option<String>,

    /// Store backing HTTP Strict Transport Security.
    ///
    /// Defaults to an [`InMemoryHstsStore`], so HSTS is enforced without any setup; supply your
    /// own [`HstsStore`] to persist policies across restarts. `None` disables HSTS — appropriate
    /// for a private-browsing session, which must not consult or add to a persistent store.
    #[cfg(not(target_arch = "wasm32"))]
    pub hsts: Option<Arc<dyn HstsStore>>,

    /// What to do when a request carrying a secure [`FetchRequest::origin`] targets an insecure
    /// URL. Defaults to [`MixedContentPolicy::Block`], and is overridable per request via
    /// [`FetchRequest::mixed_content`]. See [`mixed_content`](mod@crate::net::mixed_content).
    pub mixed_content: MixedContentPolicy,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            global_slots: 32,
            h1_per_origin: 6,
            h2_per_origin: 16,
            connect_timeout: Duration::from_secs(5),
            req_timeout: Duration::from_secs(60),
            read_idle_timeout: Duration::from_secs(15),
            total_body_timeout: Some(Duration::from_secs(180)),
            pool_max_idle_per_host: 6,
            pool_idle_timeout: Some(Duration::from_secs(90)),
            tcp_keepalive: Some(Duration::from_secs(60)),
            user_agent: None,
            #[cfg(not(target_arch = "wasm32"))]
            hsts: Some(Arc::new(InMemoryHstsStore::new())),
            mixed_content: MixedContentPolicy::default(),
        }
    }
}

/// Shared state for a single in-flight unique fetch (one URL × method × headers × decode-flag).
///
/// Every coalesced subscriber holds an `Arc` to the same entry.  The entry lives in
/// `Fetcher::inflight_map` for the duration of the fetch and is removed when the fetch
/// completes (or is cancelled by all subscribers).
///
/// # Lifecycle
///
/// 1. **Leader** — the first request for a key creates the entry and starts the real HTTP fetch.
/// 2. **Followers** — subsequent requests with the same key join via `waiter.register()` without
///    starting a second fetch.  They receive the same result when the leader finishes.
/// 3. **Cancellation** — each subscriber gets a child `CancellationToken` derived from
///    `parent_cancel`.  When a subscriber cancels, `dec_sub_and_maybe_cancel` decrements `subs`.
///    If the count reaches zero (all subscribers cancelled), `parent_cancel` is fired, which
///    in turn cancels the in-progress HTTP request.
/// 4. **Completion** — the leader removes the entry from the map (so new requests start a fresh
///    fetch instead of joining a waiter that is about to be drained), then calls
///    `waiter.finish(result)`, which fans the result out to all registered receivers.  `done` is
///    then cancelled to unblock any lingering child-cancel tasks.
pub struct FetchInflightEntry {
    /// Fires when *all* subscribers have cancelled, aborting the underlying HTTP request.
    parent_cancel: CancellationToken,
    /// Fan-out dispatcher: registers per-subscriber oneshot senders, delivers the result to all.
    waiter: Arc<Waiter>,
    /// Set to `true` if *any* subscriber requested streaming; the leader uses this to decide
    /// whether to call `perform_streaming` or `perform_buffered`.
    wants_streaming: AtomicBool,
    /// Count of currently active subscribers.  Decremented on cancellation; triggers
    /// `parent_cancel` when it reaches zero.
    subs: AtomicUsize,
    /// Cancelled by the leader after `waiter.finish()` to unblock child-cancel watcher tasks
    /// that are waiting on either subscriber cancellation or fetch completion.
    done: CancellationToken,
}

impl FetchInflightEntry {
    #[inline]
    fn inc_sub(&self) {
        self.subs.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the subscriber count and, if this was the last subscriber, cancels the
    /// parent token to abort the in-progress HTTP request.
    #[inline]
    fn dec_sub_and_maybe_cancel(&self) {
        if self.subs.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.parent_cancel.cancel();
        }
    }
}

/// One pending fetch sitting in a priority lane of the [`Fetcher`] scheduler.
///
/// Items are enqueued by [`Fetcher::submit`] and dequeued by the [`Fetcher::run`] loop, which
/// picks the next item via weighted round-robin across the four priority queues.
struct QueueItem {
    /// What to fetch and how (URL, method, headers, body, priority, …).
    req: FetchRequest,
    /// Per-request handle carrying the cancellation token for this specific subscriber.
    /// Distinct from `FetchInflightEntry::parent_cancel`, which fires only when *all*
    /// subscribers cancel; this token fires when just this one caller cancels.
    cancel: CancellationToken,
    /// One-shot channel back to the caller.  The run loop hands this to the
    /// [`FetchInflightEntry`] waiter; the result is sent when the fetch completes.
    reply: oneshot::Sender<FetchResult>,
}

/// Priority-scheduled fetcher with request coalescing, per-origin concurrency limits,
/// and fan-out to multiple subscribers.
///
/// Construct with [`Fetcher::new`], spawn [`Fetcher::run`] on a Tokio runtime, then
/// submit requests with [`Fetcher::fetch`], [`Fetcher::fetch_with_cancel`], or
/// [`Fetcher::submit`]. See the crate-level docs for a complete example.
pub struct Fetcher {
    /// Client with automatic content-decoding (gzip, brotli, deflate). Used when `auto_decode: true`.
    client: reqwest::Client,
    /// Client without any content-decoding. Used when `auto_decode: false` (raw bytes requested).
    client_raw: reqwest::Client,
    cfg: FetcherConfig,

    global_slots: Arc<Semaphore>,
    // Wrapped in Arc so spawned tasks share the same map rather than each getting a clone.
    per_origin: Arc<DashMap<String, Arc<Semaphore>>>,

    q_high: tokio::sync::Mutex<VecDeque<QueueItem>>,
    q_norm: tokio::sync::Mutex<VecDeque<QueueItem>>,
    q_low: tokio::sync::Mutex<VecDeque<QueueItem>>,
    q_idle: tokio::sync::Mutex<VecDeque<QueueItem>>,

    inflight_map: Arc<DashMap<String, Arc<FetchInflightEntry>>>,

    wake: Notify,

    ctx: Arc<dyn FetcherContext>,
}

impl Fetcher {
    /// Creates a fetcher with the given configuration and lifecycle context.
    ///
    /// Use [`NullContext`](crate::NullContext) as the context if you don't need lifecycle
    /// callbacks. Fails if the configured concurrency limits are zero.
    pub fn new(config: FetcherConfig, ctx: Arc<dyn FetcherContext>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.global_slots > 0,
            "FetcherConfig.global_slots must be >= 1"
        );
        anyhow::ensure!(
            config.h1_per_origin > 0,
            "FetcherConfig.h1_per_origin must be >= 1"
        );
        anyhow::ensure!(
            config.h2_per_origin > 0,
            "FetcherConfig.h2_per_origin must be >= 1"
        );

        let client = build_client(&config, true)?;
        let client_raw = build_client(&config, false)?;

        Ok(Self {
            client,
            client_raw,
            cfg: config.clone(),
            global_slots: Arc::new(Semaphore::new(config.global_slots)),
            per_origin: Arc::new(DashMap::new()),
            q_high: tokio::sync::Mutex::new(VecDeque::new()),
            q_norm: tokio::sync::Mutex::new(VecDeque::new()),
            q_low: tokio::sync::Mutex::new(VecDeque::new()),
            q_idle: tokio::sync::Mutex::new(VecDeque::new()),
            inflight_map: Arc::new(DashMap::new()),
            wake: Notify::new(),
            ctx,
        })
    }

    fn origin_key(url: &Url) -> String {
        url.origin().ascii_serialization()
    }

    // Weighted round-robin dequeue across the four priority lanes.
    // The 15-slot cycle gives approximate weights: High=8, Normal=4, Low=2, Idle=1.
    // When the preferred lane is empty the next non-empty lane is tried in
    // descending priority order, so no request starves as long as slots remain.
    fn pick_lane<'a>(
        &'a self,
        high: &'a mut VecDeque<QueueItem>,
        norm: &'a mut VecDeque<QueueItem>,
        low: &'a mut VecDeque<QueueItem>,
        idle: &'a mut VecDeque<QueueItem>,
        counter: &mut u8,
    ) -> Option<QueueItem> {
        let slot = *counter as usize;
        *counter = (*counter + 1) % 15;

        let try_pop = |q: &mut VecDeque<QueueItem>| q.pop_front();

        match slot {
            0..=7 => try_pop(high)
                .or_else(|| try_pop(norm))
                .or_else(|| try_pop(low))
                .or_else(|| try_pop(idle)),
            8..=11 => try_pop(norm)
                .or_else(|| try_pop(high))
                .or_else(|| try_pop(low))
                .or_else(|| try_pop(idle)),
            12..=13 => try_pop(low)
                .or_else(|| try_pop(norm))
                .or_else(|| try_pop(high))
                .or_else(|| try_pop(idle)),
            _ => try_pop(idle)
                .or_else(|| try_pop(low))
                .or_else(|| try_pop(norm))
                .or_else(|| try_pop(high)),
        }
    }

    /// Submit a request and await its result.
    ///
    /// Convenience over [`submit`](Self::submit): Reply channel internally
    /// so a fetch is a single call on a built [`FetchRequest`]. The request cannot
    /// be cancelled individually; use [`fetch_with_cancel`](Self::fetch_with_cancel) for that.
    ///
    /// Requires the [`run`](Self::run) loop to be running; if the fetcher stops before
    /// delivering, this resolves to a [`FetchResult::Error`].
    pub async fn fetch(&self, req: FetchRequest) -> FetchResult {
        self.fetch_with_cancel(req, CancellationToken::new()).await
    }

    /// Like [`fetch`](Self::fetch), with a caller-supplied cancellation token for this
    /// subscriber. Cancelling the token abandons this caller's interest in the result; the
    /// underlying HTTP request is aborted once all subscribers have cancelled.
    pub async fn fetch_with_cancel(
        &self,
        req: FetchRequest,
        cancel: CancellationToken,
    ) -> FetchResult {
        let (tx, rx) = oneshot::channel();
        self.submit(req, cancel, tx).await;
        rx.await.unwrap_or_else(|_| {
            FetchResult::Error(NetError::Cancelled(
                "fetcher stopped before delivering a result".into(),
            ))
        })
    }

    /// Enqueues a request with a caller-supplied handle and reply channel.
    ///
    /// This is the lowest-level entry point: the caller controls the [`CancellationToken`]
    /// and receives the [`FetchResult`] on `reply_tx`.
    /// Most callers want [`fetch`](Self::fetch) or [`fetch_with_cancel`](Self::fetch_with_cancel).
    pub async fn submit(
        &self,
        req: FetchRequest,
        cancel: CancellationToken,
        reply_tx: oneshot::Sender<FetchResult>,
    ) {
        log::debug!("Submitting fetch request: {:?}", req);

        let mut lane = match req.priority {
            Priority::High => self.q_high.lock().await,
            Priority::Normal => self.q_norm.lock().await,
            Priority::Low => self.q_low.lock().await,
            Priority::Idle => self.q_idle.lock().await,
        };
        lane.push_back(QueueItem {
            req,
            // handle: req_handle,\
            cancel,
            reply: reply_tx,
        });
        self.wake.notify_one();
    }

    /// Runs the scheduler loop until `shutdown` is cancelled.
    ///
    /// Dequeues requests via weighted round-robin across the four priority lanes and
    /// spawns fetch tasks subject to the global and per-origin concurrency limits.
    /// Spawn this on a Tokio runtime before calling [`fetch`](Self::fetch).
    pub async fn run(&self, shutdown: CancellationToken) {
        let mut lane_counter: u8 = 0;

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            let next = {
                let mut high = self.q_high.lock().await;
                let mut norm = self.q_norm.lock().await;
                let mut low = self.q_low.lock().await;
                let mut idle = self.q_idle.lock().await;
                self.pick_lane(&mut high, &mut norm, &mut low, &mut idle, &mut lane_counter)
            };

            // `req` is only reassigned by the HSTS upgrade below, which is native-only.
            #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
            let Some(QueueItem {
                mut req,
                cancel,
                reply: reply_tx,
            }) = next
            else {
                tokio::select! {
                    _ = self.wake.notified() => {},
                    _ = shutdown.cancelled() => {},
                }
                continue;
            };

            // Upgrade before the key is derived, or an http:// and an https:// request for the
            // same HSTS host hash to different keys and run as two fetches instead of coalescing
            // onto one. Also fixes the origin used for the per-origin limit below.
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(ref store) = self.cfg.hsts {
                if hsts::should_upgrade(store.as_ref(), &req.url, chrono::Utc::now()) {
                    req.url = hsts::upgrade(&req.url);
                }
            }

            // Pin the mixed-content policy to its resolved value before keying, so a request that
            // inherits the fetcher default and one that names the same policy explicitly land in
            // the same coalescing bucket instead of needlessly splitting.
            req.mixed_content = Some(effective_mixed_content(&req, &self.cfg));

            let key_opt = req.generate_request_key();
            let key_str = {
                let base = match key_opt {
                    Some(k) => k,
                    None => format!(
                        "{} {} @{}",
                        req.method,
                        req.url,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    ),
                };
                format!("{};D={}", base, req.auto_decode as u8)
            };

            // Register the reply channel while still holding the DashMap entry guard.
            // `register` is synchronous (no await), so holding the shard lock here is safe. The
            // leader removes the entry from the map *before* draining the waiter, and entry() and
            // remove() serialize on the shard lock — so a follower that finds the entry here is
            // guaranteed to register before the drain; otherwise it finds the map vacant and
            // becomes the leader of a fresh fetch. Registering after releasing the guard would
            // leave a window where the result is lost and the subscriber gets a RecvError.
            let (inflight_entry, is_leader) = match self.inflight_map.entry(key_str.clone()) {
                Entry::Occupied(entry) => {
                    let arc = entry.get().clone();
                    arc.waiter.register(reply_tx, req.streaming);
                    arc.inc_sub();
                    (arc, false)
                }
                Entry::Vacant(v) => {
                    let arc = Arc::new(FetchInflightEntry {
                        parent_cancel: CancellationToken::new(),
                        waiter: Arc::new(Waiter::new()),
                        wants_streaming: AtomicBool::new(req.streaming),
                        done: CancellationToken::new(),
                        subs: AtomicUsize::new(0),
                    });
                    arc.waiter.register(reply_tx, req.streaming);
                    arc.inc_sub();
                    v.insert(arc.clone());
                    (arc, true)
                }
            };

            if is_leader {
                self.ctx.on_ref_active(req.reference);
            }

            let child_cancel = cancel.clone();
            let entry_for_cancel = inflight_entry.clone();
            let done = entry_for_cancel.done.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = child_cancel.cancelled() => entry_for_cancel.dec_sub_and_maybe_cancel(),
                    _ = done.cancelled() => {}
                }
            });

            if req.streaming {
                inflight_entry
                    .wants_streaming
                    .store(true, Ordering::Relaxed);
            }

            if !is_leader {
                continue;
            }

            let observer =
                self.ctx
                    .observer_for(req.reference, req.req_id, req.kind, req.initiator);

            // Pre-flight checks. Only the leader ever sends bytes, so only the leader evaluates
            // them; rejecting here avoids waiting on a connection slot for a request that will
            // never go out. The same `preflight` runs per hop inside `get_with_redirects`, which
            // is what catches redirect targets — so this cannot reject anything the enforcement
            // path would have allowed. The upgraded URL is discarded here; the redirect loop
            // recomputes and applies it.
            let reject = match preflight(
                &req.url,
                effective_mixed_content(&req, &self.cfg),
                req.origin.as_ref(),
                &|u| self.ctx.is_url_allowed(u),
            ) {
                Preflight::Reject(reason) => Some(reason),
                Preflight::Proceed(_) => None,
            };

            if let Some(reason) = reject {
                let err = FetchResult::Error(blocked(&observer, req.url.clone(), reason));
                // Remove before finish — see the registration comment above for the ordering.
                self.inflight_map.remove(&key_str);
                inflight_entry.waiter.finish(err).await;
                inflight_entry.done.cancel();
                self.ctx.on_ref_done(req.reference);
                continue;
            }

            let client = if req.auto_decode {
                self.client.clone()
            } else {
                self.client_raw.clone()
            };
            let global = self.global_slots.clone();
            let per_origin = self.per_origin.clone();
            let cfg = self.cfg.clone();
            let inflight = self.inflight_map.clone();
            let key_for_remove = key_str.clone();
            let inflight_entry2 = inflight_entry.clone();
            let shutdown_child = shutdown.clone();
            let req_for_task = req.clone();
            let cancel_parent = inflight_entry2.parent_cancel.clone();
            let ctx_clone = self.ctx.clone();

            let title = format!("Fetcher: {}", short_url(&req.url, 80));
            spawn_named(&title, async move {
                let origin = Fetcher::origin_key(&req.url);
                let slots = per_origin
                    .entry(origin.clone())
                    .or_insert_with(|| {
                        Arc::new(Semaphore::new(per_origin_limit_for(&cfg, &req.url)))
                    })
                    .clone();

                let g = tokio::select! { p = global.acquire_owned() => Some(p), _ = shutdown_child.cancelled() => None };
                if g.is_none() {
                    return;
                }

                let h = tokio::select! { p = slots.acquire_owned() => Some(p), _ = shutdown_child.cancelled() => None };
                if h.is_none() {
                    return;
                }

                let should_stream =
                    req.streaming || inflight_entry2.wants_streaming.load(Ordering::Relaxed);

                let result = if should_stream {
                    perform_streaming(
                        &client,
                        observer.clone(),
                        &req_for_task,
                        &cfg,
                        cancel_parent.clone(),
                        ctx_clone.clone(),
                    )
                    .await
                } else {
                    perform_buffered(
                        &client,
                        observer.clone(),
                        &req_for_task,
                        &cfg,
                        cancel_parent.clone(),
                        ctx_clone.clone(),
                    )
                    .await
                };

                let fr = match &result {
                    Ok(fetch_result) => fetch_result.clone(),
                    Err(e) => FetchResult::Error(e.clone()),
                };

                // Remove from the map before draining the waiter: entry() and remove() serialize
                // on the shard lock, so any follower that found this entry has already registered,
                // and later arrivals find the map vacant and start a fresh fetch instead.
                inflight.remove(&key_for_remove);

                inflight_entry2.waiter.finish(fr).await;

                inflight_entry2.done.cancel();

                ctx_clone.on_ref_done(req.reference);
            });
        }
    }
}

/// The mixed content policy in force for `req`: its own override if it set one, otherwise the
/// fetcher-wide default.
///
/// Must stay consistent with the discriminator built into
/// [`FetchRequest::generate_request_key`] — two requests that resolve to different policies have
/// to land in different coalescing buckets, or one could inherit the other's verdict.
fn effective_mixed_content(req: &FetchRequest, cfg: &FetcherConfig) -> MixedContentPolicy {
    req.mixed_content.unwrap_or(cfg.mixed_content)
}

/// Build a [`RequestInit`] from a [`FetchRequest`], injecting a `Content-Type` header from
/// the body descriptor when the headers don't already contain one, and carrying the request's
/// initiating origin plus the fetcher's mixed content policy down to the redirect loop.
fn make_request_init(req: &FetchRequest, cfg: &FetcherConfig) -> RequestInit {
    let mut headers = req.headers.clone();
    let body = req.body.as_ref().map(|b| {
        if let Some(ref ct) = b.content_type {
            if !headers.contains_key(header::CONTENT_TYPE) {
                if let Ok(val) = ct.parse() {
                    headers.insert(header::CONTENT_TYPE, val);
                }
            }
        }
        b.clone()
    });
    RequestInit::new(req.method.clone(), headers, body)
        .with_mixed_content(req.origin.clone(), effective_mixed_content(req, cfg))
}

/// Build a reqwest client from `FetcherConfig`.
///
/// When `decode` is `true` the client automatically decompresses `gzip`, `brotli`, and `deflate`
/// response bodies and sends the corresponding `Accept-Encoding` request header.
/// When `false` neither header is added nor is any decompression performed.
fn build_client(cfg: &FetcherConfig, decode: bool) -> anyhow::Result<reqwest::Client> {
    // The browser's fetch() owns TLS, connection management, timeouts, and transparent
    // decompression; none of the tuning knobs below exist in reqwest's wasm backend.
    //
    // It also owns redirects: there is no way to ask for them un-followed, so on wasm32
    // `get_with_redirects` only ever sees the final response and the per-hop checks run once,
    // on the initial URL. The browser applies its own mixed content blocking to the hops we
    // cannot see, so this is a loss of reporting rather than of enforcement.
    #[cfg(target_arch = "wasm32")]
    {
        let _ = decode;
        let mut b = reqwest::Client::builder();
        if let Some(ref ua) = cfg.user_agent {
            b = b.user_agent(ua);
        }
        Ok(b.build()?)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
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
            .use_rustls_tls()
            .gzip(decode)
            .brotli(decode)
            .deflate(decode);
        if let Some(ref ua) = cfg.user_agent {
            b = b.user_agent(ua);
        }
        Ok(b.build()?)
    }
}

fn per_origin_limit_for(cfg: &FetcherConfig, url: &Url) -> usize {
    match url.scheme() {
        // Only HTTPS can negotiate HTTP/2 via ALPN; plain HTTP uses HTTP/1.x
        "https" => cfg.h2_per_origin,
        _ => cfg.h1_per_origin,
    }
}

async fn perform_streaming(
    client: &reqwest::Client,
    observer: Arc<dyn NetObserver + Send + Sync>,
    req: &FetchRequest,
    cfg: &FetcherConfig,
    cancel: CancellationToken,
    ctx: Arc<dyn FetcherContext>,
) -> Result<FetchResult, NetError> {
    #[cfg(not(target_arch = "wasm32"))]
    let policy = NetPolicy::from_context(&ctx).with_hsts(cfg.hsts.clone());
    #[cfg(target_arch = "wasm32")]
    let policy = NetPolicy::from_context(&ctx);

    let ResponseTop {
        meta,
        peek_buf,
        reader,
    } = fetch_response_top(
        Arc::new(client.clone()),
        req.url.clone(),
        make_request_init(req, cfg),
        cancel.clone(),
        observer.clone(),
        policy,
    )
    .await?;

    // Notify the context's cookie jar about any Set-Cookie headers in the response
    notify_cookies(&ctx, &meta);

    let opts = ReaderOptions {
        capacity: SHARED_MAX_CAPACITY,
        buf_size: 16 * 1024,
        cancel: Some(cancel.clone()),
        idle_timeout: Some(cfg.read_idle_timeout),
        total_timeout: cfg.total_body_timeout,
        // The reader counts only post-peek bytes — the peek was already read off the stream —
        // so subtract it from the budget. A body of exactly max_bytes is delivered in full.
        max_size: req
            .max_bytes
            .map(|max| max.saturating_sub(peek_buf.len()) as u64),
    };

    Ok(FetchResult::Stream {
        meta,
        peek_buf,
        shared: SharedBody::from_reader(reader, opts),
    })
}

async fn perform_buffered(
    client: &reqwest::Client,
    observer: Arc<dyn NetObserver + Send + Sync>,
    req: &FetchRequest,
    cfg: &FetcherConfig,
    cancel: CancellationToken,
    ctx: Arc<dyn FetcherContext>,
) -> Result<FetchResult, NetError> {
    #[cfg(not(target_arch = "wasm32"))]
    let policy = NetPolicy::from_context(&ctx).with_hsts(cfg.hsts.clone());
    #[cfg(target_arch = "wasm32")]
    let policy = NetPolicy::from_context(&ctx);

    let (meta, body) = fetch_response_complete(
        Arc::new(client.clone()),
        req.url.clone(),
        make_request_init(req, cfg),
        cancel.clone(),
        observer,
        req.max_bytes,
        cfg.read_idle_timeout,
        cfg.total_body_timeout,
        policy,
    )
    .await?;

    // Notify the context's cookie jar about any Set-Cookie headers in the response
    notify_cookies(&ctx, &meta);

    // `body` is already an `Arc`-backed `Bytes`; moving it into the result is zero-copy.
    Ok(FetchResult::Buffered { meta, body })
}

/// Extract `Set-Cookie` header values from `meta` and forward them to the context.
fn notify_cookies(ctx: &Arc<dyn FetcherContext>, meta: &crate::net::types::FetchResultMeta) {
    let values: Vec<&str> = meta
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !values.is_empty() {
        ctx.on_cookies_received(&meta.final_url, &values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fetcher_context::NullContext;
    use crate::net::request_ref::RequestReference;
    use crate::net::test_support::{RouteConfig, TestServer};
    use crate::net::types::{BlockReason, FetchRequest, Initiator, ResourceKind};
    use crate::types::RequestId;
    use http::{HeaderMap, Method};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    fn test_config() -> FetcherConfig {
        FetcherConfig {
            connect_timeout: Duration::from_secs(2),
            req_timeout: Duration::from_secs(5),
            read_idle_timeout: Duration::from_secs(2),
            total_body_timeout: Some(Duration::from_secs(10)),
            ..FetcherConfig::default()
        }
    }

    async fn start_server() -> crate::net::test_support::TestServerHandle {
        TestServer::new()
            .route(
                "/slow",
                RouteConfig::stall_mid_body(0, Duration::from_secs(30)),
            )
            .route(
                "/coalesce",
                RouteConfig::delay(Duration::from_millis(50), b"coalesced".to_vec()),
            )
            .route("/hang", RouteConfig::hang_after_connect())
            .route("/fast", RouteConfig::ok(b"x"))
            // 12 KiB dribbled in 1 KiB chunks: headers arrive immediately, the body takes
            // ~360 ms, so tests can subscribe to a stream before it completes (no replay).
            // Chunk size divides PEEK_MAX exactly, so the peek phase leaves no excess bytes
            // that would be pushed to subscribers before a test can attach.
            .route(
                "/dribble-big",
                RouteConfig::chunked_with_delay(
                    vec![&[b'X'; 1024][..]; 12],
                    Duration::from_millis(30),
                ),
            )
            .route(
                "/timed",
                RouteConfig::delay(Duration::from_millis(60), b"ok".to_vec()),
            )
            .route("/not-found", RouteConfig::status(404, b"not found"))
            .route("/error", RouteConfig::status(500, b"server error"))
            .start()
            .await
    }

    fn make_req(url: Url, priority: Priority) -> (FetchRequest, CancellationToken) {
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            url,
            method: Method::GET,
            headers: HeaderMap::new(),
            priority,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            origin: None,
            mixed_content: None,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };

        (req, CancellationToken::new())
    }

    fn dummy_item(priority: Priority) -> QueueItem {
        let url = Url::parse("http://example.com/").unwrap();
        let req_id = RequestId::new();
        let (tx, _rx) = oneshot::channel();
        QueueItem {
            req: FetchRequest {
                reference: RequestReference::Background(0),
                req_id,
                url,
                method: Method::GET,
                headers: HeaderMap::new(),
                priority,
                initiator: Initiator::Other,
                kind: ResourceKind::Primary,
                origin: None,
                mixed_content: None,
                streaming: false,
                auto_decode: true,
                max_bytes: None,
                body: None,
            },
            cancel: CancellationToken::new(),
            reply: tx,
        }
    }

    // ── pick_lane ─────────────────────────────────────────────────────────────

    #[test]
    fn pick_lane_empty_queues_returns_none() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        let mut counter = 0u8;
        assert!(f
            .pick_lane(
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut counter
            )
            .is_none());
        assert_eq!(counter, 1);
    }

    #[test]
    fn pick_lane_counter_wraps_at_15() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        let mut counter = 14u8;
        f.pick_lane(
            &mut VecDeque::new(),
            &mut VecDeque::new(),
            &mut VecDeque::new(),
            &mut VecDeque::new(),
            &mut counter,
        );
        assert_eq!(counter, 0);
    }

    #[test]
    fn pick_lane_high_preferred_at_slots_0_to_7() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        for slot in 0u8..8 {
            let mut h = VecDeque::from([dummy_item(Priority::High)]);
            let mut n = VecDeque::from([dummy_item(Priority::Normal)]);
            let mut counter = slot;
            let item = f
                .pick_lane(
                    &mut h,
                    &mut n,
                    &mut VecDeque::new(),
                    &mut VecDeque::new(),
                    &mut counter,
                )
                .unwrap();
            assert_eq!(item.req.priority, Priority::High, "slot {slot}");
        }
    }

    #[test]
    fn pick_lane_norm_preferred_at_slots_8_to_11() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        for slot in 8u8..12 {
            let mut h = VecDeque::from([dummy_item(Priority::High)]);
            let mut n = VecDeque::from([dummy_item(Priority::Normal)]);
            let mut counter = slot;
            let item = f
                .pick_lane(
                    &mut h,
                    &mut n,
                    &mut VecDeque::new(),
                    &mut VecDeque::new(),
                    &mut counter,
                )
                .unwrap();
            assert_eq!(item.req.priority, Priority::Normal, "slot {slot}");
        }
    }

    #[test]
    fn pick_lane_low_preferred_at_slots_12_to_13() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        for slot in 12u8..14 {
            let mut l = VecDeque::from([dummy_item(Priority::Low)]);
            let mut i = VecDeque::from([dummy_item(Priority::Idle)]);
            let mut counter = slot;
            let item = f
                .pick_lane(
                    &mut VecDeque::new(),
                    &mut VecDeque::new(),
                    &mut l,
                    &mut i,
                    &mut counter,
                )
                .unwrap();
            assert_eq!(item.req.priority, Priority::Low, "slot {slot}");
        }
    }

    #[test]
    fn pick_lane_idle_preferred_at_slot_14() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        let mut i = VecDeque::from([dummy_item(Priority::Idle)]);
        let mut counter = 14u8;
        let item = f
            .pick_lane(
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut i,
                &mut counter,
            )
            .unwrap();
        assert_eq!(item.req.priority, Priority::Idle);
    }

    #[test]
    fn pick_lane_falls_back_when_preferred_lane_empty() {
        let f = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext)).unwrap();
        // slot 0 prefers high, but high is empty → falls back to normal
        let mut n = VecDeque::from([dummy_item(Priority::Normal)]);
        let mut counter = 0u8;
        let item = f
            .pick_lane(
                &mut VecDeque::new(),
                &mut n,
                &mut VecDeque::new(),
                &mut VecDeque::new(),
                &mut counter,
            )
            .unwrap();
        assert_eq!(item.req.priority, Priority::Normal);
    }

    // ── FetchInflightEntry ─────────────────────────────────────────────────────

    #[test]
    fn inflight_entry_cancel_fires_when_last_sub_removed() {
        let entry = FetchInflightEntry {
            parent_cancel: CancellationToken::new(),
            waiter: Arc::new(Waiter::new()),
            wants_streaming: AtomicBool::new(false),
            subs: AtomicUsize::new(0),
            done: CancellationToken::new(),
        };
        entry.inc_sub();
        entry.inc_sub();
        assert!(!entry.parent_cancel.is_cancelled());
        entry.dec_sub_and_maybe_cancel();
        assert!(!entry.parent_cancel.is_cancelled());
        entry.dec_sub_and_maybe_cancel();
        assert!(entry.parent_cancel.is_cancelled());
    }

    // ── Integration (requires mock server) ────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_buffers_response() {
        let srv = start_server().await;
        let base = srv.base_url();
        let shutdown = CancellationToken::new();
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let f = fetcher.clone();
        tokio::spawn(async move { f.run(shutdown.clone()).await });

        let (req, handle) = make_req(base, Priority::Normal);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        match rx.await.unwrap() {
            FetchResult::Buffered { meta, body } => {
                assert_eq!(meta.status, 200);
                assert_eq!(&body[..], b"hello");
            }
            other => panic!("expected Buffered, got {:?}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_connection_refused_gives_error() {
        let shutdown = CancellationToken::new();
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let f = fetcher.clone();
        tokio::spawn(async move { f.run(shutdown.clone()).await });

        let (req, handle) = make_req(Url::parse("http://127.0.0.1:1/").unwrap(), Priority::Normal);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        assert!(rx.await.unwrap().is_error());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_cancellation_yields_error() {
        let srv = start_server().await;
        let base = srv.base_url();
        let shutdown = CancellationToken::new();
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let f = fetcher.clone();
        tokio::spawn(async move { f.run(shutdown.clone()).await });

        let cancel = CancellationToken::new();
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            url: base.join("slow").unwrap(),
            headers: HeaderMap::new(),
            method: Method::GET,
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            origin: None,
            mixed_content: None,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };

        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, cancel.clone(), tx).await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_error());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_priority_high_runs_first_with_single_slot() {
        let srv = start_server().await;
        let base = srv.base_url();
        let fetcher = Arc::new(
            Fetcher::new(
                FetcherConfig {
                    global_slots: 1,
                    ..test_config()
                },
                Arc::new(NullContext),
            )
            .unwrap(),
        );

        let order = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let mut join_handles = Vec::new();

        // Submit all requests before starting the run loop so all are queued
        for (prio, label) in [
            (Priority::Idle, "idle"),
            (Priority::Low, "low"),
            (Priority::Normal, "normal"),
            (Priority::High, "high"),
        ] {
            let (req, handle) = make_req(base.clone(), prio);
            let (tx, rx) = oneshot::channel();
            fetcher.submit(req, handle, tx).await;
            let order_clone = order.clone();
            join_handles.push(tokio::spawn(async move {
                let _ = rx.await;
                order_clone.lock().unwrap().push(label);
            }));
        }

        let f = fetcher.clone();
        let shutdown = CancellationToken::new();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        for jh in join_handles {
            let _ = tokio::time::timeout(Duration::from_secs(5), jh).await;
        }

        assert_eq!(order.lock().unwrap()[0], "high");
        shutdown.cancel();
    }

    #[test]
    fn per_origin_limit_for_uses_h2_for_https_only() {
        let cfg = FetcherConfig {
            h1_per_origin: 3,
            h2_per_origin: 8,
            ..FetcherConfig::default()
        };
        // Plain http uses HTTP/1.x; only https can negotiate HTTP/2 via ALPN
        assert_eq!(
            per_origin_limit_for(&cfg, &Url::parse("http://example.com/").unwrap()),
            3
        );
        assert_eq!(
            per_origin_limit_for(&cfg, &Url::parse("https://example.com/").unwrap()),
            8
        );
        assert_eq!(
            per_origin_limit_for(&cfg, &Url::parse("ftp://example.com/").unwrap()),
            3
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_streaming_returns_stream_result() {
        let srv = start_server().await;
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let url = srv.base_url();
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            url,
            method: Method::GET,
            headers: HeaderMap::new(),
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            origin: None,
            mixed_content: None,
            streaming: true,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };
        let cancel = CancellationToken::new();
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, cancel, tx).await;

        let result = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        match result {
            FetchResult::Stream {
                meta,
                peek_buf,
                shared,
            } => {
                assert_eq!(meta.status, 200);
                let mut reader =
                    crate::net::shared_body::SharedBody::combined_reader(peek_buf, shared);
                let mut body = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut body)
                    .await
                    .unwrap();
                assert_eq!(&body[..], b"hello");
            }
            other => panic!("expected Stream, got {:?}", other),
        }
        shutdown.cancel();
    }

    /// Streaming fetches must honor `max_bytes`: a subscriber sees an error when the body
    /// exceeds the cap, and a body of exactly `max_bytes` streams in full (boundary case).
    /// Uses a dribbling route so the subscriber attaches before the body completes —
    /// `SharedBody` has no replay.
    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_streaming_respects_max_bytes() {
        use futures_util::StreamExt;

        let srv = start_server().await;
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        // Over the cap: /dribble-big is 12 KiB, cap at 6 KiB (peek is 5 KiB).
        let (mut req, _) = make_req(srv.url("/dribble-big"), Priority::Normal);
        req.streaming = true;
        req.max_bytes = Some(6 * 1024);
        let result = tokio::time::timeout(Duration::from_secs(5), fetcher.fetch(req))
            .await
            .unwrap();
        match result {
            FetchResult::Stream { shared, .. } => {
                let mut sub = shared.subscribe_stream();
                let mut saw_error = false;
                while let Some(chunk) = tokio::time::timeout(Duration::from_secs(5), sub.next())
                    .await
                    .unwrap()
                {
                    if chunk.is_err() {
                        saw_error = true;
                        break;
                    }
                }
                assert!(saw_error, "stream exceeded max_bytes without an error");
            }
            other => panic!("expected Stream, got {:?}", other),
        }

        // Exactly the cap: the full body must stream through, including the boundary byte.
        let (mut req, _) = make_req(srv.url("/dribble-big"), Priority::Normal);
        req.streaming = true;
        req.max_bytes = Some(12 * 1024);
        let result = tokio::time::timeout(Duration::from_secs(5), fetcher.fetch(req))
            .await
            .unwrap();
        match result {
            FetchResult::Stream {
                peek_buf, shared, ..
            } => {
                let mut reader =
                    crate::net::shared_body::SharedBody::combined_reader(peek_buf, shared);
                let mut body = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut body)
                    .await
                    .unwrap();
                assert_eq!(body.len(), 12 * 1024);
            }
            other => panic!("expected Stream, got {:?}", other),
        }
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_non_200_status_returned_as_buffered_not_error() {
        let srv = start_server().await;
        let shutdown = CancellationToken::new();
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let f = fetcher.clone();
        tokio::spawn(async move { f.run(shutdown.clone()).await });

        for (path, expected_status, expected_body) in [
            ("/not-found", 404u16, &b"not found"[..]),
            ("/error", 500u16, &b"server error"[..]),
        ] {
            let (req, handle) = make_req(srv.url(path), Priority::Normal);
            let (tx, rx) = oneshot::channel();
            fetcher.submit(req, handle, tx).await;
            match tokio::time::timeout(Duration::from_secs(3), rx)
                .await
                .unwrap()
                .unwrap()
            {
                FetchResult::Buffered { meta, body } => {
                    assert_eq!(meta.status, expected_status, "path={path}");
                    assert_eq!(&body[..], expected_body, "path={path}");
                }
                other => panic!("expected Buffered for {path}, got {:?}", other),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_per_origin_limit_serializes_excess_requests() {
        // Test server uses plain http://, so h1_per_origin applies (not h2_per_origin)
        let srv = start_server().await;
        let fetcher = Arc::new(
            Fetcher::new(
                FetcherConfig {
                    h1_per_origin: 1,
                    global_slots: 10,
                    ..test_config()
                },
                Arc::new(NullContext),
            )
            .unwrap(),
        );

        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let start = std::time::Instant::now();
        let mut receivers = Vec::new();
        // Use distinct query params to prevent coalescing while hitting the same route.
        for i in 0..3usize {
            let url = Url::parse(&format!("{}timed?i={}", srv.base_url(), i)).unwrap();
            let (req, handle) = make_req(url, Priority::Normal);
            let (tx, rx) = oneshot::channel();
            fetcher.submit(req, handle, tx).await;
            receivers.push(rx);
        }
        for rx in receivers {
            let _ = tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .unwrap()
                .unwrap();
        }
        // With h2_per_origin=1 and 3x60ms requests the minimum wall-clock time is ~120ms
        // (two serial batches). Allow generous headroom for slow CI.
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "requests should be serialized, elapsed: {:?}",
            start.elapsed()
        );
        shutdown.cancel();
    }

    /// The `fetch` convenience must deliver the same result as the manual
    /// submit/handle/oneshot ritual, and a stopped fetcher must resolve to an error
    /// rather than hanging.
    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_fetch_convenience_delivers_result() {
        let srv = start_server().await;
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());

        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, _) = make_req(srv.url("/fast"), Priority::Normal);
        let result = tokio::time::timeout(Duration::from_secs(3), fetcher.fetch(req))
            .await
            .unwrap();
        match result {
            FetchResult::Buffered { meta, body } => {
                assert_eq!(meta.status, 200);
                assert_eq!(&body[..], b"x");
            }
            _ => panic!("expected buffered result"),
        }
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_coalesces_duplicate_requests() {
        let srv = start_server().await;
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());

        // Queue all requests before starting the run loop to maximise the coalescing window.
        let mut receivers = Vec::new();
        for _ in 0..5 {
            let (req, handle) = make_req(srv.url("/coalesce"), Priority::Normal);
            let (tx, rx) = oneshot::channel();
            fetcher.submit(req, handle, tx).await;
            receivers.push(rx);
        }

        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        for rx in receivers {
            let result = tokio::time::timeout(Duration::from_secs(3), rx)
                .await
                .unwrap()
                .unwrap();
            assert!(
                !result.is_error(),
                "every subscriber should receive a result"
            );
        }

        assert_eq!(
            srv.hit_count("/coalesce"),
            1,
            "coalescing must deduplicate to a single HTTP request"
        );
        shutdown.cancel();
    }

    /// Regression test for the follower-registration vs leader-finish race: a subscriber that
    /// joins an in-flight entry must never lose the result (RecvError) because the leader
    /// drained the waiter between the map lookup and the registration. A fast route plus many
    /// rounds of live submissions makes joins race with completions constantly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fetcher_coalescing_join_never_loses_result_under_races() {
        let srv = start_server().await;
        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());

        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        for _round in 0..20 {
            let mut receivers = Vec::new();
            for _ in 0..30 {
                let (req, handle) = make_req(srv.url("/fast"), Priority::Normal);
                let (tx, rx) = oneshot::channel();
                fetcher.submit(req, handle, tx).await;
                receivers.push(rx);
            }
            for rx in receivers {
                let result = tokio::time::timeout(Duration::from_secs(5), rx)
                    .await
                    .expect("subscriber timed out waiting for result")
                    .expect("subscriber lost the result (waiter drained before registration)");
                assert!(!result.is_error());
            }
        }

        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_request_timeout_fires() {
        let srv = start_server().await;
        let fetcher = Arc::new(
            Fetcher::new(
                FetcherConfig {
                    req_timeout: Duration::from_millis(200),
                    ..test_config()
                },
                Arc::new(NullContext),
            )
            .unwrap(),
        );

        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_req(srv.url("/hang"), Priority::Normal);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        let result = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_error(),
            "request should fail with a timeout error"
        );
        shutdown.cancel();
    }

    /// Drive one request through a fetcher configured with `cfg_policy`, where the request
    /// itself carries `req_policy`, and report whether it was blocked.
    async fn mixed_content_blocked(
        cfg_policy: MixedContentPolicy,
        req_policy: Option<MixedContentPolicy>,
    ) -> bool {
        let fetcher = Arc::new(
            Fetcher::new(
                FetcherConfig {
                    mixed_content: cfg_policy,
                    ..test_config()
                },
                Arc::new(NullContext),
            )
            .unwrap(),
        );
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        // `.invalid` is reserved and never resolves, so an unblocked request fails in the
        // transport instead — distinguishable from a block. Blocked cases short-circuit before
        // any I/O; unblocked ones do issue a DNS query.
        let (mut req, handle) = make_req(
            Url::parse("http://insecure.invalid/a.js").unwrap(),
            Priority::Normal,
        );
        req.origin = Some(Url::parse("https://example.com").unwrap().origin());
        req.mixed_content = req_policy;

        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;
        let result = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
        shutdown.cancel();

        matches!(
            result,
            FetchResult::Error(NetError::Blocked {
                reason: BlockReason::MixedContent,
                ..
            })
        )
    }

    /// A request override must win over the fetcher-wide default in both directions — that is
    /// what lets an embedder permit an image while still blocking a script on the same page.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_request_override_beats_config() {
        assert!(
            mixed_content_blocked(MixedContentPolicy::Block, None).await,
            "no override should fall back to the fetcher-wide Block"
        );
        assert!(
            !mixed_content_blocked(MixedContentPolicy::Block, Some(MixedContentPolicy::Allow))
                .await,
            "a per-request Allow must override a Block config"
        );
        assert!(
            mixed_content_blocked(MixedContentPolicy::Allow, Some(MixedContentPolicy::Block)).await,
            "a per-request Block must override an Allow config"
        );
        assert!(
            !mixed_content_blocked(MixedContentPolicy::Allow, None).await,
            "no override should fall back to the fetcher-wide Allow"
        );
    }

    /// End-to-end through the real `Fetcher`, not `fetch_response_top` directly: an https page
    /// requests a loopback URL that 302s onto plain http. The per-hop check must catch it.
    ///
    /// This is the headline guarantee of the feature — an embedder cannot see redirect targets —
    /// and every other redirect test builds its own client, so only this one exercises the
    /// client the fetcher actually ships.
    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_blocks_mixed_content_on_redirect_target() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute("http://insecure.example.com/a.js"),
            )
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (mut req, handle) = make_req(srv.url("/hop"), Priority::Normal);
        req.origin = Some(Url::parse("https://example.com").unwrap().origin());

        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;
        let result = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
        shutdown.cancel();

        assert!(
            matches!(
                result,
                FetchResult::Error(NetError::Blocked {
                    reason: BlockReason::MixedContent,
                    ..
                })
            ),
            "insecure redirect target must be blocked, got {result:?}"
        );
    }

    fn make_post_req(
        url: Url,
        body: crate::net::types::RequestBody,
    ) -> (FetchRequest, CancellationToken) {
        use http::Method;
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            url,
            method: Method::POST,
            headers: HeaderMap::new(),
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            origin: None,
            mixed_content: None,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: Some(body),
        };
        (req, CancellationToken::new())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_post_body_is_sent_and_echoed() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_post_req(
            srv.url("/echo"),
            crate::net::types::RequestBody::text("{\"x\":1}"),
        );
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        match tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap()
        {
            FetchResult::Buffered { body, meta } => {
                assert_eq!(meta.status, 200);
                assert_eq!(
                    &body[..],
                    b"{\"x\":1}",
                    "echoed body must match the POST payload"
                );
            }
            other => panic!("expected Buffered, got {:?}", other),
        }
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_301_downgrades_post_to_get_and_drops_body() {
        // A 301 on POST must follow as GET with no body (browser-compat behaviour, RFC 7231 §6.4.2).
        let srv = TestServer::new()
            .route("/post-redirect", RouteConfig::redirect_to("/landing"))
            .route("/landing", RouteConfig::echo_body())
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_post_req(
            srv.url("/post-redirect"),
            crate::net::types::RequestBody::text("original body"),
        );
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        match tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap()
        {
            FetchResult::Buffered { meta, body } => {
                assert_eq!(meta.status, 200);
                // /landing echoes the request body; GET after 301 carries no body → empty echo
                assert!(
                    body.is_empty(),
                    "body must be dropped on 301 POST→GET redirect"
                );
            }
            other => panic!("expected Buffered, got {:?}", other),
        }
        shutdown.cancel();
    }

    /// Records every URL passed to `is_url_allowed` and blocks any whose path contains `/blocked`.
    struct RecordingUrlPolicy {
        seen: parking_lot::Mutex<Vec<String>>,
    }

    impl FetcherContext for RecordingUrlPolicy {
        fn observer_for(
            &self,
            _: RequestReference,
            _: RequestId,
            _: ResourceKind,
            _: Initiator,
        ) -> Arc<dyn NetObserver + Send + Sync> {
            Arc::new(crate::net::null_emitter::NullEmitter)
        }
        fn on_ref_active(&self, _: RequestReference) {}
        fn on_ref_done(&self, _: RequestReference) {}
        fn is_url_allowed(&self, url: &Url) -> bool {
            self.seen.lock().push(url.path().to_string());
            !url.path().contains("/blocked")
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_url_policy_is_applied_to_redirect_targets() {
        // The URL policy must be consulted for every redirect target, not just the initial URL —
        // otherwise a redirect to an internal address walks straight past an embedder's SSRF
        // guard. This requires reqwest's own redirect following to stay disabled so that
        // `get_with_redirects` sees each 3xx itself; if it is ever re-enabled, reqwest follows
        // the hop internally and the policy check below never runs.
        let srv = TestServer::new()
            .route("/start", RouteConfig::redirect_to("/blocked"))
            .route("/blocked", RouteConfig::ok(b"SHOULD NEVER BE FETCHED"))
            .start()
            .await;

        let ctx = Arc::new(RecordingUrlPolicy {
            seen: parking_lot::Mutex::new(Vec::new()),
        });
        let fetcher = Arc::new(Fetcher::new(test_config(), ctx.clone()).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_req(srv.url("/start"), Priority::Normal);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        let result = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();

        assert!(
            ctx.seen.lock().iter().any(|p| p == "/blocked"),
            "redirect target must be passed to is_url_allowed, saw: {:?}",
            ctx.seen.lock()
        );
        assert_eq!(
            srv.hit_count("/blocked"),
            0,
            "a blocked redirect target must never be requested"
        );
        assert!(
            matches!(
                result,
                FetchResult::Error(NetError::Blocked {
                    reason: crate::net::types::BlockReason::UrlPolicy,
                    ..
                })
            ),
            "blocked redirect must surface as NetError::Blocked(UrlPolicy), got {:?}",
            result
        );

        shutdown.cancel();
    }

    /// Records every URL the policy is shown. With `allow: false` nothing is connected to, so a
    /// test can read back the URL the fetcher settled on without touching the network.
    struct RecordingPolicy {
        seen: parking_lot::Mutex<Vec<String>>,
        allow: bool,
    }

    impl RecordingPolicy {
        fn new(allow: bool) -> Self {
            Self {
                seen: parking_lot::Mutex::new(Vec::new()),
                allow,
            }
        }
    }

    impl FetcherContext for RecordingPolicy {
        fn observer_for(
            &self,
            _: RequestReference,
            _: RequestId,
            _: ResourceKind,
            _: Initiator,
        ) -> Arc<dyn NetObserver + Send + Sync> {
            Arc::new(crate::net::null_emitter::NullEmitter)
        }
        fn on_ref_active(&self, _: RequestReference) {}
        fn on_ref_done(&self, _: RequestReference) {}
        fn is_url_allowed(&self, url: &Url) -> bool {
            self.seen.lock().push(url.as_str().to_string());
            self.allow
        }
    }

    async fn urls_seen_for(hsts: Option<Arc<dyn HstsStore>>, request: &str) -> Vec<String> {
        let ctx = Arc::new(RecordingPolicy::new(false));
        let cfg = FetcherConfig {
            hsts,
            ..test_config()
        };
        let fetcher = Arc::new(Fetcher::new(cfg, ctx.clone()).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_req(Url::parse(request).unwrap(), Priority::Normal);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap();

        shutdown.cancel();
        let seen = ctx.seen.lock().clone();
        seen
    }

    fn armed_store(host: &str, include_subdomains: bool) -> Arc<InMemoryHstsStore> {
        let store = Arc::new(InMemoryHstsStore::new());
        store.store(
            host,
            crate::net::hsts::HstsEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                include_subdomains,
            },
        );
        store
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hsts_upgrades_url_before_key_and_policy_check() {
        // The policy runs after the key is derived and before any connection, so https here means
        // the upgrade landed early enough to key on and no plaintext request was made.
        let seen = urls_seen_for(
            Some(armed_store("hsts.example", false)),
            "http://hsts.example/p",
        )
        .await;
        assert_eq!(seen, vec!["https://hsts.example/p".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hsts_upgrades_subdomain_of_armed_host() {
        let seen = urls_seen_for(
            Some(armed_store("hsts.example", true)),
            "http://sub.hsts.example/p",
        )
        .await;
        assert_eq!(seen, vec!["https://sub.hsts.example/p".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hsts_leaves_unarmed_host_alone() {
        let seen = urls_seen_for(
            Some(armed_store("other.example", true)),
            "http://hsts.example/p",
        )
        .await;
        assert_eq!(seen, vec!["http://hsts.example/p".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hsts_none_disables_upgrading() {
        // A private-browsing fetcher passes None and must not upgrade even for an armed host.
        let seen = urls_seen_for(None, "http://hsts.example/p").await;
        assert_eq!(seen, vec!["http://hsts.example/p".to_string()]);
    }

    /// Live round trip against hsts.badssl.com, the one check against a real header and a real CA
    /// chain. Ignored by default: it needs the network and trusts a third party to keep serving
    /// the header.
    ///
    ///     cargo test --features test-support -- --ignored hsts_live
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires network access to hsts.badssl.com"]
    async fn hsts_live_round_trip_against_badssl() {
        let store = Arc::new(InMemoryHstsStore::new());
        let ctx = Arc::new(RecordingPolicy::new(true));
        let cfg = FetcherConfig {
            hsts: Some(store.clone()),
            ..FetcherConfig::default()
        };
        let fetcher = Arc::new(Fetcher::new(cfg, ctx.clone()).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        assert!(store.load("hsts.badssl.com").is_none());

        // Harvest: a real HTTPS response must arm the store.
        let req =
            FetchRequest::builder(Method::GET, Url::parse("https://hsts.badssl.com/").unwrap())
                .build();
        let res = fetcher.fetch(req).await;
        assert!(
            !matches!(res, FetchResult::Error(_)),
            "live fetch failed: {res:?}"
        );
        let entry = store
            .load("hsts.badssl.com")
            .expect("a live HSTS response must arm the store");
        assert!(entry.include_subdomains);
        assert!(!entry.is_expired(chrono::Utc::now()));

        // Upgrade: a plaintext request for the now-armed host must go out over https.
        ctx.seen.lock().clear();
        let req =
            FetchRequest::builder(Method::GET, Url::parse("http://hsts.badssl.com/").unwrap())
                .build();
        let _ = fetcher.fetch(req).await;
        let seen = ctx.seen.lock().clone();
        assert!(!seen.is_empty(), "policy should have seen the request");
        assert!(
            seen.iter().all(|u| u.starts_with("https://")),
            "plaintext must never be requested for an armed host, saw: {seen:?}"
        );

        // The live entry asserts includeSubDomains, so a subdomain inherits it.
        ctx.seen.lock().clear();
        let req = FetchRequest::builder(
            Method::GET,
            Url::parse("http://sub.hsts.badssl.com/").unwrap(),
        )
        .build();
        let _ = fetcher.fetch(req).await;
        let seen = ctx.seen.lock().clone();
        assert!(
            seen.iter().all(|u| u.starts_with("https://")),
            "subdomain of an includeSubDomains host must upgrade, saw: {seen:?}"
        );

        shutdown.cancel();
    }

    fn make_req_with_decode(
        url: Url,
        priority: Priority,
        auto_decode: bool,
    ) -> (FetchRequest, CancellationToken) {
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            url,
            method: Method::GET,
            headers: HeaderMap::new(),
            priority,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            origin: None,
            mixed_content: None,
            streaming: false,
            auto_decode,
            max_bytes: None,
            body: None,
        };
        (req, CancellationToken::new())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_auto_decode_true_decompresses_gzip() {
        let srv = TestServer::new()
            .route("/gz", RouteConfig::gzip_ok(b"hello compressed world"))
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, cancel) = make_req_with_decode(srv.url("/gz"), Priority::Normal, true);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, cancel, tx).await;

        match tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap()
        {
            FetchResult::Buffered { body, .. } => {
                assert_eq!(
                    &body[..],
                    b"hello compressed world",
                    "auto_decode=true must yield decompressed content"
                );
            }
            other => panic!("expected Buffered, got {:?}", other),
        }
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_auto_decode_false_returns_raw_bytes() {
        let srv = TestServer::new()
            .route("/gz", RouteConfig::gzip_ok(b"hello compressed world"))
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        let (req, handle) = make_req_with_decode(srv.url("/gz"), Priority::Normal, false);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

        match tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap()
        {
            FetchResult::Buffered { body, .. } => {
                assert_ne!(
                    &body[..],
                    b"hello compressed world",
                    "auto_decode=false must return raw compressed bytes"
                );
                // Gzip magic bytes: 0x1f 0x8b
                assert_eq!(
                    &body[..2],
                    &[0x1f, 0x8b],
                    "raw bytes should start with gzip magic"
                );
            }
            other => panic!("expected Buffered, got {:?}", other),
        }
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_decode_and_raw_requests_are_not_coalesced() {
        let srv = TestServer::new()
            .route("/gz", RouteConfig::gzip_ok(b"data"))
            .start()
            .await;

        let fetcher = Arc::new(Fetcher::new(test_config(), Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });

        // Submit both before the run loop processes them to maximise coalescing opportunity.
        let (req_dec, handle_dec) = make_req_with_decode(srv.url("/gz"), Priority::Normal, true);
        let (req_raw, handle_raw) = make_req_with_decode(srv.url("/gz"), Priority::Normal, false);
        let (tx_dec, rx_dec) = oneshot::channel();
        let (tx_raw, rx_raw) = oneshot::channel();
        fetcher.submit(req_dec, handle_dec, tx_dec).await;
        fetcher.submit(req_raw, handle_raw, tx_raw).await;

        let res_dec = tokio::time::timeout(Duration::from_secs(3), rx_dec)
            .await
            .unwrap()
            .unwrap();
        let res_raw = tokio::time::timeout(Duration::from_secs(3), rx_raw)
            .await
            .unwrap()
            .unwrap();

        let body_dec = match res_dec {
            FetchResult::Buffered { body, .. } => body,
            o => panic!("{o:?}"),
        };
        let body_raw = match res_raw {
            FetchResult::Buffered { body, .. } => body,
            o => panic!("{o:?}"),
        };

        assert_eq!(&body_dec[..], b"data");
        assert_eq!(&body_raw[..2], &[0x1f, 0x8b]);
        // Two separate requests must have been made.
        assert_eq!(
            srv.hit_count("/gz"),
            2,
            "decode and raw must not be coalesced"
        );
        shutdown.cancel();
    }
}

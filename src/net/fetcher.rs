//! Priority-scheduled fetcher with request coalescing and per-origin concurrency limits.

use crate::net::fetch::{
    fetch_response_complete, fetch_response_top, NetPolicy, RequestInit, ResponseTop,
};
use crate::net::fetcher_context::FetcherContext;
use crate::net::observer::NetObserver;
use crate::net::pump::{spawn_pump, PumpCfg, PumpTargets};
use crate::net::shared_body::{ReaderOptions, SharedBody};
use crate::net::types::{FetchHandle, FetchKeyData, FetchRequest, FetchResult, NetError, Priority};
use crate::net::utils::{short_url, spawn_named, Waiter};
use crate::types::RequestId;
use dashmap::{DashMap, Entry};
use http::header;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::sync::{oneshot, Notify, Semaphore};
use tokio::task::JoinHandle;
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

    /// `User-Agent` header sent with every request made by this fetcher.
    ///
    /// Set this to identify your application to servers and CDNs.
    /// `None` falls back to reqwest's built-in default (`reqwest/VERSION`).
    /// For a browser engine use something like `"Mozilla/5.0 (compatible; MyBrowser/1.0)"`.
    pub user_agent: Option<String>,
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
            user_agent: None,
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

pub struct FetchInflightMap {
    map: Arc<DashMap<FetchKeyData, Arc<FetchInflightEntry>>>,
    client: Arc<reqwest::Client>,
    observer: Arc<dyn NetObserver + Send + Sync>,
    cfg: FetcherConfig,
}

impl FetchInflightMap {
    pub fn new(
        client: Arc<reqwest::Client>,
        observer: Arc<dyn NetObserver + Send + Sync>,
        cfg: FetcherConfig,
    ) -> Self {
        Self {
            map: Arc::new(DashMap::new()),
            client,
            observer,
            cfg,
        }
    }

    pub fn join_or_start(
        &self,
        req: &FetchRequest,
        wants_stream: bool,
    ) -> (FetchHandle, oneshot::Receiver<FetchResult>, bool) {
        match self.map.entry(req.key_data.clone()) {
            Entry::Occupied(e) => {
                let entry = e.get().clone();
                let (tx, rx) = oneshot::channel();
                entry.waiter.register(tx, wants_stream);
                let handle = FetchHandle {
                    req_id: RequestId::new(),
                    key: req.key_data.clone(),
                    cancel: entry.parent_cancel.child_token(),
                };
                (handle, rx, false)
            }
            Entry::Vacant(v) => {
                let entry = Arc::new(FetchInflightEntry {
                    parent_cancel: CancellationToken::new(),
                    waiter: Arc::new(Waiter::new()),
                    wants_streaming: AtomicBool::new(wants_stream),
                    subs: AtomicUsize::new(0),
                    done: CancellationToken::new(),
                });
                let (tx, rx) = oneshot::channel();
                entry.waiter.register(tx, wants_stream);
                v.insert(entry.clone());

                let key = req.key_data.clone();
                let map = self.map.clone();

                spawn_fetch_task(
                    req.clone(),
                    entry.clone(),
                    self.client.clone(),
                    self.observer.clone(),
                    self.cfg.clone(),
                    move || {
                        map.remove(&key);
                    },
                );

                let handle = FetchHandle {
                    req_id: RequestId::new(),
                    key: req.key_data.clone(),
                    cancel: entry.parent_cancel.child_token(),
                };
                (handle, rx, true)
            }
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
    handle: FetchHandle,
    /// One-shot channel back to the caller.  The run loop hands this to the
    /// [`FetchInflightEntry`] waiter; the result is sent when the fetch completes.
    reply: oneshot::Sender<FetchResult>,
}

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

    pub async fn submit(
        &self,
        req: FetchRequest,
        req_handle: FetchHandle,
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
            handle: req_handle,
            reply: reply_tx,
        });
        self.wake.notify_one();
    }

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

            let Some(QueueItem {
                req,
                handle,
                reply: reply_tx,
            }) = next
            else {
                tokio::select! {
                    _ = self.wake.notified() => {},
                    _ = shutdown.cancelled() => {},
                }
                continue;
            };

            let key_opt = req.key_data.generate();
            // Include auto_decode in the coalescing key so decode=true and decode=false requests
            // for the same URL are never merged into a single in-flight entry.
            let key_str = {
                let base = match key_opt {
                    Some(k) => k,
                    None => format!(
                        "{} {} @{}",
                        req.key_data.method,
                        req.key_data.url,
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

            let child_cancel = handle.cancel.clone();
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

            // URL policy check — only the leader makes the actual request
            if is_leader && !self.ctx.is_url_allowed(&req.key_data.url) {
                let err = FetchResult::Error(NetError::Other(std::sync::Arc::new(
                    anyhow::anyhow!("URL blocked by policy: {}", req.key_data.url),
                )));
                // Remove before finish — see the registration comment above for the ordering.
                self.inflight_map.remove(&key_str);
                inflight_entry.waiter.finish(err).await;
                inflight_entry.done.cancel();
                self.ctx.on_ref_done(req.reference);
                continue;
            }

            if !is_leader {
                continue;
            }

            let observer =
                self.ctx
                    .observer_for(req.reference, req.req_id, req.kind, req.initiator);

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

            let title = format!("Fetcher: {}", short_url(&req.key_data.url, 80));
            spawn_named(&title, async move {
                let origin = Fetcher::origin_key(&req.key_data.url);
                let slots = per_origin
                    .entry(origin.clone())
                    .or_insert_with(|| {
                        Arc::new(Semaphore::new(per_origin_limit_for(
                            &cfg,
                            &req.key_data.url,
                        )))
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

/// Build a [`RequestInit`] from a [`FetchRequest`], injecting a `Content-Type` header from
/// the body descriptor when the headers don't already contain one.
fn make_request_init(req: &FetchRequest) -> RequestInit {
    let mut headers = req.key_data.headers.clone();
    let body = req.body.as_ref().map(|b| {
        if let Some(ref ct) = b.content_type {
            if !headers.contains_key(header::CONTENT_TYPE) {
                if let Ok(val) = ct.parse() {
                    headers.insert(header::CONTENT_TYPE, val);
                }
            }
        }
        b.bytes.clone()
    });
    RequestInit::new(req.key_data.method.clone(), headers, body)
}

/// Build a reqwest client from `FetcherConfig`.
///
/// When `decode` is `true` the client automatically decompresses `gzip`, `brotli`, and `deflate`
/// response bodies and sends the corresponding `Accept-Encoding` request header.
/// When `false` neither header is added nor is any decompression performed.
fn build_client(cfg: &FetcherConfig, decode: bool) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .connection_verbose(false)
        .http2_adaptive_window(true)
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.req_timeout)
        .use_rustls_tls()
        .gzip(decode)
        .brotli(decode)
        .deflate(decode);
    if let Some(ref ua) = cfg.user_agent {
        b = b.user_agent(ua);
    }
    Ok(b.build()?)
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
    let policy = NetPolicy::from_context(&ctx);

    let ResponseTop {
        meta,
        peek_buf,
        reader,
    } = fetch_response_top(
        Arc::new(client.clone()),
        req.key_data.url.clone(),
        make_request_init(req),
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
        max_size: None,
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
    let policy = NetPolicy::from_context(&ctx);

    let (meta, body) = fetch_response_complete(
        Arc::new(client.clone()),
        req.key_data.url.clone(),
        make_request_init(req),
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

pub fn spawn_fetch_task(
    req: FetchRequest,
    entry: Arc<FetchInflightEntry>,
    client: Arc<reqwest::Client>,
    observer: Arc<dyn NetObserver + Send + Sync>,
    cfg: FetcherConfig,
    on_finish: impl FnOnce() + Send + 'static,
) -> JoinHandle<()> {
    let url = req.key_data.url.clone();
    let cancel_parent = entry.parent_cancel.clone();

    spawn_named(&format!("Fetch: {}", short_url(&url, 80)), async move {
        struct Cleanup<F: FnOnce()>(Option<F>);
        impl<F: FnOnce()> Drop for Cleanup<F> {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }
        let _cleanup = Cleanup(Some(on_finish));

        let top = match fetch_response_top(
            client.clone(),
            url.clone(),
            make_request_init(&req),
            cancel_parent.clone(),
            observer.clone(),
            NetPolicy::default(),
        )
        .await
        {
            Ok(top) => top,
            Err(e) => {
                let _ = entry.waiter.finish(FetchResult::Error(e)).await;
                return;
            }
        };
        let ResponseTop {
            meta,
            peek_buf,
            reader,
        } = top;

        let shared = Arc::new(SharedBody::new(SHARED_MAX_CAPACITY));

        let pump_cfg = PumpCfg {
            idle: cfg.read_idle_timeout,
            total_deadline: cfg.total_body_timeout.map(|d| Instant::now() + d),
        };

        let _pump = spawn_pump(
            reader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: peek_buf.clone(),
            },
            pump_cfg,
            cancel_parent.clone(),
            observer.clone(),
            url.clone(),
        );

        let res = FetchResult::Stream {
            meta,
            peek_buf,
            shared,
        };
        let _ = entry.waiter.finish(res).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fetcher_context::FetcherContext;
    use crate::net::null_emitter::NullEmitter;
    use crate::net::observer::NetObserver;
    use crate::net::request_ref::RequestReference;
    use crate::net::test_support::{RouteConfig, TestServer};
    use crate::net::types::{FetchHandle, FetchKeyData, FetchRequest, Initiator, ResourceKind};
    use crate::types::RequestId;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    struct NullContext;

    impl FetcherContext for NullContext {
        fn observer_for(
            &self,
            _: RequestReference,
            _: RequestId,
            _: ResourceKind,
            _: Initiator,
        ) -> Arc<dyn NetObserver + Send + Sync> {
            Arc::new(NullEmitter)
        }
        fn on_ref_active(&self, _: RequestReference) {}
        fn on_ref_done(&self, _: RequestReference) {}
    }

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
            .route(
                "/timed",
                RouteConfig::delay(Duration::from_millis(60), b"ok".to_vec()),
            )
            .route("/not-found", RouteConfig::status(404, b"not found"))
            .route("/error", RouteConfig::status(500, b"server error"))
            .start()
            .await
    }

    fn make_req(url: Url, priority: Priority) -> (FetchRequest, FetchHandle) {
        let key = FetchKeyData::new(url);
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            key_data: key.clone(),
            priority,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };
        let handle = FetchHandle {
            req_id,
            key,
            cancel: CancellationToken::new(),
        };
        (req, handle)
    }

    fn dummy_item(priority: Priority) -> QueueItem {
        let url = Url::parse("http://example.com/").unwrap();
        let key = FetchKeyData::new(url);
        let req_id = RequestId::new();
        let (tx, _rx) = oneshot::channel();
        QueueItem {
            req: FetchRequest {
                reference: RequestReference::Background(0),
                req_id,
                key_data: key.clone(),
                priority,
                initiator: Initiator::Other,
                kind: ResourceKind::Primary,
                streaming: false,
                auto_decode: true,
                max_bytes: None,
                body: None,
            },
            handle: FetchHandle {
                req_id,
                key,
                cancel: CancellationToken::new(),
            },
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
        let key = FetchKeyData::new(base.join("slow").unwrap());
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            key_data: key.clone(),
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };
        let handle = FetchHandle {
            req_id,
            key,
            cancel: cancel.clone(),
        };
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

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
        let key = FetchKeyData::new(url);
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            key_data: key.clone(),
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            streaming: true,
            auto_decode: true,
            max_bytes: None,
            body: None,
        };
        let handle = FetchHandle {
            req_id,
            key,
            cancel: CancellationToken::new(),
        };
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

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

    fn make_post_req(
        url: Url,
        body: crate::net::types::RequestBody,
    ) -> (FetchRequest, FetchHandle) {
        use http::Method;
        let mut key = FetchKeyData::new(url);
        key.method = Method::POST;
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            key_data: key.clone(),
            priority: Priority::Normal,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            streaming: false,
            auto_decode: true,
            max_bytes: None,
            body: Some(body),
        };
        let handle = FetchHandle {
            req_id,
            key,
            cancel: CancellationToken::new(),
        };
        (req, handle)
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

    fn make_req_with_decode(
        url: Url,
        priority: Priority,
        auto_decode: bool,
    ) -> (FetchRequest, FetchHandle) {
        let key = FetchKeyData::new(url);
        let req_id = RequestId::new();
        let req = FetchRequest {
            reference: RequestReference::Background(0),
            req_id,
            key_data: key.clone(),
            priority,
            initiator: Initiator::Other,
            kind: ResourceKind::Primary,
            streaming: false,
            auto_decode,
            max_bytes: None,
            body: None,
        };
        let handle = FetchHandle {
            req_id,
            key,
            cancel: CancellationToken::new(),
        };
        (req, handle)
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

        let (req, handle) = make_req_with_decode(srv.url("/gz"), Priority::Normal, true);
        let (tx, rx) = oneshot::channel();
        fetcher.submit(req, handle, tx).await;

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

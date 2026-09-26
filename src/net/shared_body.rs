//! Bounded, fan-out body stream with per-subscriber queues, replay for late subscribers, and
//! drop-on-lag policy.
//!
//! `SharedBody` lets one producer push `Bytes` while any number of subscribers
//! receive them as a stream. Each subscriber has a bounded MPSC queue to cap
//! memory usage. If a subscriber can't keep up, we drop that subscriber rather
//! than stalling the producer (and other subscribers).
//!
//! Semantics:
//! - `push(Bytes)`: best-effort, non-blocking; a slow subscriber is removed and
//!   sees an error (`NetError::Read`) before its stream ends, never a clean EOF -
//!   a consumer must not mistake a body it fell behind on for a complete one.
//!   The first [`replay_limit`](SharedBody::with_replay_limit) bytes are also kept for
//!   subscribers that have yet to attach.
//! - `finish()`: closes all subscribers → they observe EOF (`None`) cleanly.
//! - `error(NetError)`: every subscriber gets the chunks already queued for it, then the
//!   error, then the end.
//! - `subscribe_stream()`: returns a `Stream<Item = Result<Bytes, NetError>>` of the whole
//!   body, whenever it is called: kept chunks first, then live ones. If the start of the body
//!   is no longer kept, the stream is a single error instead.
//! - `subscribe_live()`: only the chunks pushed from now on, for observers that do not need
//!   the body itself (progress).
//! - `combined_reader(peek, shared)`: convenient `AsyncRead` of `peek` then the body.

use crate::net::types::{MaybeSend, NetError};
use crate::net::utils::spawn_named;
use crate::types::PeekBuf;
use bytes::Bytes;
use futures_core::stream::BoxStream;
use futures_core::Stream;
use futures_util::{stream, StreamExt, TryStreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;

/// Default for how many bytes from the start of a body a [`SharedBody`] keeps for subscribers
/// that attach after the first chunk was pushed: 4 MiB.
pub const DEFAULT_REPLAY_LIMIT: usize = 4 * 1024 * 1024;

/// Bounded, fan-out byte stream with per-subscriber queues, replay and drop-on-lag.
///
/// `SharedBody` lets one producer push `Bytes` while any number of subscribers
/// receive them as a `Stream<Item = Result<bytes::Bytes, NetError>>`.
///
/// - Each subscriber has its **own bounded queue** (capacity set on creation).
/// - If a subscriber can't keep up and its queue fills, it is **dropped**
///   (non-blocking broadcast; other subscribers keep receiving) and its stream
///   ends with an error.
/// - `finish()` ends all subscribers with EOF; `error(e)` delivers `Err(e)`
///   and then ends.
///
/// Every subscriber made with [`subscribe_stream`](Self::subscribe_stream) or
/// [`subscribe_with_cap`](Self::subscribe_with_cap) gets the body **from its first byte**,
/// even one that subscribes after the body has ended. For that, the first
/// [replay limit](Self::with_replay_limit) bytes pushed are kept ([`DEFAULT_REPLAY_LIMIT`]
/// unless set otherwise). A subscriber that attaches after more than that was pushed gets an
/// error instead. A body driven by [`from_reader`](Self::from_reader) waits for the first
/// subscriber before it starts reading, so that one always gets the whole body. Useful to
/// send one response body to several consumers, such as the HTML parser and a download writer.
///
/// # Examples
///
/// Basic broadcast to two subscribers, the second one late:
/// ```
/// # use bytes::Bytes;
/// # use futures_util::StreamExt;
/// # use gosub_sonar::SharedBody;
/// let sb = SharedBody::new(8);
/// let mut a = sb.subscribe_stream();
/// sb.push(Bytes::from_static(b"hi"));
/// let mut b = sb.subscribe_stream();
/// sb.finish();
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// assert_eq!(&a.next().await.unwrap().unwrap()[..], b"hi");
/// assert!(a.next().await.is_none());
/// assert_eq!(&b.next().await.unwrap().unwrap()[..], b"hi");
/// assert!(b.next().await.is_none());
/// # });
/// ```
#[derive(Clone)]
pub struct SharedBody {
    inner: Arc<Mutex<State>>,
}

// Internal state of a shared body
struct State {
    /// Active subscribers
    subs: HashMap<u64, Subscriber>,
    /// Monotic id for subscribers
    next_id: AtomicU64,
    /// Limit on how many subscribers per queue are allowed
    max_queue: usize,
    /// If true, any additional push() is ignored. The stream is closed.
    closed: bool,
    /// Signalled once, when the first subscriber attaches. `from_reader` waits for this before
    /// it starts reading, so nothing is pushed while there is nobody to receive it.
    first_subscriber: Arc<Notify>,
    has_subscriber: bool,
    /// The error the body ended with, if any. A subscriber's stream yields it after its queue
    /// drains, and one that attaches after the end gets it after the replay.
    error: Option<NetError>,
    /// Most bytes `replay` may hold.
    replay_limit: usize,
    /// Every chunk pushed so far, while they fit in `replay_limit`; `None` once they did not,
    /// after which a new (non-live) subscriber can no longer get the whole body.
    replay: Option<Vec<Bytes>>,
    replay_bytes: usize,
}

/// One subscriber's queue, plus the flag that tells its stream why the queue
/// closed: dropped for lagging (an error is due) or finished (a clean end).
struct Subscriber {
    tx: mpsc::Sender<Result<Bytes, NetError>>,
    lagged: Arc<std::sync::atomic::AtomicBool>,
}

/// The error a subscriber gets when the start of the body is no longer kept for it.
fn replay_overflow_error(limit: usize) -> NetError {
    NetError::Read(Arc::new(anyhow::anyhow!(
        "body subscribed too late: more than the {limit} byte replay limit was already pushed, \
         so its start is no longer held"
    )))
}

impl SharedBody {
    /// Creates a new `SharedBody` with the given per-subscriber queue capacity and the
    /// default replay limit ([`DEFAULT_REPLAY_LIMIT`]).
    ///
    /// Each subscriber gets a queue with this capacity. When full, the slow
    /// subscriber is dropped rather than applying backpressure to the producer.
    ///
    /// A capacity of **1–4** keeps latency low; **32+** favors throughput.
    pub fn new(max_queue: usize) -> Self {
        Self::with_replay_limit(max_queue, DEFAULT_REPLAY_LIMIT)
    }

    /// Creates a new `SharedBody` that keeps up to `replay_limit` bytes from the start of the
    /// body for subscribers that attach late.
    ///
    /// While the body pushed so far fits in the limit, a new subscriber gets all of it and
    /// then the live chunks. Once more than that has been pushed, the kept chunks are
    /// released and a subscriber that attaches later gets a [`NetError::Read`]. Subscribers
    /// that were already attached are unaffected. `0` keeps nothing, so only subscribers
    /// that attach before the first non-empty chunk get the body.
    ///
    /// The chunks are kept (reference-counted, not copied) until the limit is passed or the
    /// last handle to the `SharedBody` is dropped, including after the body has ended.
    pub fn with_replay_limit(max_queue: usize, replay_limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                subs: HashMap::new(),
                next_id: AtomicU64::new(1),
                max_queue,
                closed: false,
                first_subscriber: Arc::new(Notify::new()),
                has_subscriber: false,
                error: None,
                replay_limit,
                replay: Some(Vec::new()),
                replay_bytes: 0,
            })),
        }
    }

    /// Does nothing. It used to make the next `n` subscribers start from the beginning of
    /// the body, which every subscriber now does (up to the replay limit). Kept so existing
    /// callers still compile.
    pub fn reserve(&self, n: usize) {
        let _ = n;
    }

    /// Pushes a chunk to all current subscribers (best-effort, non-blocking), and keeps it for
    /// later subscribers while the body so far fits in the replay limit.
    ///
    /// - If a subscriber's queue is **full**, that subscriber is removed and its
    ///   stream yields an error, then ends: it missed this chunk.
    /// - If a subscriber's queue is **closed** (the stream was dropped), it is removed.
    ///   A dropped stream deregisters itself, so this only happens when a push races
    ///   that drop.
    /// - If [`finish`](Self::finish) or [`error`](Self::error) has been called,
    ///   additional pushes are ignored.
    pub fn push(&self, chunk: Bytes) {
        let (subs, mut to_remove) = {
            let mut st = self.inner.lock();
            if st.closed {
                return;
            }
            // Keep the chunk for later subscribers, or stop keeping chunks once past the limit.
            // This happens under the same lock as the snapshot below, so a subscriber attaching
            // at the same time gets this chunk exactly once, in its replay or live.
            let total = st.replay_bytes.saturating_add(chunk.len());
            if total <= st.replay_limit {
                if let Some(kept) = st.replay.as_mut() {
                    if !chunk.is_empty() {
                        kept.push(chunk.clone());
                    }
                    st.replay_bytes = total;
                }
            } else {
                st.replay = None;
                st.replay_bytes = 0;
            }
            let subs: Vec<(u64, mpsc::Sender<_>, Arc<std::sync::atomic::AtomicBool>)> = st
                .subs
                .iter()
                .map(|(id, sub)| (*id, sub.tx.clone(), Arc::clone(&sub.lagged)))
                .collect();
            (subs, Vec::new())
        };

        // Try to send to each subscriber without blocking
        for (id, tx, lagged) in subs {
            match tx.try_send(Ok(chunk.clone())) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Too slow: it missed this chunk, and must know it did.
                    lagged.store(true, std::sync::atomic::Ordering::Release);
                    to_remove.push(id);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // This subscriber is gone; remove it
                    to_remove.push(id);
                }
            }
        }

        // Remove any subscribers that are placed on the remove list
        if !to_remove.is_empty() {
            let mut st = self.inner.lock();
            for id in &to_remove {
                st.subs.remove(id);
            }
        }
    }

    /// Ends the body with an error.
    ///
    /// After this call:
    /// - Each subscriber receives what was already queued for it, then `Err(e.clone())`,
    ///   then the end (`None`). The error is not sent through the queue, so a subscriber
    ///   whose queue is full still gets it rather than a clean end.
    /// - New subscribers get the kept chunks (if the body still fit in the replay limit),
    ///   then the same `Err(e)`, then the end.
    pub fn error(&self, e: NetError) {
        // Record the error, then drop the senders: each stream reports it once its queue is
        // drained (see `SubStream::poll_next`).
        let _dropped: Vec<mpsc::Sender<Result<Bytes, NetError>>> = {
            let mut st = self.inner.lock();
            if st.closed {
                return;
            }
            st.closed = true;
            st.error = Some(e);
            st.subs.drain().map(|(_, sub)| sub.tx).collect()
        };
    }

    /// Finishes the stream cleanly (EOF).
    ///
    /// Dropping all senders causes subscribers to yield `None`. New subscribers
    /// get the kept chunks and then the end, or an error when the body did not fit in the
    /// replay limit.
    pub fn finish(&self) {
        // closed -> drop all senders so receivers see EOF
        let _dropped: Vec<mpsc::Sender<Result<Bytes, NetError>>> = {
            let mut st = self.inner.lock();
            if st.closed {
                return;
            }
            st.closed = true;
            st.subs.drain().map(|(_, sub)| sub.tx).collect()
        };

        // dropping senders is enough; receivers yield None (EOF)
    }

    /// Subscribes to the whole body, returning a stream of body chunks with a queue of
    /// `max_queue` chunks.
    ///
    /// The stream starts with the chunks pushed before this call, then continues with live
    /// ones, in order. If more than the replay limit was pushed before this call, the stream
    /// is a single [`NetError::Read`] and then the end. Subscribing after the body ended
    /// yields the kept chunks and then the error it ended with, or the end.
    ///
    /// See also [`subscribe_stream`](Self::subscribe_stream) for using the
    /// default capacity configured at `SharedBody` creation.
    pub fn subscribe_with_cap(
        &self,
        max_queue: usize,
    ) -> BoxStream<'static, Result<Bytes, NetError>> {
        self.subscribe(max_queue, true)
    }

    /// Subscribes to the chunks pushed **from now on** only, with the default queue capacity.
    ///
    /// Nothing is replayed, so unless it attaches before the first push this stream is not
    /// the whole body, even when it ends cleanly. Meant for progress observers; use
    /// [`subscribe_stream`](Self::subscribe_stream) for the body itself.
    pub fn subscribe_live(&self) -> BoxStream<'static, Result<Bytes, NetError>> {
        let cap = self.inner.lock().max_queue;
        self.subscribe(cap, false)
    }

    fn subscribe(
        &self,
        max_queue: usize,
        replay: bool,
    ) -> BoxStream<'static, Result<Bytes, NetError>> {
        let (rx, id, lagged, prefix) = {
            let mut st = self.inner.lock();
            // The replay is taken under the same lock as the registration below, so every
            // chunk is either in it or delivered live.
            let prefix: Vec<Bytes> = if replay {
                match st.replay.clone() {
                    Some(kept) => kept,
                    None => {
                        let e = replay_overflow_error(st.replay_limit);
                        return stream::once(async move { Err(e) }).boxed();
                    }
                }
            } else {
                Vec::new()
            };
            if st.closed {
                let tail = match st.error.clone() {
                    Some(e) => stream::once(async move { Err(e) }).boxed(),
                    None => stream::empty::<Result<Bytes, NetError>>().boxed(),
                };
                return stream::iter(prefix.into_iter().map(Ok)).chain(tail).boxed();
            }

            let (tx, rx) = mpsc::channel(max_queue);
            let id = st
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let lagged = Arc::new(std::sync::atomic::AtomicBool::new(false));
            st.subs.insert(
                id,
                Subscriber {
                    tx,
                    lagged: Arc::clone(&lagged),
                },
            );
            if !st.has_subscriber {
                st.has_subscriber = true;
                // notify_one stores a permit if the pump isn't waiting yet
                st.first_subscriber.notify_one();
            }
            (rx, id, lagged, prefix)
        };

        SubStream {
            id,
            parent: self.inner.clone(),
            prefix: prefix.into(),
            inner: ReceiverStream::new(rx),
            lagged,
            done: false,
        }
        .boxed()
    }

    /// Subscribes to the whole body with the default per-subscriber queue capacity.
    ///
    /// The capacity is the `max_queue` value that was provided to [`new`](Self::new). See
    /// [`subscribe_with_cap`](Self::subscribe_with_cap) for what the stream yields.
    pub fn subscribe_stream(&self) -> BoxStream<'static, Result<Bytes, NetError>> {
        let cap = {
            let st = self.inner.lock();
            st.max_queue
        };

        self.subscribe_with_cap(cap)
    }

    /// Returns an `AsyncRead` that yields `peek` first, then the body from `shared`.
    ///
    /// This is useful when downstream code expects an `AsyncRead` instead of a
    /// `Stream` (e.g., `tokio::io::copy`). The returned reader:
    ///
    /// 1. Reads the provided `peek` buffer.
    /// 2. Continues with chunks from `shared.subscribe_stream()`, which starts at the
    ///    beginning of `shared` (within the replay limit).
    ///
    /// # Example
    /// ```ignore
    /// # use std::{pin::Pin, sync::Arc};
    /// # use tokio::io::{self, AsyncReadExt};
    /// # use gosub_net::net::shared_body::SharedBody;
    /// let shared = Arc::new(SharedBody::new(8));
    /// let mut r = SharedBody::combined_reader(b"HEAD".to_vec(), shared.clone());
    /// # tokio_test::block_on(async {
    /// let mut out = Vec::new();
    /// r.read_to_end(&mut out).await.unwrap();
    /// # let _ = out;
    /// # });
    /// ```
    pub fn combined_reader(
        peek_buf: PeekBuf,
        shared: Arc<SharedBody>,
    ) -> Pin<Box<dyn AsyncRead + Send>> {
        let head = stream::iter([Ok::<Bytes, std::io::Error>(peek_buf.into_bytes())]);
        let rest_stream = shared.subscribe_stream().map_err(|e: NetError| e.to_io());

        let combined = head.chain(rest_stream);
        Box::pin(StreamReader::new(combined))
    }
}

/// Options to wrap an `AsyncRead` into a `SharedBody` via
/// [`SharedBody::from_reader`].
///
/// These control buffering, cancellation, timeouts, and byte limits.
pub struct ReaderOptions {
    /// Per-subscriber queue capacity for the `SharedBody` created by
    /// [`from_reader`](SharedBody::from_reader).
    ///
    /// Larger values increase tolerance for short subscriber stalls, at the cost
    /// of memory. Small values drop lagging subscribers sooner.
    pub capacity: usize,
    /// Size of the temporary read buffer used when pulling from the source
    /// `AsyncRead`. Larger buffers reduce syscalls but may raise latency per chunk.
    pub buf_size: usize,
    /// Optional cooperative cancellation token. If cancelled, reading stops and
    /// subscribers receive `NetError::Cancelled`.
    pub cancel: Option<CancellationToken>,
    /// Maximum allowed time between successful read operations. When exceeded,
    /// reading stops with `NetError::Timeout("read idle timeout")`.
    pub idle_timeout: Option<Duration>,
    /// Total deadline for the entire body. When exceeded, reading stops with
    /// `NetError::Timeout("total read timeout")`.
    pub total_timeout: Option<Duration>,
    /// Maximum total number of bytes to read. A body that exceeds this limit
    /// triggers an error and closes the stream; a body of exactly this size is
    /// delivered normally.
    pub max_size: Option<u64>,
    /// How many bytes from the start of the body are kept for subscribers that attach after
    /// reading began; see [`SharedBody::with_replay_limit`]. Default
    /// [`DEFAULT_REPLAY_LIMIT`].
    pub replay_limit: usize,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            capacity: 32,
            buf_size: 16 * 1024,
            cancel: None,
            idle_timeout: None,
            total_timeout: None,
            max_size: None,
            replay_limit: DEFAULT_REPLAY_LIMIT,
        }
    }
}

impl SharedBody {
    /// Spawns a background task that reads from `reader` and pushes chunks into
    /// a new `SharedBody`, honoring cancellation, timeouts, and size limits.
    ///
    /// - On EOF: calls [`finish`](Self::finish).
    /// - On I/O error or policy violation: calls [`error`](Self::error).
    ///
    /// Reading starts when the first subscriber attaches, so that subscriber gets the whole
    /// body even if it subscribes a while after this returns. If nobody subscribes within
    /// `idle_timeout` (or `total_timeout` / cancellation hits first) the body ends with that
    /// error instead of holding the connection open.
    ///
    /// # Examples
    /// Wrap a `reqwest` body (converted to `AsyncRead`) and tee it:
    /// ```ignore
    /// # use std::sync::Arc;
    /// # use futures_util::TryStreamExt;
    /// # use gosub_net::net::shared_body::{SharedBody, ReaderOptions};
    /// # async fn demo(mut r: impl tokio::io::AsyncRead + Send + Unpin + 'static) {
    /// let body = SharedBody::from_reader(r, ReaderOptions::default());
    /// let mut a = body.subscribe_stream();
    /// let mut b = body.subscribe_stream();
    ///
    /// // A: count bytes
    /// tokio::spawn(async move {
    ///     let mut total = 0usize;
    ///     while let Some(chunk) = a.next().await {
    ///         total += chunk.unwrap().len();
    ///     }
    ///     println!("A total={}", total);
    /// });
    ///
    /// // B: collect whole body
    /// tokio::spawn(async move {
    ///     let collected = b.try_fold(Vec::new(), |mut acc, bytes| async move {
    ///         acc.extend_from_slice(&bytes);
    ///         Ok(acc)
    ///     }).await.unwrap();
    ///     println!("B len={}", collected.len());
    /// });
    /// # }
    /// ```
    pub fn from_reader<R>(mut reader: R, opts: ReaderOptions) -> Arc<Self>
    where
        R: AsyncRead + MaybeSend + 'static + Unpin,
    {
        let sb = Arc::new(SharedBody::with_replay_limit(
            opts.capacity,
            opts.replay_limit,
        ));
        let sb_clone = sb.clone();

        // read in background
        spawn_named("SharedBody::from_reader pump", async move {
            let ReaderOptions {
                capacity: _,
                buf_size,
                cancel,
                idle_timeout,
                total_timeout,
                max_size,
                replay_limit: _,
            } = opts;

            let deadline = total_timeout.map(|d| tokio::time::Instant::now() + d);
            let cancel = cancel.unwrap_or_else(CancellationToken::new);
            let mut buf = vec![0u8; buf_size];
            let mut total_read: u64 = 0; // Does NOT take into account the peek buf!

            // Some helper functions
            let check_total_deadline = |now: tokio::time::Instant| -> Result<(), NetError> {
                if let Some(dl) = deadline {
                    if now >= dl {
                        return Err(NetError::Timeout("total read timeout".to_string()));
                    }
                }
                Ok(())
            };

            // Make sure we haven't already exceeded the total deadline
            if let Err(e) = check_total_deadline(tokio::time::Instant::now()) {
                sb_clone.error(e);
                return;
            }

            // Don't read until someone is listening. A subscriber that attaches after reading
            // began only gets the start of the body if it fits in the replay limit, so reading
            // early would limit the first subscriber too. The reader typically
            // already holds bytes (the part of the first chunk beyond the peek buffer), and the
            // caller gets the SharedBody through a channel before it can subscribe. Same
            // limits as a read while waiting, so an abandoned result doesn't hold the
            // connection forever.
            let first_subscriber = sb_clone.inner.lock().first_subscriber.clone();
            let idle_sleep = async {
                match idle_timeout {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            };
            let deadline_sleep = async {
                match deadline {
                    Some(dl) => tokio::time::sleep_until(dl).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = first_subscriber.notified() => {}
                _ = cancel.cancelled() => {
                    sb_clone.error(NetError::Cancelled("read cancelled".to_string()));
                    return;
                }
                _ = idle_sleep => {
                    sb_clone.error(NetError::Timeout("no subscriber attached before read idle timeout".to_string()));
                    return;
                }
                _ = deadline_sleep => {
                    sb_clone.error(NetError::Timeout("total read timeout".to_string()));
                    return;
                }
            }

            loop {
                // User cancelled the read (fast path; the select below also observes a cancel
                // that arrives while a read is blocked)
                if cancel.is_cancelled() {
                    sb_clone.error(NetError::Cancelled("read cancelled".to_string()));
                    return;
                }

                // Check how much we can read this iteration. When the max-size budget is
                // exhausted, probe one byte: a clean EOF means the body is exactly max_size
                // (legal); any data means the limit is exceeded.
                let (read_cap, probing) = if let Some(max) = max_size {
                    let remaining = max.saturating_sub(total_read);
                    if remaining == 0 {
                        (1, true)
                    } else {
                        (remaining.min(buf.len() as u64) as usize, false)
                    }
                } else {
                    (buf.len(), false)
                };

                // Race the read against cancellation, the per-read idle timeout, and the total
                // deadline, so a blocked read cannot outlive any of them.
                let idle_sleep = async {
                    match idle_timeout {
                        Some(d) => tokio::time::sleep(d).await,
                        None => std::future::pending().await,
                    }
                };
                let deadline_sleep = async {
                    match deadline {
                        Some(dl) => tokio::time::sleep_until(dl).await,
                        None => std::future::pending().await,
                    }
                };
                let read_res = tokio::select! {
                    r = reader.read(&mut buf[..read_cap]) => r.map_err(|e| NetError::Io(Arc::new(e))),
                    _ = cancel.cancelled() => Err(NetError::Cancelled("read cancelled".to_string())),
                    _ = idle_sleep => Err(NetError::Timeout("read idle timeout".to_string())),
                    _ = deadline_sleep => Err(NetError::Timeout("total read timeout".to_string())),
                };

                match read_res {
                    Ok(0) => {
                        // EOF — also the probing case where the body ends exactly at max_size
                        sb_clone.finish();
                        return;
                    }
                    Ok(_) if probing => {
                        // The reader produced data beyond the max-size budget
                        sb_clone.error(NetError::Io(Arc::new(std::io::Error::other(
                            "max size exceeded during read",
                        ))));
                        return;
                    }
                    Ok(n) => {
                        total_read = total_read.saturating_add(n as u64);

                        // Push to shared body
                        sb_clone.push(Bytes::copy_from_slice(&buf[..n]));

                        // Did we hit the total deadline?
                        if let Err(e) = check_total_deadline(tokio::time::Instant::now()) {
                            sb_clone.error(e);
                            return;
                        }
                    }
                    Err(e) => {
                        sb_clone.error(e);
                        return;
                    }
                }
            }
        });

        sb
    }
}

/// Per-subscriber stream returned by [`SharedBody::subscribe_*`].
///
/// Deregisters itself from the parent `SharedBody` on drop. You normally do not
/// use `SubStream` directly—treat it as an opaque `Stream<Item = Result<Bytes, NetError>>`.
struct SubStream {
    id: u64,
    parent: Arc<Mutex<State>>,
    /// Replayed chunks, yielded before anything live.
    prefix: std::collections::VecDeque<Bytes>,
    inner: ReceiverStream<Result<Bytes, NetError>>,
    /// Set by the producer when it dropped this subscriber for lagging.
    lagged: Arc<std::sync::atomic::AtomicBool>,
    /// The stream has yielded its last item.
    done: bool,
}

impl Stream for SubStream {
    type Item = Result<Bytes, NetError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(chunk) = this.prefix.pop_front() {
            return Poll::Ready(Some(Ok(chunk)));
        }
        if this.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            // The queue is closed and drained. If the subscriber was dropped for lagging, it
            // gets an error; if the body failed, it gets that error; otherwise a clean end.
            Poll::Ready(None) => {
                this.done = true;
                if this.lagged.load(std::sync::atomic::Ordering::Acquire) {
                    return Poll::Ready(Some(Err(NetError::Read(Arc::new(anyhow::anyhow!(
                        "body subscriber fell behind the producer and was dropped; the body is incomplete"
                    ))))));
                }
                let error = this.parent.lock().error.clone();
                Poll::Ready(error.map(Err))
            }
            other => other,
        }
    }
}

impl Drop for SubStream {
    fn drop(&mut self) {
        self.parent.lock().subs.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test(flavor = "current_thread")]
    async fn shared_body_broadcasts_and_finishes() {
        let sb = SharedBody::new(8);

        let mut s1 = sb.subscribe_stream();
        let mut s2 = sb.subscribe_stream();

        sb.push(Bytes::from_static(b"hello"));
        sb.push(Bytes::from_static(b" world"));
        sb.finish();

        // s1 sees both chunks then EOF (None)
        let a1 = s1.next().await.unwrap().unwrap();
        let a2 = s1.next().await.unwrap().unwrap();
        let expected1: &[u8] = b"hello";
        let expected2: &[u8] = b" world";
        assert_eq!((&a1[..], &a2[..]), (expected1, expected2));
        assert!(s1.next().await.is_none());

        // s2 sees both chunks then EOF
        let b1 = s2.next().await.unwrap().unwrap();
        let b2 = s2.next().await.unwrap().unwrap();
        let expected1: &[u8] = b"hello";
        let expected2: &[u8] = b" world";
        assert_eq!((&b1[..], &b2[..]), (expected1, expected2));
        assert!(s2.next().await.is_none());
    }

    async fn collect(
        mut s: BoxStream<'static, Result<Bytes, NetError>>,
    ) -> Result<Vec<u8>, NetError> {
        let mut out = Vec::new();
        while let Some(item) = s.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_reserved_late_subscriber_starts_from_the_beginning() {
        let sb = SharedBody::new(8);
        sb.reserve(2);
        let s1 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"a"));
        sb.push(Bytes::from_static(b"b"));
        let s2 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"c"));
        sb.finish();
        assert_eq!(collect(s1).await.unwrap(), b"abc");
        assert_eq!(collect(s2).await.unwrap(), b"abc");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_reserved_subscriber_after_the_end_gets_the_whole_body() {
        let sb = SharedBody::new(8);
        sb.reserve(1);
        sb.push(Bytes::from_static(b"all"));
        sb.push(Bytes::from_static(b" of it"));
        sb.finish();
        assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"all of it");

        let sb = SharedBody::new(8);
        sb.reserve(1);
        sb.push(Bytes::from_static(b"part"));
        sb.error(NetError::Cancelled("cut".into()));
        let mut s = sb.subscribe_stream();
        assert_eq!(
            s.next().await.unwrap().unwrap(),
            Bytes::from_static(b"part")
        );
        assert!(matches!(s.next().await, Some(Err(NetError::Cancelled(_)))));
        assert!(s.next().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_seat_past_the_replay_cap_gets_an_error_not_a_short_body() {
        let sb = SharedBody::new(8);
        sb.reserve(2);
        let _s1 = sb.subscribe_stream();
        let chunk = Bytes::from(vec![0u8; 1024 * 1024]);
        for _ in 0..5 {
            sb.push(chunk.clone());
        }
        let mut s2 = sb.subscribe_stream();
        assert!(matches!(s2.next().await, Some(Err(_))));
        assert!(s2.next().await.is_none());
    }

    /// A subscriber that attaches mid-stream, without any reservation, gets the chunks it
    /// missed and then the live ones, in order.
    #[tokio::test(flavor = "current_thread")]
    async fn a_late_subscriber_gets_the_replay_then_live_chunks_in_order() {
        let sb = SharedBody::new(8);
        let s1 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"a"));
        sb.push(Bytes::from_static(b"b"));
        sb.push(Bytes::from_static(b"c"));
        let mut s2 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"d"));
        sb.push(Bytes::from_static(b"e"));
        let s3 = sb.subscribe_stream();
        sb.finish();
        let mut chunks = Vec::new();
        while let Some(chunk) = s2.next().await {
            chunks.push(chunk.unwrap());
        }
        assert_eq!(chunks, [&b"a"[..], b"b", b"c", b"d", b"e"]);
        assert_eq!(collect(s1).await.unwrap(), b"abcde");
        assert_eq!(collect(s3).await.unwrap(), b"abcde");
    }

    /// Joining mid-stream while the queue still holds chunks for others, and reading the
    /// replay while live chunks arrive behind it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_late_subscriber_reads_its_replay_while_live_chunks_queue_up() {
        let sb = SharedBody::new(8);
        let s1 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"head-"));
        let mut s2 = sb.subscribe_stream();
        assert_eq!(
            s2.next().await.unwrap().unwrap(),
            Bytes::from_static(b"head-")
        );
        sb.push(Bytes::from_static(b"mid-"));
        sb.push(Bytes::from_static(b"tail"));
        sb.finish();
        assert_eq!(collect(s2).await.unwrap(), b"mid-tail");
        assert_eq!(collect(s1).await.unwrap(), b"head-mid-tail");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_subscriber_after_completion_gets_the_whole_body() {
        let sb = SharedBody::new(8);
        let first = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"all"));
        sb.push(Bytes::from_static(b" of it"));
        sb.finish();
        assert_eq!(collect(first).await.unwrap(), b"all of it");
        // Twice, after the first consumer is done with it: the replay is not used up.
        assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"all of it");
        assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"all of it");

        // Nobody attached before the end at all.
        let sb = SharedBody::new(8);
        sb.push(Bytes::from_static(b"unseen"));
        sb.finish();
        assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"unseen");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_subscriber_after_a_failed_body_gets_what_came_then_the_error() {
        let sb = SharedBody::new(8);
        sb.push(Bytes::from_static(b"part"));
        sb.error(NetError::Cancelled("cut".into()));
        let mut s = sb.subscribe_stream();
        assert_eq!(
            s.next().await.unwrap().unwrap(),
            Bytes::from_static(b"part")
        );
        assert!(matches!(s.next().await, Some(Err(NetError::Cancelled(_)))));
        assert!(s.next().await.is_none());
    }

    /// Past the replay limit, a late subscriber gets one error and then the end, both while
    /// the body is still flowing and after it ended. Subscribers attached before the limit
    /// was passed are unaffected.
    #[tokio::test(flavor = "current_thread")]
    async fn a_late_subscriber_past_the_replay_limit_gets_an_error() {
        let sb = SharedBody::with_replay_limit(8, 10);
        let early = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"12345"));
        sb.push(Bytes::from_static(b"67890"));

        // Exactly the limit is still whole.
        let mut at_limit = sb.subscribe_stream();
        assert_eq!(
            at_limit.next().await.unwrap().unwrap(),
            Bytes::from_static(b"12345")
        );
        assert_eq!(
            at_limit.next().await.unwrap().unwrap(),
            Bytes::from_static(b"67890")
        );

        // One byte past it, the start is gone for anyone attaching now.
        sb.push(Bytes::from_static(b"!"));
        assert_eq!(
            at_limit.next().await.unwrap().unwrap(),
            Bytes::from_static(b"!")
        );
        let mut late = sb.subscribe_stream();
        let err = late.next().await.unwrap().unwrap_err();
        assert!(matches!(err, NetError::Read(_)));
        assert!(err.to_string().contains("replay limit"), "got: {err}");
        assert!(late.next().await.is_none());

        sb.finish();
        assert_eq!(collect(early).await.unwrap(), b"1234567890!");
        assert!(at_limit.next().await.is_none());

        // After a clean end and after an error, the same.
        let err = collect(sb.subscribe_stream()).await.unwrap_err();
        assert!(err.to_string().contains("replay limit"), "got: {err}");
        let sb = SharedBody::with_replay_limit(8, 3);
        sb.push(Bytes::from_static(b"four"));
        sb.error(NetError::Cancelled("cut".into()));
        let err = collect(sb.subscribe_stream()).await.unwrap_err();
        assert!(err.to_string().contains("replay limit"), "got: {err}");
    }

    /// A limit of zero keeps nothing: only a subscriber that attached before the first
    /// non-empty chunk gets the body. Empty chunks do not count.
    #[tokio::test(flavor = "current_thread")]
    async fn a_zero_replay_limit_keeps_nothing() {
        let sb = SharedBody::with_replay_limit(8, 0);
        sb.push(Bytes::new());
        let before = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"x"));
        let mut after = sb.subscribe_stream();
        assert!(matches!(after.next().await, Some(Err(NetError::Read(_)))));
        assert!(after.next().await.is_none());
        sb.finish();
        assert_eq!(collect(before).await.unwrap(), b"x");
    }

    /// A live subscriber gets only what follows, and never the replay-limit error.
    #[tokio::test(flavor = "current_thread")]
    async fn a_live_subscriber_sees_only_what_follows() {
        let sb = SharedBody::with_replay_limit(8, 1);
        let s1 = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"ab"));
        let s2 = sb.subscribe_live();
        sb.push(Bytes::from_static(b"c"));
        sb.finish();
        assert_eq!(collect(s1).await.unwrap(), b"abc");
        assert_eq!(collect(s2).await.unwrap(), b"c");
        // After the end: nothing, or the error the body ended with.
        assert_eq!(collect(sb.subscribe_live()).await.unwrap(), b"");
        let sb = SharedBody::new(8);
        sb.error(NetError::Cancelled("cut".into()));
        assert!(matches!(
            collect(sb.subscribe_live()).await,
            Err(NetError::Cancelled(_))
        ));
    }

    /// `reserve` is a no-op now that every subscriber gets the replay; calling it changes
    /// nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn reserve_changes_nothing() {
        let sb = SharedBody::new(8);
        sb.reserve(0);
        sb.reserve(3);
        sb.push(Bytes::from_static(b"x"));
        sb.finish();
        for _ in 0..5 {
            assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"x");
        }
    }

    /// When the body fails while a subscriber's queue is full, that subscriber still gets
    /// the error after its queued chunks. Before, the error was lost and it saw a clean end.
    #[tokio::test(flavor = "current_thread")]
    async fn an_error_reaches_a_subscriber_whose_queue_is_full() {
        let sb = SharedBody::new(1);
        let mut s = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"A"));
        sb.error(NetError::Cancelled("upstream broke".into()));
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"A"));
        assert!(matches!(s.next().await, Some(Err(NetError::Cancelled(_)))));
        assert!(s.next().await.is_none());
        assert!(s.next().await.is_none());
    }

    /// A subscriber dropped for lagging gets exactly one error even when the body goes on to
    /// fail (or finish) afterwards, and the others are not disturbed.
    #[tokio::test(flavor = "current_thread")]
    async fn a_lagged_subscriber_gets_one_error_however_the_body_ends() {
        let sb = SharedBody::new(1);
        let mut slow = sb.subscribe_stream();
        let mut fast = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"A"));
        assert_eq!(
            fast.next().await.unwrap().unwrap(),
            Bytes::from_static(b"A")
        );
        sb.push(Bytes::from_static(b"B"));
        sb.error(NetError::Cancelled("later".into()));
        assert_eq!(
            slow.next().await.unwrap().unwrap(),
            Bytes::from_static(b"A")
        );
        let err = slow.next().await.unwrap().unwrap_err();
        assert!(err.to_string().contains("fell behind"), "got: {err}");
        assert!(slow.next().await.is_none());
        assert_eq!(
            fast.next().await.unwrap().unwrap(),
            Bytes::from_static(b"B")
        );
        assert!(matches!(
            fast.next().await,
            Some(Err(NetError::Cancelled(_)))
        ));
        assert!(fast.next().await.is_none());
    }

    /// A consumer that drops its stream deregisters; the producer and the other subscribers
    /// carry on, and a new subscriber still gets the whole body.
    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_stream_does_not_disturb_the_others() {
        let sb = SharedBody::new(1);
        let gone = sb.subscribe_stream();
        let mut kept = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"A"));
        drop(gone);
        assert_eq!(sb.inner.lock().subs.len(), 1);
        assert_eq!(
            kept.next().await.unwrap().unwrap(),
            Bytes::from_static(b"A")
        );
        sb.push(Bytes::from_static(b"B"));
        sb.finish();
        assert_eq!(collect(kept).await.unwrap(), b"B");
        assert_eq!(collect(sb.subscribe_stream()).await.unwrap(), b"AB");
    }

    /// A push that races a stream's drop finds the queue closed. That subscriber is removed
    /// and nobody else is affected.
    #[tokio::test(flavor = "current_thread")]
    async fn a_push_to_a_closed_queue_removes_that_subscriber() {
        let sb = SharedBody::new(4);
        let (tx, rx) = mpsc::channel(4);
        drop(rx);
        sb.inner.lock().subs.insert(
            999,
            Subscriber {
                tx,
                lagged: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        );
        let s = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"x"));
        assert!(!sb.inner.lock().subs.contains_key(&999));
        sb.finish();
        assert_eq!(collect(s).await.unwrap(), b"x");
    }

    /// Subscribers attaching from other threads while the producer pushes all get the whole
    /// body, in order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_subscribers_all_get_the_whole_body() {
        const CHUNKS: usize = 400;
        let sb = SharedBody::new(CHUNKS + 1);
        let expected: Vec<u8> = (0..CHUNKS).flat_map(|i| (i as u32).to_be_bytes()).collect();
        let first = sb.subscribe_stream();

        let producer = {
            let sb = sb.clone();
            tokio::spawn(async move {
                for i in 0..CHUNKS {
                    sb.push(Bytes::copy_from_slice(&(i as u32).to_be_bytes()));
                    if i % 8 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                sb.finish();
            })
        };
        let consumers: Vec<_> = (0..16)
            .map(|n| {
                let sb = sb.clone();
                tokio::spawn(async move {
                    for _ in 0..n {
                        tokio::task::yield_now().await;
                    }
                    collect(sb.subscribe_stream()).await
                })
            })
            .collect();

        producer.await.unwrap();
        assert_eq!(collect(first).await.unwrap(), expected);
        for c in consumers {
            assert_eq!(c.await.unwrap().unwrap(), expected);
        }
    }

    /// `from_reader` honours `ReaderOptions::replay_limit`. The first subscriber gets a body
    /// much larger than the limit, and a second one that attaches after that much was read
    /// gets an error.
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_applies_the_replay_limit_to_late_subscribers_only() {
        let data = vec![5u8; 64 * 1024];
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(data.clone()),
            ReaderOptions {
                buf_size: 4096,
                capacity: 64,
                replay_limit: 8 * 1024,
                ..ReaderOptions::default()
            },
        );
        assert_eq!(drain_result(&sb).await.unwrap(), data);
        let err = drain_result(&sb).await.unwrap_err();
        assert!(err.to_string().contains("replay limit"), "got: {err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_body_drops_slow_subscriber() {
        // Small per-sub queue to force lag quickly. Only one item can be buffered.
        let sb = SharedBody::new(1);

        // Slow stream will read "slowly"
        let mut slow = sb.subscribe_stream();
        // Fast stream will read "quickly" (ie: we read before pushing more)
        let mut fast = sb.subscribe_stream();

        // Push first chunk; both get it buffered.
        sb.push(Bytes::from_static(b"A"));

        // Fast stream reads the 'A' quickly
        let fa = fast.next().await.unwrap().unwrap();

        // Fast is drained. Slow is full and thus dropped
        sb.push(Bytes::from_static(b"B"));

        // Consume 'B' from fast
        let fb = fast.next().await.unwrap().unwrap();

        // Slow should get 'A', then an error for the 'B' it missed, then the end.
        let first = slow.next().await.unwrap();
        assert!(first.is_ok());
        let tail = slow.next().await;
        assert!(
            matches!(tail, Some(Err(NetError::Read(_)))),
            "a dropped subscriber must see an error, got {tail:?}"
        );
        assert!(slow.next().await.is_none());

        // Push third chunk; There is no more slow subscriber, only fast.
        sb.push(Bytes::from_static(b"C"));

        // fast should get the remaining 'C'
        let fc = fast.next().await.unwrap().unwrap();

        // Fast should have all three chunks
        let exp1: &[u8] = b"A";
        let exp2: &[u8] = b"B";
        let exp3: &[u8] = b"C";
        assert_eq!((&fa[..], &fb[..], &fc[..]), (exp1, exp2, exp3));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn combined_reader_yields_peek_then_tail() {
        let sb = SharedBody::new(8);
        let sb2 = sb.clone();

        let peek_buf = PeekBuf::from_slice(b"PEEK-");

        // write tail in background
        tokio::spawn(async move {
            sb2.push(Bytes::from_static(b"TAIL1"));
            sb2.push(Bytes::from_static(b"TAIL2"));
            sb2.finish();
        });

        // use the static helper you defined
        let mut reader = SharedBody::combined_reader(peek_buf, Arc::new(sb));

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out[..], b"PEEK-TAIL1TAIL2");
    }

    struct BlockingReader;
    impl tokio::io::AsyncRead for BlockingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    impl Unpin for BlockingReader {}

    struct ErrorReader;
    impl tokio::io::AsyncRead for ErrorReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test",
            )))
        }
    }
    impl Unpin for ErrorReader {}

    async fn drain_result(sb: &Arc<SharedBody>) -> Result<Vec<u8>, NetError> {
        let mut stream = sb.subscribe_stream();
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_after_finish_is_noop() {
        let sb = SharedBody::new(8);
        let mut s = sb.subscribe_stream();
        sb.push(Bytes::from_static(b"before"));
        sb.finish();
        sb.push(Bytes::from_static(b"after")); // should be ignored

        let first = s.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"before");
        assert!(s.next().await.is_none(), "post-finish push must not appear");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn error_after_finish_is_noop() {
        let sb = SharedBody::new(8);
        let mut s = sb.subscribe_stream();
        sb.finish();
        sb.error(NetError::Cancelled("ignored".into())); // should be ignored

        assert!(
            s.next().await.is_none(),
            "error after finish must not reopen stream"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_delivers_all_data() {
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(b"hello reader".to_vec()),
            ReaderOptions::default(),
        );
        assert_eq!(drain_result(&sb).await.unwrap(), b"hello reader");
    }

    /// The pump must not read before anyone subscribes: a subscriber that attaches late still
    /// gets everything, including bytes the reader had ready from the start.
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_waits_for_first_subscriber() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(data.clone()),
            ReaderOptions {
                buf_size: 4096,
                // room for every chunk, so drop-on-lag can't interfere with what we test here
                capacity: 128,
                ..ReaderOptions::default()
            },
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(drain_result(&sb).await.unwrap(), data);
    }

    /// Nobody subscribing is not a reason to keep the reader open forever: the idle timeout
    /// applies to the wait too, and a subscriber that turns up afterwards gets the error.
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_gives_up_when_nobody_subscribes() {
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(b"never read".to_vec()),
            ReaderOptions {
                idle_timeout: Some(Duration::from_millis(50)),
                ..ReaderOptions::default()
            },
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let err = drain_result(&sb).await.unwrap_err();
        assert!(err.to_string().contains("no subscriber"), "got: {err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_subscriber_gets_the_terminal_error() {
        let sb = SharedBody::new(8);
        sb.error(NetError::Cancelled("gone".into()));
        let mut s = sb.subscribe_stream();
        assert!(matches!(s.next().await, Some(Err(NetError::Cancelled(_)))));
        assert!(s.next().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_cancellation_errors_subscribers() {
        let cancel = CancellationToken::new();
        let sb = SharedBody::from_reader(
            BlockingReader,
            ReaderOptions {
                cancel: Some(cancel.clone()),
                ..ReaderOptions::default()
            },
        );
        let mut stream = sb.subscribe_stream();
        cancel.cancel();
        assert!(stream.next().await.unwrap().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_idle_timeout_errors_subscribers() {
        let sb = SharedBody::from_reader(
            BlockingReader,
            ReaderOptions {
                idle_timeout: Some(Duration::from_millis(50)),
                ..ReaderOptions::default()
            },
        );
        let err = drain_result(&sb).await.unwrap_err();
        assert!(err.to_string().contains("idle"), "got: {err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_total_timeout_errors_subscribers() {
        let sb = SharedBody::from_reader(
            BlockingReader,
            ReaderOptions {
                total_timeout: Some(Duration::ZERO),
                ..ReaderOptions::default()
            },
        );
        let err = drain_result(&sb).await.unwrap_err();
        assert!(err.to_string().contains("total"), "got: {err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_io_error_errors_subscribers() {
        let sb = SharedBody::from_reader(ErrorReader, ReaderOptions::default());
        assert!(drain_result(&sb).await.is_err());
    }

    /// A body of exactly `max_size` bytes is legal: it must be delivered in full with a clean
    /// EOF, not rejected. Boundary partner to `from_reader_max_size_exceeded_errors_subscribers`.
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_exact_max_size_succeeds() {
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(vec![7u8; 10]),
            ReaderOptions {
                max_size: Some(10),
                ..ReaderOptions::default()
            },
        );
        let body = drain_result(&sb).await.unwrap();
        assert_eq!(body, vec![7u8; 10]);
    }

    /// The total deadline must fire even while a read is blocked (previously it was only
    /// checked between reads, so a stalled reader without an idle timeout hung forever).
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_total_timeout_fires_during_stalled_read() {
        let sb = SharedBody::from_reader(
            BlockingReader,
            ReaderOptions {
                total_timeout: Some(Duration::from_millis(50)),
                ..ReaderOptions::default()
            },
        );
        let err = tokio::time::timeout(Duration::from_secs(2), drain_result(&sb))
            .await
            .expect("total timeout did not interrupt the blocked read")
            .unwrap_err();
        assert!(err.to_string().contains("total"), "got: {err}");
    }

    /// Cancellation must interrupt a blocked read (previously the token was only polled
    /// between reads, so cancelling mid-read hung forever).
    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_cancel_interrupts_blocked_read() {
        let cancel = CancellationToken::new();
        let sb = SharedBody::from_reader(
            BlockingReader,
            ReaderOptions {
                cancel: Some(cancel.clone()),
                ..ReaderOptions::default()
            },
        );
        let mut stream = sb.subscribe_stream();
        // Let the reader task start and block in its read before cancelling.
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        let item = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("cancel did not interrupt the blocked read")
            .unwrap();
        assert!(item.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn from_reader_max_size_exceeded_errors_subscribers() {
        let sb = SharedBody::from_reader(
            std::io::Cursor::new(vec![0u8; 200]),
            ReaderOptions {
                max_size: Some(10),
                ..ReaderOptions::default()
            },
        );
        let mut stream = sb.subscribe_stream();
        let mut got_err = false;
        while let Some(r) = stream.next().await {
            if r.is_err() {
                got_err = true;
                break;
            }
        }
        assert!(got_err);
    }
}

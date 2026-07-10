//! Internal utilities: URL normalisation, hashing, async helpers.

use crate::net::shared_body::SharedBody;
use crate::net::types::{FetchResult, NetError};
use crate::types::PeekBuf;
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use url::Url;

static HASH_STATE: OnceLock<RandomState> = OnceLock::new();

/// Spawn a task with a human-readable name attached as a tracing span, so task activity can
/// be attributed in trace output.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_named<F, T>(name: &str, fut: F) -> JoinHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use tracing::Instrument as _;
    let span = tracing::debug_span!("task", %name);
    tokio::spawn(fut.instrument(span))
}

/// Spawn a task with a human-readable name attached as a tracing span, so task activity can
/// be attributed in trace output.
///
/// wasm32 is single-threaded and its JS-backed futures are `!Send`, so tasks go onto the
/// thread-local task set instead; the caller must drive them from a tokio `LocalSet` (or an
/// equivalent local executor).
#[cfg(target_arch = "wasm32")]
pub fn spawn_named<F, T>(name: &str, fut: F) -> JoinHandle<T>
where
    F: std::future::Future<Output = T> + 'static,
    T: 'static,
{
    use tracing::Instrument as _;
    let span = tracing::debug_span!("task", %name);
    tokio::task::spawn_local(fut.instrument(span))
}

/// Normalizes a URL by removing its fragment and returning it as a string.
pub fn normalize_url(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.as_str().to_string()
}

/// Computes a short hash for a given byte slice using a randomly seeded hasher.
///
/// The seed is fixed per process so the result is stable within one run but not
/// predictable across runs or by external observers.
pub fn short_hash(bytes: &[u8]) -> u64 {
    HASH_STATE.get_or_init(RandomState::new).hash_one(bytes)
}

/// Returns a URL string truncated to at most `max` bytes with `...` suffix.
pub fn short_url(u: &Url, max: usize) -> String {
    let s = u.as_str();
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", truncate_on_char_boundary(s, max))
    }
}

/// Truncate `s` to at most `max` bytes without slicing through a multi-byte character.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Minimal async reader backed by an in-memory `Bytes` buffer.
pub struct BytesAsyncReader {
    pub data: Bytes,
    pub pos: usize,
}

impl tokio::io::AsyncRead for BytesAsyncReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let remaining = self.data.len().saturating_sub(self.pos);
        if remaining == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let to_copy = std::cmp::min(remaining, buf.remaining());
        let end = self.pos + to_copy;
        buf.put_slice(&self.data[self.pos..end]);
        self.pos = end;
        std::task::Poll::Ready(Ok(()))
    }
}

/// An entry in the waiter, representing a listener and whether it wants streaming or buffered response.
struct WaiterEntry {
    /// Listener for this entry.
    tx: oneshot::Sender<FetchResult>,
    /// Whether the listener wants a streaming response (true) or buffered (false).
    wants_streaming: bool,
}

// Simple waiter for coalescing responses. If a fetcher detects we are requesting the same resource
// that is already queued, we add them to the waiter for that request, so the request will fetch the
// resource only once and dispatches the result to all listeners. Will also handle the case where some
// listeners want streaming results, and some want buffered results.
#[derive(Default)]
pub struct Waiter {
    /// List of listeners (oneshot senders) waiting for the result.
    /// Uses a non-async mutex so register() is synchronous and never needs to be awaited.
    listeners: Mutex<Vec<WaiterEntry>>,
}

impl Waiter {
    pub fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_arc() -> Arc<Waiter> {
        Arc::new(Waiter::new())
    }

    /// Register a consumer for this waiter. We need to know if the consumer is streaming or not.
    ///
    /// This is a plain (non-async) call — the lock is held only for the duration of the push.
    pub fn register(&self, tx: oneshot::Sender<FetchResult>, wants_streaming: bool) {
        self.listeners.lock().push(WaiterEntry {
            tx,
            wants_streaming,
        });
    }

    /// Process the fetch result with the listeners.
    ///
    /// Drains the listener list under the lock, releases the lock, then delivers results.
    /// The lock is never held across I/O so slow body streaming does not block new registrations.
    pub async fn finish(self: &Arc<Self>, result: FetchResult) {
        // Drain under lock, release before any async I/O
        let ls: Vec<WaiterEntry> = self.listeners.lock().drain(..).collect();

        match result {
            FetchResult::Buffered { meta, body } => {
                let res = FetchResult::Buffered {
                    meta: meta.clone(),
                    body: body.clone(),
                };
                for entry in ls {
                    let _ = entry.tx.send(res.clone());
                }
            }
            FetchResult::Stream {
                meta,
                peek_buf,
                shared,
            } => {
                let mut streaming_ls = Vec::new();
                let mut buffered_ls = Vec::new();
                for entry in ls {
                    if entry.wants_streaming {
                        streaming_ls.push(entry.tx);
                    } else {
                        buffered_ls.push(entry.tx);
                    }
                }

                for tx in streaming_ls {
                    let res = FetchResult::Stream {
                        meta: meta.clone(),
                        peek_buf: peek_buf.clone(),
                        shared: shared.clone(),
                    };
                    let _ = tx.send(res);
                }

                // Lock is released; stream I/O happens without blocking register()
                if !buffered_ls.is_empty() {
                    match stream_to_bytes(peek_buf, shared).await {
                        Ok(b) => {
                            let res = FetchResult::Buffered {
                                meta: meta.clone(),
                                body: b,
                            };
                            for tx in buffered_ls {
                                let _ = tx.send(res.clone());
                            }
                        }
                        Err(e) => {
                            // `e` is already a typed NetError — pass it through unwrapped.
                            let res = FetchResult::Error(e);
                            for tx in buffered_ls {
                                let _ = tx.send(res.clone());
                            }
                        }
                    }
                }
            }
            FetchResult::Error(e) => {
                let res = FetchResult::Error(e.clone());
                for entry in ls {
                    let _ = entry.tx.send(res.clone());
                }
            }
        }
    }
}

/// Convert a streaming body to a buffered fetch-result by reading it to the end.
/// This could be more efficient with allocations, probably.
pub async fn stream_to_bytes(
    peek_buf: PeekBuf,
    shared: Arc<SharedBody>,
) -> Result<Bytes, NetError> {
    let mut out = Vec::with_capacity(peek_buf.len() + 8192);
    let mut reader = SharedBody::combined_reader(peek_buf, shared);
    if let Err(e) = reader.read_to_end(&mut out).await {
        // The reader wraps stream errors in io::Error (see NetError::to_io); recover the
        // original typed NetError when one is carried, otherwise wrap the io::Error once.
        let net = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<NetError>())
            .cloned()
            .unwrap_or_else(|| NetError::Io(Arc::new(e)));
        return Err(net);
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::types::FetchResultMeta;
    use http::HeaderMap;
    use tokio::io::AsyncReadExt;
    use tokio::sync::oneshot;
    use tokio::time::{sleep, Duration};
    use url::Url;

    /// Truncation must never slice through a multi-byte character. `Url::as_str()` is ASCII in
    /// practice (punycode / percent-encoding), so exercise the boundary logic on the helper.
    #[test]
    fn truncate_on_char_boundary_is_panic_free() {
        let s = "héllo wörld"; // é and ö are 2 bytes each
        for max in 0..=s.len() + 2 {
            let t = truncate_on_char_boundary(s, max);
            assert!(t.len() <= max.min(s.len()));
            assert!(s.starts_with(t));
        }
        assert_eq!(truncate_on_char_boundary("héllo", 2), "h"); // byte 2 is inside é
        assert_eq!(truncate_on_char_boundary("héllo", 3), "hé");
    }

    #[test]
    fn short_url_truncates_with_suffix() {
        let u = Url::parse("https://example.com/a/very/long/path").unwrap();
        assert_eq!(short_url(&u, 19), "https://example.com...");
        // Under the limit: returned untouched, no suffix.
        assert_eq!(short_url(&u, 500), u.as_str());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_named_runs_task_to_completion() {
        let handle = spawn_named("test-task", async { 21 * 2 });
        assert_eq!(handle.await.unwrap(), 42);
    }

    #[test]
    fn normalize_url_strips_fragment() {
        let u = Url::parse("https://example.org/a/b#frag").unwrap();
        assert_eq!(normalize_url(&u), "https://example.org/a/b");
    }

    #[test]
    fn short_hash_differs_for_diff_inputs() {
        assert_ne!(short_hash(b"abc"), short_hash(b"abd"));
    }

    #[test]
    fn short_url_truncates() {
        let u = Url::parse("https://example.org/very/long/path/here").unwrap();
        let s = short_url(&u, 16);
        assert!(s.ends_with("..."));
        assert!(s.len() <= 19);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bytes_async_reader_reads_all() {
        let data = Bytes::from_static(b"hello world");
        let mut r = BytesAsyncReader { data, pos: 0 };
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out[..], b"hello world");
        let n = r.read(&mut [0u8; 8]).await.unwrap();
        assert_eq!(n, 0);
    }

    fn dummy_meta() -> FetchResultMeta {
        FetchResultMeta {
            final_url: Url::parse("https://example.org/").unwrap(),
            status: 200,
            status_text: "OK".into(),
            headers: HeaderMap::new(),
            content_length: None,
            content_type: None,
            has_body: true,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn waiter_finishes_buffered_to_all() {
        let waiter = Waiter::new_arc();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        waiter.register(tx1, false);
        waiter.register(tx2, true);

        let body = Bytes::from_static(b"BODY");
        let meta = dummy_meta();
        waiter
            .finish(FetchResult::Buffered {
                meta: meta.clone(),
                body: body.clone(),
            })
            .await;

        let r1 = rx1.await.unwrap();
        let r2 = rx2.await.unwrap();
        match r1 {
            FetchResult::Buffered { meta: m, body: b } => {
                assert_eq!(m.status, 200);
                assert_eq!(&b[..], b"BODY");
            }
            _ => panic!("expected buffered"),
        }
        match r2 {
            FetchResult::Buffered { meta: m, body: b } => {
                assert_eq!(m.status, 200);
                assert_eq!(&b[..], b"BODY");
            }
            _ => panic!("expected buffered"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn waiter_stream_is_fanned_out_and_buffered_followers_convert() {
        let (tx_stream, rx_stream) = oneshot::channel();
        let (tx_buf, rx_buf) = oneshot::channel();

        let waiter = Waiter::new_arc();
        waiter.register(tx_stream, true);
        waiter.register(tx_buf, false);

        let shared = Arc::new(SharedBody::new(8));
        let shared_writer = shared.clone();

        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            shared_writer.push(Bytes::from_static(b"TAIL1"));
            shared_writer.push(Bytes::from_static(b"TAIL2"));
            shared_writer.finish();
        });

        let meta = dummy_meta();
        let peek_buf = PeekBuf::from_slice(b"PEEK-");

        waiter
            .finish(FetchResult::Stream {
                meta: meta.clone(),
                peek_buf: peek_buf.clone(),
                shared: shared.clone(),
            })
            .await;

        let r_stream = rx_stream.await.unwrap();
        match r_stream {
            FetchResult::Stream {
                meta: m,
                peek_buf: p,
                ..
            } => {
                assert_eq!(m.status, 200);
                assert_eq!(&p[..], b"PEEK-");
            }
            _ => panic!("expected stream"),
        }

        let r_buf = rx_buf.await.unwrap();
        match r_buf {
            FetchResult::Buffered { meta: m, body } => {
                assert_eq!(m.status, 200);
                assert_eq!(&body[..], b"PEEK-TAIL1TAIL2");
            }
            _ => panic!("expected buffered"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn waiter_propagates_error() {
        let waiter = Waiter::new_arc();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        waiter.register(tx1, false);
        waiter.register(tx2, true);

        waiter
            .finish(FetchResult::Error(NetError::Cancelled("boom".into())))
            .await;

        let r1 = rx1.await.unwrap();
        let r2 = rx2.await.unwrap();
        assert!(matches!(r1, FetchResult::Error(_)));
        assert!(matches!(r2, FetchResult::Error(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_to_bytes_returns_peek_plus_body() {
        let shared = Arc::new(SharedBody::new(8));
        let shared_clone = shared.clone();
        tokio::spawn(async move {
            shared_clone.push(Bytes::from_static(b"-tail"));
            shared_clone.finish();
        });
        let result = stream_to_bytes(PeekBuf::from_slice(b"head"), shared)
            .await
            .unwrap();
        assert_eq!(&result[..], b"head-tail");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn waiter_stream_error_propagates_to_buffered_subscriber() {
        let (tx_buf, rx_buf) = oneshot::channel();
        let waiter = Waiter::new_arc();
        waiter.register(tx_buf, false);

        let shared = Arc::new(SharedBody::new(8));
        let shared_clone = shared.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            shared_clone.error(NetError::Cancelled("injected".into()));
        });

        waiter
            .finish(FetchResult::Stream {
                meta: dummy_meta(),
                peek_buf: PeekBuf::empty(),
                shared,
            })
            .await;

        // The typed error must survive the stream→buffered conversion unwrapped: the
        // subscriber sees the original NetError::Cancelled, not a nested Read(Io(...)).
        match rx_buf.await.unwrap() {
            FetchResult::Error(e) => {
                assert!(
                    matches!(e, NetError::Cancelled(_)),
                    "expected the original typed error, got: {e}"
                );
            }
            _ => panic!("expected an error result"),
        }
    }
}

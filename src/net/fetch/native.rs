//! The fetch layer's native side: the HTTP cache's pending writes, CORS preflight grants, header
//! order, body decoding and what the client knows about TLS, proxies and peers. On wasm32 the
//! browser's `fetch()` does all of this itself, and `wasm.rs` stands in with the same items.

use super::NetPolicy;
use crate::net::cache::{self, CacheKey, CacheOutcome, HttpCache};
use crate::net::cors::{self, CorsPreflightCache};
use crate::net::decode::Coding;
use crate::net::events::NetEvent;
use crate::net::observer::NetObserver;
use crate::net::types::NetError;
use bytes::{Bytes, BytesMut};
use futures_util::stream::BoxStream;
use futures_util::{Stream, StreamExt};
use http::{header, HeaderMap, HeaderName};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// The host of `url` when it is an IP literal, without brackets.
pub(super) fn ip_literal(url: &Url) -> Option<String> {
    match url.host()? {
        url::Host::Ipv4(a) => Some(a.to_string()),
        url::Host::Ipv6(a) => Some(a.to_string()),
        url::Host::Domain(_) => None,
    }
}

/// Whether `resp`'s connection was accepted through the override store. Needs a client built
/// with `tls_info`, which the fetcher does when overrides are enabled.
pub(super) fn over_accepted_override(policy: &NetPolicy, resp: &reqwest::Response) -> bool {
    let (Some(store), Some(host)) = (
        policy.transport.tls_overrides.as_ref(),
        resp.url().host_str(),
    ) else {
        return false;
    };
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .is_some_and(|der| store.is_accepted(host, &crate::net::tls::fingerprint(der)))
}

/// A preflight grant a hop is relying on, dropped from the cache unless the hop's response
/// passes its CORS check (Fetch §4.4, main fetch: "If corsWithPreflightResponse is a network
/// error, then clear cache entries using request"). Every way a hop can fail after its grant
/// returns early, so the drop is what catches them all.
pub(super) struct PreflightGrant {
    pub(super) cache: Arc<dyn CorsPreflightCache>,
    pub(super) origin: String,
    pub(super) url: Url,
    pub(super) kept: bool,
}

impl PreflightGrant {
    /// The hop's response passed: the grant stays cached.
    pub(super) fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for PreflightGrant {
    fn drop(&mut self) {
        if !self.kept {
            self.cache.clear(&self.origin, &self.url);
        }
    }
}

/// `headers` without the forbidden request headers (Fetch §2.2.2).
pub(super) fn without_forbidden(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if !cors::is_forbidden_request_header_value(name, value) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Reorder `headers` so the names in `order` come first (all values of a name together), with
/// the remaining headers after them in insertion order. Names without a header are skipped;
/// duplicates in `order` count once. hyper writes headers in map order, so this is the wire
/// order.
pub(super) fn apply_header_order(headers: &mut HeaderMap, order: &[HeaderName]) {
    if order.is_empty() {
        return;
    }
    let original = std::mem::take(headers);
    let mut ordered = HeaderMap::with_capacity(original.len());
    for name in order {
        if ordered.contains_key(name) {
            continue;
        }
        for value in original.get_all(name) {
            ordered.append(name.clone(), value.clone());
        }
    }
    for (name, value) in original.iter() {
        if !order.contains(name) {
            ordered.append(name.clone(), value.clone());
        }
    }
    *headers = ordered;
}

/// The `Host` value hyper-util would add for `url`: host, plus the port if not the default.
pub(super) fn host_header_value(url: &Url) -> Option<http::HeaderValue> {
    let host = url.host_str()?;
    let value = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    http::HeaderValue::from_str(&value).ok()
}

/// Apply `order` to the request's headers. No-op when `order` is `None`.
///
/// reqwest appends the default `user-agent` and hyper-util the `host` at execute time, after
/// anything we can reorder, so both are inserted here (if absent) with the values they would
/// get. `host` only when `place_host`: hyper-util adds it on HTTP/1 connections only, and we
/// don't know the connection yet, so the caller decides from what it has seen of the origin.
pub(super) fn order_hop_headers(
    mut request: reqwest::Request,
    order: Option<&[HeaderName]>,
    user_agent: Option<&http::HeaderValue>,
    place_host: bool,
) -> reqwest::Request {
    let Some(order) = order else {
        return request;
    };
    let host = if place_host {
        host_header_value(request.url())
    } else {
        None
    };
    let headers = request.headers_mut();
    if let Some(ua) = user_agent {
        headers.entry(header::USER_AGENT).or_insert(ua.clone());
    }
    if let Some(host) = host {
        headers.entry(header::HOST).or_insert(host);
    }
    apply_header_order(headers, order);
    request
}

/// The client's timeout for a request whose [`RequestInit::headers_timeout`] bounds the wait
/// for headers instead: long enough never to end a body, which its own timeouts bound.
pub(super) const NO_CLIENT_DEADLINE: Duration = Duration::from_secs(365 * 24 * 3600);

/// Copies a body on its way to the caller so it can be written to the cache when the stream ends.
///
/// Only a complete body is stored. A fetch that is cancelled, fails, or is dropped mid-stream
/// drops the collector instead, and one that grows past the cache's ceiling drops the pending
/// write and stops copying.
pub(super) struct CacheCollector {
    /// The write to perform on EOF. Taken away when the body turns out to be too large.
    store: Option<PendingStore>,
    /// Body bytes so far, starting with the peek window the caller already read.
    body: BytesMut,
    /// Ceiling from [`HttpCache::max_entry_bytes`].
    limit: usize,
}

impl CacheCollector {
    /// Collector for `store`, seeded with the bytes read before the reader was built.
    pub(super) fn new(store: PendingStore, prefix: &[u8]) -> Self {
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
    pub(super) fn feed(&mut self, chunk: &[u8]) {
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
    pub(super) fn commit(&mut self, observer: &Arc<dyn NetObserver + Send + Sync>) {
        if let Some(store) = self.store.take() {
            store.commit(std::mem::take(&mut self.body).freeze(), observer);
        }
    }
}

/// A storable response whose body has not been read yet.
///
/// `get_with_redirects` decides whether a response may be cached from its headers, but the body
/// only arrives later, in whichever consumer reads it. This carries that decision until then;
/// dropping it (a cancelled fetch, a body over the cache's ceiling) stores nothing.
pub(crate) struct PendingStore {
    pub(super) cache: Arc<dyn HttpCache>,
    pub(super) key: CacheKey,
    pub(super) url: Url,
    pub(super) status: u16,
    pub(super) response_headers: HeaderMap,
    pub(super) request_headers: HeaderMap,
    pub(super) decoded: bool,
    pub(super) requested_at: chrono::DateTime<chrono::Utc>,
    pub(super) received_at: chrono::DateTime<chrono::Utc>,
    pub(super) peer_addr: Option<std::net::SocketAddr>,
}

impl PendingStore {
    /// Largest body the cache behind this will accept.
    pub(crate) fn max_bytes(&self) -> usize {
        self.cache.max_entry_bytes()
    }

    /// This store with `decoded` set: whether a coding of the body was undone.
    pub(crate) fn decoded(mut self, decoded: bool) -> Self {
        self.decoded = decoded;
        self
    }

    /// Write the response to the cache now that its body is complete.
    pub(crate) fn commit(self, body: Bytes, observer: &Arc<dyn NetObserver + Send + Sync>) {
        let mut entry = cache::entry_from_response(
            self.status,
            &self.response_headers,
            &self.request_headers,
            body,
            self.decoded,
            self.requested_at,
            self.received_at,
        );
        entry.peer_addr = self.peer_addr;
        self.cache.put(self.key, Arc::new(entry));
        observer.on_event(NetEvent::Cache {
            url: self.url,
            outcome: CacheOutcome::Stored,
        });
    }
}
/// A response body as the fetch layer passes it on.
pub(super) type BodyStream = BoxStream<'static, Result<Bytes, NetError>>;

/// Boxes `stream` as a [`BodyStream`].
pub(super) fn boxed<S>(stream: S) -> BodyStream
where
    S: Stream<Item = Result<Bytes, NetError>> + Send + 'static,
{
    stream.boxed()
}

/// The codings to undo on a body the caller wants decoded, with the headers and length the
/// caller then gets.
pub(super) fn decoding(
    auto_decode: bool,
    bodiless: bool,
    headers: HeaderMap,
    content_length: Option<u64>,
) -> (Option<Vec<Coding>>, HeaderMap, Option<u64>) {
    let codings = if auto_decode && !bodiless {
        crate::net::decode::codings(&headers).filter(|c| !c.is_empty())
    } else {
        None
    };
    let (headers, content_length) = match codings {
        Some(_) => {
            let mut headers = headers;
            headers.remove(header::CONTENT_ENCODING);
            headers.remove(header::CONTENT_LENGTH);
            (headers, None)
        }
        None => (headers, content_length),
    };
    (codings, headers, content_length)
}

/// `body_stream` with `codings` undone.
pub(super) fn decode<S>(body_stream: S, codings: Option<Vec<Coding>>) -> BodyStream
where
    S: Stream<Item = Result<Bytes, NetError>> + Send + 'static,
{
    match codings {
        Some(codings) => crate::net::decode::decode(body_stream.boxed(), codings),
        None => body_stream.boxed(),
    }
}

/// What a failed send says beyond a transport error: a TLS failure, or a proxy that wants
/// credentials.
pub(super) fn classify_send_error(
    e: &reqwest::Error,
    url: &Url,
    observer: &Arc<dyn NetObserver + Send + Sync>,
    policy: &NetPolicy,
) -> Option<NetError> {
    if let Some(tls) = crate::net::tls::classify(e, url) {
        observer.on_event(NetEvent::TlsFailed {
            url: url.clone(),
            error: tls.clone(),
        });
        return Some(NetError::Tls(tls));
    }
    // Without a proxy to name, the tunnel failure stays a connect failure.
    if crate::net::transport::is_proxy_auth_required(e) {
        if let Some(proxy) = policy.proxy.proxy_for.as_ref().and_then(|f| f(url)) {
            return Some(NetError::ProxyAuthRequired {
                proxy: Arc::new(proxy),
                url: url.clone(),
            });
        }
    }
    None
}

/// The peer `resp` was read from, as [`FetchResultMeta::peer_addr`] reports it: `None` when
/// the request to `url` went through a proxy, whose address says nothing about the host's, or
/// when the policy cannot say whether it did.
///
/// [`FetchResultMeta::peer_addr`]: crate::net::types::FetchResultMeta::peer_addr
pub(super) fn origin_peer(
    resp: &reqwest::Response,
    url: &Url,
    policy: &NetPolicy,
) -> Option<std::net::SocketAddr> {
    match policy.proxy.proxied {
        Some(ref proxied) if !proxied(url) => resp.remote_addr(),
        _ => None,
    }
}

//! HTTP caching (RFC 9111).
//!
//! A private (per-fetcher) cache. Every hop of a fetch consults it before the request goes out and
//! writes to it when the response comes back, so a redirect is cached as its own entry and a
//! `301` can be followed without touching the network.
//!
//! The store is [`FetcherConfig::cache`], an [`HttpCache`]; the default
//! [`InMemoryHttpCache`] holds entries in memory with a byte budget. Per request,
//! [`FetchRequest::cache_mode`] picks how the cache is used, mirroring the Fetch standard's
//! request cache mode: [`CacheMode::Reload`] is a normal refresh, [`CacheMode::NoCache`] a forced
//! revalidation, [`CacheMode::NoStore`] a private-browsing style bypass.
//!
//! What is implemented, per hop:
//!
//! - freshness from `Cache-Control: max-age`, `Expires`/`Date`, or the `Last-Modified` heuristic
//!   (§4.2), with the age of the stored response corrected for `Age` and request latency (§4.2.3)
//! - request directives `no-store`, `no-cache`, `max-age`, `max-stale`, `min-fresh` and
//!   `only-if-cached` (§5.2.1)
//! - conditional revalidation of a stale entry with `If-None-Match` / `If-Modified-Since`, and a
//!   `304` that updates the stored headers and reuses the stored body (§4.3)
//! - `Vary`: one entry per combination of the request headers the response varies on (§4.1)
//! - invalidation of the target URI (and a same-origin `Location`/`Content-Location`) by an
//!   unsafe method (§4.4)
//!
//! Not implemented: shared-cache rules (`s-maxage`, the `Authorization` restriction of §3.5, since
//! this is a private cache), range requests and `206` responses, and serving stale content while
//! revalidating (`stale-while-revalidate`). A request that carries a `Range` or a condition of
//! its own goes past the cache in both directions, since only the server can answer it.
//!
//! `Set-Cookie` is stripped before a response is stored, so that a cache hit cannot re-apply a
//! cookie the jar already has, and so are the hop-by-hop headers, which describe the connection
//! rather than the response.
//!
//! [`FetcherConfig::cache`]: crate::net::fetcher::FetcherConfig::cache
//! [`FetchRequest::cache_mode`]: crate::net::types::FetchRequest::cache_mode

use crate::net::utils::split_outside_quotes;
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use http::{header, HeaderMap, HeaderName, Method};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

/// Fraction of a response's age at the time it was received that a heuristic freshness lifetime
/// covers (RFC 9111 §4.2.2).
const HEURISTIC_FRACTION: f64 = 0.1;

/// Ceiling on a heuristic freshness lifetime. The spec leaves this to the implementation; a day
/// is what browsers use.
const HEURISTIC_MAX_SECS: i64 = 24 * 60 * 60;

/// Statuses a response may be stored under without explicit cache directives (RFC 9111 §3,
/// "heuristically cacheable"). `206` is absent: partial responses need range support.
const DEFAULT_CACHEABLE: &[u16] = &[200, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501];

/// Headers that describe the connection rather than the response, and are never stored
/// (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// How a request uses the cache, mirroring the Fetch standard's request cache mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CacheMode {
    /// Normal HTTP caching: serve a fresh stored response, revalidate a stale one, store what
    /// comes back.
    #[default]
    Default,
    /// Ignore the cache in both directions: nothing is read, nothing is written, as a
    /// private-browsing session needs.
    NoStore,
    /// Always go to the network, without revalidating, and store the response. A reload.
    Reload,
    /// Always ask the server, revalidating a stored response instead of using it outright.
    /// A forced reload.
    NoCache,
    /// Use a stored response even when it is stale, and only go to the network when there is
    /// none.
    ForceCache,
    /// Use a stored response even when it is stale, and fail the request when there is none.
    OnlyIfCached,
}

/// What the cache did with a hop, reported as [`NetEvent::Cache`].
///
/// [`NetEvent::Cache`]: crate::net::events::NetEvent::Cache
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheOutcome {
    /// A stored response was used without contacting the server.
    Hit,
    /// A stored response was revalidated and the server answered `304`; the stored body was
    /// used and its headers updated.
    Validated,
    /// A response from the network was written to the cache.
    Stored,
    /// Stored responses for the URL were dropped, because an unsafe method changed it.
    Invalidated,
}

impl std::fmt::Display for CacheOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Hit => "hit",
            Self::Validated => "validated",
            Self::Stored => "stored",
            Self::Invalidated => "invalidated",
        })
    }
}

/// What a hop's cache lookup came to.
#[derive(Debug, Clone)]
pub enum CacheDecision {
    /// Use this stored response; send nothing.
    Use(Arc<CacheEntry>),
    /// Send the request with these conditional headers added. A `304` means the stored response
    /// is still good.
    Revalidate(Arc<CacheEntry>, HeaderMap),
    /// Send the request; there is nothing usable stored.
    Send,
    /// The request insisted on a stored response ([`CacheMode::OnlyIfCached`]) and there is none.
    NotCached,
}

/// The URL and method a cache entry is stored under.
///
/// The URL's fragment is dropped: it never goes on the wire, so it cannot distinguish two
/// responses. Entries that differ only in the request headers a response declared in `Vary` are
/// separate variants under one key, not separate keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Request method. Only `GET` and `HEAD` are ever stored.
    pub method: Method,
    /// Request URL, without its fragment.
    pub url: Url,
}

impl CacheKey {
    /// Key for a request, dropping the URL's fragment.
    pub fn new(method: &Method, url: &Url) -> Self {
        let mut url = url.clone();
        url.set_fragment(None);
        Self {
            method: method.clone(),
            url,
        }
    }
}

/// A stored response.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Status code of the stored response.
    pub status: u16,
    /// Stored response headers, without `Set-Cookie` and the hop-by-hop headers.
    pub headers: HeaderMap,
    /// The complete body, as it was stored.
    pub body: Bytes,
    /// The request headers this variant was selected by: one entry per name in the response's
    /// `Vary`, with the value the request carried (`None` when it carried none). Empty when the
    /// response had no `Vary`.
    pub vary: Vec<(String, Option<String>)>,
    /// Whether the body is the decoded form of a `Content-Encoding` the client unpacked. Such an
    /// entry only answers requests that also want decoding; see
    /// [`FetchRequest::auto_decode`](crate::net::types::FetchRequest::auto_decode).
    pub decoded: bool,
    /// When the request that produced this response was sent.
    pub requested_at: DateTime<Utc>,
    /// When its response arrived.
    pub received_at: DateTime<Utc>,
}

impl CacheEntry {
    /// Bytes this entry occupies: the body plus a rough estimate of the headers.
    pub fn size(&self) -> usize {
        let headers: usize = self
            .headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum();
        self.body.len() + headers
    }

    /// Whether this variant answers a request with these headers (RFC 9111 §4.1).
    ///
    /// `decoded` is the requesting fetch's auto-decode setting: a stored decoded body is not the
    /// same resource as the encoded one the raw caller asked for.
    pub fn matches(&self, request: &HeaderMap, decoded: bool) -> bool {
        if self.decoded != decoded {
            return false;
        }
        self.vary.iter().all(|(name, stored)| {
            let current = HeaderName::try_from(name.as_str())
                .ok()
                .and_then(|n| request.get(&n).and_then(|v| v.to_str().ok()))
                .map(str::to_string);
            current.as_deref() == stored.as_deref()
        })
    }

    /// How long the response may be considered fresh (RFC 9111 §4.2.1), or `None` when it carries
    /// no `max-age`, no usable `Expires`, and no `Last-Modified` to guess from.
    pub fn freshness_lifetime(&self) -> Option<TimeDelta> {
        let directives = ResponseDirectives::parse(&self.headers);
        if let Some(max_age) = directives.max_age {
            return Some(TimeDelta::seconds(max_age));
        }

        let date = header_date(&self.headers, header::DATE);
        if let Some(expires) = header_date(&self.headers, header::EXPIRES) {
            // `header_date` reports an unparsable Expires (`0`, a malformed date) as `None`.
            // That means "already expired", so the heuristic below must not be reached.
            let base = date.unwrap_or(self.received_at);
            return Some((expires - base).max(TimeDelta::zero()));
        }
        if self.headers.contains_key(header::EXPIRES) {
            return Some(TimeDelta::zero());
        }

        // Heuristic freshness (§4.2.2): a fraction of how old the response already was.
        let last_modified = header_date(&self.headers, header::LAST_MODIFIED)?;
        let base = date.unwrap_or(self.received_at);
        let age = (base - last_modified).max(TimeDelta::zero());
        let secs = ((age.num_seconds() as f64) * HEURISTIC_FRACTION) as i64;
        Some(TimeDelta::seconds(secs.min(HEURISTIC_MAX_SECS)))
    }

    /// How old the stored response is now (RFC 9111 §4.2.3), counting the `Age` it arrived with
    /// and the time the request itself took.
    pub fn current_age(&self, now: DateTime<Utc>) -> TimeDelta {
        let age_value = self
            .headers
            .get(header::AGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<i64>().ok())
            .map(TimeDelta::seconds)
            .unwrap_or_else(TimeDelta::zero);

        let apparent_age = match header_date(&self.headers, header::DATE) {
            Some(date) => (self.received_at - date).max(TimeDelta::zero()),
            None => TimeDelta::zero(),
        };
        let response_delay = (self.received_at - self.requested_at).max(TimeDelta::zero());
        let corrected_initial = apparent_age.max(age_value + response_delay);
        let resident_time = (now - self.received_at).max(TimeDelta::zero());
        corrected_initial + resident_time
    }

    /// Whether the response is still fresh (RFC 9111 §4.2).
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        match self.freshness_lifetime() {
            Some(lifetime) => self.current_age(now) < lifetime,
            None => false,
        }
    }

    /// The `ETag` and `Last-Modified` of the stored response, as conditional request headers.
    /// Empty when it has neither, i.e. when it cannot be revalidated.
    pub fn conditional_headers(&self) -> HeaderMap {
        let mut out = HeaderMap::new();
        if let Some(etag) = self.headers.get(header::ETAG) {
            out.insert(header::IF_NONE_MATCH, etag.clone());
        }
        if let Some(modified) = self.headers.get(header::LAST_MODIFIED) {
            out.insert(header::IF_MODIFIED_SINCE, modified.clone());
        }
        out
    }

    /// Whether the entry carries a validator, i.e. whether a `304` can ever come back for it.
    pub fn is_revalidatable(&self) -> bool {
        self.headers.contains_key(header::ETAG) || self.headers.contains_key(header::LAST_MODIFIED)
    }

    /// The entry as updated by a `304` (RFC 9111 §4.3.4): the stored body, the stored headers with
    /// everything the `304` carried written over them, and the age clock restarted.
    pub fn updated_by_304(
        &self,
        headers: &HeaderMap,
        requested_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Self {
        let mut updated = self.clone();
        for name in headers.keys() {
            // Content-Length describes the stored body, which the 304 did not carry.
            if HOP_BY_HOP.contains(name)
                || name == header::CONTENT_LENGTH
                || name == header::SET_COOKIE
            {
                continue;
            }
            updated.headers.remove(name);
            for value in headers.get_all(name) {
                updated.headers.append(name, value.clone());
            }
        }
        updated.requested_at = requested_at;
        updated.received_at = received_at;
        updated
    }
}

/// The `Cache-Control` directives of a response that this cache acts on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseDirectives {
    /// `no-store`: may not be written to the cache at all.
    pub no_store: bool,
    /// `no-cache`: may be stored, but never used without revalidating first.
    pub no_cache: bool,
    /// `must-revalidate`: may not be served stale, whatever the request asks for.
    pub must_revalidate: bool,
    /// `immutable`: will not change while fresh, so a forced revalidation can be skipped.
    pub immutable: bool,
    /// `private`: not for a shared cache. This one is private, so it only records the fact.
    pub private: bool,
    /// `public`.
    pub public: bool,
    /// `max-age`, in seconds.
    pub max_age: Option<i64>,
}

impl ResponseDirectives {
    /// Parse the `Cache-Control` field lines of a response.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut out = Self::default();
        for (name, value) in directives(headers) {
            match name.as_str() {
                "no-store" => out.no_store = true,
                "no-cache" => out.no_cache = true,
                "must-revalidate" | "proxy-revalidate" => out.must_revalidate = true,
                "immutable" => out.immutable = true,
                "private" => out.private = true,
                "public" => out.public = true,
                "max-age" => out.max_age = value.and_then(|v| v.parse().ok()),
                _ => {}
            }
        }
        out
    }
}

/// The `Cache-Control` directives of a request that this cache acts on (RFC 9111 §5.2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestDirectives {
    /// `no-store`: this exchange may not be written to the cache.
    pub no_store: bool,
    /// `no-cache`: a stored response may not be used without revalidating.
    pub no_cache: bool,
    /// `only-if-cached`: do not go to the network.
    pub only_if_cached: bool,
    /// `max-age`: refuse a stored response older than this many seconds.
    pub max_age: Option<i64>,
    /// `max-stale`: accept a response this many seconds past its freshness, or any amount when
    /// the directive carried no value.
    pub max_stale: Option<Option<i64>>,
    /// `min-fresh`: only accept a response that stays fresh for this many more seconds.
    pub min_fresh: Option<i64>,
}

impl RequestDirectives {
    /// Parse the `Cache-Control` field lines of a request.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut out = Self::default();
        for (name, value) in directives(headers) {
            match name.as_str() {
                "no-store" => out.no_store = true,
                "no-cache" => out.no_cache = true,
                "only-if-cached" => out.only_if_cached = true,
                "max-age" => out.max_age = value.and_then(|v| v.parse().ok()),
                "max-stale" => out.max_stale = Some(value.and_then(|v| v.parse().ok())),
                "min-fresh" => out.min_fresh = value.and_then(|v| v.parse().ok()),
                _ => {}
            }
        }
        out
    }
}

/// `(name, value)` for every `Cache-Control` directive across all field lines, names lowercased
/// and values unquoted.
fn directives(headers: &HeaderMap) -> Vec<(String, Option<String>)> {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(split_outside_quotes)
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            Some(match part.split_once('=') {
                Some((name, value)) => (
                    name.trim().to_ascii_lowercase(),
                    Some(value.trim().trim_matches('"').to_string()),
                ),
                None => (part.to_ascii_lowercase(), None),
            })
        })
        .collect()
}

/// Whether a response to this request may be stored (RFC 9111 §3).
///
/// Shared-cache rules do not apply: a response to a request carrying `Authorization` is storable
/// here, and `s-maxage` is ignored, because this cache serves one client.
pub fn is_storable(
    method: &Method,
    request: &HeaderMap,
    status: u16,
    response: &HeaderMap,
) -> bool {
    if *method != Method::GET && *method != Method::HEAD {
        return false;
    }
    if RequestDirectives::parse(request).no_store || bypasses_cache(request) {
        return false;
    }
    let directives = ResponseDirectives::parse(response);
    if directives.no_store {
        return false;
    }
    // `Vary: *` says the response depends on something the request headers do not capture, so no
    // stored entry can ever be shown to match.
    if vary_names(response).iter().any(|n| n == "*") {
        return false;
    }
    // Partial content needs range support, which this cache does not have.
    if status == 206 || response.contains_key(header::CONTENT_RANGE) {
        return false;
    }

    let has_freshness = directives.max_age.is_some() || response.contains_key(header::EXPIRES);
    let has_validator =
        response.contains_key(header::ETAG) || response.contains_key(header::LAST_MODIFIED);
    if !has_freshness && !has_validator {
        // Nothing to decide freshness by and nothing to revalidate with, so the entry could
        // never be used and storing it would only cost memory.
        return false;
    }
    // A status the caching rules do not cover is only storable when the response says so itself.
    DEFAULT_CACHEABLE.contains(&status) || has_freshness
}

/// Build the entry to store for a response.
///
/// `decoded` says whether `body` is the unpacked form of a `Content-Encoding` the HTTP client
/// removed; the encoding headers are then dropped, since they no longer describe the bytes.
pub fn entry_from_response(
    status: u16,
    response: &HeaderMap,
    request: &HeaderMap,
    body: Bytes,
    decoded: bool,
    requested_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
) -> CacheEntry {
    let mut headers = response.clone();
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    // A cache hit must not re-apply a cookie the jar has long since stored or dropped.
    headers.remove(header::SET_COOKIE);
    if decoded {
        headers.remove(header::CONTENT_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
    }

    let vary = vary_names(response)
        .into_iter()
        .filter_map(|name| {
            let header_name = HeaderName::try_from(name.as_str()).ok()?;
            let value = request
                .get(&header_name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            Some((name, value))
        })
        .collect();

    CacheEntry {
        status,
        headers,
        body,
        vary,
        decoded,
        requested_at,
        received_at,
    }
}

/// The header names a response's `Vary` lists, lowercased.
fn vary_names(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect()
}

/// Decide what a hop does with what is stored for it.
///
/// `entries` are the variants stored under the hop's key, `request` the headers the hop is about
/// to send, and `decoded` its auto-decode setting.
pub fn decide(
    entries: &[Arc<CacheEntry>],
    request: &HeaderMap,
    decoded: bool,
    mode: CacheMode,
    now: DateTime<Utc>,
) -> CacheDecision {
    let asked = RequestDirectives::parse(request);
    // A reload asks for the network itself, and `no-store` means this exchange leaves no trace.
    // A range or conditional request is one only the server can answer, whatever the cache mode
    // says.
    if mode == CacheMode::NoStore
        || mode == CacheMode::Reload
        || asked.no_store
        || bypasses_cache(request)
    {
        return CacheDecision::Send;
    }

    let only_if_cached = mode == CacheMode::OnlyIfCached || asked.only_if_cached;
    let Some(entry) = entries.iter().find(|e| e.matches(request, decoded)) else {
        return if only_if_cached {
            CacheDecision::NotCached
        } else {
            CacheDecision::Send
        };
    };

    let stored = ResponseDirectives::parse(&entry.headers);
    let revalidate = |entry: &Arc<CacheEntry>| {
        let conditional = entry.conditional_headers();
        if conditional.is_empty() {
            CacheDecision::Send
        } else {
            CacheDecision::Revalidate(entry.clone(), conditional)
        }
    };

    // A stale entry may be served when the caller says so, unless the response forbade it.
    if mode == CacheMode::ForceCache || only_if_cached {
        if stored.no_cache || (stored.must_revalidate && !entry.is_fresh(now)) {
            return match (only_if_cached, revalidate(entry)) {
                (true, _) => CacheDecision::NotCached,
                (false, decision) => decision,
            };
        }
        return CacheDecision::Use(entry.clone());
    }

    // A forced revalidation still honours `immutable`, which says the response does not change
    // while it is fresh.
    if mode == CacheMode::NoCache || asked.no_cache || stored.no_cache {
        if stored.immutable && entry.is_fresh(now) {
            return CacheDecision::Use(entry.clone());
        }
        return revalidate(entry);
    }

    let age = entry.current_age(now);
    let lifetime = entry.freshness_lifetime().unwrap_or_else(TimeDelta::zero);
    let mut usable = age < lifetime;

    if let Some(max_age) = asked.max_age {
        usable &= age <= TimeDelta::seconds(max_age);
    }
    if let Some(min_fresh) = asked.min_fresh {
        usable &= lifetime - age >= TimeDelta::seconds(min_fresh);
    }
    if !usable && !stored.must_revalidate {
        if let Some(max_stale) = asked.max_stale {
            let staleness = age - lifetime;
            usable = match max_stale {
                Some(limit) => staleness <= TimeDelta::seconds(limit),
                // `max-stale` without a value accepts any staleness.
                None => true,
            };
        }
    }

    if usable {
        CacheDecision::Use(entry.clone())
    } else {
        revalidate(entry)
    }
}

/// Whether the request asks for something a whole stored response cannot answer: a byte range,
/// or a condition of the caller's own.
///
/// Such a request bypasses the cache in both directions. Answering a `Range` request with a
/// complete stored body, or a caller's `If-None-Match` with a `200` the cache decided on, would
/// both give the caller something other than what it asked the server for.
pub fn bypasses_cache(request: &HeaderMap) -> bool {
    [
        header::RANGE,
        header::IF_RANGE,
        header::IF_NONE_MATCH,
        header::IF_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_UNMODIFIED_SINCE,
    ]
    .iter()
    .any(|name| request.contains_key(name))
}

/// Whether a method invalidates what is stored for its target (RFC 9111 §4.4).
pub fn invalidates(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Parse an HTTP-date (RFC 9110 §5.6.7). Accepts the preferred IMF-fixdate as well as the two
/// obsolete formats servers still emit.
pub fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    for format in [
        // Sun, 06 Nov 1994 08:49:37 GMT
        "%a, %d %b %Y %H:%M:%S GMT",
        // Sunday, 06-Nov-94 08:49:37 GMT
        "%A, %d-%b-%y %H:%M:%S GMT",
        // Sun Nov  6 08:49:37 1994
        "%a %b %e %H:%M:%S %Y",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc());
        }
    }
    None
}

/// A header's value as an HTTP-date, or `None` when absent or unparsable.
fn header_date(headers: &HeaderMap, name: HeaderName) -> Option<DateTime<Utc>> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date)
}

/// Where stored responses live.
///
/// The default [`InMemoryHttpCache`] keeps them in memory for the lifetime of the fetcher.
/// Implement this to persist them, share them between fetchers, or bound them differently. All
/// methods are called on the request path, so none of them may block for long.
///
/// Entries under one key are variants of the same resource, told apart by the request headers the
/// response listed in `Vary`; see [`CacheEntry::matches`].
pub trait HttpCache: Send + Sync {
    /// Every variant stored for `key`, in no particular order. Usually zero or one.
    fn get(&self, key: &CacheKey) -> Vec<Arc<CacheEntry>>;
    /// Store `entry`, replacing the variant selected by the same request headers.
    fn put(&self, key: CacheKey, entry: Arc<CacheEntry>);
    /// Drop every variant stored for `key`.
    fn invalidate(&self, key: &CacheKey);
    /// Drop everything.
    fn clear(&self);
    /// Largest body worth handing to [`put`](Self::put). A response whose length is known to
    /// exceed this is never buffered for the cache, and one that turns out to exceed it while
    /// streaming is dropped rather than stored.
    fn max_entry_bytes(&self) -> usize {
        2 * 1024 * 1024
    }
}

/// Default byte budget of an [`InMemoryHttpCache`].
const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Default per-entry ceiling of an [`InMemoryHttpCache`].
const DEFAULT_MAX_ENTRY_BYTES: usize = 2 * 1024 * 1024;

/// One stored variant, plus when it was last touched.
struct Stored {
    entry: Arc<CacheEntry>,
    last_used: u64,
}

/// Contents of an [`InMemoryHttpCache`], behind one lock.
#[derive(Default)]
struct Contents {
    variants: HashMap<CacheKey, Vec<Stored>>,
    bytes: usize,
    clock: u64,
}

/// [`HttpCache`] holding entries in memory, bounded by a byte budget.
///
/// When a `put` pushes the total over the budget, the least recently used entries are dropped
/// until it fits. Nothing is persisted: a new fetcher starts with an empty cache.
pub struct InMemoryHttpCache {
    contents: parking_lot::Mutex<Contents>,
    max_bytes: usize,
    max_entry_bytes: usize,
}

impl Default for InMemoryHttpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryHttpCache {
    /// Cache with the default limits: 16 MiB in total, 2 MiB per entry.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES)
    }

    /// Cache with an explicit total budget and per-entry ceiling.
    pub fn with_limits(max_bytes: usize, max_entry_bytes: usize) -> Self {
        Self {
            contents: parking_lot::Mutex::new(Contents::default()),
            max_bytes,
            max_entry_bytes,
        }
    }

    /// Number of stored variants.
    pub fn len(&self) -> usize {
        self.contents.lock().variants.values().map(Vec::len).sum()
    }

    /// True when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes currently held.
    pub fn byte_len(&self) -> usize {
        self.contents.lock().bytes
    }

    /// Drop the least recently used variants until the total is within budget.
    fn evict(contents: &mut Contents, max_bytes: usize) {
        while contents.bytes > max_bytes {
            let oldest = contents
                .variants
                .iter()
                .flat_map(|(key, stored)| {
                    stored
                        .iter()
                        .enumerate()
                        .map(move |(index, s)| (s.last_used, key.clone(), index))
                })
                .min_by_key(|(last_used, _, _)| *last_used);
            let Some((_, key, index)) = oldest else {
                // Nothing left to drop; the budget is smaller than a single entry.
                contents.bytes = 0;
                return;
            };
            if let Some(stored) = contents.variants.get_mut(&key) {
                let dropped = stored.remove(index);
                contents.bytes = contents.bytes.saturating_sub(dropped.entry.size());
                if stored.is_empty() {
                    contents.variants.remove(&key);
                }
            }
        }
    }
}

impl HttpCache for InMemoryHttpCache {
    fn get(&self, key: &CacheKey) -> Vec<Arc<CacheEntry>> {
        let mut contents = self.contents.lock();
        contents.clock += 1;
        let clock = contents.clock;
        match contents.variants.get_mut(key) {
            Some(stored) => stored
                .iter_mut()
                .map(|s| {
                    s.last_used = clock;
                    s.entry.clone()
                })
                .collect(),
            None => Vec::new(),
        }
    }

    fn put(&self, key: CacheKey, entry: Arc<CacheEntry>) {
        let size = entry.size();
        if size > self.max_entry_bytes {
            return;
        }
        let mut contents = self.contents.lock();
        contents.clock += 1;
        let clock = contents.clock;
        let stored = contents.variants.entry(key).or_default();
        // One variant per set of selecting request headers, so a new response for the same
        // headers replaces the old one instead of being stored beside it.
        let replaced = stored
            .iter()
            .position(|s| s.entry.vary == entry.vary && s.entry.decoded == entry.decoded);
        let freed = match replaced {
            Some(index) => {
                let old = std::mem::replace(
                    &mut stored[index],
                    Stored {
                        entry,
                        last_used: clock,
                    },
                );
                old.entry.size()
            }
            None => {
                stored.push(Stored {
                    entry,
                    last_used: clock,
                });
                0
            }
        };
        contents.bytes = contents.bytes.saturating_sub(freed) + size;
        Self::evict(&mut contents, self.max_bytes);
    }

    fn invalidate(&self, key: &CacheKey) {
        let mut contents = self.contents.lock();
        if let Some(stored) = contents.variants.remove(key) {
            let freed: usize = stored.iter().map(|s| s.entry.size()).sum();
            contents.bytes = contents.bytes.saturating_sub(freed);
        }
    }

    fn clear(&self) {
        let mut contents = self.contents.lock();
        contents.variants.clear();
        contents.bytes = 0;
    }

    fn max_entry_bytes(&self) -> usize {
        self.max_entry_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use http::HeaderValue;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn http_date(time: DateTime<Utc>) -> String {
        time.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut out = HeaderMap::new();
        for (name, value) in pairs {
            out.append(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        out
    }

    /// An entry stored at `at(0)` with the given response headers.
    fn entry(response: &[(&str, &str)]) -> Arc<CacheEntry> {
        entry_with_request(response, &[])
    }

    fn entry_with_request(response: &[(&str, &str)], request: &[(&str, &str)]) -> Arc<CacheEntry> {
        Arc::new(entry_from_response(
            200,
            &headers(response),
            &headers(request),
            Bytes::from_static(b"body"),
            false,
            at(0),
            at(0),
        ))
    }

    fn key() -> CacheKey {
        CacheKey::new(&Method::GET, &Url::parse("https://example.com/a").unwrap())
    }

    #[test]
    fn max_age_decides_freshness() {
        let stored = entry(&[("cache-control", "max-age=60")]);
        assert_eq!(stored.freshness_lifetime(), Some(TimeDelta::seconds(60)));
        assert!(stored.is_fresh(at(59)));
        assert!(!stored.is_fresh(at(61)));
    }

    #[test]
    fn expires_minus_date_decides_freshness_without_max_age() {
        let stored = entry(&[
            ("date", &http_date(at(0))),
            ("expires", &http_date(at(120))),
        ]);
        assert_eq!(stored.freshness_lifetime(), Some(TimeDelta::seconds(120)));
        assert!(stored.is_fresh(at(119)));
        assert!(!stored.is_fresh(at(121)));
    }

    #[test]
    fn max_age_wins_over_expires() {
        let stored = entry(&[
            ("cache-control", "max-age=10"),
            ("date", &http_date(at(0))),
            ("expires", &http_date(at(9999))),
        ]);
        assert_eq!(stored.freshness_lifetime(), Some(TimeDelta::seconds(10)));
    }

    #[test]
    fn an_unparsable_expires_means_already_stale() {
        // `Expires: 0` is the common way to say "do not use this without asking".
        let stored = entry(&[("date", &http_date(at(0))), ("expires", "0")]);
        assert_eq!(stored.freshness_lifetime(), Some(TimeDelta::zero()));
        assert!(!stored.is_fresh(at(0)));
    }

    #[test]
    fn heuristic_freshness_is_a_tenth_of_the_age_at_receipt() {
        // Last modified 1000s before the response was generated: 100s of heuristic freshness.
        let stored = entry(&[
            ("date", &http_date(at(0))),
            ("last-modified", &http_date(at(-1000))),
        ]);
        assert_eq!(stored.freshness_lifetime(), Some(TimeDelta::seconds(100)));
        assert!(stored.is_fresh(at(99)));
        assert!(!stored.is_fresh(at(101)));
    }

    #[test]
    fn heuristic_freshness_is_capped_at_a_day() {
        let stored = entry(&[
            ("date", &http_date(at(0))),
            ("last-modified", &http_date(at(-100 * HEURISTIC_MAX_SECS))),
        ]);
        assert_eq!(
            stored.freshness_lifetime(),
            Some(TimeDelta::seconds(HEURISTIC_MAX_SECS))
        );
    }

    #[test]
    fn a_response_with_nothing_to_go_on_is_never_fresh() {
        let stored = entry(&[("content-type", "text/plain")]);
        assert_eq!(stored.freshness_lifetime(), None);
        assert!(!stored.is_fresh(at(0)));
    }

    /// RFC 9111 §4.2.3: the response was already 30s old at the proxy, and the request took 4s.
    #[test]
    fn current_age_counts_the_age_header_and_the_request_delay() {
        let mut stored = (*entry(&[("age", "30"), ("date", &http_date(at(0)))])).clone();
        stored.requested_at = at(0);
        stored.received_at = at(4);

        // corrected initial age = max(apparent 4s, age 30s + delay 4s) = 34s, plus residence.
        assert_eq!(stored.current_age(at(4)), TimeDelta::seconds(34));
        assert_eq!(stored.current_age(at(14)), TimeDelta::seconds(44));
    }

    #[test]
    fn a_clock_skewed_date_cannot_make_a_response_younger_than_it_is() {
        // Date in the future: apparent age is clamped to zero rather than going negative.
        let mut stored = (*entry(&[("date", &http_date(at(500)))])).clone();
        stored.requested_at = at(0);
        stored.received_at = at(0);
        assert_eq!(stored.current_age(at(10)), TimeDelta::seconds(10));
    }

    #[test]
    fn a_fresh_entry_is_used_without_a_request() {
        let stored = [entry(&[("cache-control", "max-age=60")])];
        let decision = decide(
            &stored,
            &HeaderMap::new(),
            false,
            CacheMode::Default,
            at(30),
        );
        assert!(matches!(decision, CacheDecision::Use(_)), "{decision:?}");
    }

    #[test]
    fn a_stale_entry_with_a_validator_is_revalidated() {
        let stored = [entry(&[
            ("cache-control", "max-age=10"),
            ("etag", "\"v1\""),
        ])];
        match decide(
            &stored,
            &HeaderMap::new(),
            false,
            CacheMode::Default,
            at(30),
        ) {
            CacheDecision::Revalidate(_, conditional) => {
                assert_eq!(conditional.get(header::IF_NONE_MATCH).unwrap(), "\"v1\"");
                assert!(!conditional.contains_key(header::IF_MODIFIED_SINCE));
            }
            other => panic!("expected Revalidate, got {other:?}"),
        }
    }

    #[test]
    fn a_stale_entry_without_a_validator_is_refetched() {
        let stored = [entry(&[("cache-control", "max-age=10")])];
        let decision = decide(
            &stored,
            &HeaderMap::new(),
            false,
            CacheMode::Default,
            at(30),
        );
        assert!(matches!(decision, CacheDecision::Send), "{decision:?}");
    }

    #[test]
    fn last_modified_becomes_if_modified_since() {
        let stored = entry(&[("last-modified", &http_date(at(-1000)))]);
        let conditional = stored.conditional_headers();
        assert_eq!(
            conditional.get(header::IF_MODIFIED_SINCE).unwrap(),
            http_date(at(-1000)).as_str()
        );
    }

    #[test]
    fn no_cache_on_the_response_always_revalidates_even_while_fresh() {
        let stored = [entry(&[
            ("cache-control", "no-cache, max-age=600"),
            ("etag", "\"v1\""),
        ])];
        let decision = decide(&stored, &HeaderMap::new(), false, CacheMode::Default, at(1));
        assert!(
            matches!(decision, CacheDecision::Revalidate(..)),
            "{decision:?}"
        );
    }

    #[test]
    fn request_directives_are_honoured() {
        let fresh = [entry(&[
            ("cache-control", "max-age=600"),
            ("etag", "\"v1\""),
        ])];
        let mode = CacheMode::Default;

        // no-cache: revalidate despite being fresh.
        let asked = headers(&[("cache-control", "no-cache")]);
        assert!(matches!(
            decide(&fresh, &asked, false, mode, at(1)),
            CacheDecision::Revalidate(..)
        ));

        // max-age=0: the stored copy is too old for this caller.
        let asked = headers(&[("cache-control", "max-age=0")]);
        assert!(matches!(
            decide(&fresh, &asked, false, mode, at(30)),
            CacheDecision::Revalidate(..)
        ));

        // min-fresh: must stay fresh for another 300s, and it does.
        let asked = headers(&[("cache-control", "min-fresh=300")]);
        assert!(matches!(
            decide(&fresh, &asked, false, mode, at(30)),
            CacheDecision::Use(_)
        ));
        let asked = headers(&[("cache-control", "min-fresh=590")]);
        assert!(matches!(
            decide(&fresh, &asked, false, mode, at(30)),
            CacheDecision::Revalidate(..)
        ));

        // no-store on the request keeps the exchange off the cache entirely.
        let asked = headers(&[("cache-control", "no-store")]);
        assert!(matches!(
            decide(&fresh, &asked, false, mode, at(1)),
            CacheDecision::Send
        ));
    }

    #[test]
    fn max_stale_accepts_a_stale_entry_unless_the_response_forbids_it() {
        let stale = [entry(&[
            ("cache-control", "max-age=10"),
            ("etag", "\"v1\""),
        ])];
        let asked = headers(&[("cache-control", "max-stale=60")]);
        assert!(matches!(
            decide(&stale, &asked, false, CacheMode::Default, at(40)),
            CacheDecision::Use(_)
        ));
        // 70s past a 10s lifetime is more staleness than was allowed.
        assert!(matches!(
            decide(&stale, &asked, false, CacheMode::Default, at(80)),
            CacheDecision::Revalidate(..)
        ));
        // A bare max-stale accepts any amount.
        let asked = headers(&[("cache-control", "max-stale")]);
        assert!(matches!(
            decide(&stale, &asked, false, CacheMode::Default, at(9999)),
            CacheDecision::Use(_)
        ));

        let must = [entry(&[
            ("cache-control", "max-age=10, must-revalidate"),
            ("etag", "\"v1\""),
        ])];
        let asked = headers(&[("cache-control", "max-stale=60")]);
        assert!(matches!(
            decide(&must, &asked, false, CacheMode::Default, at(40)),
            CacheDecision::Revalidate(..)
        ));
    }

    #[test]
    fn cache_modes_pick_their_own_behaviour() {
        let fresh = [entry(&[
            ("cache-control", "max-age=600"),
            ("etag", "\"v1\""),
        ])];
        let stale = [entry(&[("cache-control", "max-age=1"), ("etag", "\"v1\"")])];
        let now = at(30);

        // Reload and no-store never look at what is stored.
        assert!(matches!(
            decide(&fresh, &HeaderMap::new(), false, CacheMode::Reload, now),
            CacheDecision::Send
        ));
        assert!(matches!(
            decide(&fresh, &HeaderMap::new(), false, CacheMode::NoStore, now),
            CacheDecision::Send
        ));

        // no-cache revalidates a fresh entry.
        assert!(matches!(
            decide(&fresh, &HeaderMap::new(), false, CacheMode::NoCache, now),
            CacheDecision::Revalidate(..)
        ));

        // force-cache and only-if-cached use a stale entry as it is.
        assert!(matches!(
            decide(&stale, &HeaderMap::new(), false, CacheMode::ForceCache, now),
            CacheDecision::Use(_)
        ));
        assert!(matches!(
            decide(
                &stale,
                &HeaderMap::new(),
                false,
                CacheMode::OnlyIfCached,
                now
            ),
            CacheDecision::Use(_)
        ));

        // With nothing stored, only-if-cached fails rather than reaching the network.
        assert!(matches!(
            decide(&[], &HeaderMap::new(), false, CacheMode::OnlyIfCached, now),
            CacheDecision::NotCached
        ));
        assert!(matches!(
            decide(&[], &HeaderMap::new(), false, CacheMode::ForceCache, now),
            CacheDecision::Send
        ));
    }

    #[test]
    fn immutable_survives_a_forced_revalidation_while_fresh() {
        let stored = [entry(&[
            ("cache-control", "max-age=600, immutable"),
            ("etag", "\"v1\""),
        ])];
        assert!(matches!(
            decide(
                &stored,
                &HeaderMap::new(),
                false,
                CacheMode::NoCache,
                at(30)
            ),
            CacheDecision::Use(_)
        ));
        // Once stale, even immutable is revalidated.
        assert!(matches!(
            decide(
                &stored,
                &HeaderMap::new(),
                false,
                CacheMode::NoCache,
                at(9999)
            ),
            CacheDecision::Revalidate(..)
        ));
    }

    #[test]
    fn vary_selects_between_variants() {
        let gzip = entry_with_request(
            &[("cache-control", "max-age=60"), ("vary", "accept-encoding")],
            &[("accept-encoding", "gzip")],
        );
        let plain = entry_with_request(
            &[("cache-control", "max-age=60"), ("vary", "accept-encoding")],
            &[("accept-encoding", "identity")],
        );
        assert_eq!(
            gzip.vary,
            vec![("accept-encoding".to_string(), Some("gzip".to_string()))]
        );

        let stored = [gzip.clone(), plain.clone()];
        let asked = headers(&[("accept-encoding", "identity")]);
        match decide(&stored, &asked, false, CacheMode::Default, at(1)) {
            CacheDecision::Use(used) => assert_eq!(used.vary, plain.vary),
            other => panic!("expected Use, got {other:?}"),
        }

        // A request the stored variants do not cover goes to the network.
        let asked = headers(&[("accept-encoding", "br")]);
        assert!(matches!(
            decide(&stored, &asked, false, CacheMode::Default, at(1)),
            CacheDecision::Send
        ));
    }

    #[test]
    fn a_varied_header_that_is_absent_must_stay_absent() {
        let stored = [entry_with_request(
            &[("cache-control", "max-age=60"), ("vary", "accept-language")],
            &[],
        )];
        assert!(matches!(
            decide(&stored, &HeaderMap::new(), false, CacheMode::Default, at(1)),
            CacheDecision::Use(_)
        ));
        let asked = headers(&[("accept-language", "nl")]);
        assert!(matches!(
            decide(&stored, &asked, false, CacheMode::Default, at(1)),
            CacheDecision::Send
        ));
    }

    #[test]
    fn a_decoded_body_does_not_answer_a_raw_request() {
        let mut decoded = (*entry(&[("cache-control", "max-age=60")])).clone();
        decoded.decoded = true;
        let stored = [Arc::new(decoded)];
        assert!(matches!(
            decide(&stored, &HeaderMap::new(), true, CacheMode::Default, at(1)),
            CacheDecision::Use(_)
        ));
        assert!(matches!(
            decide(&stored, &HeaderMap::new(), false, CacheMode::Default, at(1)),
            CacheDecision::Send
        ));
    }

    #[test]
    fn storability_follows_the_directives() {
        let ok = headers(&[("cache-control", "max-age=60")]);
        assert!(is_storable(&Method::GET, &HeaderMap::new(), 200, &ok));
        assert!(is_storable(&Method::HEAD, &HeaderMap::new(), 200, &ok));
        // Only safe methods with a stable identity are stored.
        assert!(!is_storable(&Method::POST, &HeaderMap::new(), 200, &ok));

        // no-store, on either side.
        let no_store = headers(&[("cache-control", "no-store")]);
        assert!(!is_storable(
            &Method::GET,
            &HeaderMap::new(),
            200,
            &no_store
        ));
        assert!(!is_storable(&Method::GET, &no_store, 200, &ok));

        // Vary: * can never be matched, so it is never stored.
        let vary_star = headers(&[("cache-control", "max-age=60"), ("vary", "*")]);
        assert!(!is_storable(
            &Method::GET,
            &HeaderMap::new(),
            200,
            &vary_star
        ));

        // Partial content needs range support.
        assert!(!is_storable(&Method::GET, &HeaderMap::new(), 206, &ok));

        // Nothing to judge freshness by and nothing to revalidate with.
        let bare = headers(&[("content-type", "text/plain")]);
        assert!(!is_storable(&Method::GET, &HeaderMap::new(), 200, &bare));
        let validator = headers(&[("etag", "\"v1\"")]);
        assert!(is_storable(
            &Method::GET,
            &HeaderMap::new(),
            200,
            &validator
        ));

        // A redirect is cacheable by default; a 500 only when it says so itself.
        assert!(is_storable(
            &Method::GET,
            &HeaderMap::new(),
            301,
            &validator
        ));
        assert!(!is_storable(
            &Method::GET,
            &HeaderMap::new(),
            500,
            &validator
        ));
        assert!(is_storable(&Method::GET, &HeaderMap::new(), 500, &ok));

        // A private cache stores what a shared one may not.
        let private = headers(&[("cache-control", "private, max-age=60")]);
        let with_auth = headers(&[("authorization", "Basic dTpw")]);
        assert!(is_storable(&Method::GET, &with_auth, 200, &private));
    }

    #[test]
    fn stored_responses_drop_cookies_and_connection_headers() {
        let stored = entry_from_response(
            200,
            &headers(&[
                ("cache-control", "max-age=60"),
                ("set-cookie", "session=abc"),
                ("connection", "keep-alive"),
                ("transfer-encoding", "chunked"),
                ("content-type", "text/html"),
            ]),
            &HeaderMap::new(),
            Bytes::from_static(b"hi"),
            false,
            at(0),
            at(0),
        );
        assert!(!stored.headers.contains_key(header::SET_COOKIE));
        assert!(!stored.headers.contains_key(header::CONNECTION));
        assert!(!stored.headers.contains_key(header::TRANSFER_ENCODING));
        assert_eq!(
            stored.headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html"
        );
    }

    #[test]
    fn a_decoded_body_is_stored_without_its_encoding_headers() {
        let stored = entry_from_response(
            200,
            &headers(&[
                ("cache-control", "max-age=60"),
                ("content-encoding", "gzip"),
                ("content-length", "20"),
            ]),
            &HeaderMap::new(),
            Bytes::from_static(b"decoded bytes"),
            true,
            at(0),
            at(0),
        );
        assert!(!stored.headers.contains_key(header::CONTENT_ENCODING));
        assert!(!stored.headers.contains_key(header::CONTENT_LENGTH));
        assert!(stored.decoded);
    }

    #[test]
    fn a_304_updates_the_headers_and_restarts_the_age() {
        let stored = entry(&[
            ("cache-control", "max-age=10"),
            ("etag", "\"v1\""),
            ("content-type", "text/html"),
            ("content-length", "4"),
        ]);
        let updated = stored.updated_by_304(
            &headers(&[
                ("cache-control", "max-age=600"),
                ("etag", "\"v2\""),
                ("content-length", "99999"),
            ]),
            at(100),
            at(100),
        );

        assert_eq!(&updated.body[..], b"body", "the stored body is reused");
        assert_eq!(updated.headers.get(header::ETAG).unwrap(), "\"v2\"");
        assert_eq!(updated.freshness_lifetime(), Some(TimeDelta::seconds(600)));
        // Not overwritten by the 304, which carried no body.
        assert_eq!(updated.headers.get(header::CONTENT_LENGTH).unwrap(), "4");
        // Headers the 304 did not mention survive.
        assert_eq!(
            updated.headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html"
        );
        // The age clock restarts, so the entry is fresh again.
        assert!(updated.is_fresh(at(150)));
    }

    #[test]
    fn a_range_or_conditional_request_goes_past_the_cache() {
        let fresh = [entry(&[("cache-control", "max-age=600")])];
        for header in [
            ("range", "bytes=0-99"),
            ("if-none-match", "\"caller\""),
            ("if-modified-since", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("if-match", "\"caller\""),
        ] {
            let asked = headers(&[header]);
            assert!(
                matches!(
                    decide(&fresh, &asked, false, CacheMode::Default, at(1)),
                    CacheDecision::Send
                ),
                "{} should bypass the cache",
                header.0
            );
            assert!(
                !is_storable(
                    &Method::GET,
                    &asked,
                    200,
                    &headers(&[("cache-control", "max-age=60")])
                ),
                "{} should not be stored",
                header.0
            );
        }
    }

    #[test]
    fn unsafe_methods_invalidate() {
        assert!(!invalidates(&Method::GET));
        assert!(!invalidates(&Method::HEAD));
        assert!(!invalidates(&Method::OPTIONS));
        assert!(invalidates(&Method::POST));
        assert!(invalidates(&Method::PUT));
        assert!(invalidates(&Method::DELETE));
        assert!(invalidates(&Method::PATCH));
    }

    #[test]
    fn http_dates_parse_in_all_three_formats() {
        let expected = Utc.with_ymd_and_hms(1994, 11, 6, 8, 49, 37).unwrap();
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(expected)
        );
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(expected));
        assert_eq!(parse_http_date("0"), None);
        assert_eq!(parse_http_date("not a date"), None);
    }

    #[test]
    fn cache_control_parsing_covers_the_shapes_servers_send() {
        let parsed = ResponseDirectives::parse(&headers(&[(
            "cache-control",
            "public, max-age=3600, must-revalidate, no-cache=\"set-cookie, x-thing\"",
        )]));
        assert!(parsed.public);
        assert_eq!(parsed.max_age, Some(3600));
        assert!(parsed.must_revalidate);
        // A qualified no-cache still means "revalidate" here: the field list is not honoured.
        assert!(parsed.no_cache);
        assert!(!parsed.no_store);

        // Directives split across field lines, and mixed case.
        let parsed = ResponseDirectives::parse(&headers(&[
            ("cache-control", "No-Store"),
            ("cache-control", "max-age=5"),
        ]));
        assert!(parsed.no_store);
        assert_eq!(parsed.max_age, Some(5));

        let asked = RequestDirectives::parse(&headers(&[(
            "cache-control",
            "no-cache, max-stale, min-fresh=30, only-if-cached",
        )]));
        assert!(asked.no_cache);
        assert_eq!(asked.max_stale, Some(None));
        assert_eq!(asked.min_fresh, Some(30));
        assert!(asked.only_if_cached);
    }

    #[test]
    fn the_key_ignores_the_fragment() {
        let a = CacheKey::new(
            &Method::GET,
            &Url::parse("https://example.com/a#one").unwrap(),
        );
        let b = CacheKey::new(
            &Method::GET,
            &Url::parse("https://example.com/a#two").unwrap(),
        );
        assert_eq!(a, b);
        let head = CacheKey::new(&Method::HEAD, &Url::parse("https://example.com/a").unwrap());
        assert_ne!(a, head);
    }

    #[test]
    fn the_in_memory_cache_stores_replaces_and_invalidates() {
        let cache = InMemoryHttpCache::new();
        assert!(cache.is_empty());
        assert!(cache.get(&key()).is_empty());

        cache.put(key(), entry(&[("cache-control", "max-age=60")]));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&key()).len(), 1);

        // Same selecting headers: replaced, not appended.
        cache.put(key(), entry(&[("cache-control", "max-age=120")]));
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get(&key())[0].freshness_lifetime(),
            Some(TimeDelta::seconds(120))
        );

        // A different variant of the same URL lives beside it.
        cache.put(
            key(),
            entry_with_request(
                &[("cache-control", "max-age=60"), ("vary", "accept-language")],
                &[("accept-language", "nl")],
            ),
        );
        assert_eq!(cache.get(&key()).len(), 2);

        cache.invalidate(&key());
        assert!(cache.get(&key()).is_empty());
        assert!(cache.is_empty());
    }

    #[test]
    fn the_in_memory_cache_evicts_the_least_recently_used_entry() {
        let one = entry(&[("cache-control", "max-age=60")]);
        // Budget for two entries and a bit.
        let cache = InMemoryHttpCache::with_limits(one.size() * 2 + 8, 1024);

        let keys: Vec<CacheKey> = ["a", "b", "c"]
            .iter()
            .map(|p| {
                CacheKey::new(
                    &Method::GET,
                    &Url::parse(&format!("https://example.com/{p}")).unwrap(),
                )
            })
            .collect();

        cache.put(keys[0].clone(), one.clone());
        cache.put(keys[1].clone(), one.clone());
        assert_eq!(cache.len(), 2);

        // Touch the first so the second becomes the oldest.
        let _ = cache.get(&keys[0]);
        cache.put(keys[2].clone(), one.clone());

        assert_eq!(cache.len(), 2);
        assert!(!cache.get(&keys[0]).is_empty(), "recently used, kept");
        assert!(
            cache.get(&keys[1]).is_empty(),
            "least recently used, dropped"
        );
        assert!(!cache.get(&keys[2]).is_empty());
        assert!(cache.byte_len() <= one.size() * 2 + 8);
    }

    #[test]
    fn an_entry_over_the_per_entry_ceiling_is_not_stored() {
        let cache = InMemoryHttpCache::with_limits(1024 * 1024, 8);
        cache.put(key(), entry(&[("cache-control", "max-age=60")]));
        assert!(cache.is_empty());
        assert_eq!(cache.byte_len(), 0);
    }

    #[test]
    fn clear_empties_the_cache() {
        let cache = InMemoryHttpCache::new();
        cache.put(key(), entry(&[("cache-control", "max-age=60")]));
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.byte_len(), 0);
    }
}

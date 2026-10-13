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
//!   `only-if-cached` (§5.2.1), and `Pragma: no-cache` from a request without `Cache-Control`
//!   (§5.4)
//! - conditional revalidation of a stale entry with `If-None-Match` / `If-Modified-Since`, and a
//!   `304` that updates the stored headers and reuses the stored body (§4.3)
//! - `Vary`: one entry per combination of the request headers the response varies on (§4.1)
//! - invalidation of the target URI (and a same-origin `Location`/`Content-Location`) by an
//!   unsafe method (§4.4)
//! - `stale-while-revalidate` (RFC 5861 §3): a stale response it covers answers a request with
//!   a client (one with an origin) in the default mode at once, on the request's first hop, and
//!   is revalidated in the background ([`CacheDecision::UseStale`], [`CacheOutcome::Stale`]).
//!   The [`Fetcher`] does that with a request of its own; see
//!   [`NetPolicy::revalidate_in_background`].
//!
//! Not implemented: shared-cache rules (`s-maxage`, the `Authorization` restriction of §3.5, since
//! this is a private cache), and range requests and `206` responses. A request that carries a
//! `Range` or a condition of its own goes past the cache in both directions, since only the
//! server can answer it.
//!
//! `Set-Cookie` is stripped before a response is stored, so that a cache hit cannot re-apply a
//! cookie the jar already has, and so are the hop-by-hop headers, which describe the connection
//! rather than the response.
//!
//! [`FetcherConfig::cache`]: crate::net::fetcher::FetcherConfig::cache
//! [`Fetcher`]: crate::net::fetcher::Fetcher
//! [`NetPolicy::revalidate_in_background`]: crate::net::fetch::NetPolicy::revalidate_in_background
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

/// Statuses whose caching rules this cache implements, for `must-understand` (RFC 9111
/// §5.2.2.3): the heuristically cacheable ones, and the redirects it follows and stores.
const UNDERSTOOD: &[u16] = &[
    200, 203, 204, 300, 301, 302, 307, 308, 404, 405, 410, 414, 501,
];

/// Headers that describe the connection rather than the response (RFC 9110 §7.6.1), or the proxy
/// the request went through, and are never stored. RFC 9111 §3.1 names the proxy ones:
/// `Proxy-Authenticate`, `Proxy-Authorization`, and [`PROXY_AUTHENTICATION_INFO`], which has no
/// constant in `http` and so is checked by name.
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// `Proxy-Authentication-Info` (RFC 9110 §11.7.3), never stored either; see [`HOP_BY_HOP`].
const PROXY_AUTHENTICATION_INFO: &str = "proxy-authentication-info";

/// The headers a response's `Connection` names (RFC 9110 §7.6.1): they describe that connection
/// like the fixed hop-by-hop ones do, so they are not stored either (RFC 9111 §3.1 allows the
/// removal at storage time).
fn connection_listed(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect()
}

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
    /// A stale stored response was used without contacting the server, as its
    /// `stale-while-revalidate` allows (RFC 5861 §3), and a revalidation of it was started in the
    /// background.
    Stale,
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
            Self::Stale => "stale",
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
    /// Use this stored response although it is stale, and revalidate it in the background: its
    /// `stale-while-revalidate` (RFC 5861 §3) still covers it. Only for [`CacheMode::Default`].
    ///
    /// Fetch serves it so only to a request with a client (HTTP-network-or-cache fetch), whose
    /// revalidation can run on after the request itself is answered. Any other request
    /// revalidates it before using it, as for [`Revalidate`](Self::Revalidate) or
    /// [`Send`](Self::Send) by whether it has validators; see [`CacheDecision::revalidated`].
    UseStale(Arc<CacheEntry>),
    /// Send the request; there is nothing usable stored.
    Send,
    /// The request insisted on a stored response ([`CacheMode::OnlyIfCached`]) and there is none.
    NotCached,
}

impl CacheDecision {
    /// The decision for a request that cannot revalidate in the background: a
    /// [`UseStale`](Self::UseStale) becomes a revalidation now, and anything else stays as it is.
    pub fn revalidated(self) -> Self {
        match self {
            Self::UseStale(entry) => revalidate(&entry),
            other => other,
        }
    }
}

/// Revalidate `entry`, or fetch afresh when it has no validators to send.
fn revalidate(entry: &Arc<CacheEntry>) -> CacheDecision {
    let conditional = entry.conditional_headers();
    if conditional.is_empty() {
        CacheDecision::Send
    } else {
        CacheDecision::Revalidate(entry.clone(), conditional)
    }
}

/// The URL and method a cache entry is stored under, and whose cookies fetched it.
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
    /// The cookie jar the response was fetched with, as
    /// [`FetcherContext::cookie_jar_key`](crate::net::fetcher_context::FetcherContext::cookie_jar_key)
    /// names it; empty for a request that carried no cookies. A response is what one jar's
    /// cookies bought, and a server that does not say `Vary: Cookie` (most do not) would
    /// otherwise have it handed to another jar's request: one cache per jar, as a browser keeps
    /// one per profile.
    pub partition: String,
}

impl CacheKey {
    /// Key for a request that carries no cookies, dropping the URL's fragment.
    pub fn new(method: &Method, url: &Url) -> Self {
        let mut url = url.clone();
        url.set_fragment(None);
        Self {
            method: method.clone(),
            url,
            partition: String::new(),
        }
    }

    /// The same key in `partition`: for a request that carries that jar's cookies.
    pub fn in_partition(mut self, partition: &str) -> Self {
        self.partition = partition.to_string();
        self
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
    /// The peer of the connection the response was read from, or of the one whose `304` last
    /// confirmed it; see [`FetchResultMeta::peer_addr`](crate::net::types::FetchResultMeta::peer_addr).
    /// `None` when the client did not report one.
    pub peer_addr: Option<std::net::SocketAddr>,
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
        // `Vary: *` always fails to match (RFC 9111 §4.1).
        if self.decoded != decoded || self.vary.iter().any(|(name, _)| name == "*") {
            return false;
        }
        self.vary.iter().all(|(name, stored)| {
            let current = HeaderName::try_from(name.as_str())
                .ok()
                .and_then(|n| vary_value(request, &n));
            current.as_deref() == stored.as_deref().map(normalize_list).as_deref()
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
        // A list (`Age: 100, 200`) counts by its first member (RFC 9111 §5.1).
        let age_value = self
            .headers
            .get(header::AGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(delta_seconds)
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

    /// Whether a `304` fails to select this entry for an update (RFC 9111 §4.3.4), i.e. names
    /// another version than the stored one. Such a `304` confirms nothing about this entry, and
    /// updating from it would pin the old body under the new validator.
    ///
    /// - A strong `ETag` selects the entry only if the stored one is the same strong tag
    ///   (strong comparison, RFC 9110 §8.8.3.2).
    /// - A weak `ETag` selects it only if the stored one matches by weak comparison.
    /// - Either `ETag` never selects an entry stored without one.
    /// - A `Last-Modified` and no `ETag` selects it only if the stored `Last-Modified` is the
    ///   same.
    /// - No validator at all selects it only if the entry has none either.
    pub fn contradicted_by(&self, response: &HeaderMap) -> bool {
        let etag = |headers: &HeaderMap| {
            headers
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|tag| tag.trim().to_string())
        };
        let opaque = |tag: &str| tag.strip_prefix("W/").unwrap_or(tag).to_string();
        match (etag(&self.headers), etag(response)) {
            (Some(stored), Some(sent)) if sent.starts_with("W/") => {
                opaque(&stored) != opaque(&sent)
            }
            (Some(stored), Some(sent)) => stored.starts_with("W/") || stored != sent,
            // The entry has no tag for the `304`'s to correspond to (the server has started
            // sending them, say): nothing proves the stored body is the one it names.
            (None, Some(_)) => true,
            (_, None) => match (
                self.headers.get(header::LAST_MODIFIED),
                response.get(header::LAST_MODIFIED),
            ) {
                (Some(stored), Some(sent)) => stored != sent,
                (None, Some(_)) => true,
                // No validator at all: it selects only an entry that has none either.
                (_, None) => self.is_revalidatable(),
            },
        }
    }

    /// Whether a `200` to a `HEAD` shows that this stored `GET` response is no longer the
    /// current one (RFC 9111 §4.3.5): its `ETag` or `Last-Modified` differs, or one side has it
    /// and the other does not, or its `Content-Length` differs from the stored body's. A decoded
    /// entry's body length says nothing about the encoded one, so it is not compared.
    pub fn changed_per_head(&self, head: &HeaderMap) -> bool {
        let differs = |name: HeaderName| self.headers.get(&name) != head.get(&name);
        let length = || {
            head.get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<usize>().ok())
                .is_some_and(|len| len != self.body.len())
        };
        differs(header::ETAG) || differs(header::LAST_MODIFIED) || (!self.decoded && length())
    }

    /// Whether the entry carries a validator, i.e. whether a `304` can ever come back for it.
    pub fn is_revalidatable(&self) -> bool {
        self.headers.contains_key(header::ETAG) || self.headers.contains_key(header::LAST_MODIFIED)
    }

    /// The entry as updated by a `304` (RFC 9111 §4.3.4): the stored body, the stored headers with
    /// everything the `304` carried written over them, and the age clock restarted.
    ///
    /// A `Vary` on the `304` replaces the stored one (RFC 9110 §15.4.5), so the entry is
    /// selected by the headers it names from now on, with the values `request`, the
    /// revalidating request, carried. A `Vary: *` leaves an entry nothing matches.
    pub fn updated_by_304(
        &self,
        headers: &HeaderMap,
        requested_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
        request: &HeaderMap,
    ) -> Self {
        let mut updated = self.clone();
        let connection = connection_listed(headers);
        for name in headers.keys() {
            // Content-Length describes the stored body, which the 304 did not carry. A decoded
            // body was stored without its Content-Encoding, and the 304's would put back a
            // claim the stored bytes no longer meet (RFC 9111 §3.2: the fields the stored
            // response depends on are not updated).
            if HOP_BY_HOP.contains(name)
                || name == PROXY_AUTHENTICATION_INFO
                || connection.contains(name)
                || name == header::CONTENT_LENGTH
                || name == header::SET_COOKIE
                || (self.decoded && name == header::CONTENT_ENCODING)
            {
                continue;
            }
            updated.headers.remove(name);
            for value in headers.get_all(name) {
                updated.headers.append(name, value.clone());
            }
        }
        if headers.contains_key(header::VARY) {
            updated.vary = vary_names(&updated.headers)
                .into_iter()
                .map(|name| {
                    let value = HeaderName::try_from(name.as_str())
                        .ok()
                        .and_then(|n| vary_value(request, &n));
                    (name, value)
                })
                .collect();
        }
        updated.requested_at = requested_at;
        updated.received_at = received_at;
        updated
    }
}

/// Largest delta-seconds value used (RFC 9111 §1.2.2: a cache treats anything greater as
/// 2^31). Keeps every duration below well within `TimeDelta`, which panics past its range.
const MAX_DELTA_SECS: i64 = 1 << 31;

/// Parse a delta-seconds value (RFC 9111 §1.2.2): digits only, clamped to `MAX_DELTA_SECS`.
fn delta_seconds(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        value
            .parse::<i64>()
            .unwrap_or(MAX_DELTA_SECS)
            .min(MAX_DELTA_SECS),
    )
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
    /// `immutable` (RFC 8246): will not change while fresh. A fresh response is used without
    /// asking anyway; a forced revalidation asks regardless, as RFC 8246 §2.1 allows.
    pub immutable: bool,
    /// `private`: not for a shared cache. This one is private, so it only records the fact.
    pub private: bool,
    /// `public`.
    pub public: bool,
    /// `must-understand` (RFC 9111 §5.2.2.3): store only if the status code's caching rules
    /// are understood, and then whatever `no-store` says.
    pub must_understand: bool,
    /// `max-age`, in seconds.
    pub max_age: Option<i64>,
    /// `stale-while-revalidate` (RFC 5861 §3), in seconds: how long past its freshness the
    /// response may still be used while it is revalidated in the background.
    pub stale_while_revalidate: Option<i64>,
}

impl ResponseDirectives {
    /// Parse the `Cache-Control` field lines of a response.
    ///
    /// A `max-age` given more than once counts the first time only (RFC 9111 §4.2.1), so a
    /// later `max-age=31536000` cannot extend an earlier `max-age=0`. One that is not a number of
    /// seconds (`max-age=abc`, `max-age=-1`, a bare `max-age`) counts as `max-age=0`: the server
    /// meant to say something about freshness, and §4.2.1 encourages taking that as stale
    /// rather than falling back to `Expires` or a guess.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut out = Self::default();
        let mut max_age_seen = false;
        let mut swr_seen = false;
        for (name, value) in directives(headers) {
            match name.as_str() {
                "no-store" => out.no_store = true,
                "no-cache" => out.no_cache = true,
                // `proxy-revalidate` is `must-revalidate` for shared caches only (RFC 9111
                // §5.2.2.8); this one is private.
                "must-revalidate" => out.must_revalidate = true,
                "immutable" => out.immutable = true,
                "private" => out.private = true,
                "public" => out.public = true,
                "must-understand" => out.must_understand = true,
                // The first one counts, as for `max-age`, and only a number of seconds: anything
                // else grants nothing (RFC 5861 §3).
                "stale-while-revalidate" if !swr_seen => {
                    swr_seen = true;
                    out.stale_while_revalidate = value.and_then(|v| delta_seconds(&v));
                }
                "max-age" if !max_age_seen => {
                    max_age_seen = true;
                    out.max_age = Some(value.and_then(|v| delta_seconds(&v)).unwrap_or(0));
                }
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
    ///
    /// A request without `Cache-Control` that says `Pragma: no-cache` asks for `no-cache`: HTTP/1.0
    /// clients and caches still send it that way, and RFC 9111 §5.4 has it count as one.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut out = Self::default();
        if !headers.contains_key(header::CACHE_CONTROL) {
            out.no_cache = headers
                .get_all(header::PRAGMA)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .any(|d| d.trim().eq_ignore_ascii_case("no-cache"));
        }
        for (name, value) in directives(headers) {
            match name.as_str() {
                "no-store" => out.no_store = true,
                "no-cache" => out.no_cache = true,
                "only-if-cached" => out.only_if_cached = true,
                "max-age" => out.max_age = value.and_then(|v| delta_seconds(&v)),
                "max-stale" => out.max_stale = Some(value.and_then(|v| delta_seconds(&v))),
                "min-fresh" => out.min_fresh = value.and_then(|v| delta_seconds(&v)),
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
    // A `304` is not a response to keep: it confirms one the client already has, and carries no
    // body of its own (RFC 9110 §15.4.5). Stored, it would answer later requests with an empty
    // `304` that nobody asked for. Sonar's own revalidations never reach this point: their
    // `304` freshens the stored entry instead.
    if status == 304 {
        return false;
    }
    if RequestDirectives::parse(request).no_store || bypasses_cache(request) {
        return false;
    }
    let directives = ResponseDirectives::parse(response);
    // `must-understand` (RFC 9111 §3, §5.2.2.3): a status whose caching rules are not known
    // here is not stored, and for one that is, the directive takes the place of the `no-store`
    // it is sent with for caches that do not know it.
    if directives.must_understand {
        if !UNDERSTOOD.contains(&status) {
            return false;
        }
    } else if directives.no_store {
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
        // Nothing to decide freshness by and nothing to revalidate with: stale on arrival, so a
        // normal request never uses it. Only a request that accepts stale responses could
        // (`CacheMode::ForceCache`, `OnlyIfCached`, `max-stale`), as a browser's back/forward
        // does. Until something here navigates history that way, storing these would only
        // push out entries that are used.
        return false;
    }
    // A status that is not heuristically cacheable is only stored with explicit freshness
    // (`max-age` or `Expires`). RFC 9111 §3 would also let `public` or `private` make one
    // storable; that is a MAY, and without freshness such a response is stale on arrival.
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
    for name in connection_listed(response) {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(PROXY_AUTHENTICATION_INFO);
    // A cache hit must not re-apply a cookie the jar has long since stored or dropped.
    headers.remove(header::SET_COOKIE);
    // A response is cached with the time it arrived when it carries none (RFC 9110 §6.6.1).
    if !headers.contains_key(header::DATE) {
        if let Ok(date) = header::HeaderValue::from_str(&format_http_date(received_at)) {
            headers.insert(header::DATE, date);
        }
    }
    if decoded {
        headers.remove(header::CONTENT_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
    }

    let vary = vary_names(response)
        .into_iter()
        .filter_map(|name| {
            let header_name = HeaderName::try_from(name.as_str()).ok()?;
            Some((name, vary_value(request, &header_name)))
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
        peer_addr: None,
    }
}

/// A request header's value as `Vary` compares it (RFC 9111 §4.1): every field line of it
/// combined into one list, with the whitespace around the list's elements normalized, so
/// `en, nl`, `en,nl` and the two lines `en` and `nl` are the same value. `None` when the request
/// carries no such header.
fn vary_value(request: &HeaderMap, name: &HeaderName) -> Option<String> {
    let lines: Vec<&str> = request
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(normalize_list(&lines.join(",")))
}

/// A comma-separated list with each element trimmed and empty ones dropped, joined by `, `.
/// Commas inside quoted strings are part of their element.
fn normalize_list(value: &str) -> String {
    split_outside_quotes(value)
        .into_iter()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
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
    // Of several that match, the most recent by `Date` (RFC 9111 §4), the time it arrived for
    // one without.
    let Some(entry) = entries
        .iter()
        .filter(|e| e.matches(request, decoded))
        .max_by_key(|e| header_date(&e.headers, header::DATE).unwrap_or(e.received_at))
    else {
        return if only_if_cached {
            CacheDecision::NotCached
        } else {
            CacheDecision::Send
        };
    };

    let stored = ResponseDirectives::parse(&entry.headers);

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

    // A forced revalidation asks the server, `immutable` or not: Fetch's `no-cache` mode always
    // makes a conditional request, and RFC 8246 §2.1 names a request's `no-cache` as the
    // override `immutable` gives way to. A response that says `no-cache` is never used
    // unvalidated (RFC 9111 §5.2.2.4).
    if mode == CacheMode::NoCache || asked.no_cache || stored.no_cache {
        return revalidate(entry);
    }

    let age = entry.current_age(now);
    let lifetime = entry.freshness_lifetime().unwrap_or_else(TimeDelta::zero);

    // Fresh, or stale by no more than the request's `max-stale` allows. `max-stale` relaxes only
    // this: the request's `max-age` and `min-fresh` below are conditions of their own
    // (RFC 9111 §5.2.1), so a caller that wants nothing older than ten seconds does not get a
    // minute-old response because it also accepts stale ones.
    let mut usable = age < lifetime;
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
    // Stale, but within what the response's `stale-while-revalidate` grants: used now and
    // revalidated behind it (RFC 5861 §3), unless `must-revalidate` forbids any stale use
    // (RFC 9111 §5.2.2.2). Fetch serves it so in the default mode alone; a forced revalidation
    // and `no-cache` already returned above.
    let mut stale_usable = false;
    if !usable && mode == CacheMode::Default && !stored.must_revalidate {
        if let Some(window) = stored.stale_while_revalidate {
            stale_usable = age - lifetime <= TimeDelta::seconds(window);
        }
    }
    // The request's own limits hold either way: a stale response is never young enough for its
    // `max-age` past that, and never fresh enough for any `min-fresh`.
    if let Some(max_age) = asked.max_age {
        let young = age <= TimeDelta::seconds(max_age);
        usable &= young;
        stale_usable &= young;
    }
    if let Some(min_fresh) = asked.min_fresh {
        usable &= lifetime - age >= TimeDelta::seconds(min_fresh);
        stale_usable = false;
    }

    if usable {
        CacheDecision::Use(entry.clone())
    } else if stale_usable {
        CacheDecision::UseStale(entry.clone())
    } else {
        revalidate(entry)
    }
}

/// The cache mode a request is handled with (Fetch, HTTP-network-or-cache fetch): `Default`
/// becomes `NoStore` when the caller sent a condition of its own (`If-None-Match`,
/// `If-Modified-Since`, `If-Match`, `If-Unmodified-Since`, `If-Range`). The caller is asking
/// the server, so the caches on the way are told not to answer for it either; sonar's own
/// cache already stays out of such a request (see [`bypasses_cache`]).
pub fn effective_mode(mode: CacheMode, request: &HeaderMap) -> CacheMode {
    let conditional = [
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_MATCH,
        header::IF_UNMODIFIED_SINCE,
        header::IF_RANGE,
    ]
    .iter()
    .any(|name| request.contains_key(name));
    if mode == CacheMode::Default && conditional {
        CacheMode::NoStore
    } else {
        mode
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
    // Matched case-insensitively (RFC 9111 §4.2). chrono reads day and month names in any
    // case already; the `GMT` in the formats below is a literal.
    let value = value.trim();
    let upper;
    let value = match value.len().checked_sub(3).and_then(|i| value.get(i..)) {
        Some(zone) if zone.eq_ignore_ascii_case("gmt") => {
            upper = format!("{}GMT", &value[..value.len() - 3]);
            upper.as_str()
        }
        _ => value,
    };
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

/// `time` as an IMF-fixdate (RFC 9110 §5.6.7), the form an HTTP-date is sent in.
fn format_http_date(time: DateTime<Utc>) -> String {
    time.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
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
    /// Drop every variant stored for `key`'s method and URL, in every partition: a write that
    /// makes the resource stale makes every jar's copy stale.
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

/// One stored variant and what it is charged against the budget.
struct Stored {
    entry: Arc<CacheEntry>,
    charged: usize,
}

/// The variants under one key, plus when the key was last touched.
struct Keyed {
    variants: Vec<Stored>,
    last_used: u64,
}

/// Contents of an [`InMemoryHttpCache`], behind one lock.
#[derive(Default)]
struct Contents {
    keys: HashMap<CacheKey, Keyed>,
    /// Keys by `last_used`, oldest first; clocks are unique so a key has one slot.
    lru: std::collections::BTreeMap<u64, CacheKey>,
    bytes: usize,
    clock: u64,
}

impl Contents {
    /// Mark `key` as used now, moving it to the young end of the LRU order.
    fn touch(&mut self, key: &CacheKey) {
        self.clock += 1;
        let clock = self.clock;
        if let Some(keyed) = self.keys.get_mut(key) {
            self.lru.remove(&keyed.last_used);
            keyed.last_used = clock;
            self.lru.insert(clock, key.clone());
        }
    }

    /// Remove `key` with every variant, returning what they were charged.
    fn remove(&mut self, key: &CacheKey) -> usize {
        let Some(keyed) = self.keys.remove(key) else {
            return 0;
        };
        self.lru.remove(&keyed.last_used);
        let freed: usize = keyed.variants.iter().map(|s| s.charged).sum();
        self.bytes = self.bytes.saturating_sub(freed);
        freed
    }
}

/// Estimated overhead of one stored variant beyond its bytes: the map slots, the `Arc`, the
/// header map's own allocation.
const STORED_OVERHEAD: usize = 256;

/// What a variant costs against the budget: the response plus the key and `Vary` list it is
/// found by, so a flood of tiny bodies under long URLs cannot sit outside the accounting.
fn charge(key: &CacheKey, entry: &CacheEntry) -> usize {
    let vary: usize = entry
        .vary
        .iter()
        .map(|(name, value)| name.len() + value.as_ref().map_or(0, String::len))
        .sum();
    entry.size() + key.url.as_str().len() + key.partition.len() + vary + STORED_OVERHEAD
}

/// [`HttpCache`] holding entries in memory, bounded by a byte budget.
///
/// When a `put` pushes the total over the budget, the least recently used keys are dropped
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
        self.contents
            .lock()
            .keys
            .values()
            .map(|k| k.variants.len())
            .sum()
    }

    /// True when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes currently held.
    pub fn byte_len(&self) -> usize {
        self.contents.lock().bytes
    }

    /// Drop the least recently used keys until the total is within budget.
    fn evict(contents: &mut Contents, max_bytes: usize) {
        while contents.bytes > max_bytes {
            let Some((_, key)) = contents.lru.pop_first() else {
                contents.bytes = 0;
                return;
            };
            // `remove` would look the slot up again; it is gone already.
            if let Some(keyed) = contents.keys.remove(&key) {
                let freed: usize = keyed.variants.iter().map(|s| s.charged).sum();
                contents.bytes = contents.bytes.saturating_sub(freed);
            }
        }
    }
}

impl HttpCache for InMemoryHttpCache {
    fn get(&self, key: &CacheKey) -> Vec<Arc<CacheEntry>> {
        let mut contents = self.contents.lock();
        contents.touch(key);
        match contents.keys.get(key) {
            Some(keyed) => keyed.variants.iter().map(|s| s.entry.clone()).collect(),
            None => Vec::new(),
        }
    }

    fn put(&self, key: CacheKey, entry: Arc<CacheEntry>) {
        if entry.size() > self.max_entry_bytes {
            return;
        }
        let charged = charge(&key, &entry);
        let mut contents = self.contents.lock();
        contents.clock += 1;
        let clock = contents.clock;
        if contents.keys.contains_key(&key) {
            contents.touch(&key);
        } else {
            contents.lru.insert(clock, key.clone());
        }
        let keyed = contents.keys.entry(key).or_insert_with(|| Keyed {
            variants: Vec::new(),
            last_used: clock,
        });
        // One variant per set of selecting request headers, so a new response for the same
        // headers replaces the old one instead of being stored beside it.
        let replaced = keyed
            .variants
            .iter()
            .position(|s| s.entry.vary == entry.vary && s.entry.decoded == entry.decoded);
        let stored = Stored { entry, charged };
        let freed = match replaced {
            Some(index) => std::mem::replace(&mut keyed.variants[index], stored).charged,
            None => {
                keyed.variants.push(stored);
                0
            }
        };
        contents.bytes = contents.bytes.saturating_sub(freed) + charged;
        Self::evict(&mut contents, self.max_bytes);
    }

    fn invalidate(&self, key: &CacheKey) {
        let mut contents = self.contents.lock();
        let doomed: Vec<CacheKey> = contents
            .keys
            .keys()
            .filter(|k| k.method == key.method && k.url == key.url)
            .cloned()
            .collect();
        for key in doomed {
            contents.remove(&key);
        }
    }

    fn clear(&self) {
        let mut contents = self.contents.lock();
        contents.keys.clear();
        contents.lru.clear();
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

    /// HTTP dates match case-insensitively (RFC 9111 §4.2), in each of the three formats.
    #[test]
    fn http_dates_match_case_insensitively() {
        let expected = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        for value in [
            "sun, 06 nov 1994 08:49:37 gmt",
            "SUN, 06 NOV 1994 08:49:37 GMT",
            "sunday, 06-nov-94 08:49:37 gmt",
            "SUN NOV  6 08:49:37 1994",
        ] {
            assert_eq!(parse_http_date(value), Some(expected), "{value}");
        }
    }

    /// RFC 9111 §4.3.5: a `HEAD` response with another validator or length than the stored
    /// `GET` shows the stored one is no longer current; the same ones show nothing.
    #[test]
    fn a_head_with_other_validators_shows_the_get_changed() {
        let stored = entry(&[
            ("cache-control", "max-age=600"),
            ("etag", "\"v1\""),
            ("last-modified", &http_date(at(-100))),
        ]);
        let same = headers(&[
            ("etag", "\"v1\""),
            ("last-modified", &http_date(at(-100))),
            ("content-length", "4"),
        ]);
        assert!(!stored.changed_per_head(&same));
        let tag = headers(&[("etag", "\"v2\""), ("last-modified", &http_date(at(-100)))]);
        assert!(stored.changed_per_head(&tag));
        let dated = headers(&[("etag", "\"v1\""), ("last-modified", &http_date(at(-5)))]);
        assert!(stored.changed_per_head(&dated));
        let longer = headers(&[
            ("etag", "\"v1\""),
            ("last-modified", &http_date(at(-100))),
            ("content-length", "40"),
        ]);
        assert!(stored.changed_per_head(&longer));
    }

    /// An `Age` that is a list counts by its first member (RFC 9111 §5.1).
    #[test]
    fn a_list_age_counts_by_its_first_member() {
        let stored = entry(&[("cache-control", "max-age=600"), ("age", "100, 200")]);
        assert_eq!(stored.current_age(at(0)), TimeDelta::seconds(100));
    }

    /// A response without `Date` is stored with the time it arrived (RFC 9110 §6.6.1); one
    /// with a `Date` keeps it.
    #[test]
    fn a_response_without_date_is_stored_with_one() {
        let stored = entry(&[("cache-control", "max-age=60")]);
        assert_eq!(stored.headers[header::DATE], http_date(at(0)).as_str());
        let dated = entry(&[
            ("cache-control", "max-age=60"),
            ("date", &http_date(at(-5))),
        ]);
        assert_eq!(dated.headers[header::DATE], http_date(at(-5)).as_str());
        assert_eq!(dated.headers.get_all(header::DATE).iter().count(), 1);
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
    fn delta_seconds_parsing() {
        assert_eq!(delta_seconds("60"), Some(60));
        assert_eq!(delta_seconds(" 60 "), Some(60));
        assert_eq!(delta_seconds("0"), Some(0));
        assert_eq!(delta_seconds("-5"), None);
        assert_eq!(delta_seconds("+5"), None);
        assert_eq!(delta_seconds(""), None);
        assert_eq!(delta_seconds("soon"), None);
        assert_eq!(delta_seconds("9223372036854775807"), Some(MAX_DELTA_SECS));
        assert_eq!(
            delta_seconds("99999999999999999999999"),
            Some(MAX_DELTA_SECS)
        );
    }

    /// Out-of-range values from the server must not panic (`TimeDelta::seconds` does past
    /// its bounds); they are clamped and the entry still ages.
    #[test]
    fn huge_max_age_and_age_do_not_panic() {
        let stored = entry(&[
            ("cache-control", "max-age=9223372036854775807"),
            ("age", "9223372036854775807"),
        ]);
        assert_eq!(
            stored.freshness_lifetime(),
            Some(TimeDelta::seconds(MAX_DELTA_SECS))
        );
        assert!(stored.current_age(at(1)) >= TimeDelta::seconds(MAX_DELTA_SECS));
        assert!(!stored.is_fresh(at(1)));

        let request = headers(&[(
            "cache-control",
            "max-age=9223372036854775807, min-fresh=9223372036854775807, \
             max-stale=9223372036854775807",
        )]);
        let _ = decide(&[stored], &request, true, CacheMode::Default, at(1));
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

    /// RFC 5861 §3: a stale response is used while it is revalidated for as long past its
    /// freshness as `stale-while-revalidate` says, and revalidated first after that.
    #[test]
    fn stale_while_revalidate_covers_its_window_only() {
        let stored = [entry(&[
            ("cache-control", "max-age=10, stale-while-revalidate=20"),
            ("etag", "\"v1\""),
        ])];
        let at_age = |secs| {
            decide(
                &stored,
                &HeaderMap::new(),
                false,
                CacheMode::Default,
                at(secs),
            )
        };
        assert!(matches!(at_age(5), CacheDecision::Use(_)));
        assert!(matches!(at_age(25), CacheDecision::UseStale(_)));
        assert!(matches!(at_age(30), CacheDecision::UseStale(_)));
        assert!(matches!(at_age(31), CacheDecision::Revalidate(..)));
    }

    /// A request that cannot revalidate in the background revalidates first: with its
    /// validators when it has them, afresh when it has none.
    #[test]
    fn a_stale_response_is_revalidated_without_a_background() {
        let swr = "max-age=0, stale-while-revalidate=60";
        let with_tag = [entry(&[("cache-control", swr), ("etag", "\"v1\"")])];
        let without = [entry(&[("cache-control", swr)])];
        let decide_at = |stored: &[Arc<CacheEntry>]| {
            decide(stored, &HeaderMap::new(), false, CacheMode::Default, at(5))
        };
        assert!(matches!(decide_at(&with_tag), CacheDecision::UseStale(_)));
        assert!(matches!(
            decide_at(&with_tag).revalidated(),
            CacheDecision::Revalidate(..)
        ));
        assert!(matches!(decide_at(&without), CacheDecision::UseStale(_)));
        assert!(matches!(
            decide_at(&without).revalidated(),
            CacheDecision::Send
        ));
    }

    /// What `stale-while-revalidate` grants gives way to anything that forbids stale use: the
    /// response's `must-revalidate`, a mode other than the default, and the request's own
    /// `max-age`, `min-fresh` and `no-cache`.
    #[test]
    fn stale_while_revalidate_yields_to_stricter_rules() {
        let swr = "max-age=10, stale-while-revalidate=600";
        let stored = [entry(&[("cache-control", swr), ("etag", "\"v1\"")])];
        let strict = [entry(&[
            (
                "cache-control",
                "max-age=10, must-revalidate, stale-while-revalidate=600",
            ),
            ("etag", "\"v1\""),
        ])];
        let stale = |stored: &[Arc<CacheEntry>], asked: &[(&str, &str)], mode| {
            matches!(
                decide(stored, &headers(asked), false, mode, at(30)),
                CacheDecision::UseStale(_)
            )
        };
        assert!(stale(&stored, &[], CacheMode::Default));
        assert!(!stale(&strict, &[], CacheMode::Default));
        assert!(!stale(&stored, &[], CacheMode::NoCache));
        assert!(!stale(
            &stored,
            &[("cache-control", "max-age=20")],
            CacheMode::Default
        ));
        assert!(stale(
            &stored,
            &[("cache-control", "max-age=40")],
            CacheMode::Default
        ));
        assert!(!stale(
            &stored,
            &[("cache-control", "min-fresh=0")],
            CacheMode::Default
        ));
        assert!(!stale(
            &stored,
            &[("cache-control", "no-cache")],
            CacheMode::Default
        ));
        // Stale use the caller asked for is no reason to revalidate.
        assert!(matches!(
            decide(
                &stored,
                &headers(&[("cache-control", "max-stale")]),
                false,
                CacheMode::Default,
                at(30)
            ),
            CacheDecision::Use(_)
        ));
    }

    /// The first `stale-while-revalidate` counts, and one that is not a number of seconds
    /// grants nothing.
    #[test]
    fn stale_while_revalidate_parsing() {
        let parse = |value: &str| {
            ResponseDirectives::parse(&headers(&[("cache-control", value)])).stale_while_revalidate
        };
        assert_eq!(parse("stale-while-revalidate=30"), Some(30));
        assert_eq!(parse("Stale-While-Revalidate=\"30\""), Some(30));
        assert_eq!(
            parse("stale-while-revalidate=30, stale-while-revalidate=90"),
            Some(30)
        );
        assert_eq!(
            parse("stale-while-revalidate=abc, stale-while-revalidate=90"),
            None
        );
        assert_eq!(parse("stale-while-revalidate"), None);
        assert_eq!(parse("stale-while-revalidate=-1"), None);
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

    /// RFC 9111 §5.2.1: `max-stale` lets a stale response through, but the request's `max-age`
    /// and `min-fresh` still hold. A response 50 s into a 100 s lifetime is too old for
    /// `max-age=10` and not fresh enough for `min-fresh=60`, whatever `max-stale` says.
    #[test]
    fn max_stale_does_not_lift_max_age_or_min_fresh() {
        let fresh = [entry(&[
            ("cache-control", "max-age=100"),
            ("etag", "\"v1\""),
        ])];
        for asked in [
            "max-age=10, max-stale",
            "max-age=10, max-stale=3600",
            "min-fresh=60, max-stale",
        ] {
            let asked = headers(&[("cache-control", asked)]);
            assert!(
                matches!(
                    decide(&fresh, &asked, false, CacheMode::Default, at(50)),
                    CacheDecision::Revalidate(..)
                ),
                "{asked:?}"
            );
        }
        // A stale response young enough for the request's max-age is still let through.
        let stale = [entry(&[
            ("cache-control", "max-age=10"),
            ("etag", "\"v1\""),
        ])];
        let asked = headers(&[("cache-control", "max-age=60, max-stale")]);
        assert!(matches!(
            decide(&stale, &asked, false, CacheMode::Default, at(30)),
            CacheDecision::Use(_)
        ));
    }

    /// RFC 9111 §5.4: a request with `Pragma: no-cache` and no `Cache-Control` is treated as if
    /// it carried `Cache-Control: no-cache`. With a `Cache-Control` present, `Pragma` is ignored.
    #[test]
    fn pragma_no_cache_counts_when_there_is_no_cache_control() {
        let fresh = [entry(&[
            ("cache-control", "max-age=100"),
            ("etag", "\"v1\""),
        ])];
        let decision = |asked: &[(&str, &str)]| {
            decide(&fresh, &headers(asked), false, CacheMode::Default, at(1))
        };
        assert!(matches!(
            decision(&[("pragma", "no-cache")]),
            CacheDecision::Revalidate(..)
        ));
        assert!(matches!(
            decision(&[("pragma", "foo, No-Cache")]),
            CacheDecision::Revalidate(..)
        ));
        assert!(matches!(
            decision(&[("pragma", "no-cache"), ("cache-control", "max-stale")]),
            CacheDecision::Use(_)
        ));
        assert!(matches!(
            decision(&[("pragma", "foo")]),
            CacheDecision::Use(_)
        ));
    }

    /// RFC 9111 §5.2.2.8: `proxy-revalidate` binds shared caches only. This cache is private,
    /// so a stale response with it may be served when the request accepts stale ones, unlike
    /// one with `must-revalidate`.
    #[test]
    fn proxy_revalidate_does_not_bind_a_private_cache() {
        let stale = [entry(&[
            ("cache-control", "max-age=10, proxy-revalidate"),
            ("etag", "\"v1\""),
        ])];
        let asked = headers(&[("cache-control", "max-stale=60")]);
        assert!(matches!(
            decide(&stale, &asked, false, CacheMode::Default, at(40)),
            CacheDecision::Use(_)
        ));
        assert!(matches!(
            decide(
                &stale,
                &HeaderMap::new(),
                false,
                CacheMode::ForceCache,
                at(40)
            ),
            CacheDecision::Use(_)
        ));
    }

    /// RFC 9111 §4.2.1: with more than one `max-age`, the first is used (or the response is
    /// taken as stale), never a later, longer one. Across field lines too.
    #[test]
    fn the_first_max_age_counts() {
        let one_line = entry(&[("cache-control", "max-age=0, max-age=600")]);
        assert!(!one_line.is_fresh(at(10)));
        let two_lines = entry(&[
            ("cache-control", "max-age=0"),
            ("cache-control", "max-age=600"),
        ]);
        assert!(!two_lines.is_fresh(at(10)));
        let longer_first = entry(&[("cache-control", "max-age=600, max-age=0")]);
        assert!(longer_first.is_fresh(at(10)));
    }

    /// RFC 9111 §3 and RFC 9110 §15.4.5: a `304` is not a representation, whatever freshness
    /// it carries, so it is never stored as one.
    #[test]
    fn a_304_is_never_stored() {
        for response in [
            headers(&[("cache-control", "max-age=60")]),
            headers(&[("cache-control", "public, max-age=60"), ("etag", "\"v1\"")]),
        ] {
            assert!(!is_storable(
                &Method::GET,
                &HeaderMap::new(),
                304,
                &response
            ));
        }
    }

    /// RFC 9111 §3.2: a `304` does not update the fields the stored response depends on. A body
    /// stored decoded keeps having no `Content-Encoding` when the `304` that confirms it repeats
    /// the encoding; a body stored as it came keeps the one it has.
    #[test]
    fn a_304_does_not_put_an_encoding_back_on_a_decoded_body() {
        let stored = |decoded| {
            entry_from_response(
                200,
                &headers(&[
                    ("cache-control", "max-age=10"),
                    ("etag", "\"v1\""),
                    ("content-encoding", "gzip"),
                ]),
                &HeaderMap::new(),
                Bytes::from_static(b"body"),
                decoded,
                at(0),
                at(0),
            )
        };
        let confirmation = headers(&[("etag", "\"v1\""), ("content-encoding", "gzip")]);

        let decoded =
            stored(true).updated_by_304(&confirmation, at(100), at(100), &HeaderMap::new());
        assert!(!decoded.headers.contains_key(header::CONTENT_ENCODING));
        let raw = stored(false).updated_by_304(&confirmation, at(100), at(100), &HeaderMap::new());
        assert_eq!(raw.headers.get(header::CONTENT_ENCODING).unwrap(), "gzip");
    }

    /// RFC 9111 §4.2.1: a response with invalid freshness information is taken as stale. An
    /// unparsable `max-age` does not fall through to `Expires` or the `Last-Modified` heuristic.
    #[test]
    fn an_invalid_max_age_is_stale() {
        for max_age in ["max-age=abc", "max-age=-1", "max-age=1.5", "max-age"] {
            let e = entry(&[
                ("cache-control", max_age),
                ("date", &http_date(at(0))),
                ("expires", &http_date(at(600))),
                ("last-modified", &http_date(at(-365 * 24 * 3600))),
            ]);
            assert!(!e.is_fresh(at(10)), "{max_age}");
        }
    }

    /// RFC 9111 §4.1: a varied header is compared after combining its field lines and
    /// normalizing the whitespace in the list. Split over two lines or written without spaces, a
    /// value matches; a request that carries more than the stored one does not.
    #[test]
    fn vary_compares_the_whole_header_however_it_is_written() {
        let stored = [entry_with_request(
            &[("cache-control", "max-age=60"), ("vary", "accept-language")],
            &[("accept-language", "en, nl")],
        )];
        let decision = |asked: &[(&str, &str)]| {
            decide(&stored, &headers(asked), false, CacheMode::Default, at(1))
        };
        for same in [
            &[("accept-language", "en, nl")][..],
            &[("accept-language", "en,nl")],
            &[("accept-language", " en ,  nl ")],
            &[("accept-language", "en"), ("accept-language", "nl")],
        ] {
            assert!(matches!(decision(same), CacheDecision::Use(_)), "{same:?}");
        }

        // Stored for `en` alone: a request for `en` and `nl` is another variant, even though its
        // first line says `en`.
        let only_en = [entry_with_request(
            &[("cache-control", "max-age=60"), ("vary", "accept-language")],
            &[("accept-language", "en")],
        )];
        let asked = headers(&[("accept-language", "en"), ("accept-language", "nl")]);
        assert!(matches!(
            decide(&only_en, &asked, false, CacheMode::Default, at(1)),
            CacheDecision::Send
        ));
    }

    /// RFC 9111 §4.3.4: a `304` selects the stored response only through a validator that
    /// corresponds to it. A strong tag by strong comparison, a weak one by weak comparison, a
    /// `Last-Modified` by equality; anything else contradicts it.
    #[test]
    fn a_304_with_a_validator_that_does_not_correspond_contradicts_the_entry() {
        let stored = entry(&[("cache-control", "max-age=10"), ("etag", "\"v1\"")]);
        let with = |etag: &str| headers(&[("etag", etag)]);
        assert!(stored.contradicted_by(&with("\"v2\"")));
        assert!(!stored.contradicted_by(&with("\"v1\"")));
        assert!(stored.contradicted_by(&with("W/\"v2\"")));
        assert!(!stored.contradicted_by(&with("W/\"v1\"")));

        let weak = entry(&[("cache-control", "max-age=10"), ("etag", "W/\"v1\"")]);
        assert!(weak.contradicted_by(&with("W/\"v2\"")));
        assert!(!weak.contradicted_by(&with("W/\"v1\"")));
        // A strong tag needs a strong stored one: strong comparison fails on a weak tag.
        assert!(weak.contradicted_by(&with("\"v1\"")));

        let dated = entry(&[
            ("cache-control", "max-age=10"),
            ("last-modified", &http_date(at(-100))),
        ]);
        let modified = |time| headers(&[("last-modified", &http_date(time))]);
        assert!(!dated.contradicted_by(&modified(at(-100))));
        assert!(dated.contradicted_by(&modified(at(-50))));
    }

    /// A `304` that brings `Vary` replaces the stored one (RFC 9110 §15.4.5): `Vary: *` leaves
    /// an entry nothing matches (RFC 9111 §4.1), and a new name selects by the value the
    /// revalidating request carried.
    #[test]
    fn a_304_that_brings_vary_replaces_it() {
        let stored = entry(&[("cache-control", "max-age=60"), ("etag", "\"v1\"")]);
        let asked = headers(&[("accept-language", "nl")]);
        assert!(stored.matches(&asked, false));

        let star = stored.updated_by_304(
            &headers(&[("etag", "\"v1\""), ("vary", "*")]),
            at(1),
            at(1),
            &asked,
        );
        assert!(!star.matches(&asked, false));

        let by_language = stored.updated_by_304(
            &headers(&[("etag", "\"v1\""), ("vary", "accept-language")]),
            at(1),
            at(1),
            &asked,
        );
        assert!(by_language.matches(&asked, false));
        assert!(!by_language.matches(&headers(&[("accept-language", "en")]), false));
    }

    /// RFC 9111 §4.3.4: a `304` without a validator selects a stored response only if that one
    /// has no validator either; one with a `Last-Modified` the entry lacks selects nothing.
    #[test]
    fn a_304_without_validators_selects_only_an_entry_without() {
        let none = HeaderMap::new();
        let tagged = entry(&[("cache-control", "max-age=10"), ("etag", "\"v1\"")]);
        assert!(tagged.contradicted_by(&none));
        let dated = entry(&[
            ("cache-control", "max-age=10"),
            ("last-modified", &http_date(at(-100))),
        ]);
        assert!(dated.contradicted_by(&none));
        let bare = entry(&[("cache-control", "max-age=10")]);
        assert!(!bare.contradicted_by(&none));
        assert!(tagged.contradicted_by(&headers(&[("last-modified", &http_date(at(-100)))])));
    }

    /// RFC 9111 §4.3.4: if none of the stored responses has the `304`'s strong validator, none
    /// is updated. An entry stored without an `ETag` has none to match, so a `304` that brings
    /// one, strong or weak, refetches.
    #[test]
    fn a_304_with_an_etag_the_entry_lacks_contradicts_it() {
        let dated = entry(&[
            ("cache-control", "max-age=10"),
            ("last-modified", &http_date(at(-100))),
        ]);
        let sent = |etag: &str| headers(&[("etag", etag), ("last-modified", &http_date(at(-100)))]);
        assert!(dated.contradicted_by(&sent("\"x\"")));
        assert!(dated.contradicted_by(&sent("W/\"x\"")));
    }

    /// Fetch, HTTP-network-or-cache fetch: a `default` request with a condition of the caller's
    /// own is a `no-store` one. A range alone is not a condition, and an explicit mode stays.
    #[test]
    fn a_callers_condition_makes_a_default_request_no_store() {
        for name in [
            "if-none-match",
            "if-modified-since",
            "if-match",
            "if-unmodified-since",
            "if-range",
        ] {
            let asked = headers(&[(name, "\"v1\"")]);
            assert_eq!(
                effective_mode(CacheMode::Default, &asked),
                CacheMode::NoStore,
                "{name}"
            );
            assert_eq!(
                effective_mode(CacheMode::Reload, &asked),
                CacheMode::Reload,
                "{name}"
            );
        }
        let range = headers(&[("range", "bytes=0-9")]);
        assert_eq!(
            effective_mode(CacheMode::Default, &range),
            CacheMode::Default
        );
        assert_eq!(
            effective_mode(CacheMode::Default, &HeaderMap::new()),
            CacheMode::Default
        );
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

    /// `must-understand` (RFC 9111 §3, §5.2.2.3): a status this cache does not know the rules
    /// of is not stored; a known one is, and the `no-store` sent with it is for caches that do
    /// not understand.
    #[test]
    fn must_understand_stores_only_understood_statuses() {
        let response = headers(&[("cache-control", "max-age=60, must-understand, no-store")]);
        let get = Method::GET;
        let none = HeaderMap::new();
        assert!(is_storable(&get, &none, 200, &response));
        assert!(!is_storable(&get, &none, 299, &response));
        let without = headers(&[("cache-control", "max-age=60, must-understand")]);
        assert!(!is_storable(&get, &none, 299, &without));
        // Without `must-understand`, `no-store` stands.
        let plain = headers(&[("cache-control", "max-age=60, no-store")]);
        assert!(!is_storable(&get, &none, 200, &plain));
    }

    /// A response that says `no-cache` is revalidated before every use (RFC 9111 §5.2.2.4),
    /// `immutable` and fresh or not.
    #[test]
    fn a_no_cache_response_is_revalidated_even_when_immutable() {
        let stored = [entry(&[
            ("cache-control", "max-age=600, immutable, no-cache"),
            ("etag", "\"v1\""),
        ])];
        assert!(matches!(
            decide(
                &stored,
                &HeaderMap::new(),
                false,
                CacheMode::Default,
                at(30)
            ),
            CacheDecision::Revalidate(..)
        ));
    }

    /// A forced revalidation asks the server even for a fresh `immutable` response: Fetch's
    /// `no-cache` mode always makes a conditional request, and RFC 8246 §2.1 names a request's
    /// `no-cache` as the override of `immutable`. A normal request uses it while fresh.
    #[test]
    fn a_forced_revalidation_asks_even_for_immutable() {
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
            CacheDecision::Revalidate(..)
        ));
        let asked = headers(&[("cache-control", "no-cache")]);
        assert!(matches!(
            decide(&stored, &asked, false, CacheMode::Default, at(30)),
            CacheDecision::Revalidate(..)
        ));
        assert!(matches!(
            decide(
                &stored,
                &HeaderMap::new(),
                false,
                CacheMode::Default,
                at(30)
            ),
            CacheDecision::Use(_)
        ));
    }

    /// When more than one stored response matches, the most recent one by `Date` is used
    /// (RFC 9111 §4), whatever order they were stored in.
    #[test]
    fn the_most_recent_matching_variant_is_used() {
        let variant = |vary: &str, date: i64| {
            Arc::new(entry_from_response(
                200,
                &headers(&[
                    ("cache-control", "max-age=600"),
                    ("vary", vary),
                    ("date", &http_date(at(date))),
                ]),
                &headers(&[("accept", "text/html"), ("accept-language", "nl")]),
                Bytes::from_static(b"body"),
                false,
                at(date),
                at(date),
            ))
        };
        let older = variant("accept", 0);
        let newer = variant("accept-language", 10);
        let asked = headers(&[("accept", "text/html"), ("accept-language", "nl")]);
        for stored in [
            [older.clone(), newer.clone()],
            [newer.clone(), older.clone()],
        ] {
            match decide(&stored, &asked, false, CacheMode::Default, at(20)) {
                CacheDecision::Use(used) => assert_eq!(used.vary, newer.vary),
                other => panic!("expected Use, got {other:?}"),
            }
        }
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

        // RFC 9111 §3.1: the headers of the proxy a request went through are not stored either.
        let stored = entry(&[
            ("cache-control", "max-age=60"),
            ("proxy-authenticate", "Basic realm=\"p\""),
            ("proxy-authentication-info", "nextnonce=\"n\""),
        ]);
        assert!(!stored.headers.contains_key(header::PROXY_AUTHENTICATE));
        assert!(!stored.headers.contains_key("proxy-authentication-info"));
        // Nor what `Connection` names: it describes that connection, not the response.
        let stored = entry(&[
            ("cache-control", "max-age=60"),
            ("connection", "close, X-Hop-Info"),
            ("x-hop-info", "1"),
            ("x-kept", "1"),
        ]);
        assert!(!stored.headers.contains_key("x-hop-info"));
        assert!(stored.headers.contains_key("x-kept"));
        let updated = stored.updated_by_304(
            &headers(&[
                ("connection", "x-hop-304"),
                ("x-hop-304", "1"),
                ("x-new", "1"),
            ]),
            at(1),
            at(1),
            &HeaderMap::new(),
        );
        assert!(!updated.headers.contains_key("x-hop-304"));
        assert!(updated.headers.contains_key("x-new"));
        let stored = entry(&[
            ("cache-control", "max-age=60"),
            ("proxy-authentication-info", "nextnonce=\"n\""),
        ]);

        // Nor does a 304 bring one in.
        let updated = stored.updated_by_304(
            &headers(&[("proxy-authentication-info", "nextnonce=\"m\"")]),
            at(1),
            at(1),
            &HeaderMap::new(),
        );
        assert!(!updated.headers.contains_key("proxy-authentication-info"));
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
            &HeaderMap::new(),
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
        let keys: Vec<CacheKey> = ["a", "b", "c"]
            .iter()
            .map(|p| {
                CacheKey::new(
                    &Method::GET,
                    &Url::parse(&format!("https://example.com/{p}")).unwrap(),
                )
            })
            .collect();
        // Budget for two entries and a bit.
        let cache = InMemoryHttpCache::with_limits(charge(&keys[0], &one) * 2 + 8, 1024);

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
        assert!(cache.byte_len() <= charge(&keys[0], &one) * 2 + 8);
    }

    /// Tiny bodies under long URLs are charged for the URL, so they cannot pile up past the
    /// budget in real memory.
    #[test]
    fn the_key_counts_against_the_budget() {
        let cache = InMemoryHttpCache::with_limits(64 * 1024, 1024);
        let one = entry(&[("cache-control", "max-age=60")]);
        for i in 0..1000 {
            let url = format!("https://example.com/{}?{}", i, "x".repeat(8 * 1024));
            cache.put(
                CacheKey::new(&Method::GET, &Url::parse(&url).unwrap()),
                one.clone(),
            );
        }
        assert!(cache.len() <= 8, "{} entries", cache.len());
        assert!(cache.byte_len() <= 64 * 1024);
    }

    #[test]
    fn invalidate_and_replace_keep_the_accounting_straight() {
        let cache = InMemoryHttpCache::with_limits(1024 * 1024, 64 * 1024);
        let k = key();
        let one = entry(&[("cache-control", "max-age=60")]);
        cache.put(k.clone(), one.clone());
        let charged = cache.byte_len();
        assert_eq!(charged, charge(&k, &one));
        // replacing the same variant does not double count
        cache.put(k.clone(), one.clone());
        assert_eq!(cache.byte_len(), charged);
        cache.invalidate(&k);
        assert_eq!(cache.byte_len(), 0);
        assert!(cache.is_empty());
    }

    /// Partitions do not see each other's entries, and an invalidation reaches all of them.
    #[test]
    fn partitions_are_separate_and_invalidated_together() {
        let cache = InMemoryHttpCache::new();
        let fresh = entry(&[("cache-control", "max-age=60")]);
        cache.put(key().in_partition("a"), fresh.clone());
        assert!(
            cache.get(&key()).is_empty(),
            "the shared partition does not see jar a's entry"
        );
        assert!(cache.get(&key().in_partition("b")).is_empty());
        cache.put(key().in_partition("b"), fresh.clone());
        cache.put(key(), fresh);
        assert_eq!(cache.len(), 3);

        cache.invalidate(&key());
        assert!(cache.is_empty(), "a write makes every jar's copy stale");
        assert_eq!(cache.byte_len(), 0);
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

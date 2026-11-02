//! The native-only half of CORS: the *CORS check*, preflight validation and the preflight
//! cache. On wasm32 the browser's `fetch()` enforces CORS itself, so none of this is built.

use super::{is_cors_safelisted_method, parse_token_list, CorsError};
use chrono::{DateTime, Utc};
use http::header::{self, HeaderMap};
use http::Method;
use std::time::Duration;
use url::Url;

/// The `Origin` serialization used in CORS comparisons: the ASCII serialization of the origin,
/// or the literal `null` once the redirect chain has tainted it (an opaque origin also
/// serializes as `null`).
pub(crate) fn serialize_origin(origin: &url::Origin, tainted: bool) -> String {
    if tainted {
        "null".to_string()
    } else {
        origin.ascii_serialization()
    }
}

/// The *CORS check* ([Fetch] §4.10.3), run against every response — including each redirect
/// hop's — once the request has left its origin in `cors` mode.
///
/// `credentials_include` is the request's credentials **mode**, not whether cookies were
/// actually attached on this hop: the spec keys the wildcard and allow-credentials rules on the
/// mode alone.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#concept-cors-check
pub(crate) fn cors_check(
    origin: &url::Origin,
    tainted: bool,
    credentials_include: bool,
    response: &HeaderMap,
) -> Result<(), CorsError> {
    let mut values = response.get_all(header::ACCESS_CONTROL_ALLOW_ORIGIN).iter();
    let Some(allow) = values.next() else {
        return Err(CorsError::MissingAllowOrigin);
    };
    // A duplicated header would compare as the joined list, which can never match an origin.
    if values.next().is_some() {
        return Err(CorsError::OriginMismatch);
    }
    if allow.as_bytes() == b"*" {
        return if credentials_include {
            Err(CorsError::WildcardWithCredentials)
        } else {
            Ok(())
        };
    }
    if allow.as_bytes() != serialize_origin(origin, tainted).as_bytes() {
        return Err(CorsError::OriginMismatch);
    }
    if !credentials_include {
        return Ok(());
    }
    // Fetch gets the header as one combined value, so a duplicate reads `true, true`, which is
    // not `true`: only a single line saying exactly `true` grants credentials.
    let mut values = response
        .get_all(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        .iter();
    match (values.next(), values.next()) {
        (Some(v), None) if v.as_bytes() == b"true" => Ok(()),
        _ => Err(CorsError::CredentialsNotAllowed),
    }
}

/// What a preflight response allowed, plus for how long it may be cached.
///
/// Produced by validating a preflight response; consulted (directly, or later out of a
/// [`CorsPreflightCache`]) via [`permits`](Self::permits).
#[derive(Debug, Clone)]
pub struct PreflightAllows {
    methods: Vec<String>,
    methods_wildcard: bool,
    headers: Vec<String>,
    headers_wildcard: bool,
    /// How long this entry may be cached: `Access-Control-Max-Age`, defaulted and capped.
    pub max_age: Duration,
}

/// `Access-Control-Max-Age` when the server sends none ([Fetch] §4.9: 5 seconds).
///
/// [Fetch]: https://fetch.spec.whatwg.org/
pub const DEFAULT_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(5);

/// Upper bound on `Access-Control-Max-Age`, matching Chromium's two-hour cap, so a
/// misconfigured server cannot pin a stale grant for days.
pub const MAX_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(2 * 60 * 60);

impl PreflightAllows {
    /// Whether these grants cover a request: its method and every one of its non-safelisted
    /// header names ([Fetch] §4.9 steps 7.5–7.7). The `*` wildcard only counts for a
    /// credential-less request, and `Authorization` must always be listed explicitly.
    ///
    /// [Fetch]: https://fetch.spec.whatwg.org/
    pub fn permits(
        &self,
        method: &Method,
        unsafe_header_names: &[String],
        credentials_include: bool,
    ) -> Result<(), CorsError> {
        let allowed = self.methods.iter().any(|m| m == method.as_str())
            || (self.methods_wildcard && !credentials_include)
            || is_cors_safelisted_method(method);
        if !allowed {
            return Err(CorsError::PreflightMethodRejected);
        }
        for name in unsafe_header_names {
            let listed = self.headers.iter().any(|h| h == name);
            let wildcard_ok =
                self.headers_wildcard && !credentials_include && name != "authorization";
            if !listed && !wildcard_ok {
                return Err(CorsError::PreflightHeaderRejected);
            }
        }
        Ok(())
    }
}

/// Validate a preflight response ([Fetch] §4.9 steps 6–7): ok status, the CORS check, then the
/// allow lists. The caller still has to test the actual request against the result with
/// [`PreflightAllows::permits`].
pub(crate) fn validate_preflight_response(
    status: u16,
    response: &HeaderMap,
    origin: &url::Origin,
    tainted: bool,
    credentials_include: bool,
) -> Result<PreflightAllows, CorsError> {
    if !(200..300).contains(&status) {
        return Err(CorsError::PreflightStatus);
    }
    cors_check(origin, tainted, credentials_include, response)?;
    let (methods, methods_wildcard) =
        parse_token_list(response, header::ACCESS_CONTROL_ALLOW_METHODS, false)?;
    let (headers, headers_wildcard) =
        parse_token_list(response, header::ACCESS_CONTROL_ALLOW_HEADERS, true)?;
    let max_age = preflight_max_age(response).min(MAX_PREFLIGHT_MAX_AGE);
    Ok(PreflightAllows {
        methods,
        methods_wildcard,
        headers,
        headers_wildcard,
        max_age,
    })
}

/// The `Access-Control-Max-Age` of a preflight response ([Fetch] §4.8 step 7.8): one value of
/// ASCII digits (`delta-seconds`). A duplicated header, a sign, a fraction or anything else is
/// a failure and gives the default of five seconds. A number too large to hold saturates.
fn preflight_max_age(response: &HeaderMap) -> Duration {
    let mut values = response.get_all(header::ACCESS_CONTROL_MAX_AGE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return DEFAULT_PREFLIGHT_MAX_AGE;
    };
    let digits = value.as_bytes().trim_ascii();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return DEFAULT_PREFLIGHT_MAX_AGE;
    }
    let seconds = std::str::from_utf8(digits)
        .ok()
        .and_then(|d| d.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds)
}

/// The request headers a preflight `OPTIONS` carries ([Fetch] §4.9 steps 1–2). The fetcher
/// adds `Origin` and the `Sec-Fetch-*` set on top through its normal per-hop machinery.
pub(crate) fn preflight_request_headers(
    method: &Method,
    unsafe_header_names: &[String],
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, http::HeaderValue::from_static("*/*"));
    if let Ok(v) = method.as_str().parse() {
        headers.insert(header::ACCESS_CONTROL_REQUEST_METHOD, v);
    }
    if !unsafe_header_names.is_empty() {
        if let Ok(v) = unsafe_header_names.join(",").parse() {
            headers.insert(header::ACCESS_CONTROL_REQUEST_HEADERS, v);
        }
    }
    headers
}

/// Cache of preflight grants, keyed per (serialized origin, URL, credentials flag) — the
/// [Fetch] §4.9.1 *CORS-preflight cache*, collapsed to one entry per key like browsers do.
///
/// The crate owns the protocol (validation, `Access-Control-Max-Age`, expiry); an
/// implementation only has to behave like a map. The default is [`InMemoryPreflightCache`];
/// supply your own to share or inspect grants, or set the config field to `None` to preflight
/// every time.
///
/// [Fetch]: https://fetch.spec.whatwg.org/
pub trait CorsPreflightCache: Send + Sync {
    /// Look up an unexpired grant. `now` is the fetcher's clock; return `None` for entries
    /// that have expired.
    fn get(
        &self,
        origin: &str,
        url: &Url,
        credentials: bool,
        now: DateTime<Utc>,
    ) -> Option<PreflightAllows>;

    /// Store a grant. `allows.max_age` is already defaulted and capped; the entry expires at
    /// `now + allows.max_age`, replacing any previous entry for the key.
    fn put(
        &self,
        origin: &str,
        url: &Url,
        credentials: bool,
        allows: PreflightAllows,
        now: DateTime<Utc>,
    );

    /// Drop the grants for `origin` and `url`, with and without credentials ([Fetch] §4.9,
    /// "clear cache entries"). Called when a request that relied on a grant ended in a network
    /// error, so the server is asked again next time rather than trusted for up to the grant's
    /// `max-age` after it may have changed its mind. The default does nothing, for a cache
    /// that cannot remove entries.
    ///
    /// [Fetch]: https://fetch.spec.whatwg.org/#concept-cache-clear
    fn clear(&self, _origin: &str, _url: &Url) {}
}

/// In-process [`CorsPreflightCache`] with no persistence; expired entries are pruned on
/// insertion, and past [`MAX_PREFLIGHT_ENTRIES`] the grant expiring soonest is dropped.
#[derive(Default)]
pub struct InMemoryPreflightCache {
    entries: parking_lot::RwLock<std::collections::HashMap<PreflightKey, PreflightEntry>>,
}

/// Most grants an [`InMemoryPreflightCache`] holds.
pub const MAX_PREFLIGHT_ENTRIES: usize = 1024;

/// (serialized origin, URL without fragment, credentials flag).
type PreflightKey = (String, String, bool);

/// A grant and the instant it expires.
type PreflightEntry = (PreflightAllows, DateTime<Utc>);

impl InMemoryPreflightCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fragments never reach the server, so they must not split cache entries.
    fn key(origin: &str, url: &Url, credentials: bool) -> PreflightKey {
        let mut url = url.clone();
        url.set_fragment(None);
        (origin.to_string(), url.to_string(), credentials)
    }
}

impl CorsPreflightCache for InMemoryPreflightCache {
    fn get(
        &self,
        origin: &str,
        url: &Url,
        credentials: bool,
        now: DateTime<Utc>,
    ) -> Option<PreflightAllows> {
        let entries = self.entries.read();
        let (allows, expires) = entries.get(&Self::key(origin, url, credentials))?;
        (*expires > now).then(|| allows.clone())
    }

    fn put(
        &self,
        origin: &str,
        url: &Url,
        credentials: bool,
        allows: PreflightAllows,
        now: DateTime<Utc>,
    ) {
        // `max_age` is capped at MAX_PREFLIGHT_MAX_AGE, so the conversion cannot overflow;
        // zero (an already-expired entry) is the safe direction if that ever changes.
        let expires =
            now + chrono::TimeDelta::from_std(allows.max_age).unwrap_or(chrono::TimeDelta::zero());
        let mut entries = self.entries.write();
        entries.retain(|_, (_, exp)| *exp > now);
        let key = Self::key(origin, url, credentials);
        if entries.len() >= MAX_PREFLIGHT_ENTRIES && !entries.contains_key(&key) {
            if let Some(soonest) = entries
                .iter()
                .min_by_key(|(_, (_, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&soonest);
            }
        }
        entries.insert(key, (allows, expires));
    }

    fn clear(&self, origin: &str, url: &Url) {
        let mut entries = self.entries.write();
        for credentials in [false, true] {
            entries.remove(&Self::key(origin, url, credentials));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preflight_cache_is_bounded() {
        let cache = InMemoryPreflightCache::new();
        let now = Utc::now();
        let allows = |secs: u64| PreflightAllows {
            methods: Vec::new(),
            methods_wildcard: false,
            headers: Vec::new(),
            headers_wildcard: false,
            max_age: Duration::from_secs(secs),
        };
        for i in 0..MAX_PREFLIGHT_ENTRIES {
            let url = Url::parse(&format!("https://api.test/{i}")).unwrap();
            // entry 0 expires soonest
            cache.put("https://a.test", &url, false, allows(100 + i as u64), now);
        }
        let extra = Url::parse("https://api.test/extra").unwrap();
        cache.put("https://a.test", &extra, false, allows(1000), now);
        assert_eq!(cache.entries.read().len(), MAX_PREFLIGHT_ENTRIES);
        let first = Url::parse("https://api.test/0").unwrap();
        assert!(cache.get("https://a.test", &first, false, now).is_none());
        assert!(cache.get("https://a.test", &extra, false, now).is_some());
    }

    /// Fetch §4.9, clear cache entries: both grants for the origin and URL go, with and without
    /// credentials; others stay.
    #[test]
    fn clear_drops_the_grants_for_one_origin_and_url() {
        let cache = InMemoryPreflightCache::new();
        let now = Utc::now();
        let allows = PreflightAllows {
            methods: Vec::new(),
            methods_wildcard: false,
            headers: Vec::new(),
            headers_wildcard: false,
            max_age: Duration::from_secs(600),
        };
        let url = Url::parse("https://api.test/x").unwrap();
        let other = Url::parse("https://api.test/y").unwrap();
        for credentials in [false, true] {
            cache.put("https://a.test", &url, credentials, allows.clone(), now);
        }
        cache.put("https://a.test", &other, false, allows.clone(), now);
        cache.put("https://b.test", &url, false, allows, now);

        cache.clear("https://a.test", &url);
        assert!(cache.get("https://a.test", &url, false, now).is_none());
        assert!(cache.get("https://a.test", &url, true, now).is_none());
        assert!(cache.get("https://a.test", &other, false, now).is_some());
        assert!(cache.get("https://b.test", &url, false, now).is_some());
    }
}

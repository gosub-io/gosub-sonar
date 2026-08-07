//! CORS — Cross-Origin Resource Sharing ([Fetch] §3.2, §4.9–4.10).
//!
//! This module holds the pure spec logic: the safelist predicates, the *CORS check* run against
//! response headers, preflight response validation, and the `Access-Control-Expose-Headers`
//! response filter. The fetcher wires these into its redirect loop; nothing here performs I/O.
//!
//! The crate owns the mechanism — the CORS check must run on every redirect hop's response,
//! and only the fetcher sees intermediate hops. The embedder owns the policy through the
//! request fields that feed these checks:
//!
//! - No [`FetchRequest::origin`](crate::FetchRequest::origin) → CORS is entirely inert, like
//!   mixed content.
//! - [`RequestMode`](crate::RequestMode) selects the regime: `SameOrigin` refuses cross-origin
//!   targets, `NoCors` restricts methods/headers and yields an [opaque](ResponseTainting::Opaque)
//!   response, `Cors` runs the full check + preflight. `Navigate` and `Websocket` are exempt
//!   (navigations are not CORS-checked; a WebSocket server opts in via its own handshake).
//! - [`RequestCredentials`](crate::net::types::RequestCredentials) decides whether cookies ride
//!   along and how strict the allow-origin match must be.
//!
//! Enforcement fails requests the spec says must fail; it never hides data from the embedder.
//! What a script may read from a response that survived is described by [`ResponseTainting`] on
//! [`FetchResultMeta`](crate::FetchResultMeta) plus [`readable_headers`] — enforcing that
//! visibility boundary (and body-sniffing policies like ORB on top of it) is the embedder's job.
//!
//! Native-only: on wasm32 the browser's `fetch()` enforces CORS itself and does not expose the
//! `Access-Control-*` headers these checks would need, so the fetcher skips them there.
//!
//! [Fetch]: https://fetch.spec.whatwg.org/

#[cfg(not(target_arch = "wasm32"))]
use chrono::{DateTime, Utc};
use http::header::{self, HeaderMap, HeaderName};
use http::Method;
use std::fmt::Display;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use url::Url;

/// Why a request failed CORS. Carried by
/// [`BlockReason::Cors`](crate::net::types::BlockReason::Cors).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CorsError {
    /// The response carried no `Access-Control-Allow-Origin` header.
    MissingAllowOrigin,
    /// `Access-Control-Allow-Origin` did not match the request's origin (or the header
    /// appeared more than once, which can never match).
    OriginMismatch,
    /// `Access-Control-Allow-Origin: *` cannot authorize a credentialed request.
    WildcardWithCredentials,
    /// The request carried credentials but `Access-Control-Allow-Credentials: true` was absent.
    CredentialsNotAllowed,
    /// The request's mode is [`SameOrigin`](crate::RequestMode::SameOrigin) but a hop targeted
    /// another origin.
    SameOriginMode,
    /// A cross-origin [`NoCors`](crate::RequestMode::NoCors) request used a method other than
    /// GET, HEAD, or POST.
    UnsafeMethodForNoCors,
    /// A cross-origin [`NoCors`](crate::RequestMode::NoCors) request carried a header that is
    /// neither CORS-safelisted nor set by the fetcher itself.
    UnsafeHeaderForNoCors,
    /// The preflight response status was not in the 2xx range.
    PreflightStatus,
    /// `Access-Control-Allow-Methods` or `Access-Control-Allow-Headers` could not be parsed.
    PreflightInvalidResponse,
    /// The preflight response did not allow the request's method.
    PreflightMethodRejected,
    /// The preflight response did not allow one of the request's non-safelisted headers.
    PreflightHeaderRejected,
    /// A redirect `Location` carried embedded `user:password` credentials — refused in cors
    /// mode, and cross-origin in any mode.
    CredentialedRedirect,
}

impl Display for CorsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::MissingAllowOrigin => "no Access-Control-Allow-Origin header",
            Self::OriginMismatch => "Access-Control-Allow-Origin does not match the origin",
            Self::WildcardWithCredentials => {
                "Access-Control-Allow-Origin '*' cannot authorize a credentialed request"
            }
            Self::CredentialsNotAllowed => "Access-Control-Allow-Credentials is not 'true'",
            Self::SameOriginMode => "same-origin mode request targeted another origin",
            Self::UnsafeMethodForNoCors => "method not allowed for a cross-origin no-cors request",
            Self::UnsafeHeaderForNoCors => "header not allowed for a cross-origin no-cors request",
            Self::PreflightStatus => "preflight response status was not ok",
            Self::PreflightInvalidResponse => "preflight response headers could not be parsed",
            Self::PreflightMethodRejected => "method not allowed by preflight response",
            Self::PreflightHeaderRejected => "header not allowed by preflight response",
            Self::CredentialedRedirect => "redirect URL with embedded credentials",
        };
        f.write_str(s)
    }
}

/// How much of a response the initiating document's scripts may read ([Fetch] §2.2.5,
/// *response tainting*).
///
/// The fetcher only *annotates* — the full response is always handed to the embedder, because
/// the embedder itself must be able to render an opaque `<img>` or feed a body sniffer. The
/// embedder enforces the visibility boundary using this value, typically via
/// [`FetchResultMeta::readable_headers`](crate::FetchResultMeta::readable_headers).
///
/// [Fetch]: https://fetch.spec.whatwg.org/#concept-request-response-tainting
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum ResponseTainting {
    /// Same-origin (or no document context): everything is readable except `Set-Cookie`.
    #[default]
    Basic,
    /// A cross-origin CORS response: readable up to the CORS-safelisted response headers plus
    /// whatever `Access-Control-Expose-Headers` names.
    Cors,
    /// A cross-origin `no-cors` response: scripts may observe that it exists, nothing more.
    Opaque,
}

/// The `Origin` serialization used in CORS comparisons: the ASCII serialization of the origin,
/// or the literal `null` once the redirect chain has tainted it (an opaque origin also
/// serializes as `null`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn serialize_origin(origin: &url::Origin, tainted: bool) -> String {
    if tainted {
        "null".to_string()
    } else {
        origin.ascii_serialization()
    }
}

/// CORS-safelisted method ([Fetch] §2.2.1): may go cross-origin without a preflight.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#cors-safelisted-method
pub fn is_cors_safelisted_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::POST)
}

/// A CORS-unsafe request-header byte ([Fetch] §2.2.2).
fn is_cors_unsafe_header_byte(b: u8) -> bool {
    matches!(b,
        0x00..=0x08 | 0x0A..=0x1F | 0x22 | 0x28 | 0x29 | 0x3A | 0x3C |
        0x3E | 0x3F | 0x40 | 0x5B..=0x5D | 0x7B | 0x7D | 0x7F)
}

/// CORS-safelisted request header ([Fetch] §2.2.2): a name/value pair that may go cross-origin
/// without being listed in a preflight response.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#cors-safelisted-request-header
pub fn is_cors_safelisted_request_header(name: &HeaderName, value: &[u8]) -> bool {
    if value.len() > 128 {
        return false;
    }
    match name.as_str() {
        "accept" => !value.iter().copied().any(is_cors_unsafe_header_byte),
        "accept-language" | "content-language" => value.iter().all(|b| {
            matches!(b,
                0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A |
                0x20 | 0x2A | 0x2C | 0x2D | 0x2E | 0x3B | 0x3D)
        }),
        "content-type" => {
            if value.iter().copied().any(is_cors_unsafe_header_byte) {
                return false;
            }
            let Ok(s) = std::str::from_utf8(value) else {
                return false;
            };
            let essence = s
                .split(';')
                .next()
                .unwrap_or("")
                .trim_matches([' ', '\t'])
                .to_ascii_lowercase();
            matches!(
                essence.as_str(),
                "application/x-www-form-urlencoded" | "multipart/form-data" | "text/plain"
            )
        }
        // A single `bytes=m-n` / `bytes=m-` range (media loads); `bytes=-m` is not safelisted.
        "range" => {
            let Some(rest) = value.strip_prefix(b"bytes=") else {
                return false;
            };
            let Ok(rest) = std::str::from_utf8(rest) else {
                return false;
            };
            match rest.split_once('-') {
                Some((start, end)) => {
                    !start.is_empty()
                        && start.bytes().all(|b| b.is_ascii_digit())
                        && end.bytes().all(|b| b.is_ascii_digit())
                }
                None => false,
            }
        }
        _ => false,
    }
}

/// Forbidden request header ([Fetch] §2.2.2): controlled by the user agent — here, by the
/// fetcher itself (`Referer`, `Origin`, `Cookie`, `Sec-Fetch-*`, …). These never count toward
/// the preflight decision: a browser sets them on cross-origin requests without asking either.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#forbidden-request-header
pub fn is_forbidden_request_header(name: &HeaderName) -> bool {
    let n = name.as_str();
    n.starts_with("proxy-")
        || n.starts_with("sec-")
        || matches!(
            n,
            "accept-charset"
                | "accept-encoding"
                | "access-control-request-headers"
                | "access-control-request-method"
                | "connection"
                | "content-length"
                | "cookie"
                | "cookie2"
                | "date"
                | "dnt"
                | "expect"
                | "host"
                | "keep-alive"
                | "origin"
                | "referer"
                | "set-cookie"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "via"
        )
}

/// The caller-set header names that a preflight must get approved: not forbidden (the fetcher
/// owns those) and not CORS-safelisted for the value they carry. Lowercase, sorted, deduplicated
/// — the exact list sent in `Access-Control-Request-Headers`.
pub(crate) fn unsafe_request_header_names(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<String> = headers
        .iter()
        .filter(|(name, value)| {
            !is_forbidden_request_header(name)
                && !is_cors_safelisted_request_header(name, value.as_bytes())
        })
        .map(|(name, _)| name.as_str().to_string())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether a cross-origin CORS-mode request with this method and these headers needs a
/// preflight before it may be sent.
pub fn preflight_needed(method: &Method, headers: &HeaderMap) -> bool {
    !is_cors_safelisted_method(method) || !unsafe_request_header_names(headers).is_empty()
}

/// The *CORS check* ([Fetch] §4.10.3), run against every response — including each redirect
/// hop's — once the request has left its origin in `cors` mode.
///
/// `credentials_include` is the request's credentials **mode**, not whether cookies were
/// actually attached on this hop: the spec keys the wildcard and allow-credentials rules on the
/// mode alone.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#concept-cors-check
#[cfg(not(target_arch = "wasm32"))]
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
    match response.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS) {
        Some(v) if v.as_bytes() == b"true" => Ok(()),
        _ => Err(CorsError::CredentialsNotAllowed),
    }
}

/// What a preflight response allowed, plus for how long it may be cached.
///
/// Produced by validating a preflight response; consulted (directly, or later out of a
/// [`CorsPreflightCache`]) via [`permits`](Self::permits).
#[cfg(not(target_arch = "wasm32"))]
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
#[cfg(not(target_arch = "wasm32"))]
pub const DEFAULT_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(5);
/// Upper bound on `Access-Control-Max-Age`, matching Chromium's two-hour cap, so a
/// misconfigured server cannot pin a stale grant for days.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(2 * 60 * 60);

#[cfg(not(target_arch = "wasm32"))]
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

/// Parse one `Access-Control-Allow-{Methods,Headers}` header list: comma-separated tokens
/// across any number of field lines. Returns the tokens (lowercased when `lowercase`) and
/// whether `*` was among them; a non-token member fails the whole parse, as the spec demands.
fn parse_token_list(
    response: &HeaderMap,
    name: HeaderName,
    lowercase: bool,
) -> Result<(Vec<String>, bool), CorsError> {
    let mut items = Vec::new();
    let mut wildcard = false;
    for value in response.get_all(&name) {
        let s = value
            .to_str()
            .map_err(|_| CorsError::PreflightInvalidResponse)?;
        for item in s.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if item.is_empty() {
                continue;
            }
            if item == "*" {
                wildcard = true;
                continue;
            }
            let is_token = item.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            });
            if !is_token {
                return Err(CorsError::PreflightInvalidResponse);
            }
            items.push(if lowercase {
                item.to_ascii_lowercase()
            } else {
                item.to_string()
            });
        }
    }
    Ok((items, wildcard))
}

/// Validate a preflight response ([Fetch] §4.9 steps 6–7): ok status, the CORS check, then the
/// allow lists. The caller still has to test the actual request against the result with
/// [`PreflightAllows::permits`].
#[cfg(not(target_arch = "wasm32"))]
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
    let max_age = response
        .get(header::ACCESS_CONTROL_MAX_AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(DEFAULT_PREFLIGHT_MAX_AGE, Duration::from_secs)
        .min(MAX_PREFLIGHT_MAX_AGE);
    Ok(PreflightAllows {
        methods,
        methods_wildcard,
        headers,
        headers_wildcard,
        max_age,
    })
}

/// The request headers a preflight `OPTIONS` carries ([Fetch] §4.9 steps 1–2). The fetcher
/// adds `Origin` and the `Sec-Fetch-*` set on top through its normal per-hop machinery.
#[cfg(not(target_arch = "wasm32"))]
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

/// CORS-safelisted response headers ([Fetch] §2.2.3): always readable from a `cors`-tainted
/// response, even without `Access-Control-Expose-Headers`.
const CORS_SAFELISTED_RESPONSE_HEADERS: [&str; 7] = [
    "cache-control",
    "content-language",
    "content-length",
    "content-type",
    "expires",
    "last-modified",
    "pragma",
];

/// The header view scripts may read, given a response's tainting ([Fetch] §4.10.2, *filtered
/// response*). The full header map stays on the metadata — this is the embedder-facing filter,
/// not a mutation.
///
/// `Set-Cookie` is never readable. An unparseable `Access-Control-Expose-Headers` exposes
/// nothing beyond the safelist; its `*` wildcard only counts for credential-less requests.
///
/// [Fetch]: https://fetch.spec.whatwg.org/
pub fn readable_headers(
    tainting: ResponseTainting,
    headers: &HeaderMap,
    credentials_include: bool,
) -> HeaderMap {
    let keep_all_but_cookies = |headers: &HeaderMap| {
        let mut out = HeaderMap::new();
        for (name, value) in headers {
            if name != header::SET_COOKIE && name.as_str() != "set-cookie2" {
                out.append(name.clone(), value.clone());
            }
        }
        out
    };
    match tainting {
        ResponseTainting::Basic => keep_all_but_cookies(headers),
        ResponseTainting::Opaque => HeaderMap::new(),
        ResponseTainting::Cors => {
            let (exposed, wildcard) =
                parse_token_list(headers, header::ACCESS_CONTROL_EXPOSE_HEADERS, true)
                    .unwrap_or((Vec::new(), false));
            if wildcard && !credentials_include {
                return keep_all_but_cookies(headers);
            }
            let mut out = HeaderMap::new();
            for (name, value) in headers {
                let n = name.as_str();
                if CORS_SAFELISTED_RESPONSE_HEADERS.contains(&n)
                    || (exposed.iter().any(|e| e == n) && n != "set-cookie" && n != "set-cookie2")
                {
                    out.append(name.clone(), value.clone());
                }
            }
            out
        }
    }
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
#[cfg(not(target_arch = "wasm32"))]
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
}

/// In-process [`CorsPreflightCache`] with no persistence; expired entries are pruned on
/// insertion.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub struct InMemoryPreflightCache {
    entries: parking_lot::RwLock<std::collections::HashMap<PreflightKey, PreflightEntry>>,
}

/// (serialized origin, URL without fragment, credentials flag).
#[cfg(not(target_arch = "wasm32"))]
type PreflightKey = (String, String, bool);
/// A grant and the instant it expires.
#[cfg(not(target_arch = "wasm32"))]
type PreflightEntry = (PreflightAllows, DateTime<Utc>);

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
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
        entries.insert(Self::key(origin, url, credentials), (allows, expires));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn origin(s: &str) -> url::Origin {
        Url::parse(s).unwrap().origin()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    // --- safelisted methods / headers ---

    #[test]
    fn safelisted_methods() {
        assert!(is_cors_safelisted_method(&Method::GET));
        assert!(is_cors_safelisted_method(&Method::HEAD));
        assert!(is_cors_safelisted_method(&Method::POST));
        assert!(!is_cors_safelisted_method(&Method::PUT));
        assert!(!is_cors_safelisted_method(&Method::DELETE));
        assert!(!is_cors_safelisted_method(&Method::PATCH));
    }

    #[test]
    fn safelisted_headers_by_name_and_value() {
        let n = |s: &str| HeaderName::from_bytes(s.as_bytes()).unwrap();
        assert!(is_cors_safelisted_request_header(
            &n("accept"),
            b"text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
        ));
        // A CORS-unsafe byte in Accept.
        assert!(!is_cors_safelisted_request_header(&n("accept"), b"a\"b"));
        assert!(is_cors_safelisted_request_header(
            &n("accept-language"),
            b"en-US,en;q=0.9"
        ));
        // Slash is outside accept-language's byte allowlist.
        assert!(!is_cors_safelisted_request_header(
            &n("accept-language"),
            b"en/US"
        ));
        assert!(is_cors_safelisted_request_header(
            &n("content-type"),
            b"text/plain;charset=UTF-8"
        ));
        assert!(is_cors_safelisted_request_header(
            &n("content-type"),
            b"MULTIPART/FORM-DATA; boundary=x"
        ));
        assert!(!is_cors_safelisted_request_header(
            &n("content-type"),
            b"application/json"
        ));
        assert!(is_cors_safelisted_request_header(&n("range"), b"bytes=0-"));
        assert!(is_cors_safelisted_request_header(
            &n("range"),
            b"bytes=200-1000"
        ));
        assert!(!is_cors_safelisted_request_header(
            &n("range"),
            b"bytes=-500"
        ));
        assert!(!is_cors_safelisted_request_header(
            &n("range"),
            b"bytes=0-50,100-150"
        ));
        assert!(!is_cors_safelisted_request_header(&n("x-custom"), b"1"));
        // Over the 128-byte value cap.
        let long = vec![b'a'; 129];
        assert!(!is_cors_safelisted_request_header(&n("accept"), &long));
    }

    #[test]
    fn unsafe_names_skip_forbidden_and_safelisted() {
        let h = headers(&[
            ("accept", "*/*"),
            ("cookie", "a=1"),
            ("referer", "https://a.example/"),
            ("sec-fetch-mode", "cors"),
            ("x-custom", "1"),
            ("authorization", "Bearer t"),
            ("content-type", "application/json"),
        ]);
        assert_eq!(
            unsafe_request_header_names(&h),
            vec!["authorization", "content-type", "x-custom"]
        );
    }

    #[test]
    fn preflight_needed_on_method_or_header() {
        let plain = headers(&[("accept", "*/*")]);
        assert!(!preflight_needed(&Method::GET, &plain));
        assert!(!preflight_needed(&Method::POST, &plain));
        assert!(preflight_needed(&Method::PUT, &plain));
        assert!(preflight_needed(
            &Method::GET,
            &headers(&[("x-custom", "1")])
        ));
        assert!(preflight_needed(
            &Method::POST,
            &headers(&[("content-type", "application/json")])
        ));
    }

    // --- CORS check ---

    #[test]
    fn cors_check_matches_origin() {
        let o = origin("https://a.example");
        let ok = headers(&[("access-control-allow-origin", "https://a.example")]);
        assert_eq!(cors_check(&o, false, false, &ok), Ok(()));
        assert_eq!(
            cors_check(&o, false, false, &HeaderMap::new()),
            Err(CorsError::MissingAllowOrigin)
        );
        let wrong = headers(&[("access-control-allow-origin", "https://b.example")]);
        assert_eq!(
            cors_check(&o, false, false, &wrong),
            Err(CorsError::OriginMismatch)
        );
        // Scheme and port are part of the origin.
        let http = headers(&[("access-control-allow-origin", "http://a.example")]);
        assert_eq!(
            cors_check(&o, false, false, &http),
            Err(CorsError::OriginMismatch)
        );
    }

    #[test]
    fn cors_check_wildcard_only_without_credentials() {
        let o = origin("https://a.example");
        let star = headers(&[("access-control-allow-origin", "*")]);
        assert_eq!(cors_check(&o, false, false, &star), Ok(()));
        assert_eq!(
            cors_check(&o, false, true, &star),
            Err(CorsError::WildcardWithCredentials)
        );
    }

    #[test]
    fn cors_check_credentials_require_allow_credentials_true() {
        let o = origin("https://a.example");
        let no_cred = headers(&[("access-control-allow-origin", "https://a.example")]);
        assert_eq!(
            cors_check(&o, false, true, &no_cred),
            Err(CorsError::CredentialsNotAllowed)
        );
        let ok = headers(&[
            ("access-control-allow-origin", "https://a.example"),
            ("access-control-allow-credentials", "true"),
        ]);
        assert_eq!(cors_check(&o, false, true, &ok), Ok(()));
        // Exact, case-sensitive match per spec.
        let bad_case = headers(&[
            ("access-control-allow-origin", "https://a.example"),
            ("access-control-allow-credentials", "True"),
        ]);
        assert_eq!(
            cors_check(&o, false, true, &bad_case),
            Err(CorsError::CredentialsNotAllowed)
        );
    }

    #[test]
    fn cors_check_tainted_origin_matches_null() {
        let o = origin("https://a.example");
        let null = headers(&[("access-control-allow-origin", "null")]);
        assert_eq!(cors_check(&o, true, false, &null), Ok(()));
        let real = headers(&[("access-control-allow-origin", "https://a.example")]);
        assert_eq!(
            cors_check(&o, true, false, &real),
            Err(CorsError::OriginMismatch)
        );
    }

    #[test]
    fn cors_check_duplicate_allow_origin_fails() {
        let mut h = headers(&[("access-control-allow-origin", "https://a.example")]);
        h.append(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://a.example"),
        );
        assert_eq!(
            cors_check(&origin("https://a.example"), false, false, &h),
            Err(CorsError::OriginMismatch)
        );
    }

    // --- preflight response validation ---

    fn ok_preflight(extra: &[(&str, &str)]) -> HeaderMap {
        let mut h = headers(&[("access-control-allow-origin", "https://a.example")]);
        for (name, value) in extra {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    #[test]
    fn preflight_rejects_non_ok_status() {
        let o = origin("https://a.example");
        assert_eq!(
            validate_preflight_response(403, &ok_preflight(&[]), &o, false, false).unwrap_err(),
            CorsError::PreflightStatus
        );
        assert_eq!(
            validate_preflight_response(301, &ok_preflight(&[]), &o, false, false).unwrap_err(),
            CorsError::PreflightStatus
        );
    }

    #[test]
    fn preflight_allows_listed_method_and_headers() {
        let o = origin("https://a.example");
        let resp = ok_preflight(&[
            ("access-control-allow-methods", "PUT, DELETE"),
            ("access-control-allow-headers", "X-Custom, Content-Type"),
        ]);
        let allows = validate_preflight_response(204, &resp, &o, false, false).unwrap();
        assert_eq!(
            allows.permits(&Method::PUT, &["x-custom".into()], false),
            Ok(())
        );
        assert_eq!(
            allows.permits(&Method::PATCH, &[], false),
            Err(CorsError::PreflightMethodRejected)
        );
        assert_eq!(
            allows.permits(&Method::PUT, &["x-other".into()], false),
            Err(CorsError::PreflightHeaderRejected)
        );
        // Safelisted methods pass even when unlisted.
        assert_eq!(allows.permits(&Method::POST, &[], false), Ok(()));
    }

    #[test]
    fn preflight_wildcard_rules() {
        let o = origin("https://a.example");
        let resp = ok_preflight(&[
            ("access-control-allow-methods", "*"),
            ("access-control-allow-headers", "*"),
        ]);
        let allows = validate_preflight_response(200, &resp, &o, false, false).unwrap();
        assert_eq!(
            allows.permits(&Method::DELETE, &["x-custom".into()], false),
            Ok(())
        );
        // The wildcard never covers Authorization.
        assert_eq!(
            allows.permits(&Method::GET, &["authorization".into()], false),
            Err(CorsError::PreflightHeaderRejected)
        );
        // With credentials, `*` is a literal token, not a wildcard.
        assert_eq!(
            allows.permits(&Method::DELETE, &[], true),
            Err(CorsError::PreflightMethodRejected)
        );
    }

    #[test]
    fn preflight_invalid_token_fails_parse() {
        let o = origin("https://a.example");
        let resp = ok_preflight(&[("access-control-allow-methods", "PUT, DEL ETE")]);
        assert_eq!(
            validate_preflight_response(200, &resp, &o, false, false).unwrap_err(),
            CorsError::PreflightInvalidResponse
        );
    }

    #[test]
    fn preflight_max_age_defaulted_and_capped() {
        let o = origin("https://a.example");
        let allows =
            validate_preflight_response(200, &ok_preflight(&[]), &o, false, false).unwrap();
        assert_eq!(allows.max_age, DEFAULT_PREFLIGHT_MAX_AGE);
        let resp = ok_preflight(&[("access-control-max-age", "600")]);
        let allows = validate_preflight_response(200, &resp, &o, false, false).unwrap();
        assert_eq!(allows.max_age, Duration::from_secs(600));
        let resp = ok_preflight(&[("access-control-max-age", "999999999")]);
        let allows = validate_preflight_response(200, &resp, &o, false, false).unwrap();
        assert_eq!(allows.max_age, MAX_PREFLIGHT_MAX_AGE);
    }

    #[test]
    fn preflight_request_headers_shape() {
        let h = preflight_request_headers(&Method::PUT, &["x-custom".into(), "x-other".into()]);
        assert_eq!(h.get(header::ACCEPT).unwrap(), "*/*");
        assert_eq!(h.get(header::ACCESS_CONTROL_REQUEST_METHOD).unwrap(), "PUT");
        assert_eq!(
            h.get(header::ACCESS_CONTROL_REQUEST_HEADERS).unwrap(),
            "x-custom,x-other"
        );
        let h = preflight_request_headers(&Method::PUT, &[]);
        assert!(h.get(header::ACCESS_CONTROL_REQUEST_HEADERS).is_none());
    }

    // --- response filtering ---

    #[test]
    fn readable_headers_by_tainting() {
        let resp = headers(&[
            ("content-type", "text/html"),
            ("x-request-id", "42"),
            ("set-cookie", "session=s"),
        ]);
        let basic = readable_headers(ResponseTainting::Basic, &resp, false);
        assert!(basic.get("content-type").is_some());
        assert!(basic.get("x-request-id").is_some());
        assert!(basic.get("set-cookie").is_none());

        let cors = readable_headers(ResponseTainting::Cors, &resp, false);
        assert!(cors.get("content-type").is_some());
        assert!(cors.get("x-request-id").is_none());
        assert!(cors.get("set-cookie").is_none());

        let opaque = readable_headers(ResponseTainting::Opaque, &resp, false);
        assert!(opaque.is_empty());
    }

    #[test]
    fn expose_headers_extends_cors_view() {
        let resp = headers(&[
            ("x-request-id", "42"),
            ("x-secret", "s"),
            ("access-control-expose-headers", "X-Request-Id"),
        ]);
        let cors = readable_headers(ResponseTainting::Cors, &resp, false);
        assert!(cors.get("x-request-id").is_some());
        assert!(cors.get("x-secret").is_none());
    }

    #[test]
    fn expose_headers_wildcard_only_without_credentials() {
        let resp = headers(&[
            ("x-request-id", "42"),
            ("set-cookie", "session=s"),
            ("access-control-expose-headers", "*"),
        ]);
        let no_creds = readable_headers(ResponseTainting::Cors, &resp, false);
        assert!(no_creds.get("x-request-id").is_some());
        assert!(no_creds.get("set-cookie").is_none());
        let creds = readable_headers(ResponseTainting::Cors, &resp, true);
        assert!(creds.get("x-request-id").is_none());
    }

    // --- preflight cache ---

    #[test]
    fn cache_roundtrip_and_expiry() {
        let cache = InMemoryPreflightCache::new();
        let url = Url::parse("https://api.example/data").unwrap();
        let o = origin("https://a.example");
        let resp = ok_preflight(&[
            ("access-control-allow-methods", "PUT"),
            ("access-control-max-age", "60"),
        ]);
        let allows = validate_preflight_response(200, &resp, &o, false, false).unwrap();
        let now = Utc::now();
        cache.put("https://a.example", &url, false, allows, now);

        let hit = cache.get("https://a.example", &url, false, now).unwrap();
        assert_eq!(hit.permits(&Method::PUT, &[], false), Ok(()));
        // Distinct key dimensions miss.
        assert!(cache.get("https://b.example", &url, false, now).is_none());
        assert!(cache.get("https://a.example", &url, true, now).is_none());
        // Fragments do not split entries.
        let frag = Url::parse("https://api.example/data#frag").unwrap();
        assert!(cache.get("https://a.example", &frag, false, now).is_some());
        // Expired entries are not returned.
        let later = now + chrono::TimeDelta::seconds(61);
        assert!(cache.get("https://a.example", &url, false, later).is_none());
    }

    #[test]
    fn origin_serialization() {
        assert_eq!(
            serialize_origin(&origin("https://a.example"), false),
            "https://a.example"
        );
        assert_eq!(serialize_origin(&origin("https://a.example"), true), "null");
        // Ports appear, default ports do not.
        assert_eq!(
            serialize_origin(&origin("https://a.example:8443"), false),
            "https://a.example:8443"
        );
    }
}

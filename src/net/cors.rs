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

use http::header::{self, HeaderMap, HeaderName};
use http::Method;
use std::fmt::Display;

#[cfg(not(target_arch = "wasm32"))]
mod preflight;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use preflight::{
    cors_check, preflight_request_headers, serialize_origin, validate_preflight_response,
};
#[cfg(not(target_arch = "wasm32"))]
pub use preflight::{
    CorsPreflightCache, InMemoryPreflightCache, PreflightAllows, DEFAULT_PREFLIGHT_MAX_AGE,
    MAX_PREFLIGHT_ENTRIES, MAX_PREFLIGHT_MAX_AGE,
};

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
            // Isomorphic decode, one byte to one char, as Fetch has it: a parameter may carry
            // bytes 0x80-0xFF, which are not UTF-8 but leave the MIME type's essence alone.
            let s: String = value.iter().map(|&b| char::from(b)).collect();
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
                        // A start past the end is no range at all (Fetch, parse a single range
                        // header value).
                        && (end.is_empty() || !decimal_greater(start, end))
                }
                None => false,
            }
        }
        _ => false,
    }
}

/// Whether the decimal number `a` is greater than `b`, both strings of ASCII digits of any
/// length, as Fetch reads a range's bounds.
fn decimal_greater(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    (a.len(), a) > (b.len(), b)
}

/// Forbidden request header ([Fetch] §2.2.2): controlled by the user agent — here, by the
/// fetcher itself (`Referer`, `Origin`, `Cookie`, `Sec-Fetch-*`, …). These never count toward
/// the preflight decision: a browser sets them on cross-origin requests without asking either.
/// A request with an initiating origin has the caller's removed before it is sent
/// ([`RequestChange::HeadersRemoved`](crate::net::types::RequestChange::HeadersRemoved)), so
/// none can go out unasked.
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

/// Forbidden request-header ([Fetch] §2.2.2) by name and value: a forbidden header name, or
/// `X-HTTP-Method`, `X-HTTP-Method-Override` or `X-Method-Override` naming a forbidden method
/// among its comma-separated values, which would smuggle one past
/// [`is_forbidden_method`].
///
/// [Fetch]: https://fetch.spec.whatwg.org/#forbidden-request-header
pub fn is_forbidden_request_header_value(name: &HeaderName, value: &http::HeaderValue) -> bool {
    if is_forbidden_request_header(name) {
        return true;
    }
    matches!(
        name.as_str(),
        "x-http-method" | "x-http-method-override" | "x-method-override"
    ) && String::from_utf8_lossy(value.as_bytes())
        .split(',')
        .filter_map(|token| http::Method::from_bytes(token.trim().as_bytes()).ok())
        .any(|method| is_forbidden_method(&method))
}

/// Forbidden method ([Fetch] §2.2.1): `CONNECT`, `TRACE` or `TRACK` in any case. Web content
/// may not send one; `TRACE` echoes the request back, credentials included.
///
/// [Fetch]: https://fetch.spec.whatwg.org/#forbidden-method
pub fn is_forbidden_method(method: &http::Method) -> bool {
    ["CONNECT", "TRACE", "TRACK"]
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method.as_str()))
}

/// Most bytes the CORS-safelisted header values of one request may add up to before they need a
/// preflight after all ([Fetch] §2.2.2, CORS-unsafe request-header names).
///
/// [Fetch]: https://fetch.spec.whatwg.org/#cors-unsafe-request-header-names
const MAX_SAFELISTED_VALUE_BYTES: usize = 1024;

/// The caller-set header names that a preflight must get approved: not forbidden (the fetcher
/// owns those) and not CORS-safelisted for the value they carry. Lowercase, sorted, deduplicated
/// — the exact list sent in `Access-Control-Request-Headers`.
///
/// Each safelisted value is at most 128 bytes, but a request may repeat them: when all of them
/// together come to more than [`MAX_SAFELISTED_VALUE_BYTES`], every safelisted name needs
/// approval too, as Fetch has it. Without that, a page could send a cross-origin server any
/// amount of data in "safe" headers without its consent. The no-cors check uses the same list,
/// which makes it a little stricter than Fetch's per-name rule for no-cors, never looser.
pub(crate) fn unsafe_request_header_names(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut safelisted: Vec<String> = Vec::new();
    let mut safelisted_bytes = 0usize;
    for (name, value) in headers {
        if is_forbidden_request_header(name) {
            continue;
        }
        if is_cors_safelisted_request_header(name, value.as_bytes()) {
            safelisted.push(name.as_str().to_string());
            safelisted_bytes += value.len();
        } else {
            names.push(name.as_str().to_string());
        }
    }
    if safelisted_bytes > MAX_SAFELISTED_VALUE_BYTES {
        names.extend(safelisted);
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether a cross-origin CORS-mode request with this method and these headers needs a
/// preflight before it may be sent.
pub fn preflight_needed(method: &Method, headers: &HeaderMap) -> bool {
    !is_cors_safelisted_method(method) || !unsafe_request_header_names(headers).is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use http::HeaderValue;
    use std::time::Duration;
    use url::Url;

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
        // Fetch §2.2.2: `Content-Type` is isomorphic decoded, so a byte above 0x7F in a
        // parameter leaves `text/plain` safelisted.
        assert!(is_cors_safelisted_request_header(
            &n("content-type"),
            b"text/plain;charset=\xE9"
        ));
        assert!(!is_cors_safelisted_request_header(
            &n("content-type"),
            b"text/pl\xE9in"
        ));
        // Fetch, parse a single range header value: a start past the end is failure. Compared
        // as numbers, of any length, not as text.
        for invalid in [
            &b"bytes=5-1"[..],
            b"bytes=10-9",
            b"bytes=100000000000000000000-1",
        ] {
            assert!(
                !is_cors_safelisted_request_header(&n("range"), invalid),
                "{}",
                String::from_utf8_lossy(invalid)
            );
        }
        for valid in [
            &b"bytes=5-5"[..],
            b"bytes=9-10",
            b"bytes=007-10",
            b"bytes=1-100000000000000000000",
        ] {
            assert!(
                is_cors_safelisted_request_header(&n("range"), valid),
                "{}",
                String::from_utf8_lossy(valid)
            );
        }
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

    /// Fetch §2.2.2, CORS-unsafe request-header names: "If safelistValueSize is greater than
    /// 1024, then for each name of potentiallyUnsafeNames, append name to unsafeNames." Exactly
    /// 1024 bytes of safelisted values is fine; one more needs a preflight, for every name.
    #[test]
    fn safelisted_values_over_1024_bytes_need_a_preflight() {
        let value = |n: usize| "a".repeat(n);
        let at_limit = headers(&[
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept", &value(128)),
            ("accept-language", &value(128)),
        ]);
        assert!(unsafe_request_header_names(&at_limit).is_empty());
        assert!(!preflight_needed(&Method::GET, &at_limit));

        let mut over = at_limit.clone();
        over.append("content-language", "a".parse().unwrap());
        assert_eq!(
            unsafe_request_header_names(&over),
            vec!["accept", "accept-language", "content-language"]
        );
        assert!(preflight_needed(&Method::GET, &over));

        // Forbidden headers are the fetcher's and do not count toward the total.
        let mut with_forbidden = at_limit.clone();
        with_forbidden.append("user-agent", "a".repeat(2000).parse().unwrap());
        with_forbidden.append("referer", "a".repeat(2000).parse().unwrap());
        assert_eq!(
            unsafe_request_header_names(&with_forbidden),
            vec!["user-agent"]
        );
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
        // Fetch §4.10, CORS check: the header is *got*, so two lines read `true, true`, which
        // is not `true`; nor is `true` followed by `false`.
        for second in ["true", "false"] {
            let twice = headers(&[
                ("access-control-allow-origin", "https://a.example"),
                ("access-control-allow-credentials", "true"),
                ("access-control-allow-credentials", second),
            ]);
            assert_eq!(
                cors_check(&o, false, true, &twice),
                Err(CorsError::CredentialsNotAllowed),
                "true, {second}"
            );
        }
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

        // Fetch §4.8 step 7.8: anything but one `delta-seconds` is a failure, and gives 5 s.
        let max_age = |values: &[&str]| {
            let pairs: Vec<(&str, &str)> = values
                .iter()
                .map(|v| ("access-control-max-age", *v))
                .collect();
            validate_preflight_response(200, &ok_preflight(&pairs), &o, false, false)
                .unwrap()
                .max_age
        };
        for failure in [
            &["+600"][..],
            &["-1"],
            &["1.5"],
            &["600", "600"],
            &["ten"],
            &[""],
        ] {
            assert_eq!(max_age(failure), DEFAULT_PREFLIGHT_MAX_AGE, "{failure:?}");
        }
        assert_eq!(max_age(&[" 600 "]), Duration::from_secs(600));
        // Too large for a u64 is still a number of seconds: capped, not defaulted.
        assert_eq!(max_age(&["99999999999999999999999"]), MAX_PREFLIGHT_MAX_AGE);
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

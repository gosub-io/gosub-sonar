//! Computing the `Origin` header and the `Sec-Fetch-*` fetch metadata headers ([spec]).
//!
//! The `Sec-Fetch-*` headers describe how a request came about: what the resource is for
//! ([`Sec-Fetch-Dest`]), the request mode ([`Sec-Fetch-Mode`]), how the target relates to the
//! initiating site ([`Sec-Fetch-Site`]), and whether a user asked for it ([`Sec-Fetch-User`]).
//! `Origin` names the initiator on requests with side effects (non-GET) and on CORS requests.
//!
//! Set [`FetchRequest::destination`] and [`FetchRequest::mode`] to describe the request;
//! [`FetchRequest::origin`] is the initiating origin behind `Sec-Fetch-Site` and `Origin`.
//! The fetcher owns these headers and overwrites hand-set values, matching the forbidden
//! header name rules in browsers.
//!
//! Like `Referer`, the values are recomputed at every redirect hop. `Sec-Fetch-Site` can only
//! degrade across a chain, and `Origin` becomes the literal `null` once the chain redirects
//! away from an origin the request had already left.
//!
//! There is no public suffix list, so sibling subdomains (`a.example.com` → `b.example.com`)
//! report `cross-site` instead of `same-site`. Same host on another port reports `same-site`,
//! since a site has no port.
//!
//! Inert on `wasm32`: these are forbidden header names there, so the browser strips ours and
//! applies its own.
//!
//! [spec]: https://w3c.github.io/webappsec-fetch-metadata/
//! [`Sec-Fetch-Dest`]: RequestDestination
//! [`Sec-Fetch-Mode`]: RequestMode
//! [`Sec-Fetch-Site`]: SecFetchSite
//! [`Sec-Fetch-User`]: crate::net::types::Initiator
//! [`FetchRequest::destination`]: crate::net::types::FetchRequest::destination
//! [`FetchRequest::mode`]: crate::net::types::FetchRequest::mode
//! [`FetchRequest::origin`]: crate::net::types::FetchRequest::origin

use crate::net::mixed_content::is_potentially_trustworthy;
use crate::net::referrer::ReferrerPolicy;
use http::{header, HeaderMap, HeaderValue, Method};
use url::{Origin, Url};

static SEC_FETCH_DEST: header::HeaderName = header::HeaderName::from_static("sec-fetch-dest");
static SEC_FETCH_MODE: header::HeaderName = header::HeaderName::from_static("sec-fetch-mode");
static SEC_FETCH_SITE: header::HeaderName = header::HeaderName::from_static("sec-fetch-site");
static SEC_FETCH_USER: header::HeaderName = header::HeaderName::from_static("sec-fetch-user");

/// What the fetched resource will be used as — the request's *destination* ([Fetch §2.2.5]),
/// sent as `Sec-Fetch-Dest`.
///
/// [Fetch §2.2.5]: https://fetch.spec.whatwg.org/#concept-request-destination
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum RequestDestination {
    /// No particular destination (the default — e.g. `fetch()`, beacons, downloads).
    /// Sent as the token `empty`.
    #[default]
    Empty,
    /// `<audio>`
    Audio,
    /// `audioWorklet.addModule()`
    AudioWorklet,
    /// A top-level navigation
    Document,
    /// `<embed>`
    Embed,
    /// `@font-face`
    Font,
    /// `<frame>` navigation
    Frame,
    /// `<iframe>` navigation
    Iframe,
    /// `<img>`, `background-image`, favicon, …
    Image,
    /// JSON module import
    Json,
    /// `<link rel="manifest">`
    Manifest,
    /// `<object>`
    Object,
    /// `CSS.paintWorklet.addModule()`
    PaintWorklet,
    /// CSP or other reporting
    Report,
    /// `<script>`, module imports, `importScripts()`
    Script,
    /// Service worker registration
    ServiceWorker,
    /// `new SharedWorker()`
    SharedWorker,
    /// `<link rel="stylesheet">`, `@import`
    Style,
    /// `<track>`
    Track,
    /// `<video>`
    Video,
    /// `new Worker()`
    Worker,
    /// `<?xml-stylesheet?>` XSLT
    Xslt,
}

impl RequestDestination {
    /// The token sent in `Sec-Fetch-Dest`. The empty destination is sent as `empty`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Audio => "audio",
            Self::AudioWorklet => "audioworklet",
            Self::Document => "document",
            Self::Embed => "embed",
            Self::Font => "font",
            Self::Frame => "frame",
            Self::Iframe => "iframe",
            Self::Image => "image",
            Self::Json => "json",
            Self::Manifest => "manifest",
            Self::Object => "object",
            Self::PaintWorklet => "paintworklet",
            Self::Report => "report",
            Self::Script => "script",
            Self::ServiceWorker => "serviceworker",
            Self::SharedWorker => "sharedworker",
            Self::Style => "style",
            Self::Track => "track",
            Self::Video => "video",
            Self::Worker => "worker",
            Self::Xslt => "xslt",
        }
    }
}

/// How the request relates to cross-origin rules — the request's *mode* ([Fetch §2.2.5]),
/// sent as `Sec-Fetch-Mode`.
///
/// This crate does not enforce CORS; the mode only shapes the `Sec-Fetch-Mode` and `Origin`
/// headers so the server sees the same request a browser would send.
///
/// [Fetch §2.2.5]: https://fetch.spec.whatwg.org/#concept-request-mode
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum RequestMode {
    /// Cross-origin allowed without the response being readable cross-origin — how browsers
    /// load `<img>`, `<script>`, and most other markup-initiated subresources. The default.
    #[default]
    NoCors,
    /// A CORS request (`fetch()`, `XMLHttpRequest`, `crossorigin` attributes). Sends `Origin`
    /// on cross-origin requests.
    Cors,
    /// Only same-origin fetches make sense for this request.
    SameOrigin,
    /// A navigation (document, frame, or iframe load). Enables `Sec-Fetch-User`.
    Navigate,
    /// A WebSocket handshake. Always sends `Origin`.
    Websocket,
}

impl RequestMode {
    /// The token sent in `Sec-Fetch-Mode`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCors => "no-cors",
            Self::Cors => "cors",
            Self::SameOrigin => "same-origin",
            Self::Navigate => "navigate",
            Self::Websocket => "websocket",
        }
    }
}

/// The relation between the initiating origin and the request target, sent as `Sec-Fetch-Site`.
///
/// Ordered so that [`min`](Ord::min) degrades correctly across a redirect chain:
/// `same-origin` > `same-site` > `cross-site`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum SecFetchSite {
    /// The request was not triggered by web content at all (no initiating origin — e.g. an
    /// address bar navigation or a bookmark).
    None,
    /// The target belongs to a different site than the initiator.
    CrossSite,
    /// Same site (same scheme and registrable domain), different origin.
    SameSite,
    /// The target is the initiator's own origin.
    SameOrigin,
}

impl SecFetchSite {
    /// The token sent in `Sec-Fetch-Site`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CrossSite => "cross-site",
            Self::SameSite => "same-site",
            Self::SameOrigin => "same-origin",
        }
    }
}

/// Classify one hop's target against the initiating origin.
///
/// Never returns [`SecFetchSite::None`]; that value means there is no initiating origin at
/// all. Sibling subdomains classify as [`CrossSite`](SecFetchSite::CrossSite) for lack of a
/// public suffix list; same host on another port is [`SameSite`](SecFetchSite::SameSite).
pub(crate) fn classify_site(initiator: &Origin, target: &Url) -> SecFetchSite {
    let target_origin = target.origin();
    if *initiator == target_origin {
        return SecFetchSite::SameOrigin;
    }
    match (initiator, &target_origin) {
        (Origin::Tuple(s1, h1, _), Origin::Tuple(s2, h2, _)) if s1 == s2 && h1 == h2 => {
            SecFetchSite::SameSite
        }
        _ => SecFetchSite::CrossSite,
    }
}

/// Set (or clear) the four `Sec-Fetch-*` headers for one hop.
///
/// Per spec these only go to potentially trustworthy targets; a plaintext hop has them
/// removed, including values carried over from an earlier hop. `Sec-Fetch-User` is only ever
/// `?1` on a user-activated navigation; otherwise the header is absent.
pub(crate) fn apply_sec_fetch_headers(
    headers: &mut HeaderMap,
    target: &Url,
    destination: RequestDestination,
    mode: RequestMode,
    site: SecFetchSite,
    user_activated: bool,
) {
    if !is_potentially_trustworthy(target) {
        headers.remove(&SEC_FETCH_DEST);
        headers.remove(&SEC_FETCH_MODE);
        headers.remove(&SEC_FETCH_SITE);
        headers.remove(&SEC_FETCH_USER);
        return;
    }
    headers.insert(
        &SEC_FETCH_DEST,
        HeaderValue::from_static(destination.as_str()),
    );
    headers.insert(&SEC_FETCH_MODE, HeaderValue::from_static(mode.as_str()));
    headers.insert(&SEC_FETCH_SITE, HeaderValue::from_static(site.as_str()));
    if mode == RequestMode::Navigate && user_activated {
        headers.insert(&SEC_FETCH_USER, HeaderValue::from_static("?1"));
    } else {
        headers.remove(&SEC_FETCH_USER);
    }
}

/// The `Origin` header value for one hop, or `None` when the header must be omitted
/// (Fetch, *append a request `Origin` header*).
///
/// The header is sent on any method other than GET/HEAD, and on CORS-mode or WebSocket
/// requests that cross an origin. `tainted` is the request's *tainted origin flag*; once set,
/// the value is the literal `null`. On non-CORS requests the referrer policy caps `Origin`
/// the same way it caps `Referer`, so the header cannot leak what the policy just hid.
pub(crate) fn origin_header_value(
    initiator: &Origin,
    tainted: bool,
    method: &Method,
    mode: RequestMode,
    referrer_policy: ReferrerPolicy,
    target: &Url,
) -> Option<String> {
    let cors_like = matches!(mode, RequestMode::Cors | RequestMode::Websocket);
    let needed = !matches!(*method, Method::GET | Method::HEAD)
        || (cors_like && (tainted || *initiator != target.origin()));
    if !needed {
        return None;
    }
    if tainted {
        return Some("null".to_string());
    }
    // An opaque origin has no serialisation other than `null`.
    let Origin::Tuple(scheme, _, _) = initiator else {
        return Some("null".to_string());
    };
    if !cors_like {
        let cloaked = match referrer_policy {
            ReferrerPolicy::NoReferrer => true,
            ReferrerPolicy::NoReferrerWhenDowngrade
            | ReferrerPolicy::StrictOrigin
            | ReferrerPolicy::StrictOriginWhenCrossOrigin => {
                scheme == "https" && target.scheme() != "https"
            }
            ReferrerPolicy::SameOrigin => *initiator != target.origin(),
            ReferrerPolicy::Origin
            | ReferrerPolicy::OriginWhenCrossOrigin
            | ReferrerPolicy::UnsafeUrl => false,
        };
        if cloaked {
            return Some("null".to_string());
        }
    }
    Some(initiator.ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn o(s: &str) -> Origin {
        u(s).origin()
    }

    #[test]
    fn site_classification() {
        let init = o("https://example.com");
        assert_eq!(
            classify_site(&init, &u("https://example.com/a")),
            SecFetchSite::SameOrigin
        );
        // A site has no port: same scheme and host on another port is still the same site.
        assert_eq!(
            classify_site(&init, &u("https://example.com:8443/a")),
            SecFetchSite::SameSite
        );
        // Schemeful sites: http and https on one host are different sites.
        assert_eq!(
            classify_site(&init, &u("http://example.com/a")),
            SecFetchSite::CrossSite
        );
        assert_eq!(
            classify_site(&init, &u("https://other.com/a")),
            SecFetchSite::CrossSite
        );
        // Without a public suffix list a sibling subdomain degrades to cross-site.
        assert_eq!(
            classify_site(&init, &u("https://sub.example.com/a")),
            SecFetchSite::CrossSite
        );
    }

    /// `min` is how the redirect loop degrades the value across a chain, so the variant order
    /// is load-bearing.
    #[test]
    fn site_ordering_degrades() {
        assert_eq!(
            SecFetchSite::SameOrigin.min(SecFetchSite::CrossSite),
            SecFetchSite::CrossSite
        );
        assert_eq!(
            SecFetchSite::SameSite.min(SecFetchSite::SameOrigin),
            SecFetchSite::SameSite
        );
    }

    #[test]
    fn sec_fetch_headers_are_only_sent_to_trustworthy_targets() {
        let mut headers = HeaderMap::new();
        apply_sec_fetch_headers(
            &mut headers,
            &u("https://example.com/a"),
            RequestDestination::Image,
            RequestMode::NoCors,
            SecFetchSite::SameOrigin,
            false,
        );
        assert_eq!(headers.get("sec-fetch-dest").unwrap(), "image");
        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "no-cors");
        assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-origin");
        assert!(headers.get("sec-fetch-user").is_none());

        // A plaintext hop must clear values carried over from a trustworthy hop.
        apply_sec_fetch_headers(
            &mut headers,
            &u("http://example.com/a"),
            RequestDestination::Image,
            RequestMode::NoCors,
            SecFetchSite::SameOrigin,
            false,
        );
        assert!(headers.get("sec-fetch-dest").is_none());
        assert!(headers.get("sec-fetch-mode").is_none());
        assert!(headers.get("sec-fetch-site").is_none());
    }

    #[test]
    fn sec_fetch_user_requires_a_user_activated_navigation() {
        let target = u("https://example.com/a");
        let cases = [
            (RequestMode::Navigate, true, Some("?1")),
            (RequestMode::Navigate, false, None),
            (RequestMode::NoCors, true, None),
        ];
        for (mode, activated, expected) in cases {
            let mut headers = HeaderMap::new();
            apply_sec_fetch_headers(
                &mut headers,
                &target,
                RequestDestination::Document,
                mode,
                SecFetchSite::None,
                activated,
            );
            assert_eq!(
                headers.get("sec-fetch-user").map(|v| v.to_str().unwrap()),
                expected,
                "{mode:?} activated={activated}"
            );
        }
    }

    fn origin_for(
        initiator: &str,
        tainted: bool,
        method: Method,
        mode: RequestMode,
        policy: ReferrerPolicy,
        target: &str,
    ) -> Option<String> {
        origin_header_value(&o(initiator), tainted, &method, mode, policy, &u(target))
    }

    #[test]
    fn origin_is_sent_for_side_effect_methods_and_cors() {
        let policy = ReferrerPolicy::default();
        // A plain no-cors GET carries no Origin.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::GET,
                RequestMode::NoCors,
                policy,
                "https://other.com/a"
            ),
            None
        );
        // POST always identifies its sender.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::POST,
                RequestMode::NoCors,
                policy,
                "https://other.com/a"
            )
            .as_deref(),
            Some("https://example.com")
        );
        // A CORS GET sends Origin only when it actually crosses one.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::GET,
                RequestMode::Cors,
                policy,
                "https://example.com/a"
            ),
            None
        );
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::GET,
                RequestMode::Cors,
                policy,
                "https://other.com/a"
            )
            .as_deref(),
            Some("https://example.com")
        );
        // A WebSocket handshake always sends it cross-origin.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::GET,
                RequestMode::Websocket,
                policy,
                "wss://other.com/a"
            )
            .as_deref(),
            Some("https://example.com")
        );
    }

    /// The referrer policy caps Origin on non-CORS requests, exactly as it caps Referer.
    #[test]
    fn origin_is_cloaked_by_the_referrer_policy() {
        // no-referrer hides the origin everywhere.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::POST,
                RequestMode::NoCors,
                ReferrerPolicy::NoReferrer,
                "https://example.com/a"
            )
            .as_deref(),
            Some("null")
        );
        // The strict policies hide it on an https → http downgrade.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::POST,
                RequestMode::NoCors,
                ReferrerPolicy::default(),
                "http://other.com/a"
            )
            .as_deref(),
            Some("null")
        );
        // same-origin hides it from every other origin.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::POST,
                RequestMode::NoCors,
                ReferrerPolicy::SameOrigin,
                "https://other.com/a"
            )
            .as_deref(),
            Some("null")
        );
        // CORS requests are exempt: the protocol requires the true origin.
        assert_eq!(
            origin_for(
                "https://example.com",
                false,
                Method::POST,
                RequestMode::Cors,
                ReferrerPolicy::NoReferrer,
                "https://other.com/a"
            )
            .as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn tainted_and_opaque_origins_serialise_as_null() {
        assert_eq!(
            origin_for(
                "https://example.com",
                true,
                Method::POST,
                RequestMode::NoCors,
                ReferrerPolicy::default(),
                "https://example.com/a"
            )
            .as_deref(),
            Some("null")
        );
        // data: URLs have an opaque origin.
        let opaque = u("data:text/html,hi").origin();
        assert_eq!(
            origin_header_value(
                &opaque,
                false,
                &Method::POST,
                RequestMode::NoCors,
                ReferrerPolicy::default(),
                &u("https://example.com/a")
            )
            .as_deref(),
            Some("null")
        );
    }
}

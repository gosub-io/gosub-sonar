//! Low-level fetch functions used by the [`super::fetcher::Fetcher`].

use crate::net::auth::{
    self, AuthChallenge, AuthTarget, CredentialStore, Credentials, ProtectionSpace,
    MAX_AUTH_ATTEMPTS,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::cache::{self, CacheDecision, CacheKey, HttpCache};
use crate::net::cache::{CacheEntry, CacheMode, CacheOutcome};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::cors::CorsPreflightCache;
use crate::net::cors::{self, CorsError, ResponseTainting};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::dns::DnsResolver;
use crate::net::events::NetEvent;
use crate::net::fetch_metadata::{self, RequestDestination, RequestMode, SecFetchSite};
use crate::net::fetcher_context::{CookieHop, FetcherContext};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::hsts::{self, HstsStore};
use crate::net::mixed_content::{self, MixedContentAction, MixedContentPolicy};
use crate::net::observer::NetObserver;
use crate::net::port_blocking;
use crate::net::referrer::{self, ReferrerPolicy};
use crate::net::request_ref::RequestReference;
#[cfg(not(target_arch = "wasm32"))]
use crate::net::tls::TlsOverrideStore;
use crate::net::transport::TransportError;
use crate::net::types::{
    BlockReason, FetchResultMeta, NetError, RequestBody, RequestChange, RequestCredentials,
    UpgradeReason,
};
use crate::net::utils::BytesAsyncReader;
use crate::types::PeekBuf;
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use futures_util::{stream, StreamExt, TryStreamExt};
use http::{header, HeaderMap, HeaderName, Method};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;
use url::{Origin, Url};

/// Headers that must be stripped when following a redirect to a different origin (RFC 9110 §15.4).
///
/// `Referer` and `Origin` are included so hand-set values cannot leak to a third-party host.
/// When the caller supplies a referrer or an initiating origin instead, the values are
/// recomputed for each hop anyway, so removing them here costs nothing. A hand-set
/// `Proxy-Authorization` belongs to the proxy that demanded it (RFC 9110 §11.7.2), and the next
/// host may be reached directly; a configured rule's is recomputed per hop.
const SENSITIVE_REDIRECT_HEADERS: &[header::HeaderName] = &[
    header::AUTHORIZATION,
    header::COOKIE,
    header::REFERER,
    header::ORIGIN,
    header::PROXY_AUTHORIZATION,
];

/// `Referrer-Policy` is not in `http`'s well-known header set, so name it once here rather than
/// repeating a string literal at the use site.
static REFERRER_POLICY: header::HeaderName = header::HeaderName::from_static("referrer-policy");

/// Emit the block event and build the matching error, so the two can never drift apart.
pub(crate) fn blocked(
    observer: &Arc<dyn NetObserver + Send + Sync>,
    url: Url,
    reason: BlockReason,
) -> NetError {
    observer.on_event(NetEvent::Blocked {
        url: url.clone(),
        reason,
    });
    NetError::Blocked { reason, url }
}

/// `headers` with leading and trailing whitespace taken off every value (Fetch, normalize a
/// header value). A field value has none (RFC 9110 §5.5), and over HTTP/2 a value with any is
/// a malformed request (RFC 9113 §8.2.1) that a server resets.
fn trimmed_values(headers: HeaderMap) -> HeaderMap {
    let is_ws = |b: &u8| matches!(b, b' ' | b'\t');
    let mut out = HeaderMap::with_capacity(headers.len());
    let mut name = None;
    for (n, value) in headers {
        if let Some(n) = n {
            name = Some(n);
        }
        let Some(ref name) = name else { continue };
        let bytes = value.as_bytes();
        let start = bytes.iter().position(|b| !is_ws(b)).unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|b| !is_ws(b))
            .map_or(start, |i| i + 1);
        let value = if start == 0 && end == bytes.len() {
            value
        } else {
            match header::HeaderValue::from_bytes(&bytes[start..end]) {
                Ok(mut trimmed) => {
                    trimmed.set_sensitive(value.is_sensitive());
                    trimmed
                }
                Err(_) => value,
            }
        };
        out.append(name.clone(), value);
    }
    out
}

/// `method` normalized (Fetch §2.2.1): a byte-case-insensitive `DELETE`, `GET`, `HEAD`,
/// `OPTIONS`, `POST` or `PUT` is uppercased, any other method is left as it is. Every check in
/// this crate that compares against [`Method::GET`] and the rest relies on it.
pub(crate) fn normalize_method(method: Method) -> Method {
    [
        Method::DELETE,
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::POST,
        Method::PUT,
    ]
    .into_iter()
    .find(|m| m.as_str().eq_ignore_ascii_case(method.as_str()))
    .unwrap_or(method)
}

/// Remove the `user:password@` from `url`. Returns whether there was one, so the caller can
/// report [`RequestChange::UrlCredentialsRemoved`]. The client would turn embedded credentials
/// into an `Authorization` header, which lets a page or a redirect send credentials of its
/// choosing along with the user's cookies. Browsers do not send them either. Credentials for a
/// server come from the auth hook, after a challenge.
fn strip_url_credentials(url: &mut Url) -> bool {
    if url.username().is_empty() && url.password().is_none() {
        return false;
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    true
}

/// Report one [`RequestChange`] for the hop to `url`.
fn modified(observer: &Arc<dyn NetObserver + Send + Sync>, url: &Url, change: RequestChange) {
    observer.on_event(NetEvent::RequestModified {
        url: url.clone(),
        change,
    });
}

/// The host of `url` when it is an IP literal, without brackets.
#[cfg(not(target_arch = "wasm32"))]
fn ip_literal(url: &Url) -> Option<String> {
    match url.host()? {
        url::Host::Ipv4(a) => Some(a.to_string()),
        url::Host::Ipv6(a) => Some(a.to_string()),
        url::Host::Domain(_) => None,
    }
}

/// Hand a response's `Set-Cookie` values to the policy's jar. Returns whether there were any.
/// A value is read as UTF-8, the way browsers read cookies, not as visible ASCII only: a
/// non-ASCII cookie value is common and valid, and `to_str` would drop it. Bytes that are not
/// UTF-8 at all are left out.
fn report_set_cookie(policy: &NetPolicy, url: &Url, headers: &HeaderMap) -> bool {
    let values: Vec<&str> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| std::str::from_utf8(v.as_bytes()).ok())
        .collect();
    if values.is_empty() {
        return false;
    }
    (policy.on_cookies)(url, &values);
    true
}

/// Whether `resp`'s connection was accepted through the override store. Needs a client built
/// with `tls_info`, which the fetcher does when overrides are enabled.
#[cfg(not(target_arch = "wasm32"))]
fn over_accepted_override(policy: &NetPolicy, resp: &reqwest::Response) -> bool {
    let (Some(store), Some(host)) = (policy.tls_overrides.as_ref(), resp.url().host_str()) else {
        return false;
    };
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .is_some_and(|der| store.is_accepted(host, &crate::net::tls::fingerprint(der)))
}

/// The text of a `Location` header. Servers send non-ASCII targets as UTF-8; anything that is
/// not valid UTF-8 is decoded byte for byte, as browsers do. Either way the URL parser then
/// percent-encodes what it has to.
fn location_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

/// What [`hop_checks`] decided about one hop.
pub(crate) enum HopCheck {
    /// Send the request to this URL, which may be an upgraded form of the one checked.
    Proceed(Url),
    /// Refuse the request.
    Reject(BlockReason),
}

/// Apply the pre-dispatch checks to a single hop: scheme allowlist, mixed content, bad ports,
/// then the embedder's URL allowlist.
///
/// Both the scheduler's pre-dispatch check and the per-hop redirect loop call this, so the two
/// cannot reach different conclusions about the same URL. Order matters: a mixed content upgrade
/// rewrites the URL, and `url_allowed` must vet the URL that will actually be sent — an embedder
/// that rejects `http://` should not see a request the upgrade would have made `https://`.
pub(crate) fn hop_checks(
    url: &Url,
    mixed_content: MixedContentPolicy,
    origin: Option<&Origin>,
    destination: RequestDestination,
    allowed_bad_ports: &[u16],
    url_allowed: &dyn Fn(&Url) -> bool,
) -> HopCheck {
    if !matches!(url.scheme(), "http" | "https") {
        return HopCheck::Reject(BlockReason::UnsupportedScheme);
    }

    let target = match mixed_content::evaluate_for(mixed_content, origin, url, destination) {
        MixedContentAction::Allow => url.clone(),
        MixedContentAction::Upgrade(upgraded) => upgraded,
        MixedContentAction::Block => return HopCheck::Reject(BlockReason::MixedContent),
    };

    // On the URL the upgrade settled, as main fetch orders it.
    if port_blocking::should_block(&target, allowed_bad_ports) {
        return HopCheck::Reject(BlockReason::BadPort);
    }

    if !url_allowed(&target) {
        return HopCheck::Reject(BlockReason::UrlPolicy);
    }

    HopCheck::Proceed(target)
}

/// What one party (the origin server or the proxy) has been sent for a hop's authentication.
#[derive(Default)]
struct AuthSlot {
    /// The `Authorization` or `Proxy-Authorization` value to send.
    header: Option<header::HeaderValue>,
    /// How many times this party was answered on this hop.
    attempt: u32,
    /// Credentials sent but not yet accepted: stored once the party lets the request through,
    /// forgotten when it challenges again.
    unproven: Option<(ProtectionSpace, Credentials)>,
}

impl AuthSlot {
    /// The party let the request to `url` through: remember the password it accepted, and
    /// where. Only a password: a `Raw` answer was computed for the challenge it answered (a
    /// Digest nonce, a Negotiate token), and replaying it would only draw another challenge.
    fn accepted(&mut self, policy: &NetPolicy, url: &Url) {
        if let (Some(store), Some((space, credentials))) =
            (policy.credentials.as_ref(), self.unproven.take())
        {
            if matches!(credentials, Credentials::Basic { .. }) {
                store.store(space.clone(), credentials);
                store.accepted_at(&space, url);
            }
        }
    }
}

/// A preflight grant a hop is relying on, dropped from the cache unless the hop's response
/// passes its CORS check (Fetch §4.4, main fetch: "If corsWithPreflightResponse is a network
/// error, then clear cache entries using request"). Every way a hop can fail after its grant
/// returns early, so the drop is what catches them all.
#[cfg(not(target_arch = "wasm32"))]
struct PreflightGrant {
    cache: Arc<dyn CorsPreflightCache>,
    origin: String,
    url: Url,
    kept: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl PreflightGrant {
    /// The hop's response passed: the grant stays cached.
    fn keep(mut self) {
        self.kept = true;
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for PreflightGrant {
    fn drop(&mut self) {
        if !self.kept {
            self.cache.clear(&self.origin, &self.url);
        }
    }
}

/// Callback type for the URL allowlist check.
pub type UrlFilter = Box<dyn Fn(&Url) -> bool + Send + Sync>;

/// Callback type for per-URL cookie jar queries.
pub type CookieJarFn = Box<dyn Fn(&CookieHop<'_>) -> Option<String> + Send + Sync>;

/// Callback type for reporting `Set-Cookie` values received on a response.
pub type CookieSinkFn = Box<dyn Fn(&Url, &[&str]) + Send + Sync>;

/// Callback type for reporting the HTTP version of a response.
pub type ProtocolSinkFn = Box<dyn Fn(&Url, http::Version) + Send + Sync>;

/// Callback type for asking whether a URL's origin is known to speak HTTP/2 or HTTP/3.
pub type ProtocolHintFn = Box<dyn Fn(&Url) -> bool + Send + Sync>;

/// Callback type for answering an authentication challenge.
pub type AuthChallengeFn = Box<dyn Fn(&AuthChallenge) -> Option<Credentials> + Send + Sync>;

/// Callback type for the `Proxy-Authorization` a configured proxy needs for one URL.
#[cfg(not(target_arch = "wasm32"))]
pub type ProxyAuthorizationFn = Box<dyn Fn(&Url) -> Option<http::HeaderValue> + Send + Sync>;

/// Callback type returning the http(s) proxy a plain-`http` request goes through.
#[cfg(not(target_arch = "wasm32"))]
pub type ProxyForFn = Box<dyn Fn(&Url) -> Option<Url> + Send + Sync>;

/// Callback type saying whether a request goes through a proxy of any kind.
#[cfg(not(target_arch = "wasm32"))]
pub type ProxiedFn = Box<dyn Fn(&Url) -> bool + Send + Sync>;

/// Network-level request policies threaded through the fetch stack.
///
/// Bundles the URL allowlist check and the cookie-jar query so both can be applied at
/// every redirect hop without passing separate generic parameters.
///
/// Construct with [`NetPolicy::default`] (no-op, allows everything) or
/// [`NetPolicy::from_context`] to wire up a [`FetcherContext`] implementation.
pub struct NetPolicy {
    /// Return `false` to block a URL. Called for the initial URL and each redirect target.
    pub url_allowed: UrlFilter,
    /// Return cookies for a hop in `"name=value; name2=value2"` format, or `None`. Called on
    /// each hop after cross-origin cookie stripping, so the jar is always consulted for the
    /// correct origin, with the hop's URL, method and the chain before it (see [`CookieHop`]).
    pub cookies_for: CookieJarFn,
    /// Called with the raw `Set-Cookie` values of every response, redirect hops included, so a
    /// cookie set mid-chain (a session cookie on a login 302) reaches the jar before the next
    /// hop. Not called for a hop the request's credentials mode kept cookies off (Fetch: only
    /// with *includeCredentials*), so a `credentials: omit` request cannot write the jar.
    pub on_cookies: CookieSinkFn,
    /// Called with the URL and HTTP version of every response in the chain, redirects included.
    /// The fetcher uses this to pick the h1 or h2 per-origin connection limit. Not called on
    /// wasm32 (the browser's `fetch()` doesn't expose the version). Set via
    /// [`NetPolicy::with_protocol_sink`].
    pub on_protocol: ProtocolSinkFn,
    /// Whether a URL's origin is known to speak HTTP/2 or HTTP/3. Used when applying a
    /// [`RequestInit::header_order`]: no `host` header is added for such origins, since h2
    /// carries it in `:authority`. Defaults to `false` for every URL. Set via
    /// [`NetPolicy::with_protocol_hint`].
    pub speaks_h2: ProtocolHintFn,
    /// HSTS store consulted to upgrade each hop, and updated from each hop's response.
    /// `None` disables HSTS. Set via [`NetPolicy::with_hsts`].
    #[cfg(not(target_arch = "wasm32"))]
    pub hsts: Option<Arc<dyn HstsStore>>,
    /// The client's TLS override store, if any. A response over an accepted override does not
    /// update HSTS (RFC 6797 §8.1). Set via [`NetPolicy::with_tls_overrides`].
    #[cfg(not(target_arch = "wasm32"))]
    pub tls_overrides: Option<Arc<dyn TlsOverrideStore>>,
    /// Cache of CORS preflight grants. `None` still preflights when the spec requires it,
    /// asking the server every time. Set via [`NetPolicy::with_cors_preflight_cache`].
    #[cfg(not(target_arch = "wasm32"))]
    pub cors_preflight: Option<Arc<dyn CorsPreflightCache>>,
    /// Called for each challenge of a `401`/`407` response until one yields credentials to retry
    /// the hop with. The default answers no challenge, leaving the response for the caller.
    /// See [`auth`](mod@crate::net::auth).
    pub on_auth_challenge: AuthChallengeFn,
    /// Credentials remembered per protection space, consulted before `on_auth_challenge` and
    /// updated from its answers. `None` still authenticates, asking the hook every time.
    /// Set via [`NetPolicy::with_credential_store`].
    pub credentials: Option<Arc<dyn CredentialStore>>,
    /// Store of cached responses, consulted before every hop and written to after it.
    /// `None` disables caching. Set via [`NetPolicy::with_cache`].
    /// See [`cache`](mod@crate::net::cache).
    #[cfg(not(target_arch = "wasm32"))]
    pub cache: Option<Arc<dyn HttpCache>>,
    /// The user agent configured on the HTTP client, purely so that
    /// [`NetEvent::RequestSent`] can report it.
    ///
    /// It exists because the client will not say. A default header set on the client is
    /// merged when a request is *executed*, not when it is built, and is never exposed for
    /// reading -- so a request assembled here carries no user agent even though one is about
    /// to be sent. Telling the policy what was configured is the only way an observer can be
    /// shown the truth.
    ///
    /// `None` reports no user agent rather than inventing one, which is the honest answer
    /// for a client this crate did not build. Set via [`NetPolicy::with_user_agent`].
    pub user_agent: Option<http::HeaderValue>,
    /// The `Proxy-Authorization` a configured proxy needs for a given URL, asked per hop.
    ///
    /// Like the user agent, this exists so that a header the client would add on its own is
    /// written -- and therefore reported -- here instead. Unlike the user agent it depends on
    /// the URL, since which proxy applies is a per-request decision.
    ///
    /// `None` leaves the header to the client, which is the honest answer when the proxy in
    /// use was not configured through this crate. Set via
    /// [`NetPolicy::with_proxy_authorization`].
    #[cfg(not(target_arch = "wasm32"))]
    pub proxy_authorization: Option<ProxyAuthorizationFn>,
    /// The http(s) proxy a request goes through, without credentials. A `407` is only treated
    /// as a proxy challenge on a plain-`http` hop this names; any other `407` is returned as
    /// is. On an `https` hop it names the proxy in
    /// [`NetError::ProxyAuthRequired`].
    /// `None` (default): no hop is proxied. Set via [`NetPolicy::with_proxy_for`].
    #[cfg(not(target_arch = "wasm32"))]
    pub proxy_for: Option<ProxyForFn>,
    /// Whether a request goes through a proxy (http, https or socks). A proxied response's
    /// connection peer is the proxy, so [`FetchResultMeta::peer_addr`] is `None` for it.
    /// `None` (default): unknown, so no response reports a peer either - a client built with
    /// reqwest's defaults reads proxies from the environment, and its peer may well be one.
    /// The [`Fetcher`](crate::net::fetcher::Fetcher) always sets it. Set via
    /// [`NetPolicy::with_proxied`].
    #[cfg(not(target_arch = "wasm32"))]
    pub proxied: Option<ProxiedFn>,
    /// The resolver a hop with an IP-literal host is checked against; see
    /// [`dns`](mod@crate::net::dns). `None` skips the check. Set via
    /// [`NetPolicy::with_dns_resolver`].
    #[cfg(not(target_arch = "wasm32"))]
    pub dns_resolver: Option<Arc<dyn DnsResolver>>,
    /// Bad ports to fetch from anyway; see
    /// [`FetcherConfig::allowed_bad_ports`](crate::net::fetcher::FetcherConfig::allowed_bad_ports).
    /// Empty (default): every bad port is refused. Set via
    /// [`NetPolicy::with_allowed_bad_ports`].
    pub allowed_bad_ports: Vec<u16>,
    /// The cache partition a hop that carries cookies reads and writes: whose jar
    /// [`cookies_for`](Self::cookies_for) answers from, so one jar's responses are never
    /// served to another's requests. A hop without cookies uses the shared, empty partition.
    /// Set by [`NetPolicy::from_context`] from
    /// [`FetcherContext::cookie_jar_key`].
    pub cache_partition: String,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            url_allowed: Box::new(|_| true),
            cookies_for: Box::new(|_| None),
            on_cookies: Box::new(|_, _| {}),
            on_protocol: Box::new(|_, _| {}),
            speaks_h2: Box::new(|_| false),
            user_agent: None,
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
            #[cfg(not(target_arch = "wasm32"))]
            tls_overrides: None,
            #[cfg(not(target_arch = "wasm32"))]
            cors_preflight: None,
            on_auth_challenge: Box::new(|_| None),
            credentials: None,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
            #[cfg(not(target_arch = "wasm32"))]
            proxy_authorization: None,
            #[cfg(not(target_arch = "wasm32"))]
            proxy_for: None,
            #[cfg(not(target_arch = "wasm32"))]
            proxied: None,
            #[cfg(not(target_arch = "wasm32"))]
            dns_resolver: None,
            allowed_bad_ports: Vec::new(),
            cache_partition: String::new(),
        }
    }
}

impl NetPolicy {
    /// Build a policy that delegates to a [`FetcherContext`] implementation, for the request
    /// tagged `reference`: the cookie hooks are asked on its behalf.
    pub fn from_context(ctx: &Arc<dyn FetcherContext>, reference: RequestReference) -> Self {
        let ctx_url = ctx.clone();
        let ctx_cookies = ctx.clone();
        let ctx_sink = ctx.clone();
        let ctx_auth = ctx.clone();
        Self {
            url_allowed: Box::new(move |url| ctx_url.is_url_allowed(url)),
            cookies_for: Box::new(move |hop| ctx_cookies.cookies_for_hop(reference, hop)),
            on_cookies: Box::new(move |url, values| {
                ctx_sink.on_cookies_received(reference, url, values)
            }),
            on_protocol: Box::new(|_, _| {}),
            speaks_h2: Box::new(|_| false),
            // Filled in by the fetcher, which is what knows how its client was built.
            user_agent: None,
            #[cfg(not(target_arch = "wasm32"))]
            hsts: None,
            #[cfg(not(target_arch = "wasm32"))]
            tls_overrides: None,
            #[cfg(not(target_arch = "wasm32"))]
            cors_preflight: None,
            on_auth_challenge: Box::new(move |challenge| ctx_auth.on_auth_challenge(challenge)),
            credentials: None,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
            // Filled in by the fetcher, which is what knows how its proxies were configured.
            #[cfg(not(target_arch = "wasm32"))]
            proxy_authorization: None,
            #[cfg(not(target_arch = "wasm32"))]
            proxy_for: None,
            #[cfg(not(target_arch = "wasm32"))]
            proxied: None,
            #[cfg(not(target_arch = "wasm32"))]
            dns_resolver: None,
            allowed_bad_ports: Vec::new(),
            cache_partition: ctx.cookie_jar_key(reference),
        }
    }

    /// Tell the policy which user agent the client was built with, so
    /// [`NetEvent::RequestSent`] can report it. A value that is not a valid header is
    /// dropped rather than reported wrongly.
    pub fn with_user_agent(mut self, user_agent: Option<&str>) -> Self {
        self.user_agent = user_agent.and_then(|ua| http::HeaderValue::from_str(ua).ok());
        self
    }

    /// Attaches the exceptions for [`NetPolicy::allowed_bad_ports`].
    pub fn with_allowed_bad_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_bad_ports = ports;
        self
    }

    /// Tell the policy how to compute the `Proxy-Authorization` for a URL, so that
    /// [`NetEvent::RequestSent`] reports the header rather than leaving the client to add it
    /// after the report was emitted.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_proxy_authorization(mut self, f: ProxyAuthorizationFn) -> Self {
        self.proxy_authorization = Some(f);
        self
    }

    /// Attaches the callback for [`NetPolicy::proxy_for`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_proxy_for(mut self, f: ProxyForFn) -> Self {
        self.proxy_for = Some(f);
        self
    }

    /// Attaches the callback for [`NetPolicy::proxied`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_proxied(mut self, f: ProxiedFn) -> Self {
        self.proxied = Some(f);
        self
    }

    /// Attaches the resolver for [`NetPolicy::dns_resolver`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_dns_resolver(mut self, resolver: Option<Arc<dyn DnsResolver>>) -> Self {
        self.dns_resolver = resolver;
        self
    }

    /// Attaches a callback that receives the URL and HTTP version of every response.
    pub fn with_protocol_sink(mut self, sink: ProtocolSinkFn) -> Self {
        self.on_protocol = sink;
        self
    }

    /// Attaches a callback that says whether a URL's origin is known to speak HTTP/2 or HTTP/3.
    pub fn with_protocol_hint(mut self, hint: ProtocolHintFn) -> Self {
        self.speaks_h2 = hint;
        self
    }

    /// Attaches the HSTS store this policy should consult and update. `None` disables HSTS.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_hsts(mut self, store: Option<Arc<dyn HstsStore>>) -> Self {
        self.hsts = store;
        self
    }

    /// Attaches the store for [`NetPolicy::tls_overrides`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_tls_overrides(mut self, store: Option<Arc<dyn TlsOverrideStore>>) -> Self {
        self.tls_overrides = store;
        self
    }

    /// Attaches the CORS preflight cache this policy should consult and update.
    /// `None` still preflights when required, without caching the grants.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_cors_preflight_cache(mut self, cache: Arc<dyn CorsPreflightCache>) -> Self {
        self.cors_preflight = Some(cache);
        self
    }

    /// Drops the CORS preflight cache: preflights still run when required, but no grant is
    /// remembered between them.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clear_preflight_cache(mut self) -> Self {
        self.cors_preflight = None;
        self
    }

    /// Attaches the credential store consulted for authentication challenges, and updated when
    /// credentials from [`NetPolicy::on_auth_challenge`] turn out to work. `None` asks the hook
    /// for every challenge.
    pub fn with_credential_store(mut self, store: Option<Arc<dyn CredentialStore>>) -> Self {
        self.credentials = store;
        self
    }

    /// Replaces the callback answering authentication challenges.
    pub fn with_auth_challenge_fn(mut self, hook: AuthChallengeFn) -> Self {
        self.on_auth_challenge = hook;
        self
    }

    /// Attaches the store of cached responses. `None` disables caching.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_cache(mut self, cache: Option<Arc<dyn HttpCache>>) -> Self {
        self.cache = cache;
        self
    }
}

/// Bundled HTTP method, headers, and optional body passed through the fetch stack.
///
/// Using a struct instead of three separate parameters keeps function arities stable as
/// the set of per-request properties grows (e.g. adding trailers, priority hints, etc.).
pub struct RequestInit {
    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, …).
    pub method: Method,
    /// Request headers. The policy's cookie jar and any `Content-Type` derived from the body
    /// are injected before the request is sent.
    pub headers: HeaderMap,
    /// Optional body. `None` for GET/HEAD.
    /// Automatically dropped when a 301, 302, or 303 redirect requires a method downgrade.
    pub body: Option<RequestBody>,
    /// Origin of the document that initiated this request. `None` disables mixed content
    /// checks; see [`mixed_content`](mod@crate::net::mixed_content).
    pub origin: Option<Origin>,
    /// How to treat an insecure hop requested by a secure `origin`. Applied to the initial URL
    /// and re-applied to every redirect target.
    pub mixed_content: MixedContentPolicy,
    /// URL of the initiating document, used to compute `Referer`. `None` sends no referrer.
    pub referrer: Option<Url>,
    /// How much of `referrer` to reveal. Ignored when `referrer` is `None`.
    pub referrer_policy: ReferrerPolicy,
    /// What the resource will be used as, sent in `Sec-Fetch-Dest`.
    /// See [`fetch_metadata`](mod@crate::net::fetch_metadata).
    pub destination: RequestDestination,
    /// The request's mode, sent in `Sec-Fetch-Mode` and selecting the CORS regime.
    /// See [`cors`](mod@crate::net::cors).
    pub mode: RequestMode,
    /// Whether the request stems from a user action. Sends `Sec-Fetch-User: ?1` when the mode
    /// is [`RequestMode::Navigate`]; ignored for other modes.
    pub user_activated: bool,
    /// Whether cookies from the policy's jar ride along, and how strict the credentialed CORS
    /// rules are. See [`RequestCredentials`].
    pub credentials: RequestCredentials,
    /// How this request uses the HTTP cache. Inert without [`NetPolicy::cache`].
    /// See [`cache`](mod@crate::net::cache).
    pub cache_mode: CacheMode,
    /// Whether the HTTP client decompresses the body. A cache entry records it, since a decoded
    /// body is not the bytes a raw caller asked for.
    pub auto_decode: bool,
    /// Order in which headers are sent, applied per hop; `None` keeps insertion order. See
    /// [`FetcherConfig::header_order`](crate::net::fetcher::FetcherConfig::header_order).
    pub header_order: Option<Vec<HeaderName>>,
    /// Deadline for each hop, from its first byte sent until its body is read. `None` leaves
    /// it to the client's own request timeout.
    pub timeout: Option<Duration>,
    /// Wall-clock budget for following redirects. Starts when the first redirect response
    /// arrives and must cover every later hop up to the final response headers. `None` sets
    /// no limit; the hop count is still capped.
    pub redirect_timeout: Option<Duration>,
    /// Longest silence allowed while the body arrives: from the response headers to its first
    /// bytes, and between reads after that. `None` sets no limit of its own.
    pub read_idle_timeout: Option<Duration>,
    /// Wall-clock budget for the whole body, counted from when the response headers arrive.
    /// `None` sets no limit.
    pub total_body_timeout: Option<Duration>,
    /// Largest body accepted, in bytes. Checked here only for a body that ends inside the peek
    /// window; the reader of the rest is the caller's to hold to it. `None` sets no limit.
    pub max_bytes: Option<usize>,
}

impl Default for RequestInit {
    fn default() -> Self {
        Self::get(HeaderMap::new())
    }
}

impl RequestInit {
    /// Plain GET request with the given headers and no body.
    pub fn get(headers: HeaderMap) -> Self {
        Self::new(Method::GET, headers, None)
    }

    /// POST request with the given headers and body bytes.
    pub fn post(headers: HeaderMap, body: impl Into<Bytes>) -> Self {
        Self::new(Method::POST, headers, Some(RequestBody::bytes(body.into())))
    }

    /// Request with an explicit method, headers, and optional body.
    ///
    /// Mixed content checks are off until an origin is supplied — see
    /// [`with_mixed_content`](Self::with_mixed_content).
    pub fn new(method: Method, headers: HeaderMap, body: Option<RequestBody>) -> Self {
        Self {
            method,
            headers,
            body,
            origin: None,
            mixed_content: MixedContentPolicy::default(),
            referrer: None,
            referrer_policy: ReferrerPolicy::default(),
            destination: RequestDestination::default(),
            mode: RequestMode::default(),
            user_activated: false,
            credentials: RequestCredentials::default(),
            cache_mode: CacheMode::default(),
            auto_decode: true,
            header_order: None,
            timeout: None,
            redirect_timeout: None,
            read_idle_timeout: None,
            total_body_timeout: None,
            max_bytes: None,
        }
    }

    /// Attach the initiating document's URL and the policy controlling how much of it is sent
    /// in the `Referer` header. `None` sends no referrer.
    pub fn with_referrer(mut self, referrer: Option<Url>, policy: ReferrerPolicy) -> Self {
        self.referrer = referrer;
        self.referrer_policy = policy;
        self
    }

    /// Attach the request's destination and mode for the `Sec-Fetch-*` headers, and whether it
    /// stems from a user action (`Sec-Fetch-User`, navigations only).
    /// See [`fetch_metadata`](mod@crate::net::fetch_metadata).
    pub fn with_fetch_metadata(
        mut self,
        destination: RequestDestination,
        mode: RequestMode,
        user_activated: bool,
    ) -> Self {
        self.destination = destination;
        self.mode = mode;
        self.user_activated = user_activated;
        self
    }

    /// Attach the initiating document's origin and the policy to apply to insecure hops.
    ///
    /// With `origin` set to `None` the policy has no effect: mixed content is defined relative
    /// to a document, and without one there is nothing to protect.
    pub fn with_mixed_content(
        mut self,
        origin: Option<Origin>,
        policy: MixedContentPolicy,
    ) -> Self {
        self.origin = origin;
        self.mixed_content = policy;
        self
    }

    /// Attach the request's credentials mode (default: [`RequestCredentials::Include`]).
    pub fn with_credentials(mut self, credentials: RequestCredentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Attach how this request uses the cache, and whether the client decodes the body. The two
    /// together decide which stored responses may answer it.
    /// See [`cache`](mod@crate::net::cache).
    pub fn with_cache(mut self, mode: CacheMode, auto_decode: bool) -> Self {
        self.cache_mode = mode;
        self.auto_decode = auto_decode;
        self
    }

    /// Bounds each hop's wait for response headers, overriding the client's request timeout.
    /// `None` leaves the client's own timeout in force.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the order in which headers are sent. `None` keeps insertion order.
    pub fn with_header_order(mut self, order: Option<Vec<HeaderName>>) -> Self {
        self.header_order = order;
        self
    }

    /// Bounds the time spent following redirects, counted from the first redirect response.
    /// `None` sets no limit.
    pub fn with_redirect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.redirect_timeout = timeout;
        self
    }

    /// Bounds the body: `idle` is the longest silence allowed while it arrives, `total` the
    /// budget for all of it, counted from when the response headers arrive. `None` sets no limit.
    pub fn with_body_timeouts(mut self, idle: Option<Duration>, total: Option<Duration>) -> Self {
        self.read_idle_timeout = idle;
        self.total_body_timeout = total;
        self
    }

    /// The largest body accepted, in bytes. `None` sets no limit.
    pub fn with_max_bytes(mut self, max_bytes: Option<usize>) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

/// Reorder `headers` so the names in `order` come first (all values of a name together), with
/// the remaining headers after them in insertion order. Names without a header are skipped;
/// duplicates in `order` count once. hyper writes headers in map order, so this is the wire
/// order.
#[cfg(not(target_arch = "wasm32"))]
fn apply_header_order(headers: &mut HeaderMap, order: &[HeaderName]) {
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
#[cfg(not(target_arch = "wasm32"))]
fn host_header_value(url: &Url) -> Option<http::HeaderValue> {
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
#[cfg(not(target_arch = "wasm32"))]
fn order_hop_headers(
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

/// Peek buffer size (first bytes of body). Used for detecting mime type
const PEEK_MAX: usize = 5 * 1024;
/// Maximum number of redirects allowed
const MAX_REDIRECTS: usize = 20;
/// Ceiling on the body buffer pre-allocation. Content-Length is server-controlled, so we never
/// allocate more than this up front; larger honest bodies grow the buffer as bytes arrive.
const MAX_PREALLOC: usize = 1024 * 1024;

/// The top of a response (HTTP headers + first 5KB of the body, if any), plus a stream
/// for the remainder of the body.
pub struct ResponseTop {
    /// Metadata about the result
    pub meta: FetchResultMeta,
    /// Peek buffer of the first PEEK_MAX of data
    pub peek_buf: PeekBuf,
    /// When the whole body must have arrived, from [`RequestInit::total_body_timeout`] counted
    /// from the response headers. `None` for no limit.
    pub body_deadline: Option<tokio::time::Instant>,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data)
    #[cfg(not(target_arch = "wasm32"))]
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// Stream reader to read the REMAINDER of the body (this does NOT include peek buffer read data).
    /// Not `Send` on wasm32: reqwest's fetch-backed body stream wraps JS types.
    #[cfg(target_arch = "wasm32")]
    pub reader: Box<dyn AsyncRead + Unpin>,
}

/// This function will make a request to a given URL and returns the top of the response. These
/// are most likely the headers and the first 5 KB of body. This can be used to determine mime type
/// of the resource fetched. It will also return a stream reader that is able to read the remainder
/// of the body (minus the peek buffer).
///
/// Crate-private because `client` must not follow redirects itself: reqwest has no per-request
/// redirect policy, and a client that follows them sends each next hop before
/// `get_with_redirects` sees it, so the per-hop checks (bad ports, URL policy, mixed content,
/// HSTS, CORS) never run on it. [`Fetcher`](crate::net::fetcher::Fetcher) builds its clients
/// with redirects off.
pub(crate) async fn fetch_response_top(
    client: Arc<reqwest::Client>,
    url: Url,
    // Method, headers, and optional body for this request.
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ResponseTop, NetError> {
    let mut url = url;
    let credentials_removed = strip_url_credentials(&mut url);
    let result = fetch_response_top_inner(
        client,
        url.clone(),
        init,
        cancel,
        observer.clone(),
        policy,
        credentials_removed,
    )
    .await;

    // One terminal event per failed request, whatever went wrong and wherever it went
    // wrong. The events that name a specific cause - `Blocked`, `TlsFailed` - are emitted
    // on the way here and stay; without this an observer would see `Started` and then
    // silence, unable to tell a dead request from a slow one.
    //
    // Cancellation is not a failure and already reported itself as `Cancelled`.
    if let Err(ref e) = result {
        if !matches!(e, NetError::Cancelled(_)) {
            observer.on_event(NetEvent::Failed {
                url,
                error: anyhow::Error::new(e.clone()),
            });
        }
    }

    result
}

/// The body of [`fetch_response_top`], split out so every error exit funnels through the
/// one place that reports the failure.
async fn fetch_response_top_inner(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
    url_credentials_removed: bool,
) -> Result<ResponseTop, NetError> {
    let started = Instant::now();
    let (read_idle_timeout, total_body_timeout) = (init.read_idle_timeout, init.total_body_timeout);
    let max_bytes = init.max_bytes;
    observer.on_event(NetEvent::Started { url: url.clone() });
    if url_credentials_removed {
        modified(&observer, &url, RequestChange::UrlCredentialsRemoved);
    }

    // Bind this request's observer for the duration of the HTTP exchange. Work that
    // happens below the request layer - DNS resolution inside the connection pool - has no
    // other way to reach it.
    let outcome = crate::net::observer::CURRENT_OBSERVER
        .scope(
            observer.clone(),
            get_with_redirects(
                client.clone(),
                url.clone(),
                init,
                cancel.clone(),
                observer.clone(),
                policy,
            ),
        )
        .await?;
    let ChainOutcome {
        response,
        url: final_url,
        tainting,
        peer_addr,
        #[cfg(not(target_arch = "wasm32"))]
        store,
    } = outcome;
    // The body's budget starts now that the final response's headers are in.
    let body_deadline = total_body_timeout.map(|total| tokio::time::Instant::now() + total);

    // A stored response has no stream to read: the body is already here, so it is split into the
    // peek window and a reader over the remainder, and handed back in the same shape as a
    // response off the wire.
    let resp = match response {
        HopResponse::Cached(entry) => {
            let peek_len = entry.body.len().min(PEEK_MAX);
            let meta = FetchResultMeta {
                tainting,
                final_url: final_url.clone(),
                status: entry.status,
                status_text: http::StatusCode::from_u16(entry.status)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .unwrap_or("")
                    .to_string(),
                headers: {
                    // A stored response says how old it is (RFC 9111 §4): the cache's own
                    // `Age`, replacing the one it arrived with.
                    let mut headers = entry.headers.clone();
                    let age = entry.current_age(chrono::Utc::now()).num_seconds().max(0);
                    headers.insert(header::AGE, header::HeaderValue::from(age));
                    headers
                },
                content_length: Some(entry.body.len() as u64),
                content_type: entry
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                has_body: !entry.body.is_empty(),
                from_cache: true,
                peer_addr,
            };
            let rest = BytesAsyncReader {
                data: entry.body.slice(peek_len..),
                pos: 0,
            };
            let reader = ProgressReader::new(
                rest,
                cancel.clone(),
                observer.clone(),
                final_url,
                started,
                meta.content_length,
                peek_len as u64,
            );
            // A cache hit reports a preview too. No tee here: the entry is already whole in
            // memory, so it is cut to the budget directly.
            if let Some(limit) = observer.body_capture_limit(&meta.headers, meta.content_length) {
                let take = entry.body.len().min(limit);
                observer.on_event(NetEvent::BodyPreview {
                    url: meta.final_url.clone(),
                    body: entry.body[..take].to_vec(),
                    truncated: take < entry.body.len(),
                });
            }

            return Ok(ResponseTop {
                meta,
                peek_buf: PeekBuf::from_vec(entry.body[..peek_len].to_vec()),
                body_deadline,
                reader: Box::new(reader),
            });
        }
        HopResponse::Network(resp) => resp,
    };

    // Response is received, setup our meta structure
    let mut meta = FetchResultMeta {
        tainting,
        final_url,
        status: resp.status().as_u16(),
        status_text: resp.status().canonical_reason().unwrap_or("").to_string(),
        headers: resp.headers().clone(),
        content_length: resp.content_length(), // More often than not, this is None
        content_type: resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        has_body: true, // Don't know yet
        from_cache: false,
        peer_addr,
    };

    // A body that declares more than the cap is refused before any of it is read. The checks
    // on what arrives stay for a body that declares nothing, or less than it sends.
    if let (Some(max), Some(len)) = (max_bytes, meta.content_length) {
        if len > max as u64 {
            return Err(NetError::Read(Arc::new(anyhow!(
                "content-length {len} exceeds maximum size of {max} bytes"
            ))));
        }
    }

    // Peek the stream up to PEEK_MAX bytes. A body that stops part way is a transport failure,
    // so it is classified here rather than left as an opaque read error.
    let mut body_stream = resp
        .bytes_stream()
        .map_err(|e| NetError::Transport(TransportError::from_client(&e)));
    let mut received_net: u64 = 0;
    let mut peek_buf_vec: Vec<u8> = Vec::with_capacity(PEEK_MAX);
    let mut excess: Option<Bytes> = None;

    let observer_clone = observer.clone();

    // We might need more fetches than one. Although it's unlikely unless you set PEEK_MAX to >8KB
    while peek_buf_vec.len() < PEEK_MAX {
        // The body's timeouts hold from its first byte: a body that stalls inside the peek
        // window is cut off as it would be after it.
        let idle = async {
            match read_idle_timeout {
                Some(idle) => tokio::time::sleep(idle).await,
                None => std::future::pending().await,
            }
        };
        let deadline = async {
            match body_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let next = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                observer_clone.on_event(NetEvent::Cancelled { url: meta.final_url.clone(), reason: "peek stream cancelled" });
                return Err(NetError::Cancelled("peek stream cancelled".into()));
            }
            // Read bytes from stream
            n = body_stream.next() => n,
            _ = idle => return Err(NetError::Timeout("read idle timeout".into())),
            _ = deadline => return Err(NetError::Timeout("total body timeout".into())),
        };

        match next {
            // We received a chunk of data
            Some(Ok(chunk)) => {
                received_net += chunk.len() as u64;

                let need = PEEK_MAX.saturating_sub(peek_buf_vec.len());
                let fits = chunk.len() <= need;
                if fits {
                    // Entire chunk fits in our peek_buf.
                    peek_buf_vec.extend_from_slice(&chunk);
                } else {
                    // Chunk does not fit. For instance: Peek Buf = 12Kb. We read 8Kb in the first
                    // read, and 8kb in the second. In this case we have read 16kb when we only need
                    // the first 12kb. We fill the peek buf until full, and keep the rest in the
                    // 'excess' buffer
                    peek_buf_vec.extend_from_slice(&chunk[..need]);
                    excess = Some(chunk.slice(need..));
                }

                // Counted as the body goes to the caller: the peek here, the excess when the
                // reader below hands it on, so the count never goes back.
                observer.on_event(NetEvent::Progress {
                    received_bytes: peek_buf_vec.len() as u64,
                    elapsed: started.elapsed(),
                    expected_length: meta.content_length,
                });
                if !fits {
                    break;
                }
            }
            Some(Err(e)) => {
                // Reported by the caller, along with every other failure path. The error
                // is returned as it came rather than flattened into a generic one, so what
                // reaches the observer still names the cause.
                return Err(e);
            }
            None => {
                // Stream ended successfully
                break;
            }
        }
    }

    // The reader of the rest is held to what is left of the cap, which a peek already over it
    // does not show, so it is refused here, before the request counts as answered.
    if let Some(max) = max_bytes {
        if peek_buf_vec.len() > max {
            return Err(NetError::Read(Arc::new(anyhow!(
                "body exceeded maximum size of {max} bytes"
            ))));
        }
    }

    // Save the length before we store the excess into a body stream
    let excess_len = excess.as_ref().map(|b| b.len() as u64).unwrap_or(0);

    // It's possible that we have read too much, and we have an exccess buffer, so we create
    // a new stream that starts at the end of the peek buffer WITH the excess buffer in front.
    //
    //  |--- Peek buffer ---|---- Excess buffer ----| ---- body stream ----|
    //                                              ^ stream starts here
    //                      ^  new body stream "rereads" the excess buffer and starts here
    // boxed() demands a `Send` stream; reqwest's wasm body stream is `!Send` (single thread).
    #[cfg(not(target_arch = "wasm32"))]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed()
    } else {
        body_stream.boxed()
    };
    #[cfg(target_arch = "wasm32")]
    let body_stream = if let Some(ex) = excess {
        stream::once(async move { Ok::<Bytes, NetError>(ex) })
            .chain(body_stream)
            .boxed_local()
    } else {
        body_stream.boxed_local()
    };

    // Capture only when the observer asked for one, up to the limit it gave. It sees the
    // headers first, so an oversized or unwanted response is refused before anything is
    // copied.
    //
    // The peek window is handed over separately and read first, so it is seeded into the
    // capture as the body's opening bytes; the wrapper copies the remainder as the consumer
    // pulls it.
    #[cfg(not(target_arch = "wasm32"))]
    let body_stream = match observer.body_capture_limit(&meta.headers, meta.content_length) {
        Some(limit) => crate::net::body_capture::CapturingBody::new(
            body_stream,
            observer.clone(),
            meta.final_url.clone(),
            limit,
            &peek_buf_vec,
        )
        .boxed(),
        None => body_stream,
    };
    #[cfg(target_arch = "wasm32")]
    let body_stream = match observer.body_capture_limit(&meta.headers, meta.content_length) {
        Some(limit) => crate::net::body_capture::CapturingBody::new(
            body_stream,
            observer.clone(),
            meta.final_url.clone(),
            limit,
            &peek_buf_vec,
        )
        .boxed_local(),
        None => body_stream,
    };

    // Update last remaining items in meta struct
    let peek_buf = PeekBuf::from_vec(peek_buf_vec);
    let has_body_by_len = meta.content_length.unwrap_or(0) > 0 || !peek_buf.is_empty();
    meta.has_body = has_body_by_len;

    // Wrap our body stream into a progress reader. This way it will emit net events to the observer
    // whenever it is read.
    let stream = body_stream.map_err(|e: NetError| e.to_io());
    let inner_reader = StreamReader::new(stream);

    // The progress count so far: the peek, which is what reached the caller.
    let already_delivered = received_net - excess_len;

    // The body's end names the URL it came from, the last hop of the chain.
    let progress_reader = ProgressReader::new(
        inner_reader,
        cancel.clone(),
        observer.clone(),
        meta.final_url.clone(),
        started,
        meta.content_length,
        already_delivered,
    );
    // A response the cache accepted is copied as the caller reads it, and written when the body
    // is complete. A body already known to be too large is not collected at all.
    #[cfg(not(target_arch = "wasm32"))]
    let progress_reader = progress_reader.with_cache(store.and_then(|store| {
        let too_large = meta
            .content_length
            .is_some_and(|len| len as usize > store.max_bytes());
        (!too_large).then(|| CacheCollector::new(store, peek_buf.as_slice()))
    }));

    Ok(ResponseTop {
        meta,
        peek_buf,
        body_deadline,
        reader: Box::new(progress_reader),
    })
}

/// Copies a body on its way to the caller so it can be written to the cache when the stream ends.
///
/// Only a complete body is stored. A fetch that is cancelled, fails, or is dropped mid-stream
/// drops the collector instead, and one that grows past the cache's ceiling drops the pending
/// write and stops copying.
#[cfg(not(target_arch = "wasm32"))]
struct CacheCollector {
    /// The write to perform on EOF. Taken away when the body turns out to be too large.
    store: Option<PendingStore>,
    /// Body bytes so far, starting with the peek window the caller already read.
    body: BytesMut,
    /// Ceiling from [`HttpCache::max_entry_bytes`].
    limit: usize,
}

#[cfg(not(target_arch = "wasm32"))]
impl CacheCollector {
    /// Collector for `store`, seeded with the bytes read before the reader was built.
    fn new(store: PendingStore, prefix: &[u8]) -> Self {
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
    fn feed(&mut self, chunk: &[u8]) {
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
    fn commit(&mut self, observer: &Arc<dyn NetObserver + Send + Sync>) {
        if let Some(store) = self.store.take() {
            store.commit(std::mem::take(&mut self.body).freeze(), observer);
        }
    }
}

/// Progres reader is a simple stream that will wrap another AsyncRead stream, and emit progress
/// events to the observer.
struct ProgressReader<R> {
    /// Actual reader
    inner: R,
    /// Cancellation token
    cancel: CancellationToken,
    // Observer to emit events to
    observer: Arc<dyn NetObserver + Send + Sync>,
    /// Url we are reading from. For event emission
    url: Url,
    /// When we started reading, since we already read the peek buffer from this stream
    started: Instant,
    /// Expected length of the resource, if known
    expected_length: Option<u64>,
    /// Number of bytes already received (from the peek buffer)
    received: u64,
    /// When the body last actually moved. A reader can sit unread for a long time before it
    /// is dropped, and reporting `started.elapsed()` then would describe the wait rather than
    /// the transfer.
    last_activity: Instant,
    /// Whether we already emitted a cancelled event
    cancel_emitted: bool,
    /// Whether we already emitted a finished event (guards against duplicate EOF polls)
    finished_emitted: bool,
    /// Whether we already emitted a failed event (a reader may be polled again after an error)
    failed_emitted: bool,
    /// Copies the body for the HTTP cache, when this response is one that may be stored.
    #[cfg(not(target_arch = "wasm32"))]
    cache: Option<CacheCollector>,
}

impl<R: AsyncRead + Unpin> ProgressReader<R> {
    fn new(
        inner: R,
        cancel: CancellationToken,
        observer: Arc<dyn NetObserver + Send + Sync>,
        url: Url,
        started: Instant,
        expected_length: Option<u64>,
        already_received: u64,
    ) -> Self {
        Self {
            inner,
            cancel,
            observer,
            url,
            started,
            expected_length,
            received: already_received,
            last_activity: Instant::now(),
            cancel_emitted: false,
            finished_emitted: false,
            failed_emitted: false,
            #[cfg(not(target_arch = "wasm32"))]
            cache: None,
        }
    }

    /// Collect the body for the HTTP cache as it is read.
    #[cfg(not(target_arch = "wasm32"))]
    fn with_cache(mut self, collector: Option<CacheCollector>) -> Self {
        self.cache = collector;
        self
    }
}

impl<R> Drop for ProgressReader<R> {
    /// Report the end of a request whose reader is dropped without reaching end-of-stream.
    ///
    /// `Finished` is otherwise only emitted from a read that returns zero bytes, so a
    /// consumer that takes what it needs and drops the reader would end the request with no
    /// terminal event at all -- breaking this module's contract that every request reports
    /// exactly one of `Finished`, `Failed` or `Cancelled`, and leaving an observer with a
    /// request that never comes back.
    ///
    /// Which event depends on whether the body actually arrived. A consumer whose response
    /// fit in the peek window has the whole thing and is genuinely finished; one that
    /// abandoned a partly-read body is not, and saying `Finished` there would report a
    /// transfer that did not happen. Without a declared length there is no way to tell, so
    /// it is treated as abandoned rather than guessed complete.
    ///
    /// The elapsed time is measured to the last read that moved bytes, not to the drop. A
    /// reader can sit untouched for a long time before its owner lets go -- fifteen seconds
    /// is routine -- and `started.elapsed()` would report that wait as the transfer time,
    /// which is a plausible number and a false one.
    fn drop(&mut self) {
        if self.finished_emitted || self.cancel_emitted || self.failed_emitted {
            return;
        }
        let complete = self
            .expected_length
            .is_some_and(|expected| self.received >= expected);
        if complete {
            self.observer.on_event(NetEvent::Finished {
                received_bytes: self.received,
                elapsed: self.last_activity.saturating_duration_since(self.started),
                url: self.url.clone(),
            });
        } else {
            self.observer.on_event(NetEvent::Cancelled {
                url: self.url.clone(),
                reason: "body reader dropped before end of stream",
            });
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // When cancelled, we are directly done
        if self.cancel.is_cancelled() {
            // Only if the read has not ended already: one end per request.
            if !self.cancel_emitted && !self.finished_emitted && !self.failed_emitted {
                self.observer.on_event(NetEvent::Cancelled {
                    url: self.url.clone(),
                    reason: "progress reader cancelled",
                });
                self.cancel_emitted = true;
            }

            let err = NetError::Cancelled("progress reader cancelled".into());
            return std::task::Poll::Ready(Err(err.to_io()));
        }

        // Pull new bytes from the reader
        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let std::task::Poll::Ready(Ok(())) = &poll {
            let new_len = buf.filled().len();
            let read_bytes = (new_len - pre_len) as u64;

            // nothing read, then we have reached the end of the stream
            if read_bytes == 0 && !self.finished_emitted {
                self.finished_emitted = true;
                // The body is complete, so a response waiting to be cached can be written.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let observer = self.observer.clone();
                    if let Some(collector) = self.cache.as_mut() {
                        collector.commit(&observer);
                    }
                }
                self.observer.on_event(NetEvent::Finished {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    url: self.url.clone(),
                });
            }
            if read_bytes > 0 {
                self.last_activity = Instant::now();
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(collector) = self.cache.as_mut() {
                    let filled = buf.filled();
                    collector.feed(&filled[pre_len..new_len]);
                }
                self.received += read_bytes;
                self.observer.on_event(NetEvent::Progress {
                    received_bytes: self.received,
                    elapsed: self.started.elapsed(),
                    expected_length: self.expected_length,
                });
            }
        }

        // A body that dies mid-stream is past the point where `fetch_response_top` can
        // report it - the caller already has this reader - so the terminal event is emitted
        // here instead. Errors are reported once: a reader may be polled again afterwards.
        if let std::task::Poll::Ready(Err(e)) = &poll {
            if !self.failed_emitted && !self.cancel.is_cancelled() {
                self.failed_emitted = true;
                self.observer.on_event(NetEvent::Failed {
                    url: self.url.clone(),
                    error: anyhow!("body read failed: {e}"),
                });
            }
        }

        poll
    }
}

/// Spare capacity kept available for each `read_buf` so it never returns 0 for lack of room
/// (which the loop would misread as EOF).
const READ_CHUNK: usize = 16 * 1024;

/// Fetch a complete resource, returning the metadata and the full body as `Bytes`.
///
/// The body is assembled with a single copy per chunk: bytes are read straight from the
/// underlying stream into a pre-sized [`BytesMut`] (sized from `Content-Length` when known) and
/// then `freeze`d into an `Arc`-backed [`Bytes`]. Handing the result to the caller — and the
/// `Bytes::from`/`freeze` at the boundary — is zero-copy, so the only memcpy of the payload is the
/// unavoidable assembly into one contiguous buffer.
///
/// Crate-private for the reason [`fetch_response_top`] is.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_response_complete(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    // We can cap the amount of bytes we want to read (None for unlimited)
    max_bytes: Option<usize>,
    // Maximum time allowed between reads
    read_idle_timeout: Duration,
    // Total time of read allowed (if any)
    total_body_timeout: Option<Duration>,
    policy: NetPolicy,
) -> Result<(FetchResultMeta, Bytes), NetError> {
    let init = init
        .with_body_timeouts(Some(read_idle_timeout), total_body_timeout)
        .with_max_bytes(max_bytes);
    let ResponseTop {
        meta,
        peek_buf,
        body_deadline,
        mut reader,
    } = fetch_response_top(client, url, init, cancel.clone(), observer.clone(), policy).await?;

    // Pre-size from Content-Length when known to avoid reallocations as the body grows; otherwise
    // start from the peek length. The peek bytes have already been read off the stream, so seed the
    // buffer with them (a one-off copy of the small peek region, not the whole body). Content-Length
    // is untrusted, so the pre-allocation is clamped to MAX_PREALLOC (and max_bytes when set).
    let advertised = meta.content_length.map(|n| n as usize).unwrap_or(0);
    let ceiling = max_bytes.unwrap_or(MAX_PREALLOC).min(MAX_PREALLOC);
    let initial_cap = advertised.min(ceiling).max(peek_buf.len());
    let mut body_buf = BytesMut::with_capacity(initial_cap);
    body_buf.extend_from_slice(peek_buf.as_slice());

    loop {
        // Ensure there is spare capacity so `read_buf` reads directly into the buffer (single copy
        // from the stream) rather than returning 0 for lack of room.
        if body_buf.capacity() - body_buf.len() < READ_CHUNK {
            body_buf.reserve(READ_CHUNK);
        }

        // The total budget is a deadline: a read that blocks is cut off when it passes, not
        // only checked between reads.
        let deadline = async {
            match body_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let n = tokio::select! {
            // Stream cancelled
            _ = cancel.cancelled() => {
                return Err(NetError::Cancelled("fetch_request_complete cancelled".into()));
            }
            _ = deadline => return Err(NetError::Timeout("total body timeout".into())),
            // Read bytes, or timeout when not read something in time. `read_buf` reads directly into
            // the spare capacity of `body_buf`, so there is no intermediate scratch buffer.
            r = timeout(read_idle_timeout, reader.read_buf(&mut body_buf)) => {
                match r {
                    Err(_) => return Err(NetError::Timeout("fetch_request_complete timeout".into())),
                    Ok(Err(e)) => return Err(NetError::Io(Arc::new(e))),
                    Ok(Ok(n)) => n,
                }
            }
        };

        if n == 0 {
            // Stream ended normally
            break;
        }

        if let Some(max) = max_bytes {
            // Too many bytes are read. We throw an error (@TODO: should we do this? not just cap
            // the buffer and return that?
            if body_buf.len() > max {
                return Err(NetError::Read(Arc::new(anyhow!(
                    "fetch_request_complete exceeded maximum size of {} bytes",
                    max
                ))));
            }
        }
    }

    // `freeze` converts the `BytesMut` into an `Arc`-backed `Bytes` without copying.
    Ok((meta, body_buf.freeze()))
}

/// Map a failed `send()` to a `NetError`: TLS handshake failures become `NetError::Tls` (plus a
/// `NetEvent::TlsFailed`), everything else becomes a classified `NetError::Transport`.
///
/// Classified here rather than left to the caller: a send that never got a connection and one
/// whose body stopped part way read the same from above, and separating them means asking the
/// HTTP client.
fn send_error(
    e: reqwest::Error,
    url: &Url,
    what: &str,
    observer: &Arc<dyn NetObserver + Send + Sync>,
    policy: &NetPolicy,
) -> NetError {
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(tls) = crate::net::tls::classify(&e, url) {
        observer.on_event(NetEvent::TlsFailed {
            url: url.clone(),
            error: tls.clone(),
        });
        return NetError::Tls(tls);
    }
    // Without a proxy to name, the tunnel failure stays a connect failure.
    #[cfg(not(target_arch = "wasm32"))]
    if crate::net::transport::is_proxy_auth_required(&e) {
        if let Some(proxy) = policy.proxy_for.as_ref().and_then(|f| f(url)) {
            return NetError::ProxyAuthRequired {
                proxy: Arc::new(proxy),
                url: url.clone(),
            };
        }
    }
    #[cfg(target_arch = "wasm32")]
    let _ = (url, observer, policy);
    let mut err = TransportError::from_client(&e);
    err.message = format!("{what}: {}", err.message);
    NetError::Transport(err)
}

/// A hop's response: what the server sent, or what the cache had.
///
/// A stored response is not a `reqwest::Response` and cannot be made into one, so the redirect
/// loop and its consumers read both through this.
pub(crate) enum HopResponse {
    /// A response from the network.
    Network(reqwest::Response),
    /// A stored response, used as it was or confirmed by a `304`.
    Cached(Arc<CacheEntry>),
}

impl HopResponse {
    /// Status code of the response.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Network(resp) => resp.status().as_u16(),
            Self::Cached(entry) => entry.status,
        }
    }

    /// Response headers. A stored response carries the headers as they were stored: without
    /// `Set-Cookie`, and with the `304`'s updates already merged in.
    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Self::Network(resp) => resp.headers(),
            Self::Cached(entry) => &entry.headers,
        }
    }

    /// Whether this is a redirect the chain should follow: 301, 302, 303, 307 or 308, Fetch's
    /// redirect statuses. Any other 3xx is a response like any other (a 300 is a page listing
    /// the choices, a 304 nobody asked for still goes to the caller), even with a `Location`.
    pub(crate) fn is_redirection(&self) -> bool {
        matches!(self.status(), 301 | 302 | 303 | 307 | 308)
    }
}

/// The peer `resp` was read from, as [`FetchResultMeta::peer_addr`] reports it: `None` when
/// the request to `url` went through a proxy, whose address says nothing about the host's, or
/// when the policy cannot say whether it did.
fn origin_peer(
    resp: &reqwest::Response,
    url: &Url,
    policy: &NetPolicy,
) -> Option<std::net::SocketAddr> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        match policy.proxied {
            Some(ref proxied) if !proxied(url) => resp.remote_addr(),
            _ => None,
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (resp, url, policy);
        None
    }
}

/// A storable response whose body has not been read yet.
///
/// `get_with_redirects` decides whether a response may be cached from its headers, but the body
/// only arrives later, in whichever consumer reads it. This carries that decision until then;
/// dropping it (a cancelled fetch, a body over the cache's ceiling) stores nothing.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct PendingStore {
    cache: Arc<dyn HttpCache>,
    key: CacheKey,
    url: Url,
    status: u16,
    response_headers: HeaderMap,
    request_headers: HeaderMap,
    decoded: bool,
    requested_at: chrono::DateTime<chrono::Utc>,
    received_at: chrono::DateTime<chrono::Utc>,
    peer_addr: Option<std::net::SocketAddr>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PendingStore {
    /// Largest body the cache behind this will accept.
    pub(crate) fn max_bytes(&self) -> usize {
        self.cache.max_entry_bytes()
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

/// What a whole redirect chain came to.
pub(crate) struct ChainOutcome {
    /// The first response that was not a redirect.
    pub(crate) response: HopResponse,
    /// URL of the hop that produced it, i.e. the final URL of the chain.
    pub(crate) url: Url,
    /// Response tainting of the chain — see [`cors`](mod@crate::net::cors).
    pub(crate) tainting: ResponseTainting,
    /// Where that response came from — see [`FetchResultMeta::peer_addr`].
    pub(crate) peer_addr: Option<std::net::SocketAddr>,
    /// Set when that response may be cached once its body has been read.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) store: Option<PendingStore>,
}

/// Find credentials for the first challenge that has any: the credential store first, then the
/// embedder's hook, walking the challenges in the order the server listed them.
///
/// Returns the protection space they belong to, so they can be stored or dropped depending on
/// what the server makes of them, the credentials, and the value for the credentials header.
fn credentials_for_challenges(
    policy: &NetPolicy,
    challenges: &[AuthChallenge],
) -> Option<(ProtectionSpace, Credentials, header::HeaderValue)> {
    for challenge in challenges {
        let space = challenge.protection_space();
        let known = policy
            .credentials
            .as_ref()
            .and_then(|store| store.credentials_for(&space));
        let credentials = match known.or_else(|| (policy.on_auth_challenge)(challenge)) {
            Some(credentials) => credentials,
            None => continue,
        };
        // Credentials that cannot be expressed as a header value are not an answer; try the next
        // challenge instead of re-sending the request unchanged.
        if let Some(value) = credentials.header_value() {
            return Some((space, credentials, value));
        }
    }
    None
}

/// Perform a GET request, following redirects up to MAX_REDIRECTS times, while sending out net events.
///
/// Follow a chain of HTTP redirects, returning the first non-redirect response.
///
/// - `init.method` and `init.body` are preserved on 307/308; downgraded to GET (body dropped)
///   on 301/302/303, matching browser behaviour (RFC 7231 §6.4).
/// - `Authorization` and `Cookie` are stripped on cross-origin redirects (RFC 9110 §15.4);
///   the cookie jar is re-queried for the new origin.
/// - Only `http` and `https` targets are followed; other schemes are rejected.
/// - Credentials embedded in the URL (`user:password@`) are dropped, from the initial URL
///   and from every `Location`, so the client never turns them into an `Authorization`
///   header. A cross-origin or cors-mode `Location` with credentials is refused outright.
/// - Insecure hops requested by a secure `init.origin` are blocked or upgraded per
///   `init.mixed_content`, re-evaluated at every hop so a redirect cannot escape the check.
/// - `Referer` is recomputed at every hop, since the same-origin and downgrade determinations
///   change as the chain moves, from the referrer the previous hop sent (Fetch, main fetch step
///   9): `init.referrer` on the first hop, and what was left of it after that. A referrer once
///   reduced to its origin, or withheld, stays so for the rest of the chain. A
///   `Referrer-Policy` header on a 3xx response replaces the policy for the remaining hops, but
///   cannot bring back what an earlier hop already cut.
/// - `Origin` and the `Sec-Fetch-*` headers are likewise recomputed at every hop from
///   `init.origin`, `init.destination`, and `init.mode`. `Sec-Fetch-Site` only degrades across
///   the chain, and `Origin` collapses to `null` once the chain redirects away from an origin
///   the request had already left — see [`fetch_metadata`](mod@crate::net::fetch_metadata).
/// - Every upgrade to `https` is reported as [`NetEvent::SecurityUpgraded`], and every other
///   change a policy makes to a hop as [`NetEvent::RequestModified`].
/// - `policy.url_allowed` and `policy.cookies_for` are called at every hop.
/// - A `401`/`407` hop is re-sent with credentials from the credential store or
///   `policy.on_auth_challenge` (see [`auth`](mod@crate::net::auth)); only a response that is
///   not a challenge continues through the chain.
/// - `Set-Cookie` values on 3xx responses are reported via `policy.on_cookies` and the jar is
///   re-queried for the next hop; the final response's cookies are the caller's responsibility.
/// - CORS is enforced per hop when `init.origin` is set — the same-origin/no-cors mode rules
///   before sending, a preflight (with `policy.cors_preflight` as its cache) when the method or
///   headers need one, and the CORS check on every response of a cors-tainted chain. The chain's
///   final [`ResponseTainting`] is returned beside the response — see
///   [`cors`](mod@crate::net::cors).
async fn get_with_redirects(
    client: Arc<reqwest::Client>,
    url: Url,
    init: RequestInit,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver + Send + Sync>,
    policy: NetPolicy,
) -> Result<ChainOutcome, NetError> {
    let mut url = url;
    let mut current_method = normalize_method(init.method);
    // Where the chain has been: every hop's URL before the current one (Fetch, request's URL
    // list), for the cookie hook to judge `SameSite` across the chain.
    let mut url_list: Vec<Url> = Vec::new();
    let mut current_headers = trimmed_values(init.headers);
    let mut current_body = init.body;
    let origin = init.origin;
    // The message framing is the body's (RFC 9112 §6): a caller's `Content-Length` that does
    // not match it cuts the body short or leaves the server waiting for bytes that never come,
    // and a `Transfer-Encoding` would contradict the one the connection picks. Web content
    // may not set any forbidden request-header (Fetch §2.2.2): those are the user agent's,
    // and the CORS rules below take that for granted.
    let mut removed: Vec<header::HeaderName> = Vec::new();
    for name in current_headers.keys() {
        let forbidden = origin.is_some()
            && current_headers
                .get_all(name)
                .iter()
                .any(|value| cors::is_forbidden_request_header_value(name, value));
        let framing = *name == header::CONTENT_LENGTH || *name == header::TRANSFER_ENCODING;
        if forbidden || framing {
            removed.push(name.clone());
        }
    }
    for name in &removed {
        current_headers.remove(name);
    }
    if !removed.is_empty() {
        modified(
            &observer,
            &url,
            RequestChange::HeadersRemoved { headers: removed },
        );
    }
    // Set here rather than left to the client, which would add it while executing the request,
    // after `RequestSent` was reported. Matches what `build_client` enables for a decoding
    // client; a caller that asked for raw bytes advertises nothing it cannot decode.
    //
    // A range counts bytes of the representation as it is sent, so a ranged request asks for
    // it unencoded (Fetch §4.6), appended to a value the caller set itself.
    if current_headers.contains_key(header::RANGE) {
        current_headers.append(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("identity"),
        );
    } else if !current_headers.contains_key(header::ACCEPT_ENCODING) {
        current_headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static(if init.auto_decode {
                "gzip, br, deflate"
            } else {
                "identity"
            }),
        );
    }
    // Web content may not send these (Fetch §2.2.1). A request without an origin is the
    // embedder's own and may.
    if origin.is_some() && cors::is_forbidden_method(&current_method) {
        return Err(blocked(&observer, url, BlockReason::ForbiddenMethod));
    }
    // A redirect may replace this for the remaining hops (Fetch, HTTP-redirect fetch).
    let mut referrer_policy = init.referrer_policy;
    // The request's referrer as the chain has left it (Fetch, main fetch step 9): each hop
    // determines its `Referer` from what the hop before it sent, not from the document URL, so
    // a referrer once cut down to its origin stays cut down, and one once withheld stays
    // withheld, however the chain moves or what policy a redirect announces.
    let mut chain_referrer = init.referrer.clone();
    // `Sec-Fetch-Site` describes the whole chain, not the current hop: it starts at same-origin
    // and can only degrade, so a detour through a foreign site is still visible when the chain
    // lands back home.
    let mut site = SecFetchSite::SameOrigin;
    // The tainted origin flag (Fetch, HTTP-redirect fetch): once set, `Origin` is sent as the
    // literal `null` for every remaining hop.
    let mut origin_tainted = false;
    // `RequestChange::OriginTainted` is reported once per chain, on the first `null` it causes.
    let mut taint_reported = false;
    // Whether the `Cookie` in `current_headers` came from the jar rather than from the caller.
    let mut cookie_from_jar = false;
    // Response tainting (Fetch §2.2.5): basic until the chain leaves the initiating origin,
    // then cors/opaque per the request mode — and it stays there even if a detour redirects
    // back home, which is why the CORS check below keys on this and not on the hop's URL.
    let mut tainting = ResponseTainting::Basic;
    // The credentialed CORS rules key on the request's credentials *mode*, not on whether
    // cookies were actually attached on a given hop. Only the native checks consult it — on
    // wasm32 the browser enforces the credentialed rules itself.
    #[cfg(not(target_arch = "wasm32"))]
    let credentials_include = init.credentials == RequestCredentials::Include;

    // Armed by the first redirect; `None` until then, and for good without a budget.
    let mut redirect_deadline: Option<tokio::time::Instant> = None;

    // `redirects` counts the redirects followed so far. One request more than the limit: the
    // chain may follow MAX_REDIRECTS redirects, and only a redirect after those is an error
    // (Fetch, HTTP-redirect fetch: a network error when the count is already 20).
    for redirects in 0..=MAX_REDIRECTS {
        // HSTS upgrade first: a stored policy forces `https` for a known host regardless of the
        // mixed-content setting. `hop_checks` then re-checks the scheme and mixed content on the
        // (possibly upgraded) URL and runs `url_allowed` last, so the policy hook always vets the
        // URL actually sent. All of this re-runs on every hop: an https document may be redirected
        // onto plain http, which the caller cannot see and so cannot check for itself.
        //
        // The URL as it stood before an HSTS rewrite is kept for the referrer: Fetch determines
        // the referrer (main fetch step 9) before it applies HSTS (step 11), so an `https`
        // document linking to `http://` is a downgrade for the referrer even when HSTS then sends
        // the request over TLS.
        #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
        let mut before_hsts: Option<Url> = None;
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref store) = policy.hsts {
            if hsts::should_upgrade(store.as_ref(), &url, chrono::Utc::now()) {
                before_hsts = Some(url.clone());
                let upgraded = hsts::upgrade(&url);
                observer.on_event(NetEvent::SecurityUpgraded {
                    from: url.clone(),
                    to: upgraded.clone(),
                    reason: UpgradeReason::Hsts,
                });
                url = upgraded;
            }
        }

        match hop_checks(
            &url,
            init.mixed_content,
            origin.as_ref(),
            init.destination,
            &policy.allowed_bad_ports,
            &|u| (policy.url_allowed)(u),
        ) {
            HopCheck::Reject(reason) => return Err(blocked(&observer, url, reason)),
            HopCheck::Proceed(target) => {
                if target != url {
                    observer.on_event(NetEvent::SecurityUpgraded {
                        from: url.clone(),
                        to: target.clone(),
                        reason: UpgradeReason::MixedContent,
                    });
                    url = target;
                }
            }
        }

        // The client connects to an IP literal without asking the resolver, so a policy in
        // it would never see e.g. 169.254.169.254. Ask it here with the literal as the name;
        // an Err refuses the hop like a refused name would. The returned addresses are unused.
        #[cfg(not(target_arch = "wasm32"))]
        if let (Some(resolver), Some(literal)) = (policy.dns_resolver.as_ref(), ip_literal(&url)) {
            let refused = tokio::select! {
                _ = cancel.cancelled() => {
                    observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "all callers cancelled" });
                    return Err(NetError::Cancelled("all callers cancelled".into()));
                }
                r = resolver.resolve(&literal) => r.err(),
            };
            if let Some(e) = refused {
                return Err(NetError::Transport(TransportError {
                    kind: crate::net::transport::TransportErrorKind::Connect,
                    message: format!("dns error: {e}"),
                }));
            }
        }

        // CORS regime for this hop (Fetch, main fetch). Only a request with a document context
        // is subject to it, and only once the chain has left the initiating origin — a tainted
        // chain counts as having left even when a detour lands back home. Navigations are not
        // CORS-checked, and a WebSocket server opts in via its own handshake instead.
        if let Some(ref o) = origin {
            let has_left_origin = origin_tainted || *o != url.origin();
            if has_left_origin {
                match init.mode {
                    RequestMode::SameOrigin => {
                        return Err(blocked(
                            &observer,
                            url,
                            BlockReason::Cors(CorsError::SameOriginMode),
                        ));
                    }
                    // A no-cors request may go cross-origin, but only in the shape markup can
                    // produce: safelisted method, no headers the fetcher does not own. The
                    // response becomes opaque.
                    RequestMode::NoCors => {
                        tainting = ResponseTainting::Opaque;
                        if !cors::is_cors_safelisted_method(&current_method) {
                            return Err(blocked(
                                &observer,
                                url,
                                BlockReason::Cors(CorsError::UnsafeMethodForNoCors),
                            ));
                        }
                        if !cors::unsafe_request_header_names(&current_headers).is_empty() {
                            return Err(blocked(
                                &observer,
                                url,
                                BlockReason::Cors(CorsError::UnsafeHeaderForNoCors),
                            ));
                        }
                    }
                    RequestMode::Cors => tainting = ResponseTainting::Cors,
                    RequestMode::Navigate | RequestMode::Websocket => {}
                }
            }
        }

        // Recomputed per hop from what the last hop sent; see `chain_referrer`. Judged against
        // the URL before any HSTS rewrite, with only a mixed content upgrade applied, which
        // Fetch makes first (main fetch step 6); see `before_hsts`.
        if let Some(ref source) = init.referrer {
            let referrer_target = match before_hsts {
                Some(ref plain) => {
                    match mixed_content::evaluate_for(
                        init.mixed_content,
                        origin.as_ref(),
                        plain,
                        init.destination,
                    ) {
                        MixedContentAction::Upgrade(upgraded) => upgraded,
                        _ => plain.clone(),
                    }
                }
                None => url.clone(),
            };
            let determined = chain_referrer.as_ref().and_then(|current| {
                referrer::determine(current, referrer_policy, &referrer_target)
            });
            let sent = match determined {
                Some(value) => match value.as_str().parse() {
                    Ok(header_value) => {
                        current_headers.insert(header::REFERER, header_value);
                        Some(value)
                    }
                    // A URL that will not go into a header is not worth failing the request over.
                    Err(_) => {
                        current_headers.remove(header::REFERER);
                        None
                    }
                },
                // Drop any value from an earlier hop: this one is not allowed a referrer.
                None => {
                    current_headers.remove(header::REFERER);
                    None
                }
            };
            chain_referrer = sent.clone();
            // Measured against what would go out with no policy. A source that is never sent
            // (not http or https) has nothing to reduce.
            if let Some(full) = referrer::strip(source) {
                if sent.as_ref() != Some(&full) {
                    modified(
                        &observer,
                        &url,
                        RequestChange::ReferrerReduced {
                            from: full,
                            to: sent,
                            policy: referrer_policy,
                        },
                    );
                }
            }
        }

        // Origin and Sec-Fetch-* are likewise recomputed per hop.
        let hop_site = match origin {
            Some(ref o) => {
                site = site.min(fetch_metadata::classify_site(o, &url));
                site
            }
            // No initiating origin means the request was not triggered by web content.
            None => SecFetchSite::None,
        };
        fetch_metadata::apply_sec_fetch_headers(
            &mut current_headers,
            &url,
            init.destination,
            init.mode,
            hop_site,
            init.user_activated,
        );

        // Without an initiating origin there is nothing to compute; a hand-set `Origin`
        // header then goes out verbatim, like a hand-set `Referer`.
        if let Some(ref o) = origin {
            match fetch_metadata::origin_header_value(
                o,
                origin_tainted,
                &current_method,
                init.mode,
                referrer_policy,
                &url,
            ) {
                Some(value) => {
                    // `null` for an origin that has a serialisation is a change worth reporting.
                    // An opaque origin serialises to `null` anyway.
                    if value == "null" && matches!(o, Origin::Tuple(..)) {
                        if origin_tainted {
                            if !taint_reported {
                                taint_reported = true;
                                modified(&observer, &url, RequestChange::OriginTainted);
                            }
                        } else {
                            modified(
                                &observer,
                                &url,
                                RequestChange::OriginHidden {
                                    policy: referrer_policy,
                                },
                            );
                        }
                    }
                    match value.parse() {
                        Ok(value) => {
                            current_headers.insert(header::ORIGIN, value);
                        }
                        Err(_) => {
                            current_headers.remove(header::ORIGIN);
                        }
                    }
                }
                None => {
                    current_headers.remove(header::ORIGIN);
                }
            }
        }

        // CORS preflight (Fetch §4.9): a cross-origin cors-mode request whose method or headers
        // markup could not produce must be approved by the server before it is sent. Running
        // this per hop is what modern browsers do after a redirect moves the target — the
        // grant is per (origin, URL), so a new URL needs its own, usually served from the
        // cache. The OPTIONS goes out credential-less and never follows redirects (the client
        // has redirects disabled; a 3xx fails the ok-status test).
        //
        // Native-only: on wasm32 the browser preflights itself and does not surface the
        // `Access-Control-*` response headers this validation would need.
        #[cfg(not(target_arch = "wasm32"))]
        let mut preflight_grant: Option<PreflightGrant> = None;
        #[cfg(not(target_arch = "wasm32"))]
        if init.mode == RequestMode::Cors && tainting == ResponseTainting::Cors {
            if let Some(ref o) = origin {
                let unsafe_names = cors::unsafe_request_header_names(&current_headers);
                if !cors::is_cors_safelisted_method(&current_method) || !unsafe_names.is_empty() {
                    let serialized = cors::serialize_origin(o, origin_tainted);
                    let now = chrono::Utc::now();
                    // A grant made with credentials also covers the request without them
                    // (Fetch, "method cache entry match"). It is judged by the credentialed
                    // rules it was made under, where a `*` is a literal, not a wildcard.
                    let granted = policy.cors_preflight.as_ref().is_some_and(|cache| {
                        let fits = |credentialed: bool| {
                            cache
                                .get(&serialized, &url, credentialed, now)
                                .is_some_and(|allows| {
                                    allows
                                        .permits(&current_method, &unsafe_names, credentialed)
                                        .is_ok()
                                })
                        };
                        fits(credentials_include) || (!credentials_include && fits(true))
                    });
                    if !granted {
                        let mut pf_headers =
                            cors::preflight_request_headers(&current_method, &unsafe_names);
                        if let Ok(v) = serialized.parse() {
                            pf_headers.insert(header::ORIGIN, v);
                        }
                        // The preflight has the request's referrer (Fetch §4.8 step 1), as this
                        // hop computed it above.
                        if let Some(referer) = current_headers.get(header::REFERER) {
                            pf_headers.insert(header::REFERER, referer.clone());
                        }
                        fetch_metadata::apply_sec_fetch_headers(
                            &mut pf_headers,
                            &url,
                            init.destination,
                            init.mode,
                            hop_site,
                            false,
                        );
                        observer.on_event(NetEvent::CorsPreflight { url: url.clone() });
                        let pf_started = Instant::now();
                        let fut = client
                            .request(Method::OPTIONS, url.clone())
                            .headers(pf_headers)
                            .send();
                        tokio::pin!(fut);
                        let pf_resp = tokio::select! {
                            _ = cancel.cancelled() => {
                                observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "cancelled during CORS preflight" });
                                return Err(NetError::Cancelled("cancelled during CORS preflight".into()));
                            }
                            r = &mut fut => r.map_err(|e| send_error(e, &url, "CORS preflight request failed", &observer, &policy))?
                        };
                        // Reported before validation: a preflight the server answered cost
                        // this round-trip whether or not the answer turns out to permit the
                        // request. A rejection is separately reported as `Blocked`.
                        observer.on_event(NetEvent::CorsPreflightDone {
                            url: url.clone(),
                            elapsed: pf_started.elapsed(),
                        });
                        let allows = cors::validate_preflight_response(
                            pf_resp.status().as_u16(),
                            pf_resp.headers(),
                            o,
                            origin_tainted,
                            credentials_include,
                        )
                        .and_then(|allows| {
                            allows
                                .permits(&current_method, &unsafe_names, credentials_include)
                                .map(|()| allows)
                        })
                        .map_err(|e| blocked(&observer, url.clone(), BlockReason::Cors(e)))?;
                        if let Some(cache) = policy.cors_preflight.as_ref() {
                            cache.put(&serialized, &url, credentials_include, allows, now);
                        }
                    }
                    preflight_grant = policy.cors_preflight.as_ref().map(|cache| PreflightGrant {
                        cache: cache.clone(),
                        origin: serialized,
                        url: url.clone(),
                        kept: false,
                    });
                }
            }
        }

        // Cookies from the jar and an answer to an authentication challenge are both
        // credentials, so the request's credentials mode gates them together.
        // Cookies are only injected when no Cookie header is already set; this naturally handles
        // cross-origin redirects: the cookie was stripped above, so the jar is re-queried for the
        // new origin.
        let attach_credentials = match init.credentials {
            RequestCredentials::Include => true,
            RequestCredentials::Omit => false,
            // Without a document origin to compare against, "same-origin" has no meaning and
            // the request is first-party tooling; it keeps its cookies.
            RequestCredentials::SameOrigin => origin
                .as_ref()
                .is_none_or(|o| !origin_tainted && *o == url.origin()),
        };
        if !attach_credentials && init.credentials == RequestCredentials::SameOrigin {
            modified(&observer, &url, RequestChange::CredentialsWithheld);
        }
        // A hop that carries a jar's cookies is cached for that jar alone.
        #[cfg(not(target_arch = "wasm32"))]
        let cache_partition = if attach_credentials {
            policy.cache_partition.as_str()
        } else {
            ""
        };
        if attach_credentials && !current_headers.contains_key(header::COOKIE) {
            if let Some(cookie_str) =
                (policy.cookies_for)(&CookieHop::new(&url, &current_method, &url_list))
            {
                if let Ok(mut val) = cookie_str.parse::<http::HeaderValue>() {
                    val.set_sensitive(true);
                    current_headers.insert(header::COOKIE, val);
                    cookie_from_jar = true;
                }
            }
        }

        // The HTTP cache (RFC 9111), consulted per hop with the headers this hop will actually
        // send, so `Vary` selects on the cookies and the negotiation headers as sent. A fresh
        // stored response ends the hop without a request; a stale one that can be revalidated
        // adds its conditional headers to the send below. See [`cache`](mod@crate::net::cache).
        //
        // The mode as Fetch handles it: a caller's own condition turns `Default` into `NoStore`.
        // Read here from the caller's headers, before any conditional header of the cache's own.
        #[cfg(not(target_arch = "wasm32"))]
        let cache_mode = cache::effective_mode(init.cache_mode, &current_headers);
        #[cfg(not(target_arch = "wasm32"))]
        let (cache_hit, mut revalidating, mut conditional) = match policy.cache {
            Some(ref cache) => {
                let key = CacheKey::new(&current_method, &url).in_partition(cache_partition);
                let stored = cache.get(&key);
                match cache::decide(
                    &stored,
                    &current_headers,
                    init.auto_decode,
                    cache_mode,
                    chrono::Utc::now(),
                ) {
                    CacheDecision::Use(entry) => (Some(entry), None, HeaderMap::new()),
                    CacheDecision::Revalidate(entry, conditional) => {
                        (None, Some(entry), conditional)
                    }
                    CacheDecision::Send => (None, None, HeaderMap::new()),
                    // `only-if-cached`, with nothing stored to answer it.
                    CacheDecision::NotCached => {
                        return Err(blocked(&observer, url, BlockReason::NotCached))
                    }
                }
            }
            None => (None, None, HeaderMap::new()),
        };
        // No cache on wasm32, so every hop goes out as it is.
        #[cfg(target_arch = "wasm32")]
        let (cache_hit, conditional): (Option<Arc<CacheEntry>>, HeaderMap) =
            (None, HeaderMap::new());

        // Authentication (RFC 9110 §11): a 401 or 407 is re-sent with credentials whenever they
        // can be found for one of its challenges, at most `MAX_AUTH_ATTEMPTS` times each. Only a
        // response that is not a challenge leaves this loop. See
        // [`auth`](mod@crate::net::auth).
        //
        // The proxy and the origin server are asked separately, and a hop through an
        // authenticating proxy to a protected server needs both answers at once
        // (`Proxy-Authorization` and `Authorization`, RFC 9110 §11.6-11.7): each has its own
        // header, attempt count and unaccepted credentials.
        let mut server_auth = AuthSlot::default();
        let mut proxy_auth = AuthSlot::default();
        // A site already logged in to gets its `Basic` credentials with the first send, as a
        // browser does, instead of after a `401` every time (RFC 7617 §2.2; Fetch's
        // authentication entry). Under the same conditions as answering a challenge, for this
        // hop's own URL: a redirect elsewhere is looked up for where it goes, and finds nothing
        // on another origin.
        if attach_credentials
            && tainting == ResponseTainting::Basic
            && !current_headers.contains_key(header::AUTHORIZATION)
        {
            if let Some((_, credentials)) = policy
                .credentials
                .as_ref()
                .and_then(|store| store.upfront_for(&url))
            {
                server_auth.header = credentials.header_value();
            }
        }

        // Timestamps of the exchange that produced the response below, for the age of a cache
        // entry made from it (RFC 9111 §4.2.3). A retried hop overwrites them, so they always
        // describe the send that was kept.
        #[cfg(not(target_arch = "wasm32"))]
        let mut requested_at = chrono::Utc::now();
        #[cfg(not(target_arch = "wasm32"))]
        let mut received_at = requested_at;

        let hop = match cache_hit {
            Some(entry) => {
                // The CORS check applies to a response wherever it came from (Fetch §4.10.3).
                // The entry may have been stored by a same-origin fetch, which needed no
                // `Access-Control-Allow-Origin`; handing it to a cross-origin caller would read
                // it past the check the network path enforces. Blocked rather than re-sent,
                // as browsers do: a server whose allow-origin depends on `Origin` says
                // `Vary: Origin`, and then the entry is not a match in the first place.
                #[cfg(not(target_arch = "wasm32"))]
                if tainting == ResponseTainting::Cors {
                    if let Some(ref o) = origin {
                        if let Err(e) =
                            cors::cors_check(o, origin_tainted, credentials_include, &entry.headers)
                        {
                            return Err(blocked(&observer, url, BlockReason::Cors(e)));
                        }
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(grant) = preflight_grant.take() {
                    grant.keep();
                }
                observer.on_event(NetEvent::Cache {
                    url: url.clone(),
                    outcome: CacheOutcome::Hit,
                });
                HopResponse::Cached(entry)
            }
            None => loop {
                // The credentials and conditional headers are added for the send only, so a redirect
                // from this hop starts from the caller's headers again.
                let mut hop_headers = current_headers.clone();
                for (target, slot) in [
                    (AuthTarget::Server, &server_auth),
                    (AuthTarget::Proxy, &proxy_auth),
                ] {
                    if let Some(ref value) = slot.header {
                        hop_headers.insert(target.credentials_header(), value.clone());
                    }
                }
                for (name, value) in conditional.iter() {
                    hop_headers.insert(name.clone(), value.clone());
                }
                // What the cache mode asks of every cache on the way, not just this one (Fetch,
                // HTTP-network-or-cache fetch): a forced revalidation says `max-age=0`, a reload
                // or a no-store request `no-cache`. Each only when the caller set none. Added for
                // the send, after the CORS decision, as Fetch does: neither header is
                // CORS-safelisted, and the mode alone must not cost a preflight.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let cache_control = match cache_mode {
                        CacheMode::NoCache => Some("max-age=0"),
                        CacheMode::NoStore | CacheMode::Reload => {
                            if !hop_headers.contains_key(header::PRAGMA) {
                                hop_headers.insert(
                                    header::PRAGMA,
                                    header::HeaderValue::from_static("no-cache"),
                                );
                            }
                            Some("no-cache")
                        }
                        _ => None,
                    };
                    if let Some(value) = cache_control {
                        if !hop_headers.contains_key(header::CACHE_CONTROL) {
                            hop_headers.insert(
                                header::CACHE_CONTROL,
                                header::HeaderValue::from_static(value),
                            );
                        }
                    }
                }
                // Written here rather than left to the client, which would add it while
                // executing the request -- after this hop was reported. Only when nothing has
                // already answered a `407` for this hop, which is both the credential that was
                // actually accepted and what the client itself would defer to.
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(ref proxy_authorization) = policy.proxy_authorization {
                    if !hop_headers.contains_key(header::PROXY_AUTHORIZATION) {
                        if let Some(mut value) = proxy_authorization(&url) {
                            value.set_sensitive(true);
                            hop_headers.insert(header::PROXY_AUTHORIZATION, value);
                        }
                    }
                }
                let mut req_builder = client
                    .request(current_method.clone(), url.clone())
                    .headers(hop_headers);
                // A per-request timeout replaces the client's for this request only, so it
                // can be set shorter or longer than the client-wide default. Redirects and
                // authenticated retries come back through here, so every hop gets a fresh one.
                if let Some(timeout) = init.timeout {
                    req_builder = req_builder.timeout(timeout);
                }
                if let Some(ref body) = current_body {
                    // Built fresh per send so a streamed body can be replayed on 307/308 and for an
                    // authenticated retry of this hop.
                    let (hop_body, explicit_len) = body.to_reqwest_body()?;
                    // Set here rather than left to the connection, which would otherwise
                    // compute the same number while encoding the request -- below any layer
                    // holding a header map, and so below anything that could report it. A
                    // stream needs it regardless, being unsized as far as the client knows.
                    if let Some(len) = explicit_len {
                        req_builder = req_builder.header(header::CONTENT_LENGTH, len);
                    }
                    req_builder = req_builder.body(hop_body);
                } else if current_method == Method::POST || current_method == Method::PUT {
                    // Fetch §4.6: a POST or PUT without a body says so, which strict servers
                    // require (RFC 9110 §8.6) and the connection would not add.
                    req_builder = req_builder.header(header::CONTENT_LENGTH, 0);
                }
                // Built rather than sent straight away, so what is reported is the request the
                // client assembled rather than the arguments it was handed.
                //
                // Reported here rather than beside `Started`: the headers are only final for
                // this hop at this point. Credentials and conditional headers are added just
                // above, and a redirect starts over from the caller's set, so an earlier
                // event would describe a request that was never sent.
                //
                // `build()` does not merge the client's own default headers -- those are
                // applied when the request executes, which is after this. For a client built
                // by `Fetcher` that costs nothing, because every header it would default is
                // written by this crate before the request is assembled. The user agent is the
                // exception, since it is configured on the client and cannot be read back, so
                // `NetPolicy::with_user_agent` carries the value and it is filled in below.
                //
                // What is left is added by the connection and determined by the protocol:
                // `host` (or `:authority` over HTTP/2), and `transfer-encoding: chunked` on
                // HTTP/1.1 for a body of unknown length. Neither reaches a `reqwest::Request`,
                // and neither is guessed at here.
                let request = req_builder.build().map_err(|e| {
                    send_error(
                        e,
                        &url,
                        "net.get_with_redirects request build failed",
                        &observer,
                        &policy,
                    )
                })?;
                #[cfg(not(target_arch = "wasm32"))]
                let request = order_hop_headers(
                    request,
                    init.header_order.as_deref(),
                    policy.user_agent.as_ref(),
                    !(policy.speaks_h2)(&url),
                );
                let mut reported = request.headers().clone();
                // Only when the assembled request does not already carry one: a header set
                // per-request wins over the client default, and reporting the default over
                // the top of it would be a lie in the one direction that matters.
                if let Some(ref ua) = policy.user_agent {
                    reported
                        .entry(http::header::USER_AGENT)
                        .or_insert(ua.clone());
                }
                observer.on_event(NetEvent::RequestSent {
                    url: url.clone(),
                    method: request.method().clone(),
                    headers: reported,
                });

                let fut = client.execute(request);
                tokio::pin!(fut);
                let deadline = async {
                    match redirect_deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::pin!(deadline);
                #[cfg(not(target_arch = "wasm32"))]
                {
                    requested_at = chrono::Utc::now();
                }

                let resp = tokio::select! {
                    _ = cancel.cancelled() => {
                        observer.on_event(NetEvent::Cancelled { url: url.clone(), reason: "all callers cancelled" });
                        return Err(NetError::Cancelled("all callers cancelled".into()));
                    }
                    _ = &mut deadline => {
                        return Err(NetError::Timeout(format!(
                            "redirect chain exceeded {:?} after {} redirects",
                            init.redirect_timeout.unwrap_or_default(),
                            redirects
                        )));
                    }
                    r = &mut fut => r.map_err(|e| send_error(e, &url, "net.get_with_redirects request failed", &observer, &policy))?
                };
                #[cfg(not(target_arch = "wasm32"))]
                {
                    received_at = chrono::Utc::now();
                }

                // Report the HTTP version of every hop, not just the final response, so the fetcher's
                // per-origin limits also learn about intermediate origins. reqwest's wasm Response has
                // no version().
                #[cfg(not(target_arch = "wasm32"))]
                (policy.on_protocol)(resp.url(), resp.version());

                // Per hop, like the other events in this loop: the first one marks
                // time-to-first-byte for the request, and a redirect chain reports each hop
                // it waited on. A hop served from the cache received no headers over the
                // wire and reports `Cache` instead.
                observer.on_event(NetEvent::ResponseHeaders {
                    url: resp.url().clone(),
                    status: resp.status().as_u16(),
                    headers: resp.headers().clone(),
                });

                // A `101` is a final response only to a WebSocket handshake (Fetch §4.7,
                // HTTP-network fetch) or a request that asked for an upgrade itself. Any other is
                // a protocol switch nothing here speaks, not a response to hand on.
                if resp.status() == http::StatusCode::SWITCHING_PROTOCOLS
                    && init.mode != RequestMode::Websocket
                    && !current_headers.contains_key(header::UPGRADE)
                {
                    return Err(NetError::Other(Arc::new(anyhow!(
                        "{url}: 101 Switching Protocols to a request that asked for no upgrade"
                    ))));
                }

                // Harvest HSTS from every hop, not just the final one: a 301 http->https is the usual way
                // a site first arms it, and that response is consumed below.
                // RFC 6797 §8.1: not from a connection the user clicked through.
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(ref store) = policy.hsts {
                    if !over_accepted_override(&policy, &resp) {
                        hsts::record(store.as_ref(), &url, resp.headers(), chrono::Utc::now());
                    }
                }

                // The CORS check (Fetch §4.10.3) runs on *every* response of a cors-tainted chain —
                // redirects included, and also a final same-origin hop reached through a cross-origin
                // detour. Native-only: on wasm32 the browser has already enforced this.
                #[cfg(not(target_arch = "wasm32"))]
                if tainting == ResponseTainting::Cors {
                    if let Some(ref o) = origin {
                        if let Err(e) =
                            cors::cors_check(o, origin_tainted, credentials_include, resp.headers())
                        {
                            return Err(blocked(&observer, url, BlockReason::Cors(e)));
                        }
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(grant) = preflight_grant.take() {
                    grant.keep();
                }

                // A `304` answers a revalidation: the stored body stands, with the headers the
                // response carried written over the stored ones (RFC 9111 §4.3.4).
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(ref entry) = revalidating {
                    // A `304` that names another version than the stored one confirms nothing
                    // (RFC 9111 §4.3.4): updating from it would pin the old body under the new
                    // tag, and every later revalidation would confirm it again. The entry goes,
                    // and the hop is asked again without conditions, once.
                    if resp.status().as_u16() == 304 && entry.contradicted_by(resp.headers()) {
                        if let Some(ref cache) = policy.cache {
                            cache.invalidate(&CacheKey::new(&current_method, &url));
                        }
                        revalidating = None;
                        conditional = HeaderMap::new();
                        continue;
                    }
                    if resp.status().as_u16() == 304 {
                        let mut updated = entry.updated_by_304(
                            resp.headers(),
                            requested_at,
                            received_at,
                            &current_headers,
                        );
                        // The connection that confirmed the entry is where it now comes from.
                        updated.peer_addr = origin_peer(&resp, &url, &policy);
                        let updated = Arc::new(updated);
                        if let Some(ref cache) = policy.cache {
                            cache.put(
                                CacheKey::new(&current_method, &url).in_partition(cache_partition),
                                updated.clone(),
                            );
                        }
                        observer.on_event(NetEvent::Cache {
                            url: url.clone(),
                            outcome: CacheOutcome::Validated,
                        });
                        // The stored copy keeps no cookies, but the jar gets what the `304`
                        // set (RFC 6265 §3): a session rotated on a revalidation is not lost.
                        if attach_credentials {
                            report_set_cookie(&policy, &url, resp.headers());
                        }
                        break HopResponse::Cached(updated);
                    }
                }

                // After the checks above: a response CORS refuses is blocked even when it asks for
                // credentials.
                let Some(target) = AuthTarget::for_status(resp.status().as_u16()) else {
                    // Neither the proxy nor the server objected: whatever each was sent is
                    // accepted.
                    server_auth.accepted(&policy, &url);
                    proxy_auth.accepted(&policy, &url);
                    break HopResponse::Network(resp);
                };
                // A server challenge means the proxy let the request through, so the proxy
                // credentials sent with it are accepted.
                if target == AuthTarget::Server {
                    proxy_auth.accepted(&policy, &url);
                }
                let slot = match target {
                    AuthTarget::Server => &mut server_auth,
                    AuthTarget::Proxy => &mut proxy_auth,
                };

                // Only the proxy carrying a plain-http hop can send a 407 we see: over https
                // the proxy's 407 fails the CONNECT tunnel and comes back as a send error. So a
                // 407 *response* on an https or direct hop is the origin server's, and
                // answering it would leak the proxy credentials (or the password dialog) to
                // any server that sends the status. wasm32: the browser owns the proxy.
                #[cfg(not(target_arch = "wasm32"))]
                let proxy = (url.scheme() == "http")
                    .then(|| policy.proxy_for.as_ref().and_then(|f| f(&url)))
                    .flatten();
                #[cfg(target_arch = "wasm32")]
                let proxy: Option<Url> = None;
                let may_answer = match target {
                    // Server credentials follow the request's credentials mode, and are only
                    // attached to a chain the CORS regime left untainted. `Authorization` is not a
                    // CORS-safelisted header, so adding it to a cors request would need a preflight
                    // of its own, and adding it to a no-cors one would be a header markup cannot
                    // produce. Navigations and requests without a document origin stay basic, and
                    // those are the ones a browser shows its password dialog for.
                    AuthTarget::Server => attach_credentials && tainting == ResponseTainting::Basic,
                    // `Proxy-Authorization` never reaches the origin, so CORS and the credentials
                    // mode don't apply; only whether there is a proxy to answer.
                    AuthTarget::Proxy => proxy.is_some(),
                };
                let challenges = auth::parse_challenges(
                    resp.headers(),
                    target,
                    &url,
                    slot.attempt,
                    proxy.as_ref(),
                );
                let answer = if may_answer && slot.attempt < MAX_AUTH_ATTEMPTS {
                    // What was sent to this party last time has just been rejected: drop it so
                    // the store stops handing back a password it no longer takes.
                    if let (Some(store), Some((space, _))) =
                        (policy.credentials.as_ref(), slot.unproven.take())
                    {
                        store.forget(&space);
                    }
                    credentials_for_challenges(&policy, &challenges)
                } else {
                    None
                };

                observer.on_event(NetEvent::AuthRequired {
                    url: url.clone(),
                    target,
                    challenges,
                    retried: answer.is_some(),
                });

                let Some((space, credentials, value)) = answer else {
                    break HopResponse::Network(resp);
                };
                slot.header = Some(value);
                slot.unproven = Some((space, credentials));
                slot.attempt += 1;
            },
        };

        // A method that changed the resource makes what is stored for it wrong, including for
        // the `Location` it points at (RFC 9111 §4.4). Only a successful one: a rejected POST
        // changed nothing.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref cache) = policy.cache {
            if cache::invalidates(&current_method) && hop.status() < 400 {
                let mut targets = vec![url.clone()];
                for name in [header::LOCATION, header::CONTENT_LOCATION] {
                    let target = hop
                        .headers()
                        .get(&name)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| url.join(v).ok());
                    // Only same-origin: a response cannot invalidate another site's entries.
                    if let Some(target) = target.filter(|t| t.origin() == url.origin()) {
                        targets.push(target);
                    }
                }
                for target in targets {
                    // Entries are keyed by method, so both of the cacheable ones go; in every
                    // partition (see `HttpCache::invalidate`).
                    for method in [Method::GET, Method::HEAD] {
                        cache.invalidate(&CacheKey::new(&method, &target));
                    }
                }
                observer.on_event(NetEvent::Cache {
                    url: url.clone(),
                    outcome: CacheOutcome::Invalidated,
                });
            }
        }

        // A `HEAD` that shows the resource changed makes the stored `GET` stale (RFC 9111
        // §4.3.5); it is dropped, in every partition, like a write would drop it.
        #[cfg(not(target_arch = "wasm32"))]
        if let (Some(cache), HopResponse::Network(resp)) = (policy.cache.as_ref(), &hop) {
            if current_method == Method::HEAD && resp.status().as_u16() == 200 {
                let get = CacheKey::new(&Method::GET, &url);
                let stored = cache.get(&get.clone().in_partition(cache_partition));
                if stored.iter().any(|e| e.changed_per_head(resp.headers())) {
                    cache.invalidate(&get);
                    observer.on_event(NetEvent::Cache {
                        url: url.clone(),
                        outcome: CacheOutcome::Invalidated,
                    });
                }
            }
        }

        let peer_addr = match &hop {
            HopResponse::Network(resp) => origin_peer(resp, &url, &policy),
            HopResponse::Cached(entry) => entry.peer_addr,
        };

        // Whether this response may be stored. The body is not here yet: a redirect has none
        // worth keeping and is stored right away, while the final response's write waits for the
        // reader of its body.
        #[cfg(not(target_arch = "wasm32"))]
        let pending_store = match (&hop, policy.cache.as_ref()) {
            // `no-store` is both directions: the lookup above skipped the cache, and nothing
            // about this exchange is written to it either.
            (HopResponse::Network(resp), Some(cache))
                if cache_mode != CacheMode::NoStore
                    && cache::is_storable(
                        &current_method,
                        &current_headers,
                        resp.status().as_u16(),
                        resp.headers(),
                    ) =>
            {
                Some(PendingStore {
                    cache: cache.clone(),
                    key: CacheKey::new(&current_method, &url).in_partition(cache_partition),
                    url: url.clone(),
                    status: resp.status().as_u16(),
                    response_headers: resp.headers().clone(),
                    request_headers: current_headers.clone(),
                    decoded: init.auto_decode,
                    requested_at,
                    received_at,
                    peer_addr,
                })
            }
            _ => None,
        };

        if !hop.is_redirection() {
            if attach_credentials {
                report_set_cookie(&policy, &url, hop.headers());
            }
            return Ok(ChainOutcome {
                response: hop,
                url: url.clone(),
                tainting,
                peer_addr,
                #[cfg(not(target_arch = "wasm32"))]
                store: pending_store,
            });
        }

        // The budget starts here rather than at the first request, so a request that is not
        // redirected is bounded by the request timeout alone.
        if redirect_deadline.is_none() {
            redirect_deadline = init
                .redirect_timeout
                .map(|budget| tokio::time::Instant::now() + budget);
        }

        // A redirect is stored now: the caller never sees its body, and a stored `301` lets the
        // next fetch skip the hop entirely.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(store) = pending_store {
            store.commit(Bytes::new(), &observer);
        }

        // A redirect — resolve the Location header
        let status = hop.status();
        let from = match hop {
            HopResponse::Network(ref resp) => resp.url().clone(),
            HopResponse::Cached(_) => url.clone(),
        };

        // A redirect may tighten (or loosen) the policy for the rest of the chain. Read every
        // field line, not just the first: a server may split the list across lines, and the
        // last token we understand wins across all of them.
        if let Some(updated) = hop
            .headers()
            .get_all(&REFERRER_POLICY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(ReferrerPolicy::parse_header)
            .next_back()
        {
            referrer_policy = updated;
        }

        // Report Set-Cookie values on this hop to the jar before following the redirect —
        // login flows commonly set the session cookie on a 302. Dropping our Cookie header
        // makes the next hop re-query the now-updated jar instead of resending a stale value.
        if attach_credentials && report_set_cookie(&policy, &from, hop.headers()) {
            current_headers.remove(header::COOKIE);
            cookie_from_jar = false;
        }

        let loc = hop
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|v| location_text(v.as_bytes()))
            .ok_or_else(|| {
                NetError::Redirect(Arc::new(anyhow!(
                    "redirect status {} without Location header",
                    status
                )))
            })?;
        let loc = loc.as_str();

        let to = from.join(loc).map_err(|e| {
            NetError::Redirect(Arc::new(anyhow!("invalid redirect URL '{}': {}", loc, e)))
        })?;

        // A `Location` with embedded `user:password` is refused for a cors-mode request, and
        // for any request when it points at another origin than the hop it came from: following
        // it would replay attacker-chosen credentials against the new target.
        //
        // Deliberately stricter than Fetch §4.5 steps 9-10, which only refuse a cors-mode
        // request whose Location's origin differs from the *request's* origin, or a chain whose
        // response tainting is already cors, and otherwise follow with the credentials kept.
        // Credentials in a redirect target are an attack pattern rather than something a site
        // relies on, and sonar strips them from what it follows anyway, so refusing more only
        // costs a redirect browsers would follow.
        if (!to.username().is_empty() || to.password().is_some())
            && (init.mode == RequestMode::Cors || from.origin() != to.origin())
        {
            return Err(blocked(
                &observer,
                to,
                BlockReason::Cors(CorsError::CredentialedRedirect),
            ));
        }
        let mut to = to;
        let location_credentials_removed = strip_url_credentials(&mut to);

        // Method and body semantics per RFC 7231 §6.4
        let method_before = current_method.clone();
        match status {
            // 301/302: browsers always downgrade POST to GET (§6.4.2–3); we follow suit.
            // HEAD stays HEAD (no body involved); all other methods become GET.
            301 | 302 => {
                if current_method != Method::HEAD {
                    current_method = Method::GET;
                }
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 303 See Other: always GET, always drop body.
            303 => {
                current_method = Method::GET;
                current_body = None;
                current_headers.remove(header::CONTENT_TYPE);
                current_headers.remove(header::CONTENT_LENGTH);
                current_headers.remove(header::TRANSFER_ENCODING);
            }
            // 307/308, the only redirects left: preserve method and body.
            _ => {}
        }

        // Strip credential headers when redirecting to a different origin (RFC 9110 §15.4).
        // Cookie will be re-applied from the jar at the top of the next loop iteration.
        let mut stripped = Vec::new();
        if from.origin() != to.origin() {
            for h in SENSITIVE_REDIRECT_HEADERS {
                if current_headers.remove(h).is_none() {
                    continue;
                }
                // Only what the caller set and nothing puts back. Jar cookies are fetched again
                // for the new origin, and a computed `Referer` or `Origin` is recomputed.
                let reported = match *h {
                    header::COOKIE => !cookie_from_jar,
                    header::REFERER => init.referrer.is_none(),
                    header::ORIGIN => origin.is_none(),
                    _ => true,
                };
                if reported {
                    stripped.push(h.clone());
                }
            }
            cookie_from_jar = false;
        }

        // Fetch's redirect-taint, per hop: a redirect to another origin from a hop that was
        // itself not the request's origin taints the chain, and `Origin` reads `null` from
        // then on. The first cross-origin hop still sends the real origin, which CORS needs.
        if let Some(ref o) = origin {
            if to.origin() != from.origin() && *o != from.origin() {
                origin_tainted = true;
            }
        }

        observer.on_event(NetEvent::Redirected {
            from,
            to: to.clone(),
            status,
        });

        // After `Redirected`, so the stream first says where the chain goes, then how the hop changed.
        if location_credentials_removed {
            modified(&observer, &to, RequestChange::UrlCredentialsRemoved);
        }
        if method_before != current_method {
            modified(
                &observer,
                &to,
                RequestChange::MethodDowngraded {
                    from: method_before,
                    to: current_method.clone(),
                },
            );
        }
        if !stripped.is_empty() {
            modified(
                &observer,
                &to,
                RequestChange::SensitiveHeadersStripped { headers: stripped },
            );
        }

        url_list.push(std::mem::replace(&mut url, to));
    }

    Err(NetError::Redirect(Arc::new(anyhow!("too many redirects"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::auth::{AuthScheme, InMemoryCredentialStore};
    use crate::net::referrer::ReferrerPolicy;
    use crate::net::test_support::{CacheRouteOptions, RecordingObserver, RouteConfig, TestServer};
    use cow_utils::CowUtils;
    use http::HeaderMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    fn names(headers: &HeaderMap) -> Vec<String> {
        headers
            .iter()
            .map(|(n, _)| n.as_str().to_string())
            .collect()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn apply_header_order_named_first_rest_in_place() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", "1".parse().unwrap());
        headers.insert(header::ACCEPT, "*/*".parse().unwrap());
        headers.insert("x-b", "2".parse().unwrap());
        headers.insert(header::HOST, "example.org".parse().unwrap());
        headers.insert("x-c", "3".parse().unwrap());

        super::apply_header_order(&mut headers, &[header::HOST, header::ACCEPT]);

        assert_eq!(names(&headers), ["host", "accept", "x-a", "x-b", "x-c"]);
        assert_eq!(headers[header::HOST], "example.org");
        assert_eq!(headers["x-c"], "3");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn apply_header_order_keeps_repeated_values_together() {
        let mut headers = HeaderMap::new();
        headers.append("x-a", "1".parse().unwrap());
        headers.append(header::COOKIE, "a=1".parse().unwrap());
        headers.append("x-b", "2".parse().unwrap());
        headers.append(header::COOKIE, "b=2".parse().unwrap());

        super::apply_header_order(&mut headers, &[header::COOKIE]);

        let cookies: Vec<_> = headers
            .get_all(header::COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert_eq!(names(&headers), ["cookie", "cookie", "x-a", "x-b"]);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn apply_header_order_skips_absent_and_duplicate_names() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", "1".parse().unwrap());
        headers.insert("x-b", "2".parse().unwrap());

        super::apply_header_order(
            &mut headers,
            &[
                header::HOST,
                HeaderName::from_static("x-b"),
                HeaderName::from_static("x-b"),
            ],
        );

        assert_eq!(names(&headers), ["x-b", "x-a"]);
        assert_eq!(headers.len(), 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn apply_header_order_empty_is_noop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-b", "2".parse().unwrap());
        headers.insert("x-a", "1".parse().unwrap());
        super::apply_header_order(&mut headers, &[]);
        assert_eq!(names(&headers), ["x-b", "x-a"]);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn hop_request() -> reqwest::Request {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", "1".parse().unwrap());
        headers.insert(header::ACCEPT, "*/*".parse().unwrap());
        reqwest::Client::new()
            .get("http://example.org:8080/")
            .headers(headers)
            .build()
            .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn order_hop_headers_adds_host_and_user_agent() {
        let ua = http::HeaderValue::from_static("ua/1");
        let order = [header::HOST, header::USER_AGENT, header::ACCEPT];
        let request = super::order_hop_headers(hop_request(), Some(&order), Some(&ua), true);
        assert_eq!(
            names(request.headers()),
            ["host", "user-agent", "accept", "x-a"]
        );
        assert_eq!(request.headers()[header::HOST], "example.org:8080");
        assert_eq!(request.headers()[header::USER_AGENT], "ua/1");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn order_hop_headers_no_host_for_h2_origin() {
        let ua = http::HeaderValue::from_static("ua/1");
        let order = [header::HOST, header::USER_AGENT, header::ACCEPT];
        let request = super::order_hop_headers(hop_request(), Some(&order), Some(&ua), false);
        assert_eq!(names(request.headers()), ["user-agent", "accept", "x-a"]);
        assert!(!request.headers().contains_key(header::HOST));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn order_hop_headers_keeps_caller_host_and_user_agent() {
        let ua = http::HeaderValue::from_static("default/1");
        let mut request = hop_request();
        request
            .headers_mut()
            .insert(header::USER_AGENT, "mine/2".parse().unwrap());
        request
            .headers_mut()
            .insert(header::HOST, "other.example".parse().unwrap());
        let order = [header::HOST, header::USER_AGENT];
        let request = super::order_hop_headers(request, Some(&order), Some(&ua), true);
        assert_eq!(
            names(request.headers()),
            ["host", "user-agent", "x-a", "accept"]
        );
        assert_eq!(request.headers()[header::USER_AGENT], "mine/2");
        assert_eq!(request.headers()[header::HOST], "other.example");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn order_hop_headers_none_is_noop() {
        let ua = http::HeaderValue::from_static("ua/1");
        let request = super::order_hop_headers(hop_request(), None, Some(&ua), true);
        assert_eq!(names(request.headers()), ["x-a", "accept"]);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn host_header_value_port_handling() {
        let host = |u: &str| {
            super::host_header_value(&Url::parse(u).unwrap())
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(host("https://example.org/").as_deref(), Some("example.org"));
        assert_eq!(
            host("https://example.org:443/").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            host("http://example.org:8080/").as_deref(),
            Some("example.org:8080")
        );
        assert_eq!(host("http://[::1]:8080/").as_deref(), Some("[::1]:8080"));
        assert_eq!(host("data:text/plain,hi"), None);
    }

    struct TestObserver;
    impl NetObserver for TestObserver {
        fn on_event(&self, _: NetEvent) {}
    }

    fn observer() -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(TestObserver)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_request_line_is_reported_with_the_headers_that_were_sent() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("x-marker", "present".parse().unwrap());
        let rec = Arc::new(RecordingObserver::new());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(headers),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1, "one hop, one request line");
        let (method, url, headers) = &sent[0];
        assert_eq!(method, http::Method::GET);
        assert_eq!(url, &srv.url("/"));
        // The caller's headers are included in the report.
        assert_eq!(headers.get("x-marker").unwrap(), "present");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_shorter_than_the_budget_is_captured_whole() {
        let body = pattern(64);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].0, body,
            "the capture is the body, byte for byte"
        );
        assert!(!previews[0].1, "a body that fits is not truncated");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_larger_than_the_peek_window_is_captured_past_it() {
        // Well past the peek window, so the capture cannot be just the buffered peek.
        let body = pattern(PEEK_MAX * 4);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        // The tee fills as the consumer pulls, so the body has to be read.
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert!(
            previews[0].0.len() > PEEK_MAX,
            "the capture reaches past the peek window (got {})",
            previews[0].0.len()
        );
        assert_eq!(
            previews[0].0, body,
            "and it is the whole body, byte for byte"
        );
        assert!(!previews[0].1, "and not truncated");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_over_the_budget_stops_at_it_and_says_so() {
        let body = pattern(PEEK_MAX * 3);
        let limit = PEEK_MAX + 512; // deliberately not a window multiple
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        // The recorder has no limit of its own; this wrapper imposes the budget and passes
        // the events through.
        struct Capped(Arc<RecordingObserver>, usize);
        impl NetObserver for Capped {
            fn on_event(&self, ev: NetEvent) {
                self.0.on_event(ev);
            }
            fn body_capture_limit(&self, _: &HeaderMap, _: Option<u64>) -> Option<usize> {
                Some(self.1)
            }
        }

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            Arc::new(Capped(rec.clone(), limit)),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");
        drain(top).await;

        let previews = rec.body_previews();
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].0.len(), limit, "stops exactly at the budget");
        assert_eq!(
            previews[0].0,
            body[..limit],
            "and it is the start of the body"
        );
        assert!(
            previews[0].1,
            "a body that continued is reported as truncated"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refusing_a_capture_leaves_the_body_intact() {
        // The default `body_capture_limit` is None, which keeps the tee off the path.
        let body = pattern(PEEK_MAX * 2);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        assert_eq!(drain(top).await, body, "the body arrives whole");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_reported_headers_include_the_client_s_user_agent() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        // Set on the *client*, where reqwest merges it at execute time and never exposes it
        // for reading. The policy is told separately, which is the only route to reporting it.
        let client = Arc::new(
            reqwest::Client::builder()
                .user_agent("probe-agent/1.0")
                .build()
                .unwrap(),
        );

        fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default().with_user_agent(Some("probe-agent/1.0")),
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0]
                .2
                .get(http::header::USER_AGENT)
                .map(|v| v.to_str().unwrap()),
            Some("probe-agent/1.0")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn headers_this_crate_adds_are_reported_too() {
        // The question a network panel exists to answer: not "what did the caller ask for"
        // but "what went out". Cookies, Referer, Origin and the Sec-Fetch-* set are all
        // computed here, after the caller's map is handed over, and must show up.
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());
        let target = srv.url("/");

        let policy = NetPolicy {
            cookies_for: Box::new(|_| Some("session=abc123".to_string())),
            ..NetPolicy::default()
        };

        fetch_response_top(
            client(),
            target.clone(),
            RequestInit::get(HeaderMap::new())
                .with_referrer(Some(target.clone()), ReferrerPolicy::UnsafeUrl)
                .with_fetch_metadata(RequestDestination::Image, RequestMode::NoCors, false),
            CancellationToken::new(),
            rec.clone(),
            policy,
        )
        .await
        .expect("fetch");

        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1);
        let headers = &sent[0].2;

        // The caller set none of these.
        assert_eq!(
            headers.get(header::COOKIE).map(|v| v.to_str().unwrap()),
            Some("session=abc123"),
            "a cookie from the jar is reported"
        );
        assert!(
            headers.contains_key(header::REFERER),
            "a computed Referer is reported"
        );
        assert!(
            headers.contains_key("sec-fetch-dest") && headers.contains_key("sec-fetch-mode"),
            "computed fetch metadata is reported"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_user_agent_is_invented_when_the_policy_was_not_told_one() {
        // A client this crate did not build. Reporting a guess would be worse than reporting
        // nothing, so the header is simply absent.
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        assert!(!rec.requests_sent()[0]
            .2
            .contains_key(http::header::USER_AGENT));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_per_request_user_agent_wins_over_the_client_default() {
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(b"hi".to_vec()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "per-request/2.0".parse().unwrap());

        fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(headers),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default().with_user_agent(Some("client-default/1.0")),
        )
        .await
        .expect("fetch");

        assert_eq!(
            rec.requests_sent()[0]
                .2
                .get(http::header::USER_AGENT)
                .map(|v| v.to_str().unwrap()),
            Some("per-request/2.0"),
            "the header on the request is what is sent, so it is what is reported"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abandoning_a_partly_read_body_reports_a_cancellation() {
        // Not "finished": the transfer did not happen, and reporting a completion with the
        // handful of bytes that did arrive would describe a request nobody made.
        let body = pattern(PEEK_MAX * 2);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let ResponseTop { mut reader, .. } = top;
        let mut sip = [0u8; 128];
        let _ = reader.read(&mut sip).await.unwrap();
        drop(reader);

        assert_eq!(
            rec.finished().len(),
            0,
            "an abandoned body is not a completed one"
        );
        assert_eq!(
            rec.cancellations(),
            vec!["body reader dropped before end of stream"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_body_that_arrived_whole_reports_finished_when_dropped_unread() {
        // The common case behind this: a response small enough to fit the peek window. Its
        // consumer has the entire body without ever touching the reader, so dropping it is
        // not an abandonment -- and the time reported must be the transfer, not however long
        // the owner sat on the reader afterwards.
        let body = pattern(64);
        let srv = TestServer::new()
            .route("/", RouteConfig::ok(body.clone()))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());

        let top = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await
        .expect("fetch");

        let ResponseTop { reader, .. } = top;
        let idle = Duration::from_millis(300);
        tokio::time::sleep(idle).await;
        drop(reader);

        let finished = rec.finished();
        assert_eq!(finished.len(), 1);
        assert_eq!(
            finished[0].0,
            body.len() as u64,
            "the whole body is accounted for"
        );
        assert!(
            finished[0].1 < idle,
            "the idle wait before the drop is not reported as transfer time (got {:?})",
            finished[0].1
        );
        assert!(rec.cancellations().is_empty());
    }

    /// A body refused for its size before the result is handed over is a failed request: the
    /// observer hears `Failed`, not the `Finished` of a body that arrived whole.
    #[tokio::test(flavor = "current_thread")]
    async fn a_body_refused_inside_the_peek_window_reports_failed() {
        let srv = TestServer::new()
            .route("/", RouteConfig::chunked(vec![&[b'x'; 1000][..]]))
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_complete(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            Some(100),
            Duration::from_secs(2),
            None,
            NetPolicy::default(),
        )
        .await;
        assert!(matches!(res, Err(NetError::Read(_))), "{res:?}");
        let events = rec.event_names();
        assert!(events.contains(&"Failed".to_string()), "{events:?}");
        assert!(!events.contains(&"Finished".to_string()), "{events:?}");
    }

    /// Read a response to the end and return the whole body, peek window included. The
    /// capture only fills as the consumer pulls.
    async fn drain(top: ResponseTop) -> Vec<u8> {
        let ResponseTop {
            peek_buf,
            mut reader,
            ..
        } = top;
        let mut body = peek_buf.into_bytes().to_vec();
        reader.read_to_end(&mut body).await.unwrap();
        body
    }

    /// Deterministic, position-dependent byte pattern. Any truncation or mis-ordering during body
    /// assembly changes the bytes, so an exact compare catches it.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }
    fn client() -> Arc<reqwest::Client> {
        Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        )
    }

    /// A TLS `TestServer` plus a client that trusts its certificate and resolves its domain to
    /// the loopback listener. No DNS or public CA involved.
    async fn tls_server_and_client(
        routes: Vec<(&str, RouteConfig)>,
    ) -> (
        crate::net::test_support::TestServerHandle,
        Arc<reqwest::Client>,
    ) {
        let mut srv = TestServer::new().tls("hsts.test");
        for (path, cfg) in routes {
            srv = srv.route(path, cfg);
        }
        let srv = srv.start().await;

        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Not `add_root_certificate`: that leaves reqwest on the platform verifier and
            // passes this CA as an *extra* root, which on Windows and macOS still defers to
            // the OS trust store and rejects a CA generated in-process. `tls_certs_only`
            // replaces the roots outright, so verification is pure rustls WebPKI.
            .tls_certs_only([cert])
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        (srv, Arc::new(client))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn untrusted_certificate_is_a_tls_error() {
        let srv = TestServer::new()
            .tls("tls.test")
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        // client that doesn't trust the self-signed cert
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        let rec = Arc::new(RecordingObserver::new());

        let err = fetch_response_top(
            Arc::new(client),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        let tls = match err {
            Ok(_) => panic!("expected an error"),
            Err(NetError::Tls(tls)) => tls,
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
        };
        assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::UnknownIssuer);
        assert_eq!(tls.host, "tls.test");
        assert!(tls.certificate.is_none());
        assert_eq!(rec.tls_errors(), vec![tls]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn certificate_for_another_host_is_a_tls_error() {
        let srv = TestServer::new()
            .tls("tls.test")
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        // trust the cert, but connect with a name it wasn't issued for
        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .tls_certs_only([cert])
            .resolve("other.test", srv.socket_addr())
            .build()
            .unwrap();
        let url = Url::parse(&format!("https://other.test:{}/", srv.socket_addr().port())).unwrap();

        let err = fetch_response_top(
            Arc::new(client),
            url,
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;

        match err {
            Err(NetError::Tls(tls)) => {
                assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::HostnameMismatch);
                assert_eq!(tls.host, "other.test");
            }
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    // Fetch from a TLS server with a certificate that is valid between the given dates. The
    // cert is trusted, so validity is the only thing that can fail.
    async fn tls_error_for_validity(
        not_before: crate::net::test_support::Ymd,
        not_after: crate::net::test_support::Ymd,
    ) -> crate::net::tls::TlsError {
        let srv = TestServer::new()
            .tls("tls.test")
            .tls_validity(not_before, not_after)
            .route("/", RouteConfig::ok(b"x".to_vec()))
            .start()
            .await;
        let cert = reqwest::Certificate::from_pem(srv.cert_pem().unwrap()).unwrap();
        let client = reqwest::Client::builder()
            .tls_certs_only([cert])
            .resolve(srv.tls_domain().unwrap(), srv.socket_addr())
            .build()
            .unwrap();
        match fetch_response_top(
            Arc::new(client),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        {
            Err(NetError::Tls(tls)) => tls,
            Err(other) => panic!("expected NetError::Tls, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_certificate_is_a_tls_error() {
        let tls = tls_error_for_validity((2000, 1, 1), (2001, 1, 1)).await;
        assert_eq!(tls.kind, crate::net::tls::TlsErrorKind::Expired, "{tls}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn not_yet_valid_certificate_is_a_tls_error() {
        let tls = tls_error_for_validity((3000, 1, 1), (3001, 1, 1)).await;
        assert_eq!(
            tls.kind,
            crate::net::tls::TlsErrorKind::NotYetValid,
            "{tls}"
        );
    }

    /// The plain mock server cannot cover this: HSTS ignores plaintext responses and IP-literal
    /// hosts, so only a TLS server with a domain name can arm a store.
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_recorded_from_a_real_https_response() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                )],
                b"hello".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());

        let entry = crate::net::hsts::HstsStore::load(store.as_ref(), "hsts.test")
            .expect("an https response carrying the header must arm the store");
        assert!(entry.include_subdomains);
        assert!(!entry.is_expired(chrono::Utc::now()));
    }

    /// The same header over plain HTTP must arm nothing (§8.1).
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_is_not_recorded_over_plaintext() {
        let srv = TestServer::new()
            .route(
                "/",
                RouteConfig::ok_with_headers(
                    &[("Strict-Transport-Security", "max-age=31536000")],
                    b"hello".to_vec(),
                ),
            )
            .start()
            .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        let res = fetch_response_top(
            client(),
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok());
        assert!(store.is_empty(), "plaintext must never arm HSTS");
    }

    /// max-age=0 disarms a previously armed host (§6.1.1).
    #[tokio::test(flavor = "current_thread")]
    async fn hsts_max_age_zero_disarms_over_tls() {
        let (srv, client) = tls_server_and_client(vec![(
            "/",
            RouteConfig::ok_with_headers(
                &[("Strict-Transport-Security", "max-age=0")],
                b"bye".to_vec(),
            ),
        )])
        .await;

        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        crate::net::hsts::HstsStore::store(
            store.as_ref(),
            "hsts.test",
            crate::net::hsts::HstsEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                include_subdomains: false,
            },
        );

        let res = fetch_response_top(
            client,
            srv.url("/"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default().with_hsts(Some(store.clone())),
        )
        .await;
        assert!(res.is_ok(), "tls fetch failed: {:?}", res.err());
        assert!(store.is_empty(), "max-age=0 must remove the entry");
    }

    async fn server() -> crate::net::test_support::TestServerHandle {
        // 64 KiB pattern, chunked so the body arrives in many pieces with no Content-Length.
        let big = pattern(64 * 1024);
        let big_chunks: Vec<&[u8]> = big.chunks(5_000).collect();
        // Exactly one READ_CHUNK worth of body, chunked (no Content-Length).
        let exact = vec![b'Y'; super::READ_CHUNK];
        TestServer::new()
            .route("/big", RouteConfig::ok(vec![b'X'; 12 * 1024]))
            .route("/big-chunked", RouteConfig::chunked(big_chunks))
            .route("/exact-chunk", RouteConfig::chunked(vec![exact.as_slice()]))
            .route("/large-cl", RouteConfig::ok(pattern(64 * 1024)))
            .route("/redirect", RouteConfig::redirect_to("/big"))
            .route(
                "/slow",
                RouteConfig::stall_mid_body(super::PEEK_MAX, Duration::from_millis(2_000)),
            )
            .route("/drop", RouteConfig::drop_mid_body(100, 10_000))
            // Declares an absurd Content-Length, sends exactly the peek window, then drops. The
            // peek loop stops at PEEK_MAX without another read, so the fetch reaches the body
            // phase with the hostile Content-Length intact.
            .route(
                "/huge-cl",
                RouteConfig::drop_mid_body(super::PEEK_MAX, 1 << 45),
            )
            .route("/xl-cl", RouteConfig::ok(pattern(2 * 1024 * 1024)))
            .route(
                "/login",
                RouteConfig::redirect_with_cookie("/whoami", "session=abc123; Path=/"),
            )
            .route("/whoami", RouteConfig::echo_cookie_header())
            .route("/empty", RouteConfig::ok(b""))
            .route("/nohead", RouteConfig::no_location_redirect())
            .route("/loop", RouteConfig::redirect_self())
            .route("/hop1", RouteConfig::redirect_to("/hop2"))
            .route("/hop2", RouteConfig::redirect_to("/hop3"))
            .route("/hop3", RouteConfig::ok(b"final"))
            // 3xx answers that are not redirects, one of them with a Location to tempt it.
            .route(
                "/multiple-choices",
                RouteConfig::StatusThenOk {
                    code: 300,
                    headers: vec![("Location".into(), "/hop3".into())],
                    failures: usize::MAX,
                    body: b"never".to_vec(),
                },
            )
            .route("/not-modified", RouteConfig::status(304, b""))
            .route(
                "/slow-hop1",
                RouteConfig::redirect_with_delay("/slow-hop2", Duration::from_millis(150)),
            )
            .route(
                "/slow-hop2",
                RouteConfig::redirect_with_delay("/hop3", Duration::from_millis(150)),
            )
            .route(
                "/late-redirect",
                RouteConfig::redirect_with_delay("/hop3", Duration::from_millis(300)),
            )
            .route(
                "/chunked",
                RouteConfig::chunked(vec![b"hel", b"lo ", b"wor", b"ld"]),
            )
            .start()
            .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn top_returns_peek_and_reader_rest() {
        let srv = server().await;
        let ResponseTop {
            meta,
            peek_buf,
            mut reader,
            ..
        } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(peek_buf.len(), super::PEEK_MAX);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(peek_buf.len() + rest.len(), 12 * 1024);
        assert!(meta.has_body);
        assert_eq!(meta.status, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/redirect"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
        assert!(meta.has_body);
    }

    /// The open-count proves a 307 replays the body by opening a fresh reader.
    #[tokio::test(flavor = "current_thread")]
    async fn stream_body_is_uploaded_and_replayed_on_307() {
        use crate::net::types::BoxedAsyncRead;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let srv = TestServer::new()
            .route("/hop", RouteConfig::redirect_307("/echo"))
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        const PAYLOAD: &[u8] = b"streamed payload";
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = opened.clone();
        let body = RequestBody::stream(
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(Box::pin(PAYLOAD) as BoxedAsyncRead)
            },
            Some(PAYLOAD.len() as u64),
        );

        let (meta, echoed) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&echoed[..], PAYLOAD);
        assert_eq!(
            opened.load(Ordering::SeqCst),
            2,
            "307 must replay the body by opening a fresh reader"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_body_streams_from_disk() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"file payload").unwrap();
        let body = RequestBody::file(tmp.path()).unwrap();

        let (meta, echoed) = super::fetch_response_complete(
            client(),
            srv.url("/echo"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&echoed[..], b"file payload");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stream_body_open_failure_fails_the_request() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_body())
            .start()
            .await;

        let body = RequestBody::stream(|| Err(std::io::Error::other("source is gone")), None);

        let res = super::fetch_response_complete(
            client(),
            srv.url("/echo"),
            RequestInit::new(Method::POST, HeaderMap::new(), Some(body)),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await;

        assert!(
            matches!(res, Err(NetError::Io(_))),
            "factory failure must surface as NetError::Io, got {res:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_timeout_triggers_on_slow_body() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_millis(100),
            Some(Duration::from_secs(2)),
            NetPolicy::default(),
        )
        .await;

        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("timeout"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_peek_is_honored() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    /// Uses a chunked route (no Content-Length) so the in-loop size check is what fires; responses
    /// that declare an oversized Content-Length up front are rejected earlier, see
    /// `huge_content_length_rejected_before_body_read`.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_max_bytes_exceeded() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(100),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("exceeded"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_complete_cancel_mid_body() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_complete(
            client(),
            srv.url("/slow"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        );
        cancel.cancel();
        let res = fut.await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("cancel"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn progress_reader_cancel_returns_error() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let ResponseTop { mut reader, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        cancel.cancel();
        assert!(reader.read(&mut vec![0u8; 1024]).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drop_mid_body_produces_error() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/drop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_body_has_no_body_flag_and_empty_peek() {
        let srv = server().await;
        let ResponseTop { meta, peek_buf, .. } = super::fetch_response_top(
            client(),
            srv.url("/empty"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert!(peek_buf.is_empty());
        assert!(!meta.has_body);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multi_hop_redirects_are_followed() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"final");
    }

    /// `user:password@` in a URL would become an `Authorization` header in the client.
    #[tokio::test(flavor = "current_thread")]
    async fn credentials_in_the_initial_url_are_dropped() {
        let srv = TestServer::new()
            .route("/echo-headers", RouteConfig::echo_request_headers())
            .start()
            .await;
        let mut url = srv.url("/echo-headers");
        url.set_username("user").unwrap();
        url.set_password(Some("pw")).unwrap();

        let rec = Arc::new(RecordingObserver::new());
        let (meta, body) = super::fetch_response_complete(
            client(),
            url,
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert!(
            !String::from_utf8_lossy(&body)
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{body:?}"
        );
        assert_eq!(meta.final_url.username(), "");
        assert_eq!(meta.final_url.password(), None);
        let sent = rec.requests_sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.username(), "", "reported without credentials");
    }

    /// Same-origin, so not refused like a cross-origin one, but still not sent.
    #[tokio::test(flavor = "current_thread")]
    async fn credentials_in_a_same_origin_location_are_dropped() {
        let srv = TestServer::new()
            .route("/echo-headers", RouteConfig::echo_request_headers())
            .route(
                "/hop",
                RouteConfig::redirect_to_with_credentials("user:pw", "/echo-headers"),
            )
            .start()
            .await;

        let rec = Arc::new(RecordingObserver::new());
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert!(
            !String::from_utf8_lossy(&body)
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{body:?}"
        );
        assert_eq!(meta.final_url.username(), "");
        assert_eq!(meta.final_url.password(), None);
        assert!(rec
            .requests_sent()
            .iter()
            .all(|(_, url, _)| url.username().is_empty()));
    }

    #[test]
    fn location_text_decodes_utf8_then_bytes() {
        assert_eq!(location_text(b"/plain"), "/plain");
        assert_eq!(location_text("/caf\u{e9}".as_bytes()), "/caf\u{e9}");
        assert_eq!(location_text(b"/caf\xe9"), "/caf\u{e9}", "latin-1 byte");
    }

    /// A `Location` with non-ASCII characters is followed, percent-encoded.
    #[tokio::test(flavor = "current_thread")]
    async fn a_non_ascii_location_is_followed() {
        let srv = TestServer::new()
            .route("/hop", RouteConfig::redirect_to("/caf\u{e9}"))
            .route("/caf%C3%A9", RouteConfig::ok(b"bonjour"))
            .start()
            .await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"bonjour");
        assert_eq!(meta.final_url.path(), "/caf%C3%A9");
    }

    /// GET `path` with `redirect_timeout`, returning the result and how long it took.
    async fn get_with_redirect_timeout(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        redirect_timeout: Option<Duration>,
    ) -> (Result<(FetchResultMeta, Bytes), NetError>, Duration) {
        let started = Instant::now();
        let res = super::fetch_response_complete(
            client(),
            srv.url(path),
            RequestInit::get(HeaderMap::new()).with_redirect_timeout(redirect_timeout),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await;
        (res, started.elapsed())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_timeout_ends_a_slow_chain() {
        let srv = server().await;
        // The first redirect arms the budget; the next hop takes 150 ms, the budget is 100 ms.
        let (res, elapsed) =
            get_with_redirect_timeout(&srv, "/slow-hop1", Some(Duration::from_millis(100))).await;
        assert!(
            matches!(res, Err(NetError::Timeout(_))),
            "expected a timeout, got {res:?}"
        );
        assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_timeout_starts_at_the_first_redirect() {
        let srv = server().await;
        // The first hop takes 300 ms to answer with its redirect; that wait is the request
        // timeout's business, not the redirect budget's.
        let (res, _) =
            get_with_redirect_timeout(&srv, "/late-redirect", Some(Duration::from_millis(100)))
                .await;
        let (meta, body) = res.unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"final");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_redirect_timeout_by_default() {
        let srv = server().await;
        let (res, _) = get_with_redirect_timeout(&srv, "/slow-hop1", None).await;
        assert_eq!(res.unwrap().0.status, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_redirect_chain() {
        let srv = server().await;
        let cancel = CancellationToken::new();
        let fut = super::fetch_response_top(
            client(),
            srv.url("/hop1"),
            RequestInit::get(HeaderMap::new()),
            cancel.clone(),
            observer(),
            NetPolicy::default(),
        );
        cancel.cancel();
        assert!(fut.await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_is_assembled_correctly() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_without_location_header_errors() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/nohead"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    /// Only 301/302/303/307/308 are redirects. A 300 is returned even with a `Location`, and a
    /// 304 that is not an answer to sonar's own revalidation goes to the caller as it is.
    #[tokio::test(flavor = "current_thread")]
    async fn a_3xx_that_is_not_a_redirect_is_returned() {
        let srv = server().await;
        for (path, status) in [("/multiple-choices", 300), ("/not-modified", 304)] {
            let ResponseTop { meta, .. } = super::fetch_response_top(
                client(),
                srv.url(path),
                RequestInit::get(HeaderMap::new()),
                CancellationToken::new(),
                observer(),
                NetPolicy::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(meta.status, status, "{path}");
        }
        assert_eq!(
            srv.hit_count("/hop3"),
            0,
            "the 300's Location is not followed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_loop_exceeds_max_redirects() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/loop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .cow_to_ascii_lowercase()
            .contains("redirect"));
        // The first request and MAX_REDIRECTS redirects; the redirect after those is refused.
        assert_eq!(srv.hit_count("/loop"), super::MAX_REDIRECTS + 1);
    }

    /// Exactly MAX_REDIRECTS redirects are followed; one more is an error.
    #[tokio::test(flavor = "current_thread")]
    async fn the_redirect_limit_is_the_number_of_redirects_followed() {
        let max = super::MAX_REDIRECTS;
        // /c{n} redirects to /c{n-1}, so /c{n} is a chain of exactly n redirects.
        let mut srv = TestServer::new().route("/c0", RouteConfig::ok(b"end"));
        for n in 1..=max + 1 {
            srv = srv.route(
                &format!("/c{n}"),
                RouteConfig::redirect_to(format!("/c{}", n - 1)),
            );
        }
        let srv = srv.start().await;
        let fetch = |n: usize| {
            super::fetch_response_top(
                client(),
                srv.url(&format!("/c{n}")),
                RequestInit::get(HeaderMap::new()),
                CancellationToken::new(),
                observer(),
                NetPolicy::default(),
            )
        };

        let ResponseTop { meta, .. } = fetch(max).await.expect("a chain at the limit");
        assert_eq!(meta.status, 200);
        assert!(fetch(max + 1).await.is_err(), "one redirect over the limit");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn url_filter_blocks_request() {
        let srv = server().await;
        let res = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            NetPolicy {
                url_allowed: Box::new(|_| false),
                ..NetPolicy::default()
            },
        )
        .await;
        assert!(matches!(
            res.err(),
            Some(NetError::Blocked {
                reason: BlockReason::UrlPolicy,
                ..
            })
        ));
    }

    /// A secure document must not reach a plain-http sub-resource. No server is needed — the
    /// block happens before any connection is attempted.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_blocks_insecure_subresource() {
        let res = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.example.com/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;
        assert!(matches!(
            res.err(),
            Some(NetError::Blocked {
                reason: BlockReason::MixedContent,
                ..
            })
        ));
    }

    /// The test server binds to loopback, which is potentially trustworthy — the same request
    /// must go through. Guards against over-blocking, not under-blocking.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_allows_loopback_subresource() {
        let srv = server().await;
        assert!(srv.url("/big").host_str().unwrap().contains("127.0.0.1"));
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    /// An insecure document has nothing to downgrade, so the check must not fire for it.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_ignores_insecure_initiator() {
        let srv = server().await;
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("http://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    /// The case an embedder cannot check for itself: the initial URL is fine, and the *redirect
    /// target* is the insecure hop. Enforcement has to live inside the redirect loop to catch it.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_blocks_insecure_redirect_target() {
        // Loopback is trustworthy, so redirect off-box to get a genuinely insecure hop.
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute("http://insecure.example.com/a.js"),
            )
            .start()
            .await;

        let res = super::fetch_response_top(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await;

        match res.err() {
            Some(NetError::Blocked { reason, url }) => {
                assert_eq!(reason, BlockReason::MixedContent);
                // The blocked hop is reported, not the URL originally requested.
                assert_eq!(url.as_str(), "http://insecure.example.com/a.js");
            }
            other => panic!("expected a mixed content block, got {other:?}"),
        }
    }

    /// Under `Upgrade` the same redirect is rewritten to https instead of blocked.
    ///
    /// Asserting only "did not block" would be worthless here: an `Upgrade` silently degraded to
    /// `Allow` would send plain http to a host that does not resolve and fail identically. The
    /// emitted `SecurityUpgraded` event is the only evidence the rewrite actually happened.
    #[tokio::test(flavor = "current_thread")]
    async fn mixed_content_upgrades_insecure_redirect_target() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute("http://insecure.invalid/a.js"),
            )
            .start()
            .await;

        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Upgrade,
            ),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        assert_eq!(
            rec.upgrades(),
            vec![(
                "http://insecure.invalid/a.js".to_string(),
                "https://insecure.invalid/a.js".to_string(),
                crate::net::types::UpgradeReason::MixedContent
            )],
            "the hop must be rewritten to https"
        );
        assert!(
            !matches!(res.as_ref().err(), Some(NetError::Blocked { .. })),
            "upgrade must rewrite the hop, not block it"
        );
        assert_eq!(rec.blocked_reason(), None);
    }

    /// Fetch `path` on `srv` with the given referrer and return the `Referer` the server saw.
    async fn referer_seen_by_server(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        referrer: Option<&str>,
        policy: ReferrerPolicy,
    ) -> String {
        let (_, body) = super::fetch_response_complete(
            client(),
            srv.url(path),
            RequestInit::get(HeaderMap::new())
                .with_referrer(referrer.map(|r| Url::parse(r).unwrap()), policy),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            None,
            NetPolicy::default(),
        )
        .await
        .unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    /// The default policy sends the bare origin to a cross-origin target.
    #[tokio::test(flavor = "current_thread")]
    async fn referer_header_is_sent() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        // The server is on loopback (trustworthy), so this is not a downgrade; cross-origin
        // under the default policy means the bare origin.
        assert_eq!(
            referer_seen_by_server(
                &srv,
                "/echo",
                Some("https://example.com/page?q=1#frag"),
                ReferrerPolicy::default(),
            )
            .await,
            "https://example.com/"
        );
    }

    /// No referrer configured must mean no header at all, not an empty one — the echo route
    /// reports `<absent>` only when the header is genuinely missing.
    #[tokio::test(flavor = "current_thread")]
    async fn no_referrer_sends_no_header() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        assert_eq!(
            referer_seen_by_server(&srv, "/echo", None, ReferrerPolicy::default()).await,
            "<absent>"
        );
        assert_eq!(
            referer_seen_by_server(
                &srv,
                "/echo",
                Some("https://example.com/page"),
                ReferrerPolicy::NoReferrer,
            )
            .await,
            "<absent>"
        );
    }

    /// Fetch, main fetch step 9: each hop determines its referrer from the one the previous hop
    /// sent. Leaving the referrer's origin reveals only that origin, and a redirect landing back
    /// home does not bring the path back: the request's referrer is the origin by then.
    ///
    /// Two servers are required. One server cannot express "cross-origin then same-origin".
    #[tokio::test(flavor = "current_thread")]
    async fn a_reduced_referrer_stays_reduced_after_a_redirect() {
        let home = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;
        // A different port is a different origin, and loopback keeps it out of downgrade rules.
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/echo").as_str()),
            )
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        let doc = format!("{}page?q=1", home.base_url());
        let policy = ReferrerPolicy::default();

        // Leaving home is cross-origin, so only the bare origin is revealed.
        assert_eq!(
            referer_seen_by_server(&away, "/echo", Some(&doc), policy).await,
            home.base_url().as_str()
        );

        // Redirected back home: same-origin again, but the request's referrer is the bare
        // origin now, and that is all that comes back.
        assert_eq!(
            referer_seen_by_server(&away, "/hop", Some(&doc), policy).await,
            home.base_url().as_str()
        );
    }

    /// Fetch, main fetch step 9, and Referrer Policy §8.2: a redirect may change the policy for
    /// the hops after it, but the policy applies to the referrer as the chain has left it. A
    /// server answering with `Referrer-Policy: unsafe-url` cannot recover the full URL an
    /// origin-only policy cut away.
    #[tokio::test(flavor = "current_thread")]
    async fn a_redirect_policy_cannot_widen_the_referrer_again() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_with_referrer_policy("/echo", "unsafe-url"),
            )
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;
        let doc = "https://example.com/secret?tok=1";
        for policy in [
            ReferrerPolicy::Origin,
            ReferrerPolicy::StrictOriginWhenCrossOrigin,
        ] {
            assert_eq!(
                referer_seen_by_server(&srv, "/hop", Some(doc), policy).await,
                "https://example.com/",
                "{policy}"
            );
        }
    }

    /// Mixed Content §4.4: a top-level navigation from an `https` document to an `http` URL is
    /// not mixed content; the same URL as a script is. Nothing listens at the target, so the
    /// navigation fails to connect, but it is not blocked.
    #[tokio::test(flavor = "current_thread")]
    async fn a_top_level_navigation_is_not_blocked_as_mixed_content() {
        let reason = |destination, mode| async move {
            let rec = Arc::new(RecordingObserver::new());
            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(
                    Some(Url::parse("https://example.com/").unwrap().origin()),
                    MixedContentPolicy::Block,
                )
                .with_fetch_metadata(destination, mode, true);
            let _ = super::fetch_response_top(
                client(),
                Url::parse("http://insecure.invalid/").unwrap(),
                init,
                CancellationToken::new(),
                rec.clone(),
                NetPolicy::default(),
            )
            .await;
            rec.blocked_reason()
        };
        assert_eq!(
            reason(RequestDestination::Document, RequestMode::Navigate).await,
            None
        );
        assert_eq!(
            reason(RequestDestination::Script, RequestMode::NoCors).await,
            Some(BlockReason::MixedContent)
        );
    }

    /// Mixed Content §4.1: under the default policy, an `http` image on a secure page is fetched
    /// over `https` instead of being blocked; a script at the same URL is blocked.
    #[tokio::test(flavor = "current_thread")]
    async fn an_insecure_image_is_upgraded_by_default() {
        let outcome = |destination| async move {
            let rec = Arc::new(RecordingObserver::new());
            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(
                    Some(Url::parse("https://example.com/").unwrap().origin()),
                    MixedContentPolicy::default(),
                )
                .with_fetch_metadata(destination, RequestMode::NoCors, false);
            // Nothing listens there; what matters is what was decided before the send.
            let _ = super::fetch_response_top(
                client(),
                Url::parse("http://cdn.invalid/cat.png").unwrap(),
                init,
                CancellationToken::new(),
                rec.clone(),
                NetPolicy::default(),
            )
            .await;
            (rec.blocked_reason(), rec.upgrades())
        };
        let (blocked, upgrades) = outcome(RequestDestination::Image).await;
        assert_eq!(blocked, None);
        assert_eq!(
            upgrades,
            vec![(
                "http://cdn.invalid/cat.png".to_string(),
                "https://cdn.invalid/cat.png".to_string(),
                UpgradeReason::MixedContent
            )]
        );
        let (blocked, _) = outcome(RequestDestination::Script).await;
        assert_eq!(blocked, Some(BlockReason::MixedContent));
    }

    /// Fetch, main fetch: the referrer is determined (step 9) before HSTS rewrites the URL
    /// (step 11). An `https` document requesting `http://` on an HSTS host is a downgrade for the
    /// referrer, so `strict-origin-when-cross-origin` sends none, though the request itself goes
    /// out over TLS. With the URL already `https`, the origin is sent as usual.
    #[tokio::test(flavor = "current_thread")]
    async fn the_referrer_is_judged_before_the_hsts_upgrade() {
        let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
        crate::net::hsts::HstsStore::store(
            store.as_ref(),
            "hsts.test",
            crate::net::hsts::HstsEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                include_subdomains: false,
            },
        );
        let sent = |target: &'static str| {
            let store = store.clone();
            async move {
                let rec = Arc::new(RecordingObserver::new());
                let init = RequestInit::get(HeaderMap::new()).with_referrer(
                    Some(Url::parse("https://example.com/page").unwrap()),
                    ReferrerPolicy::StrictOriginWhenCrossOrigin,
                );
                // Nothing listens there; the referrer is decided before the send fails.
                let _ = super::fetch_response_top(
                    client(),
                    Url::parse(target).unwrap(),
                    init,
                    CancellationToken::new(),
                    rec.clone(),
                    NetPolicy::default().with_hsts(Some(store)),
                )
                .await;
                rec.modifications()
                    .into_iter()
                    .find_map(|(_, change)| match change {
                        RequestChange::ReferrerReduced { to, .. } => {
                            Some(to.map(|u| u.to_string()))
                        }
                        _ => None,
                    })
            }
        };
        assert_eq!(sent("http://hsts.test/x").await, Some(None));
        assert_eq!(
            sent("https://hsts.test/x").await,
            Some(Some("https://example.com/".to_string()))
        );
    }

    /// Fetch, main fetch step 9: once a hop determines no referrer, the request's referrer is
    /// `no-referrer`, and the hops after it send none either, even back on the document's own
    /// origin under `same-origin`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_withheld_referrer_stays_withheld_after_a_redirect() {
        let home = TestServer::new()
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/echo").as_str()),
            )
            .start()
            .await;
        let doc = format!("{}page?q=1", home.base_url());
        assert_eq!(
            referer_seen_by_server(&away, "/hop", Some(&doc), ReferrerPolicy::SameOrigin).await,
            "<absent>"
        );
    }

    /// A `Referrer-Policy` header on a redirect replaces the policy for the remaining hops.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_referrer_policy_header_applies_to_later_hops() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_with_referrer_policy("/echo", "no-referrer"),
            )
            .route("/echo", RouteConfig::echo_referer_header())
            .start()
            .await;

        // Same-origin with the server, so without the header the full URL would be sent.
        let doc = format!("{}page?q=1", srv.base_url());
        let seen =
            referer_seen_by_server(&srv, "/hop", Some(&doc), ReferrerPolicy::default()).await;

        assert_eq!(
            seen, "<absent>",
            "the redirect's no-referrer policy must suppress the header on the next hop"
        );
    }

    /// Fetch `path` on `srv` with `init` and return the response body as text. Pair with
    /// [`RouteConfig::echo_request_header`] to see a header exactly as the server received it.
    async fn header_seen_by_server(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
    ) -> String {
        let (_, body) = super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            None,
            NetPolicy::default(),
        )
        .await
        .unwrap();
        String::from_utf8_lossy(&body).to_string()
    }

    /// Even a bare request carries fetch metadata: empty destination, no-cors mode, and a
    /// site of `none` when no initiating origin is set. `Sec-Fetch-User` must be absent,
    /// not `?0`.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_headers_are_sent_by_default() {
        let srv = TestServer::new()
            .route("/dest", RouteConfig::echo_request_header("sec-fetch-dest"))
            .route("/mode", RouteConfig::echo_request_header("sec-fetch-mode"))
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .route("/user", RouteConfig::echo_request_header("sec-fetch-user"))
            .start()
            .await;

        let cases = [
            ("/dest", "empty"),
            ("/mode", "no-cors"),
            ("/site", "none"),
            ("/user", "<absent>"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                header_seen_by_server(&srv, path, RequestInit::get(HeaderMap::new())).await,
                expected,
                "{path}"
            );
        }
    }

    /// `Sec-Fetch-Site` reports the target's relation to the initiating origin. The server is
    /// on loopback, so its own origin is same-origin, the same host on another port is
    /// same-site, and a foreign host is cross-site.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_site_reflects_the_initiating_origin() {
        let srv = TestServer::new()
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .start()
            .await;

        let mut other_port = srv.base_url();
        other_port.set_port(Some(1)).unwrap();

        let cases = [
            (srv.base_url(), "same-origin"),
            (other_port, "same-site"),
            (Url::parse("https://example.com").unwrap(), "cross-site"),
        ];
        for (initiator, expected) in cases {
            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(Some(initiator.origin()), MixedContentPolicy::default());
            assert_eq!(
                header_seen_by_server(&srv, "/site", init).await,
                expected,
                "{initiator}"
            );
        }
    }

    /// The site relation covers the whole redirect chain: a detour through a foreign origin
    /// degrades the value for good, even when the chain lands back on the initiator's own
    /// origin.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_site_degrades_across_redirects() {
        let home = TestServer::new()
            .route("/site", RouteConfig::echo_request_header("sec-fetch-site"))
            .start()
            .await;
        // Both servers are on 127.0.0.1, so the detour through `away` (another port) is a
        // same-site hop; loopback cannot express a cross-site one.
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/site").as_str()),
            )
            .start()
            .await;

        let init = RequestInit::get(HeaderMap::new()).with_mixed_content(
            Some(home.base_url().origin()),
            MixedContentPolicy::default(),
        );
        assert_eq!(
            header_seen_by_server(&away, "/hop", init).await,
            "same-site",
            "the foreign hop must cap the value even though the final hop is same-origin"
        );
    }

    /// `Sec-Fetch-User: ?1` is only sent on user-activated navigation requests, which Fetch
    /// defines by destination; everything else omits the header.
    #[tokio::test(flavor = "current_thread")]
    async fn sec_fetch_user_marks_user_navigations() {
        let srv = TestServer::new()
            .route("/user", RouteConfig::echo_request_header("sec-fetch-user"))
            .start()
            .await;

        let cases = [
            (
                RequestDestination::Document,
                RequestMode::Navigate,
                true,
                "?1",
            ),
            (
                RequestDestination::Document,
                RequestMode::Navigate,
                false,
                "<absent>",
            ),
            (RequestDestination::Embed, RequestMode::NoCors, true, "?1"),
            (
                RequestDestination::Image,
                RequestMode::NoCors,
                true,
                "<absent>",
            ),
        ];
        for (destination, mode, activated, expected) in cases {
            let init = RequestInit::get(HeaderMap::new()).with_fetch_metadata(
                destination,
                mode,
                activated,
            );
            assert_eq!(
                header_seen_by_server(&srv, "/user", init).await,
                expected,
                "{destination:?} {mode:?} activated={activated}"
            );
        }
    }

    /// A POST carries an `Origin` header; a plain no-cors GET does not, even with an
    /// initiating origin configured.
    #[tokio::test(flavor = "current_thread")]
    async fn origin_header_is_sent_for_post_but_not_plain_get() {
        let srv = TestServer::new()
            .route("/origin", RouteConfig::echo_request_header("origin"))
            .start()
            .await;
        let initiator = srv.base_url().origin();

        let post = RequestInit::post(HeaderMap::new(), b"x".to_vec())
            .with_mixed_content(Some(initiator.clone()), MixedContentPolicy::default());
        assert_eq!(
            header_seen_by_server(&srv, "/origin", post).await,
            initiator.ascii_serialization()
        );

        let get = RequestInit::get(HeaderMap::new())
            .with_mixed_content(Some(initiator), MixedContentPolicy::default());
        assert_eq!(
            header_seen_by_server(&srv, "/origin", get).await,
            "<absent>"
        );
    }

    /// After a tainting cross-origin redirect the final server sees the literal `null`,
    /// not the initiator and not a missing header.
    #[tokio::test(flavor = "current_thread")]
    async fn origin_header_becomes_null_after_a_cross_origin_redirect() {
        let home = TestServer::new()
            .route("/origin", RouteConfig::echo_request_header("origin"))
            .start()
            .await;
        let away = TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_absolute(home.url("/origin").as_str()),
            )
            .start()
            .await;

        // Websocket mode: cors-like, so the cross-origin GET carries an Origin header at all,
        // but exempt from CORS response checks — the mock routes here grant nothing, and this
        // test is about the Origin *value*, not enforcement. The chain is home → away → home:
        // away redirecting elsewhere is the tainting hop.
        let init = RequestInit::get(HeaderMap::new())
            .with_fetch_metadata(RequestDestination::Empty, RequestMode::Websocket, false)
            .with_mixed_content(
                Some(home.base_url().origin()),
                MixedContentPolicy::default(),
            );
        assert_eq!(header_seen_by_server(&away, "/hop", init).await, "null");
    }

    /// The other side of the rule: hops that stay on the origin the chain crossed into do not
    /// taint, so `Origin` keeps its real value (Fetch, redirect-taint).
    #[tokio::test(flavor = "current_thread")]
    async fn origin_header_survives_same_origin_hops_after_a_cross_origin_redirect() {
        let home = TestServer::new()
            .route("/", RouteConfig::ok(b""))
            .start()
            .await;
        let away = TestServer::new()
            .route("/hop1", RouteConfig::redirect_to("/hop2"))
            .route("/hop2", RouteConfig::redirect_to("/origin"))
            .route("/origin", RouteConfig::echo_request_header("origin"))
            .start()
            .await;
        let init = RequestInit::get(HeaderMap::new())
            .with_fetch_metadata(RequestDestination::Empty, RequestMode::Websocket, false)
            .with_mixed_content(
                Some(home.base_url().origin()),
                MixedContentPolicy::default(),
            );
        assert_eq!(
            header_seen_by_server(&away, "/hop1", init).await,
            home.base_url().origin().ascii_serialization()
        );
    }

    /// A block must be observable, not just returned. Devtools has no other way to report why a
    /// resource never loaded, and nothing else in the test suite asserts the event is emitted.
    #[tokio::test(flavor = "current_thread")]
    async fn blocking_emits_a_blocked_event() {
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.example.com/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            ),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;

        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::MixedContent));
    }

    /// The URL allowlist rejection must be observable too — same helper, same guarantee.
    #[tokio::test(flavor = "current_thread")]
    async fn url_filter_block_emits_a_blocked_event() {
        let srv = server().await;
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy {
                url_allowed: Box::new(|_| false),
                ..NetPolicy::default()
            },
        )
        .await;

        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::UrlPolicy));
    }

    /// A bad port is refused before anything is sent, on the first hop and on a redirect, and
    /// the refusal is reported like any other block.
    #[tokio::test(flavor = "current_thread")]
    async fn a_bad_port_is_blocked_on_every_hop() {
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            Url::parse("http://127.0.0.1:25/").unwrap(),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::BadPort));

        let srv = TestServer::new()
            .route(
                "/to-smtp",
                RouteConfig::redirect_absolute("http://127.0.0.1:25/"),
            )
            .start()
            .await;
        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_top(
            client(),
            srv.url("/to-smtp"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            rec.clone(),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        assert_eq!(rec.blocked_reason(), Some(BlockReason::BadPort));
        assert_eq!(srv.hit_count("/to-smtp"), 1, "the first hop was fetched");
    }

    /// A bad port the policy allows is fetched like any other; the block is what an
    /// allowance lifts, not the request. Uses an unprivileged bad port a test can listen on.
    #[tokio::test(flavor = "current_thread")]
    async fn an_allowed_bad_port_is_fetched() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let unprivileged = [
            6665u16, 6666, 6667, 6668, 6669, 6679, 6697, 10080, 4190, 6566,
        ];
        let mut listener = None;
        for port in unprivileged {
            if let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                listener = Some((l, port));
                break;
            }
        }
        let Some((listener, port)) = listener else {
            eprintln!("skipping: no unprivileged bad port is free");
            return;
        };
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let fetch = |policy: NetPolicy| {
            super::fetch_response_top(
                client(),
                url.clone(),
                RequestInit::get(HeaderMap::new()),
                CancellationToken::new(),
                Arc::new(RecordingObserver::new()),
                policy,
            )
        };

        assert!(
            fetch(NetPolicy::default()).await.is_err(),
            "blocked by default"
        );
        let top = fetch(NetPolicy::default().with_allowed_bad_ports(vec![port]))
            .await
            .expect("an allowed port is fetched");
        assert_eq!(top.meta.status, 200);
    }

    /// Regression: `url_allowed` must see the post-upgrade URL. An embedder that rejects plain
    /// http would otherwise kill a request the upgrade would have made https — and the two check
    /// sites (scheduler pre-flight and redirect loop) must agree on that.
    #[tokio::test(flavor = "current_thread")]
    async fn url_allowlist_vets_the_upgraded_url() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();

        let _ = super::fetch_response_top(
            client(),
            Url::parse("http://insecure.invalid/a.js").unwrap(),
            RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Upgrade,
            ),
            CancellationToken::new(),
            observer(),
            NetPolicy {
                url_allowed: Box::new(move |u| {
                    seen_cb.lock().unwrap().push(u.to_string());
                    true
                }),
                ..NetPolicy::default()
            },
        )
        .await;

        assert_eq!(
            *seen.lock().unwrap(),
            vec!["https://insecure.invalid/a.js"],
            "the allowlist must be shown the upgraded URL, never the http original"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_headers_are_sent() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        // Just verify the request completes successfully with custom headers
        let ResponseTop { meta, .. } = super::fetch_response_top(
            client(),
            srv.url("/big"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            NetPolicy::default(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
    }

    // Body assembly / READ_CHUNK reservation path.

    /// A large body with no Content-Length (chunked) forces `initial_cap == 0`, so every byte of
    /// growth goes through the `reserve(READ_CHUNK)` guard across many loop iterations. Verifies
    /// the loop never mistakes a full buffer for EOF and assembles all 64 KiB in order.
    #[tokio::test(flavor = "current_thread")]
    async fn large_chunked_body_without_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big-chunked"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 64 * 1024);
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// A chunked body of exactly `READ_CHUNK` bytes lands on the reservation boundary: after the
    /// data is read the spare capacity is fully consumed, and the next `read_buf` must reserve more
    /// before it can observe the real EOF. Guards against an off-by-one false EOF at the boundary.
    #[tokio::test(flavor = "current_thread")]
    async fn chunked_body_exactly_read_chunk_size_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/exact-chunk"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), super::READ_CHUNK);
        assert!(body.iter().all(|&b| b == b'Y'));
    }

    /// A body larger than READ_CHUNK *with* Content-Length exercises the pre-sized path (buffer
    /// seeded to the full length up front). The reservation guard should rarely fire, and the body
    /// must still come back byte-for-byte.
    #[tokio::test(flavor = "current_thread")]
    async fn large_body_with_content_length_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/large-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(64 * 1024));
        assert_eq!(&body[..], pattern(64 * 1024).as_slice());
    }

    /// `max_bytes` is checked with a strict `>`, so a body whose length equals the cap exactly must
    /// succeed. Boundary partner to `fetch_complete_max_bytes_exceeded`.
    #[tokio::test(flavor = "current_thread")]
    async fn max_bytes_equal_to_body_size_succeeds() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/big"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(12 * 1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(body.len(), 12 * 1024);
    }

    /// A response whose Content-Length already exceeds `max_bytes` is rejected right after the
    /// header/peek phase, before any body bytes beyond the peek are read.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_rejected_before_body_read() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            Some(1024),
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("content-length"), "unexpected error: {msg}");
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    }

    /// With no `max_bytes`, a hostile Content-Length must not drive the buffer pre-allocation
    /// (it is clamped to MAX_PREALLOC). The connection then drops, so the fetch surfaces a read
    /// error instead of attempting a multi-terabyte allocation.
    #[tokio::test(flavor = "current_thread")]
    async fn huge_content_length_does_not_preallocate() {
        let srv = server().await;
        let res = super::fetch_response_complete(
            client(),
            srv.url("/huge-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await;
        assert!(res.is_err());
    }

    /// A body larger than MAX_PREALLOC still assembles correctly: the pre-allocation is clamped,
    /// and the read loop grows the buffer as real bytes arrive.
    #[tokio::test(flavor = "current_thread")]
    async fn body_larger_than_prealloc_cap_is_assembled() {
        let srv = server().await;
        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/xl-cl"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(meta.content_length, Some(2 * 1024 * 1024));
        assert_eq!(&body[..], pattern(2 * 1024 * 1024).as_slice());
    }

    /// The jar is handed a UTF-8 cookie value as it is; only bytes that are not UTF-8 at all
    /// are left out.
    #[test]
    fn a_utf8_set_cookie_reaches_the_jar() {
        let received: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = received.clone();
        let policy = NetPolicy {
            on_cookies: Box::new(move |_, values| {
                sink.lock()
                    .unwrap()
                    .extend(values.iter().map(|v| v.to_string()));
            }),
            ..NetPolicy::default()
        };
        let mut headers = HeaderMap::new();
        headers.append(header::SET_COOKIE, "a=1".parse().unwrap());
        headers.append(
            header::SET_COOKIE,
            http::HeaderValue::from_bytes("b=h\u{e9}llo".as_bytes()).unwrap(),
        );
        headers.append(
            header::SET_COOKIE,
            http::HeaderValue::from_bytes(b"c=\xff\xfe").unwrap(),
        );

        let url = Url::parse("https://site.test/").unwrap();
        assert!(report_set_cookie(&policy, &url, &headers));
        assert_eq!(
            *received.lock().unwrap(),
            vec!["a=1".to_string(), "b=h\u{e9}llo".to_string()]
        );
    }

    /// A cookie set on an intermediate 302 must be reported via `on_cookies` before the next hop,
    /// and the next hop must carry the updated jar contents instead of a stale Cookie header.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_reaches_jar_and_next_hop() {
        let srv = server().await;

        type ReceivedCookies = Vec<(Url, Vec<String>)>;
        let jar: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let received: Arc<std::sync::Mutex<ReceivedCookies>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let jar_read = jar.clone();
        let jar_write = jar.clone();
        let received_sink = received.clone();
        let policy = NetPolicy {
            cookies_for: Box::new(move |_| jar_read.lock().unwrap().clone()),
            on_cookies: Box::new(move |url, values| {
                received_sink
                    .lock()
                    .unwrap()
                    .push((url.clone(), values.iter().map(|v| v.to_string()).collect()));
                // Store only the name=value part, as a real jar would.
                if let Some(v) = values.first() {
                    let nv = v.split(';').next().unwrap_or(v).trim().to_string();
                    *jar_write.lock().unwrap() = Some(nv);
                }
            }),
            ..NetPolicy::default()
        };

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        // The /whoami route echoes back the Cookie header the follow-up request carried.
        assert_eq!(&body[..], b"session=abc123");

        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.path(), "/login");
        assert_eq!(received[0].1, vec!["session=abc123; Path=/".to_string()]);
    }

    /// `on_protocol` is called for every hop (the 302 and the final 200), with that hop's URL.
    #[tokio::test(flavor = "current_thread")]
    async fn redirect_reports_protocol_of_every_hop() {
        let srv = server().await;
        let seen: Arc<std::sync::Mutex<Vec<(String, http::Version)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_protocol_sink(Box::new(move |url, version| {
            sink.lock().unwrap().push((url.path().to_string(), version));
        }));

        let (meta, _) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);

        let seen = seen.lock().unwrap();
        // test server is plain http, so 1.1 on both hops
        assert_eq!(
            *seen,
            vec![
                ("/login".to_string(), http::Version::HTTP_11),
                ("/whoami".to_string(), http::Version::HTTP_11),
            ]
        );
    }

    /// When a redirect hop sets cookies but no jar is wired up, the pre-existing Cookie header is
    /// dropped for subsequent hops rather than resending a value the server just replaced.
    type SeenCookies = Arc<std::sync::Mutex<Vec<(Url, String)>>>;

    /// Records every `Set-Cookie` handed to the jar, keyed by the URL it came from.
    fn recording_jar() -> (NetPolicy, SeenCookies) {
        let seen: SeenCookies = Default::default();
        let sink = seen.clone();
        let policy = NetPolicy {
            on_cookies: Box::new(move |url, values| {
                let mut seen = sink.lock().unwrap();
                for v in values {
                    seen.push((url.clone(), v.to_string()));
                }
            }),
            ..NetPolicy::default()
        };
        (policy, seen)
    }

    fn set_cookie_server() -> crate::net::test_support::TestServer {
        TestServer::new()
            .route(
                "/hop",
                RouteConfig::redirect_with_cookie("/final", "mid=1; Path=/"),
            )
            .route(
                "/final",
                RouteConfig::ok_with_headers(&[("Set-Cookie", "end=1; Path=/")], b"ok"),
            )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_cookie_reaches_the_jar_with_credentials() {
        let srv = set_cookie_server().start().await;
        let (policy, seen) = recording_jar();
        let (meta, _) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            policy,
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen[0], (srv.url("/hop"), "mid=1; Path=/".to_string()));
        assert_eq!(seen[1], (srv.url("/final"), "end=1; Path=/".to_string()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_cookie_is_ignored_without_credentials() {
        let srv = set_cookie_server().start().await;
        let (policy, seen) = recording_jar();
        let (meta, _) = super::fetch_response_complete(
            client(),
            srv.url("/hop"),
            RequestInit::get(HeaderMap::new()).with_credentials(RequestCredentials::Omit),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(3),
            Some(Duration::from_secs(5)),
            policy,
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_set_cookie_drops_stale_cookie_header() {
        let srv = server().await;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::COOKIE, "stale=1".parse().unwrap());

        let (meta, body) = super::fetch_response_complete(
            client(),
            srv.url("/login"),
            RequestInit::get(headers),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"");
    }

    /// base64("user:pass"), the credentials the auth routes below accept.
    const GOOD_AUTH: &str = "Basic dXNlcjpwYXNz";

    async fn auth_server() -> crate::net::test_support::TestServerHandle {
        TestServer::new()
            .route(
                "/protected",
                RouteConfig::require_auth(
                    r#"Basic realm="Secure Area""#,
                    GOOD_AUTH,
                    b"secret".to_vec(),
                ),
            )
            .route(
                "/via-proxy",
                RouteConfig::require_proxy_auth(r#"Basic realm="corp""#, GOOD_AUTH, b"ok".to_vec()),
            )
            .start()
            .await
    }

    /// Run one fetch against the auth server with the given request and policy.
    async fn auth_fetch(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
        policy: NetPolicy,
        observer: Arc<dyn NetObserver + Send + Sync>,
    ) -> Result<(FetchResultMeta, Bytes), NetError> {
        super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer,
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
    }

    /// A policy whose hook answers every challenge with the given credentials, counting calls.
    fn answering_policy(credentials: Credentials) -> (NetPolicy, Arc<Mutex<Vec<AuthChallenge>>>) {
        let seen: Arc<Mutex<Vec<AuthChallenge>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_auth_challenge_fn(Box::new(move |challenge| {
            sink.lock().unwrap().push(challenge.clone());
            Some(credentials.clone())
        }));
        (policy, seen)
    }

    /// RFC 9110 §11.6-11.7: a hop through an authenticating proxy to a protected server needs
    /// `Proxy-Authorization` and `Authorization` on one send. Answering the server's 401 keeps
    /// the proxy's credentials on the request, each party gets its own attempts, and the proxy
    /// password, accepted when the 401 came through the proxy, stays in the store.
    #[tokio::test(flavor = "current_thread")]
    async fn a_proxy_and_a_server_challenge_are_answered_together() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let base = Url::parse(&format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let sends = Arc::new(Mutex::new(Vec::<(bool, bool)>::new()));
        let log = sends.clone();
        // Plays both parts: a proxy wanting `Proxy-Authorization`, and behind it a server
        // wanting `Authorization`. The hook answers both with user:pass.
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let carries = |name: &str| {
                    head.lines().any(|l| {
                        l.split_once(':').is_some_and(|(n, v)| {
                            n.eq_ignore_ascii_case(name) && v.trim() == GOOD_AUTH
                        })
                    })
                };
                let (proxy_ok, server_ok) =
                    (carries("proxy-authorization"), carries("authorization"));
                log.lock().unwrap().push((proxy_ok, server_ok));
                let response = if !proxy_ok {
                    "HTTP/1.1 407 Proxy Authentication Required\r\n\
                     Proxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                } else if !server_ok {
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"site\"\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, _) = answering_policy(Credentials::basic("user", "pass"));
        let proxy = base.clone();
        let policy = policy
            .with_credential_store(Some(store.clone()))
            .with_proxy_for(Box::new(move |_| Some(proxy.clone())));

        let (meta, _) = super::fetch_response_complete(
            client(),
            base.join("x").unwrap(),
            RequestInit::get(HeaderMap::new()),
            CancellationToken::new(),
            observer(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(
            *sends.lock().unwrap(),
            vec![(false, false), (true, false), (true, true)],
            "(proxy credentials, server credentials) per send"
        );
        let space = |target, realm: &str| ProtectionSpace {
            target,
            scheme: AuthScheme::Basic,
            origin: Some(base.origin().ascii_serialization()),
            realm: realm.into(),
        };
        assert!(store
            .credentials_for(&space(AuthTarget::Proxy, "corp"))
            .is_some());
        assert!(store
            .credentials_for(&space(AuthTarget::Server, "site"))
            .is_some());
    }

    /// RFC 7617 §2.2 and Fetch's authentication entry: once a `Basic` password was accepted at
    /// `/area/page`, a request below `/area/` sends it with the first send, so it costs one
    /// request instead of two. A path outside that directory still has to be challenged first.
    #[tokio::test(flavor = "current_thread")]
    async fn stored_basic_credentials_are_sent_upfront() {
        let protected = |body: &'static [u8]| {
            RouteConfig::require_auth(r#"Basic realm="Secure Area""#, GOOD_AUTH, body.to_vec())
        };
        let srv = TestServer::new()
            .route("/area/page", protected(b"page"))
            .route("/area/other", protected(b"other"))
            .route("/outside", protected(b"outside"))
            .start()
            .await;
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, _) = answering_policy(Credentials::basic("user", "pass"));
        let policy = policy.with_credential_store(Some(store.clone()));
        let (meta, _) = auth_fetch(
            &srv,
            "/area/page",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(srv.hit_count("/area/page"), 2, "challenged, then answered");

        // No hook this time: only the store can answer.
        let stored = || NetPolicy::default().with_credential_store(Some(store.clone()));
        let (meta, _) = auth_fetch(
            &srv,
            "/area/other",
            RequestInit::get(HeaderMap::new()),
            stored(),
            observer(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(srv.hit_count("/area/other"), 1, "sent upfront");

        // Outside `/area/`: challenged first, then answered from the store as before.
        let (meta, _) = auth_fetch(
            &srv,
            "/outside",
            RequestInit::get(HeaderMap::new()),
            stored(),
            observer(),
        )
        .await
        .unwrap();
        assert_eq!(meta.status, 200);
        assert_eq!(srv.hit_count("/outside"), 2, "not sent upfront");

        // Credentials withheld by the request's mode are not sent upfront either.
        let omit = RequestInit::get(HeaderMap::new()).with_credentials(RequestCredentials::Omit);
        let (meta, _) = auth_fetch(&srv, "/area/other", omit, stored(), observer())
            .await
            .unwrap();
        assert_eq!(meta.status, 401);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_basic_challenge_is_answered_and_the_hop_retried() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        // The 401 and the authenticated retry.
        assert_eq!(srv.hit_count("/protected"), 2);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].scheme, AuthScheme::Basic);
        assert_eq!(seen[0].realm.as_deref(), Some("Secure Area"));
        assert_eq!(seen[0].target, AuthTarget::Server);
        assert_eq!(seen[0].attempt, 0);

        let events = rec.auth_required();
        assert_eq!(events.len(), 1);
        assert!(events[0].1, "the challenge was answered");
        assert_eq!(events[0].0.len(), 1);
    }

    /// Without credentials the 401 itself is the response.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unanswered_challenge_is_returned_to_the_caller() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            NetPolicy::default(),
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);

        // The challenge still reaches the observer, so an embedder that can only answer
        // asynchronously can prompt and re-submit.
        let events = rec.auth_required();
        assert_eq!(events.len(), 1);
        assert!(!events[0].1);
        assert_eq!(events[0].0[0].realm.as_deref(), Some("Secure Area"));
    }

    /// Credentials the hook supplied are remembered once they work, so the second request answers
    /// the challenge without asking again.
    #[tokio::test(flavor = "current_thread")]
    async fn accepted_credentials_are_remembered_in_the_store() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());

        for expected_calls in [1, 1] {
            let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
            let policy = policy.with_credential_store(Some(store.clone()));
            let (meta, _) = auth_fetch(
                &srv,
                "/protected",
                RequestInit::get(HeaderMap::new()),
                policy,
                observer(),
            )
            .await
            .unwrap();
            assert_eq!(meta.status, 200);
            // The hook answers the first request; the second is served from the store, which is
            // why each fresh hook here sees at most one call.
            assert!(seen.lock().unwrap().len() <= expected_calls);
        }

        assert_eq!(store.len(), 1);
        let space = ProtectionSpace {
            target: AuthTarget::Server,
            scheme: AuthScheme::Basic,
            origin: Some(srv.url("/protected").origin().ascii_serialization()),
            realm: "Secure Area".into(),
        };
        assert_eq!(
            store.credentials_for(&space),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// Stored credentials the server rejects are dropped, and the hook is asked for better ones.
    #[tokio::test(flavor = "current_thread")]
    async fn rejected_stored_credentials_are_forgotten_and_replaced() {
        let srv = auth_server().await;
        let space = ProtectionSpace {
            target: AuthTarget::Server,
            scheme: AuthScheme::Basic,
            origin: Some(srv.url("/protected").origin().ascii_serialization()),
            realm: "Secure Area".into(),
        };
        let store = Arc::new(InMemoryCredentialStore::new());
        store.store(space.clone(), Credentials::basic("user", "stale"));

        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
        let policy = policy.with_credential_store(Some(store.clone()));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        // Unauthenticated, stale password, good password.
        assert_eq!(srv.hit_count("/protected"), 3);

        // The hook was only consulted after the stored password had been rejected.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].attempt, 1);
        assert_eq!(
            store.credentials_for(&space),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// An embedder that keeps handing back credentials the server refuses must not loop forever.
    #[tokio::test(flavor = "current_thread")]
    async fn the_retry_gives_up_after_max_attempts() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "wrong"));

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        // The unauthenticated request plus MAX_AUTH_ATTEMPTS answers to it.
        assert_eq!(srv.hit_count("/protected"), 1 + MAX_AUTH_ATTEMPTS as usize);
        assert_eq!(seen.lock().unwrap().len(), MAX_AUTH_ATTEMPTS as usize);

        let events = rec.auth_required();
        assert_eq!(events.len(), 1 + MAX_AUTH_ATTEMPTS as usize);
        assert!(
            !events.last().unwrap().1,
            "the last challenge was given up on"
        );
    }

    /// A `407` from the hop's proxy is answered with `Proxy-Authorization`; the protection
    /// space is the proxy's, not the target origin's.
    #[tokio::test(flavor = "current_thread")]
    async fn a_proxy_challenge_is_answered_with_proxy_authorization() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
        // the test server plays the proxy
        let proxy_url = srv.base_url();
        let proxy_origin = proxy_url.origin().ascii_serialization();
        let policy = policy
            .with_credential_store(Some(store.clone()))
            .with_proxy_for(Box::new(move |_| Some(proxy_url.clone())));

        let (meta, body) = auth_fetch(
            &srv,
            "/via-proxy",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"ok");
        assert_eq!(srv.hit_count("/via-proxy"), 2);
        assert_eq!(seen.lock().unwrap()[0].target, AuthTarget::Proxy);
        assert_eq!(
            store.credentials_for(&ProtectionSpace {
                target: AuthTarget::Proxy,
                scheme: AuthScheme::Basic,
                origin: Some(proxy_origin),
                realm: "corp".into(),
            }),
            Some(Credentials::basic("user", "pass"))
        );
    }

    /// A `407` on an unproxied hop comes from the origin server: returned as is, no stored
    /// credentials or hook involved.
    #[tokio::test(flavor = "current_thread")]
    async fn a_407_from_an_unproxied_hop_is_not_answered() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());
        store.store(
            ProtectionSpace {
                target: AuthTarget::Proxy,
                scheme: AuthScheme::Basic,
                origin: None,
                realm: "corp".into(),
            },
            Credentials::basic("user", "pass"),
        );
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));
        let policy = policy.with_credential_store(Some(store));

        let (meta, _) = auth_fetch(
            &srv,
            "/via-proxy",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 407);
        assert_eq!(srv.hit_count("/via-proxy"), 1, "never re-sent");
        assert!(seen.lock().unwrap().is_empty(), "the hook was not asked");
    }

    /// `RequestCredentials::Omit` means no credentials of any kind, so the challenge is not even
    /// offered to the embedder.
    #[tokio::test(flavor = "current_thread")]
    async fn a_credential_less_request_is_never_authenticated() {
        let srv = auth_server().await;
        let rec = Arc::new(RecordingObserver::new());
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, _) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()).with_credentials(RequestCredentials::Omit),
            policy,
            rec.clone(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);
        assert!(seen.lock().unwrap().is_empty());
        // Still reported, so the caller can see why the request came back a 401.
        assert_eq!(rec.auth_required().len(), 1);
    }

    /// `Authorization` is not CORS-safelisted, so a cors-tainted chain is left alone instead of
    /// getting credentials added behind the preflight's back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cors_request_is_not_authenticated() {
        let srv = auth_server().await;
        let (policy, seen) = answering_policy(Credentials::basic("user", "pass"));

        let init = RequestInit::get(HeaderMap::new())
            .with_mixed_content(
                Some(Url::parse("http://other.test/").unwrap().origin()),
                MixedContentPolicy::Allow,
            )
            .with_fetch_metadata(RequestDestination::Empty, RequestMode::NoCors, false);

        let (meta, _) = auth_fetch(&srv, "/protected", init, policy, observer())
            .await
            .unwrap();

        assert_eq!(meta.status, 401);
        assert_eq!(srv.hit_count("/protected"), 1);
        assert!(seen.lock().unwrap().is_empty());
    }

    /// The retry rebuilds the request, body included.
    #[tokio::test(flavor = "current_thread")]
    async fn a_challenged_post_is_replayed_with_its_body() {
        let srv = auth_server().await;
        let (policy, _) = answering_policy(Credentials::basic("user", "pass"));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::post(HeaderMap::new(), Bytes::from_static(b"payload")),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        assert_eq!(srv.hit_count("/protected"), 2);
    }

    /// A `Raw` answer is used but not remembered; the hook recomputes it for the next challenge.
    #[tokio::test(flavor = "current_thread")]
    async fn a_computed_answer_is_used_but_not_stored() {
        let srv = auth_server().await;
        let store = Arc::new(InMemoryCredentialStore::new());
        let (policy, seen) = answering_policy(Credentials::Raw(GOOD_AUTH.into()));
        let policy = policy.with_credential_store(Some(store.clone()));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(store.is_empty(), "a computed answer is not replayable");
    }

    /// Credentials that cannot become a header value are not an answer, so the next challenge
    /// gets a turn: here the `Basic` one the server also offered.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unusable_answer_falls_through_to_the_next_challenge() {
        let srv = TestServer::new()
            .route(
                "/protected",
                RouteConfig::require_auth(
                    r#"Digest realm="d", nonce="n", Basic realm="Secure Area""#,
                    GOOD_AUTH,
                    b"secret".to_vec(),
                ),
            )
            .start()
            .await;

        let seen: Arc<Mutex<Vec<AuthChallenge>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let policy = NetPolicy::default().with_auth_challenge_fn(Box::new(move |challenge| {
            sink.lock().unwrap().push(challenge.clone());
            match challenge.scheme {
                // A colon in the user-id makes these unrepresentable.
                AuthScheme::Digest => Some(Credentials::basic("bad:name", "x")),
                _ => Some(Credentials::basic("user", "pass")),
            }
        }));

        let (meta, body) = auth_fetch(
            &srv,
            "/protected",
            RequestInit::get(HeaderMap::new()),
            policy,
            observer(),
        )
        .await
        .unwrap();

        assert_eq!(meta.status, 200);
        assert_eq!(&body[..], b"secret");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "both challenges were offered");
        assert_eq!(seen[0].scheme, AuthScheme::Digest);
        assert_eq!(seen[1].scheme, AuthScheme::Basic);
    }

    /// A policy with a fresh in-memory cache, plus the cache itself.
    fn caching_policy() -> (NetPolicy, Arc<crate::net::cache::InMemoryHttpCache>) {
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());
        (NetPolicy::default().with_cache(Some(cache.clone())), cache)
    }

    /// A policy that knows the test client connects straight to the host.
    fn direct() -> NetPolicy {
        NetPolicy::default().with_proxied(Box::new(|_| false))
    }

    /// A response from the cache carries an `Age` the cache generated (RFC 9111 §4): here the
    /// fifty seconds its `Date` already put on it, not the `Age: 7` it arrived with.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cache_hit_carries_a_generated_age() {
        let date = (chrono::Utc::now() - chrono::TimeDelta::seconds(50))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let srv = TestServer::new()
            .route(
                "/aged",
                RouteConfig::Cacheable(CacheRouteOptions {
                    extra_headers: vec![("date".into(), date), ("age".into(), "7".into())],
                    ..CacheRouteOptions::max_age(600, b"x".to_vec())
                }),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        let _ = cache_fetch(&srv, "/aged", RequestInit::default(), policy, observer()).await;
        let (meta, _) = cache_fetch(
            &srv,
            "/aged",
            RequestInit::default(),
            NetPolicy::default().with_cache(Some(cache)),
            observer(),
        )
        .await;
        assert!(meta.from_cache);
        let age: i64 = meta.headers[header::AGE].to_str().unwrap().parse().unwrap();
        assert!((50..60).contains(&age), "Age: {age}");
        assert_eq!(meta.headers.get_all(header::AGE).iter().count(), 1);
    }

    /// A `HEAD` whose `ETag` is not the stored `GET`'s drops the stored `GET` (RFC 9111 §4.3.5),
    /// so the next `GET` goes to the server.
    #[tokio::test(flavor = "current_thread")]
    async fn a_head_with_another_etag_drops_the_stored_get() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let base = Url::parse(&format!("http://{}/r", listener.local_addr().unwrap())).unwrap();
        let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = gets.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counted = counted.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let response = if head.starts_with("HEAD ") {
                        "HTTP/1.1 200 OK\r\nETag: \"v2\"\r\nContent-Length: 4\r\n\
                         Connection: close\r\n\r\n"
                    } else {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=600\r\n\
                         Content-Length: 4\r\nConnection: close\r\n\r\nbody"
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());
        let send = |method: Method| {
            super::fetch_response_complete(
                client(),
                base.clone(),
                RequestInit::new(method, HeaderMap::new(), None),
                CancellationToken::new(),
                observer(),
                None,
                Duration::from_secs(5),
                Some(Duration::from_secs(10)),
                NetPolicy::default().with_cache(Some(cache.clone())),
            )
        };
        send(Method::GET).await.unwrap();
        send(Method::GET).await.unwrap();
        assert_eq!(
            gets.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second GET is a hit"
        );
        send(Method::HEAD).await.unwrap();
        send(Method::GET).await.unwrap();
        assert_eq!(
            gets.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the HEAD dropped it"
        );
    }

    /// A `Set-Cookie` on the `304` that confirms a stored response reaches the jar
    /// (RFC 6265 §3), like one on any other response.
    #[tokio::test(flavor = "current_thread")]
    async fn set_cookie_on_a_revalidation_304_reaches_the_jar() {
        let srv = TestServer::new()
            .route(
                "/session",
                RouteConfig::Cacheable(CacheRouteOptions {
                    cache_control: Some("max-age=0".into()),
                    extra_headers: vec![("set-cookie".into(), "sid=rotated".into())],
                    ..CacheRouteOptions::default().with_etag("\"v1\"")
                }),
            )
            .start()
            .await;
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());
        let seen = Arc::new(std::sync::Mutex::new(0usize));
        let policy = || {
            let seen = seen.clone();
            NetPolicy {
                on_cookies: Box::new(move |_, values| {
                    *seen.lock().unwrap() += values.len();
                }),
                ..NetPolicy::default()
            }
            .with_cache(Some(cache.clone()))
        };
        let obs = Arc::new(RecordingObserver::new());
        let _ = cache_fetch(
            &srv,
            "/session",
            RequestInit::default(),
            policy(),
            obs.clone(),
        )
        .await;
        let (meta, _) = cache_fetch(
            &srv,
            "/session",
            RequestInit::default(),
            policy(),
            obs.clone(),
        )
        .await;
        assert!(meta.from_cache, "the second fetch is a revalidation");
        assert_eq!(*seen.lock().unwrap(), 2, "the 304's cookie reached the jar");
    }

    /// Fetch `path` through the policy, returning the metadata and body.
    async fn cache_fetch(
        srv: &crate::net::test_support::TestServerHandle,
        path: &str,
        init: RequestInit,
        policy: NetPolicy,
        observer: Arc<dyn NetObserver + Send + Sync>,
    ) -> (FetchResultMeta, Bytes) {
        super::fetch_response_complete(
            client(),
            srv.url(path),
            init,
            CancellationToken::new(),
            observer,
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await
        .unwrap()
    }

    /// A `304` sonar did not ask for (no revalidation of its own) goes to the caller and is not
    /// stored, even with freshness: the next fetch asks the server again instead of being
    /// answered with an empty `304` from the cache.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unsolicited_304_is_not_stored() {
        let srv = TestServer::new()
            .route(
                "/not-modified",
                RouteConfig::StatusThenOk {
                    code: 304,
                    headers: vec![("Cache-Control".into(), "max-age=60".into())],
                    failures: usize::MAX,
                    body: Vec::new(),
                },
            )
            .start()
            .await;
        let (_, cache) = caching_policy();
        for round in 1..=2 {
            let policy = NetPolicy::default().with_cache(Some(cache.clone()));
            let (meta, _) = cache_fetch(
                &srv,
                "/not-modified",
                RequestInit::default(),
                policy,
                observer(),
            )
            .await;
            assert_eq!(meta.status, 304);
            assert!(!meta.from_cache, "round {round}");
        }
        assert!(cache.is_empty());
        assert_eq!(srv.hit_count("/not-modified"), 2);
    }

    /// Fetch, HTTP-network-or-cache fetch: the cache mode tells the caches on the way too.
    /// `no-cache` sends `Cache-Control: max-age=0`; `reload` and `no-store` send
    /// `Pragma: no-cache` and `Cache-Control: no-cache`; each only when the caller set none.
    /// With or without a cache of sonar's own, since a proxy's cache is the one this is for.
    #[tokio::test(flavor = "current_thread")]
    async fn the_cache_mode_is_sent_for_the_caches_on_the_way() {
        let srv = TestServer::new()
            .route("/echo", RouteConfig::echo_request_headers())
            .start()
            .await;
        let sent = |mode: CacheMode, own: Option<(&'static str, &'static str)>| {
            let srv = &srv;
            async move {
                let mut headers = HeaderMap::new();
                if let Some((name, value)) = own {
                    headers.insert(name, header::HeaderValue::from_static(value));
                }
                let init = RequestInit::get(headers).with_cache(mode, true);
                let (_, body) =
                    cache_fetch(srv, "/echo", init, NetPolicy::default(), observer()).await;
                let lines = String::from_utf8(body.to_vec()).unwrap();
                let get = |name: &str| {
                    lines.lines().find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| v.trim().to_string())
                    })
                };
                (get("cache-control"), get("pragma"))
            }
        };
        let some = |v: &str| Some(v.to_string());

        assert_eq!(sent(CacheMode::Default, None).await, (None, None));
        assert_eq!(sent(CacheMode::ForceCache, None).await, (None, None));
        assert_eq!(
            sent(CacheMode::NoCache, None).await,
            (some("max-age=0"), None)
        );
        assert_eq!(
            sent(CacheMode::Reload, None).await,
            (some("no-cache"), some("no-cache"))
        );
        assert_eq!(
            sent(CacheMode::NoStore, None).await,
            (some("no-cache"), some("no-cache"))
        );
        // The caller's own value stands.
        assert_eq!(
            sent(CacheMode::Reload, Some(("cache-control", "max-age=5"))).await,
            (some("max-age=5"), some("no-cache"))
        );
        assert_eq!(
            sent(CacheMode::NoCache, Some(("cache-control", "no-cache"))).await,
            (some("no-cache"), None)
        );
        // A caller's own condition makes a default request a no-store one, which says so too.
        assert_eq!(
            sent(CacheMode::Default, Some(("if-none-match", "\"v1\""))).await,
            (some("no-cache"), some("no-cache"))
        );
        // A range is not a condition.
        assert_eq!(
            sent(CacheMode::Default, Some(("range", "bytes=0-9"))).await,
            (None, None)
        );
    }

    /// RFC 9111 §4.3.4: a `304` naming another strong `ETag` than the stored one does not
    /// confirm it. The stored body is not served under the new tag; the hop is asked again
    /// without conditions, and that response is the one used and stored.
    #[tokio::test(flavor = "current_thread")]
    async fn a_304_naming_another_version_refetches() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A server that contradicts itself: its responses carry `"v1"`, but a matching
        // `If-None-Match` is answered with a `304` that names `"v2"`. Bodies count requests.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let served = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let hit = served.fetch_add(1, Ordering::SeqCst) + 1;
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let response = if request.contains("\r\nif-none-match: \"v1\"") {
                    "HTTP/1.1 304 Not Modified\r\nETag: \"v2\"\r\nCache-Control: max-age=0\r\n\
                     Connection: close\r\n\r\n"
                        .to_string()
                } else {
                    let body = format!("hit-{hit}");
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/flip")).unwrap();
        let (_, cache) = caching_policy();
        let fetch = || {
            super::fetch_response_complete(
                client(),
                url.clone(),
                RequestInit::default(),
                CancellationToken::new(),
                observer(),
                None,
                Duration::from_secs(5),
                Some(Duration::from_secs(10)),
                NetPolicy::default().with_cache(Some(cache.clone())),
            )
        };

        let (_, body) = fetch().await.unwrap();
        assert_eq!(&body[..], b"hit-1");
        // Stale at once: revalidated, answered 304 with "v2", asked again without conditions.
        let (meta, body) = fetch().await.unwrap();
        assert_eq!(meta.status, 200);
        assert!(!meta.from_cache);
        assert_eq!(
            &body[..],
            b"hit-3",
            "the refetched body, not the stored one"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        assert_eq!(cache.len(), 1, "the refetched response replaced the entry");
    }

    /// A fresh stored response answers the next fetch without a request going out.
    #[tokio::test(flavor = "current_thread")]
    async fn a_fresh_response_is_served_from_the_cache() {
        let srv = TestServer::new()
            .route(
                "/fresh",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(60, b"v1".to_vec()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (meta, body) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, observer()).await;
        assert_eq!(meta.status, 200);
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(cache.len(), 1);

        let (policy, _) = (NetPolicy::default().with_cache(Some(cache.clone())), ());
        let rec = Arc::new(RecordingObserver::new());
        let (meta, body) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, rec.clone()).await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-1", "the stored body, not a second request");
        assert_eq!(srv.hit_count("/fresh"), 1, "the server was not asked again");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Hit]);
    }

    /// What one jar's cookies fetched is cached for that jar: another jar's request goes to the
    /// network, and so does one that carries no cookies at all.
    #[tokio::test(flavor = "current_thread")]
    async fn a_jars_cached_response_is_not_served_to_another_jar() {
        let srv = TestServer::new()
            .route(
                "/mine",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(60, b"v1".to_vec()).counting()),
            )
            .start()
            .await;
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());
        let jar = |partition: &str| NetPolicy {
            cache_partition: partition.to_string(),
            ..NetPolicy::default().with_cache(Some(cache.clone()))
        };

        let (_, body) =
            cache_fetch(&srv, "/mine", RequestInit::default(), jar("a"), observer()).await;
        assert_eq!(&body[..], b"hit-1");
        let (meta, body) =
            cache_fetch(&srv, "/mine", RequestInit::default(), jar("a"), observer()).await;
        assert!(meta.from_cache, "the same jar is served from its cache");
        assert_eq!(&body[..], b"hit-1");

        let (meta, body) =
            cache_fetch(&srv, "/mine", RequestInit::default(), jar("b"), observer()).await;
        assert!(!meta.from_cache, "another jar's response is not served");
        assert_eq!(&body[..], b"hit-2");

        let omit = RequestInit::default().with_credentials(RequestCredentials::Omit);
        let (meta, _) = cache_fetch(&srv, "/mine", omit, jar("a"), observer()).await;
        assert!(
            !meta.from_cache,
            "a request without cookies does not read a jar's entry"
        );
        assert_eq!(srv.hit_count("/mine"), 3);
    }

    /// A stored response is CORS-checked like a fresh one: an entry stored by a same-origin
    /// fetch carries no `Access-Control-Allow-Origin`, and a cross-origin caller must not
    /// read it from the cache when it could not read it from the network.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cache_hit_is_cors_checked() {
        let srv = TestServer::new()
            .route(
                "/private",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(60, b"secret".to_vec())),
            )
            .route(
                "/public",
                RouteConfig::Cacheable(CacheRouteOptions {
                    extra_headers: vec![("Access-Control-Allow-Origin".into(), "*".into())],
                    ..CacheRouteOptions::max_age(60, b"open".to_vec())
                }),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        cache_fetch(&srv, "/private", RequestInit::default(), policy, observer()).await;
        let (policy, _) = (NetPolicy::default().with_cache(Some(cache.clone())), ());
        cache_fetch(&srv, "/public", RequestInit::default(), policy, observer()).await;
        assert_eq!(cache.len(), 2);

        let cors_from_other = || {
            RequestInit::get(HeaderMap::new())
                .with_mixed_content(
                    Some(Url::parse("http://other.test/").unwrap().origin()),
                    MixedContentPolicy::Allow,
                )
                .with_fetch_metadata(RequestDestination::Empty, RequestMode::Cors, false)
                .with_credentials(RequestCredentials::Omit)
        };

        let rec = Arc::new(RecordingObserver::new());
        let res = super::fetch_response_complete(
            client(),
            srv.url("/private"),
            cors_from_other(),
            CancellationToken::new(),
            rec.clone(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            NetPolicy::default().with_cache(Some(cache.clone())),
        )
        .await;
        assert!(
            matches!(
                res,
                Err(NetError::Blocked {
                    reason: BlockReason::Cors(_),
                    ..
                })
            ),
            "{res:?}"
        );
        assert_eq!(srv.hit_count("/private"), 1, "blocked, not re-fetched");

        // An entry that does allow the origin is served from the cache.
        let (meta, body) = cache_fetch(
            &srv,
            "/public",
            cors_from_other(),
            NetPolicy::default().with_cache(Some(cache.clone())),
            observer(),
        )
        .await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"open");
        assert_eq!(srv.hit_count("/public"), 1);
    }

    /// A stale entry is revalidated, and a `304` reuses the stored body.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_response_is_revalidated_and_a_304_reuses_the_body() {
        let srv = TestServer::new()
            .route(
                "/stale",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(0, b"original".to_vec()).with_etag("\"v1\""),
                ),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (_, body) =
            cache_fetch(&srv, "/stale", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"original");
        assert_eq!(cache.len(), 1);

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) =
            cache_fetch(&srv, "/stale", RequestInit::default(), policy, rec.clone()).await;

        // The server was asked, answered 304, and the stored body came back.
        assert_eq!(srv.hit_count("/stale"), 2);
        assert_eq!(meta.status, 200, "the 304 is not what the caller sees");
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"original");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Validated]);
    }

    /// A response reports the peer it was read from, and a cache hit the peer its entry was
    /// stored from, so the address cannot be answered afresh by DNS when the entry is used.
    #[tokio::test(flavor = "current_thread")]
    async fn the_peer_address_is_reported_and_kept_with_the_cache_entry() {
        let srv = TestServer::new()
            .route(
                "/fresh",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(60, b"v1".to_vec())),
            )
            .route(
                "/stale",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(0, b"original".to_vec()).with_etag("\"v1\""),
                ),
            )
            .start()
            .await;
        let peer = Some(srv.socket_addr());
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::new());

        let policy = direct().with_cache(Some(cache.clone()));
        let (meta, _) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, observer()).await;
        assert!(!meta.from_cache);
        assert_eq!(meta.peer_addr, peer);

        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, _) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), policy, observer()).await;
        assert!(meta.from_cache);
        assert_eq!(meta.peer_addr, peer);

        // Stored, then confirmed by a 304: the confirming connection's peer.
        for _ in 0..2 {
            let policy = direct().with_cache(Some(cache.clone()));
            let (meta, _) =
                cache_fetch(&srv, "/stale", RequestInit::default(), policy, observer()).await;
            assert_eq!(meta.peer_addr, peer);
        }
        assert_eq!(srv.hit_count("/stale"), 2);

        assert_eq!(FetchResultMeta::synthetic(srv.url("/x")).peer_addr, None);

        // Through a proxy the peer is the proxy, not the host: no address at all.
        let proxied = NetPolicy::default().with_proxied(Box::new(|_| true));
        let (meta, _) =
            cache_fetch(&srv, "/fresh", RequestInit::default(), proxied, observer()).await;
        assert!(!meta.from_cache);
        assert_eq!(meta.peer_addr, None);

        // A policy that cannot say whether the client was proxied reports no address either.
        let (meta, _) = cache_fetch(
            &srv,
            "/fresh",
            RequestInit::default(),
            NetPolicy::default(),
            observer(),
        )
        .await;
        assert_eq!(meta.peer_addr, None);
    }

    /// A stale entry the server cannot confirm is refetched, and the fresh response takes its
    /// place instead of piling up beside it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_entry_without_a_validator_is_refetched_and_replaced() {
        let srv = TestServer::new()
            .route(
                "/changing",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(0, Vec::new()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        let (_, body) = cache_fetch(
            &srv,
            "/changing",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(cache.len(), 1);

        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/changing",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/changing"), 2);
        assert_eq!(cache.len(), 1, "replaced, not piled up");
    }

    /// `no-store` keeps a response out of the cache; `Cache-Control` with nothing to go on keeps
    /// it out too.
    #[tokio::test(flavor = "current_thread")]
    async fn responses_that_may_not_be_stored_are_not_stored() {
        let srv = TestServer::new()
            .route(
                "/no-store",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(60, b"x".to_vec()).with_cache_control("no-store"),
                ),
            )
            .route("/plain", RouteConfig::ok(b"x"))
            .start()
            .await;
        let (policy, cache) = caching_policy();
        cache_fetch(
            &srv,
            "/no-store",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert!(cache.is_empty());

        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        cache_fetch(&srv, "/plain", RequestInit::default(), policy, observer()).await;
        assert!(
            cache.is_empty(),
            "no directives and no validator: nothing to store"
        );
    }

    /// A cacheable redirect is stored, so the next fetch skips the hop entirely.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cacheable_redirect_is_stored_and_reused() {
        let target = TestServer::new()
            .route("/target", RouteConfig::ok(b"arrived"))
            .start()
            .await;
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::RedirectAbsoluteWithHeaders {
                    headers: vec![("Cache-Control".into(), "max-age=600".into())],
                    target: target.url("/target").to_string(),
                },
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let (_, body) = cache_fetch(&srv, "/hop", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"arrived");
        assert_eq!(srv.hit_count("/hop"), 1);
        assert_eq!(cache.len(), 1, "the redirect itself is the entry");

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (_, body) =
            cache_fetch(&srv, "/hop", RequestInit::default(), policy, rec.clone()).await;

        assert_eq!(&body[..], b"arrived");
        assert_eq!(srv.hit_count("/hop"), 1, "the redirect came from the cache");
        assert_eq!(
            target.hit_count("/target"),
            2,
            "the target itself is not cacheable"
        );
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Hit]);
    }

    /// An unsafe method drops what is stored for the URL it changed.
    #[tokio::test(flavor = "current_thread")]
    async fn a_post_invalidates_the_stored_response() {
        let srv = TestServer::new()
            .route(
                "/resource",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, b"v1".to_vec())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        cache_fetch(
            &srv,
            "/resource",
            RequestInit::default(),
            policy,
            observer(),
        )
        .await;
        assert_eq!(cache.len(), 1);

        let rec = Arc::new(RecordingObserver::new());
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        cache_fetch(
            &srv,
            "/resource",
            RequestInit::post(HeaderMap::new(), Bytes::from_static(b"update")),
            policy,
            rec.clone(),
        )
        .await;

        assert!(cache.is_empty(), "the stored response is now wrong");
        assert_eq!(rec.cache_outcomes(), vec![CacheOutcome::Invalidated]);
    }

    /// The cache modes reach past the normal rules in both directions.
    #[tokio::test(flavor = "current_thread")]
    async fn cache_modes_bypass_and_force() {
        let srv = TestServer::new()
            .route(
                "/mode",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, Vec::new()).counting()),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();
        let (_, body) =
            cache_fetch(&srv, "/mode", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], b"hit-1");

        // Reload ignores the fresh entry and stores what comes back.
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/mode",
            RequestInit::default().with_cache(CacheMode::Reload, true),
            policy,
            observer(),
        )
        .await;
        assert!(!meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/mode"), 2);

        // Force-cache uses the stored response even when the request would normally revalidate.
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));
        let (meta, body) = cache_fetch(
            &srv,
            "/mode",
            RequestInit::default().with_cache(CacheMode::ForceCache, true),
            policy,
            observer(),
        )
        .await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(srv.hit_count("/mode"), 2);
    }

    /// `only-if-cached` fails rather than reaching the network.
    #[tokio::test(flavor = "current_thread")]
    async fn only_if_cached_without_an_entry_is_refused() {
        let srv = TestServer::new()
            .route("/nothing", RouteConfig::ok(b"x"))
            .start()
            .await;
        let (policy, _cache) = caching_policy();
        let rec = Arc::new(RecordingObserver::new());

        let err = super::fetch_response_complete(
            client(),
            srv.url("/nothing"),
            RequestInit::default().with_cache(CacheMode::OnlyIfCached, true),
            CancellationToken::new(),
            rec.clone(),
            None,
            Duration::from_secs(5),
            Some(Duration::from_secs(10)),
            policy,
        )
        .await;

        match err {
            Err(NetError::Blocked { reason, .. }) => assert_eq!(reason, BlockReason::NotCached),
            other => panic!("expected a NotCached block, got {other:?}"),
        }
        assert_eq!(srv.hit_count("/nothing"), 0, "nothing went out");
        assert_eq!(rec.blocked_reason(), Some(BlockReason::NotCached));
    }

    /// `Vary` keeps one entry per set of request headers the response depends on.
    #[tokio::test(flavor = "current_thread")]
    async fn vary_stores_one_entry_per_variant() {
        let srv = TestServer::new()
            .route(
                "/varies",
                RouteConfig::Cacheable(
                    CacheRouteOptions::max_age(600, Vec::new())
                        .counting()
                        .with_vary("accept-language"),
                ),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let fetch = |policy: NetPolicy, language: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_LANGUAGE, language.parse().unwrap());
            (policy, RequestInit::get(headers))
        };

        let (policy, init) = fetch(policy, "nl");
        let (_, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert_eq!(&body[..], b"hit-1");

        // A different language is a different variant, so it goes to the server.
        let (policy, init) = fetch(NetPolicy::default().with_cache(Some(cache.clone())), "en");
        let (_, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert_eq!(&body[..], b"hit-2");
        assert_eq!(cache.len(), 2);

        // The first variant is still there.
        let (policy, init) = fetch(NetPolicy::default().with_cache(Some(cache.clone())), "nl");
        let (meta, body) = cache_fetch(&srv, "/varies", init, policy, observer()).await;
        assert!(meta.from_cache);
        assert_eq!(&body[..], b"hit-1");
        assert_eq!(srv.hit_count("/varies"), 2);
    }

    /// A body past the cache's ceiling is delivered as usual, and not stored.
    #[tokio::test(flavor = "current_thread")]
    async fn a_body_over_the_ceiling_is_not_stored() {
        let big = pattern(64 * 1024);
        let srv = TestServer::new()
            .route(
                "/big",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, big.clone())),
            )
            .start()
            .await;
        let cache = Arc::new(crate::net::cache::InMemoryHttpCache::with_limits(
            1024 * 1024,
            1024,
        ));
        let policy = NetPolicy::default().with_cache(Some(cache.clone()));

        let (_, body) = cache_fetch(&srv, "/big", RequestInit::default(), policy, observer()).await;
        assert_eq!(&body[..], big.as_slice(), "the caller still gets it all");
        assert!(cache.is_empty());
    }

    /// The streaming path fills the cache too: the body is collected as the caller reads it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_streamed_body_is_stored_once_it_is_read_to_the_end() {
        let body = pattern(32 * 1024);
        let srv = TestServer::new()
            .route(
                "/stream",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, body.clone())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let ResponseTop {
            peek_buf,
            mut reader,
            ..
        } = super::fetch_response_top(
            client(),
            srv.url("/stream"),
            RequestInit::default(),
            CancellationToken::new(),
            observer(),
            policy,
        )
        .await
        .unwrap();

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        let mut received = peek_buf.as_slice().to_vec();
        received.extend_from_slice(&rest);
        assert_eq!(received, body);

        // Stored complete, peek window included.
        let stored = cache.get(&crate::net::cache::CacheKey::new(
            &Method::GET,
            &srv.url("/stream"),
        ));
        assert_eq!(stored.len(), 1);
        assert_eq!(&stored[0].body[..], body.as_slice());
    }

    /// A stream the caller abandons mid-body leaves nothing behind.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unfinished_body_is_not_stored() {
        let body = pattern(32 * 1024);
        let srv = TestServer::new()
            .route(
                "/partial",
                RouteConfig::Cacheable(CacheRouteOptions::max_age(600, body.clone())),
            )
            .start()
            .await;
        let (policy, cache) = caching_policy();

        let ResponseTop { mut reader, .. } = super::fetch_response_top(
            client(),
            srv.url("/partial"),
            RequestInit::default(),
            CancellationToken::new(),
            observer(),
            policy,
        )
        .await
        .unwrap();

        // Read a little and drop the reader.
        let mut scratch = vec![0u8; 128];
        let _ = reader.read(&mut scratch).await.unwrap();
        drop(reader);

        assert!(cache.is_empty(), "an incomplete body is not a cache entry");
    }

    /// `NetEvent::SecurityUpgraded` and `NetEvent::RequestModified`: one event per change, in
    /// the right place in the stream, and nothing when nothing changed.
    mod security_events {
        use super::*;
        use crate::net::types::{RequestChange, UpgradeReason};

        /// Fetch `url` to the end with a recording observer and return it. The result is not
        /// checked. Some chains here end at a host that does not resolve.
        async fn recorded(
            client: Arc<reqwest::Client>,
            url: Url,
            init: RequestInit,
            policy: NetPolicy,
        ) -> Arc<RecordingObserver> {
            let rec = Arc::new(RecordingObserver::new());
            let _ = super::super::fetch_response_complete(
                client,
                url,
                init,
                CancellationToken::new(),
                rec.clone(),
                None,
                Duration::from_secs(5),
                None,
                policy,
            )
            .await;
            rec
        }

        /// A body read to its end has ended: a cancel that comes after adds no second end.
        #[tokio::test(flavor = "current_thread")]
        async fn a_cancel_after_the_end_adds_no_second_end() {
            let srv = TestServer::new()
                .route("/", RouteConfig::ok(vec![b'y'; 20 * 1024]))
                .start()
                .await;
            let rec = Arc::new(RecordingObserver::new());
            let cancel = CancellationToken::new();
            let mut top = super::super::fetch_response_top(
                client(),
                srv.url("/"),
                RequestInit::default(),
                cancel.clone(),
                rec.clone(),
                NetPolicy::default(),
            )
            .await
            .unwrap();
            let mut sink = Vec::new();
            top.reader.read_to_end(&mut sink).await.unwrap();
            cancel.cancel();
            let _ = top.reader.read(&mut [0u8; 16]).await;
            drop(top);
            let ends: Vec<_> = rec
                .event_names()
                .into_iter()
                .filter(|n| matches!(n.as_str(), "Finished" | "Failed" | "Cancelled"))
                .collect();
            assert_eq!(ends, ["Finished"]);
        }

        /// `Progress` counts what reached the caller and never goes back, also where the
        /// first bytes, read to sniff the body, end and the rest of it begins.
        #[tokio::test(flavor = "current_thread")]
        async fn progress_never_goes_back() {
            let body = vec![b'x'; 64 * 1024];
            let srv = TestServer::new()
                .route("/big", RouteConfig::ok(body.clone()))
                .start()
                .await;
            let rec = Arc::new(RecordingObserver::new());
            let mut top = super::super::fetch_response_top(
                client(),
                srv.url("/big"),
                RequestInit::default(),
                CancellationToken::new(),
                rec.clone(),
                NetPolicy::default(),
            )
            .await
            .unwrap();
            // Small reads, so the bytes read past the sniffed ones are counted in steps.
            let mut small = [0u8; 256];
            while top.reader.read(&mut small).await.unwrap() > 0 {}
            let progress = rec.progress();
            assert!(progress.len() > 1, "{progress:?}");
            assert!(progress.windows(2).all(|w| w[0] <= w[1]), "{progress:?}");
            assert_eq!(progress.last(), Some(&(body.len() as u64)));
        }

        /// `Finished` names the URL that finished loading: after a redirect, the last hop.
        #[tokio::test(flavor = "current_thread")]
        async fn finished_names_the_final_url() {
            let srv = TestServer::new()
                .route("/a", RouteConfig::redirect_to("/c"))
                .route("/c", RouteConfig::ok(b"x"))
                .start()
                .await;
            let rec = recorded(
                client(),
                srv.url("/a"),
                RequestInit::default(),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(rec.finished_urls(), [srv.url("/c")]);
        }

        fn changes(rec: &RecordingObserver) -> Vec<RequestChange> {
            rec.modifications().into_iter().map(|(_, c)| c).collect()
        }

        /// Leading and trailing whitespace is taken off every header value (Fetch, normalize);
        /// whitespace inside a value stays, and so does every value of a repeated header.
        #[tokio::test(flavor = "current_thread")]
        async fn header_values_are_trimmed() {
            let srv = TestServer::new()
                .default_route(RouteConfig::ok(b"x"))
                .start()
                .await;
            let mut headers = HeaderMap::new();
            headers.insert("x-a", "\t v w \t".parse().unwrap());
            headers.append("x-b", " one".parse().unwrap());
            headers.append("x-b", "two ".parse().unwrap());
            let rec = recorded(
                client(),
                srv.url("/"),
                RequestInit::get(headers),
                NetPolicy::default(),
            )
            .await;
            let sent = rec.requests_sent().pop().unwrap().2;
            assert_eq!(sent.get("x-a").unwrap(), "v w");
            let b: Vec<_> = sent.get_all("x-b").iter().collect();
            assert_eq!(b, ["one", "two"]);
        }

        /// The header a hop sent under `name`, as a string.
        fn sent_header(rec: &RecordingObserver, name: &str) -> Option<String> {
            rec.requests_sent()
                .pop()
                .unwrap()
                .2
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        }

        /// `Accept-Encoding` is the fetcher's: what a decoding client can decode, `identity`
        /// for a caller that wants the bytes as they come, and a caller's own value left alone
        /// when the request is not web content.
        #[tokio::test(flavor = "current_thread")]
        async fn accept_encoding_is_set_by_the_fetcher() {
            let srv = TestServer::new()
                .default_route(RouteConfig::ok(b"x"))
                .start()
                .await;
            let rec = recorded(
                client(),
                srv.url("/"),
                RequestInit::get(HeaderMap::new()),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(
                sent_header(&rec, "accept-encoding").as_deref(),
                Some("gzip, br, deflate")
            );

            let raw = RequestInit::get(HeaderMap::new()).with_cache(CacheMode::Default, false);
            let rec = recorded(client(), srv.url("/"), raw, NetPolicy::default()).await;
            assert_eq!(
                sent_header(&rec, "accept-encoding").as_deref(),
                Some("identity")
            );

            let mut own = HeaderMap::new();
            own.insert(header::ACCEPT_ENCODING, "zstd".parse().unwrap());
            let rec = recorded(
                client(),
                srv.url("/"),
                RequestInit::get(own),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(
                sent_header(&rec, "accept-encoding").as_deref(),
                Some("zstd")
            );
        }

        /// A `101` nobody asked for is a network error, not the response (Fetch §4.7).
        #[tokio::test(flavor = "current_thread")]
        async fn an_unsolicited_101_is_a_network_error() {
            let srv = TestServer::new()
                .route("/switch", RouteConfig::status(101, b""))
                .start()
                .await;
            let res = super::super::fetch_response_complete(
                client(),
                srv.url("/switch"),
                RequestInit::get(HeaderMap::new()),
                CancellationToken::new(),
                observer(),
                None,
                Duration::from_secs(3),
                Some(Duration::from_secs(5)),
                NetPolicy::default(),
            )
            .await;
            assert!(matches!(res, Err(NetError::Other(_))), "{res:?}");
        }

        /// A request with `Range` asks for the representation unencoded (Fetch §4.6), and a
        /// caller's own `Accept-Encoding` gets `identity` appended.
        #[tokio::test(flavor = "current_thread")]
        async fn a_range_request_asks_for_identity() {
            let srv = TestServer::new()
                .default_route(RouteConfig::ok(b"x"))
                .start()
                .await;
            let mut ranged = HeaderMap::new();
            ranged.insert(header::RANGE, "bytes=0-9".parse().unwrap());
            let rec = recorded(
                client(),
                srv.url("/"),
                RequestInit::get(ranged.clone()),
                NetPolicy::default(),
            )
            .await;
            let sent = rec.requests_sent().pop().unwrap().2;
            let values: Vec<_> = sent.get_all(header::ACCEPT_ENCODING).iter().collect();
            assert_eq!(values, ["identity"]);

            ranged.insert(header::ACCEPT_ENCODING, "zstd".parse().unwrap());
            let rec = recorded(
                client(),
                srv.url("/"),
                RequestInit::get(ranged),
                NetPolicy::default(),
            )
            .await;
            let sent = rec.requests_sent().pop().unwrap().2;
            let values: Vec<_> = sent.get_all(header::ACCEPT_ENCODING).iter().collect();
            assert_eq!(values, ["zstd", "identity"]);
        }

        /// Web content may not set a forbidden request-header (Fetch §2.2.2): on a request with
        /// an initiating origin they are removed and reported, a method override naming a
        /// forbidden method included. Other headers stay. Without an origin the request is the
        /// embedder's, and its headers go out.
        #[tokio::test(flavor = "current_thread")]
        async fn forbidden_headers_are_removed_from_web_content() {
            let srv = TestServer::new()
                .route("/headers", RouteConfig::echo_request_headers())
                .start()
                .await;
            let headers = |override_method: &str| {
                let mut h = HeaderMap::new();
                h.insert(header::COOKIE, "session=stolen".parse().unwrap());
                h.insert(header::HOST, "evil.example".parse().unwrap());
                h.insert(header::ACCEPT_ENCODING, "zstd".parse().unwrap());
                h.insert("sec-purpose", "prefetch".parse().unwrap());
                h.insert("proxy-x", "1".parse().unwrap());
                h.insert("x-http-method-override", override_method.parse().unwrap());
                h.insert(header::AUTHORIZATION, "Bearer t".parse().unwrap());
                h
            };
            let origin = Some(srv.url("/").origin());

            let init = RequestInit::get(headers("GET, trace"))
                .with_mixed_content(origin.clone(), MixedContentPolicy::default());
            let rec = Arc::new(RecordingObserver::new());
            let (_, echoed) = super::super::fetch_response_complete(
                client(),
                srv.url("/headers"),
                init,
                CancellationToken::new(),
                rec.clone(),
                None,
                Duration::from_secs(3),
                Some(Duration::from_secs(5)),
                NetPolicy::default(),
            )
            .await
            .unwrap();
            let mut removed = match changes(&rec).as_slice() {
                [RequestChange::HeadersRemoved { headers }] => headers.clone(),
                other => panic!("{other:?}"),
            };
            removed.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            assert_eq!(
                removed,
                vec![
                    header::ACCEPT_ENCODING,
                    header::COOKIE,
                    header::HOST,
                    header::HeaderName::from_static("proxy-x"),
                    header::HeaderName::from_static("sec-purpose"),
                    header::HeaderName::from_static("x-http-method-override"),
                ]
            );
            let echoed = String::from_utf8_lossy(&echoed).to_ascii_lowercase();
            for gone in [
                "session=stolen",
                "evil.example",
                "zstd",
                "sec-purpose",
                "proxy-x",
                "x-http-method-override",
            ] {
                assert!(!echoed.contains(gone), "{gone} was sent: {echoed}");
            }
            assert!(echoed.contains("authorization: bearer t"), "{echoed}");
            assert!(
                echoed.contains("accept-encoding: gzip, br, deflate"),
                "{echoed}"
            );

            // An override naming an allowed method is not forbidden.
            let init = RequestInit::get(headers("PATCH"))
                .with_mixed_content(origin, MixedContentPolicy::default());
            let rec = recorded(client(), srv.url("/headers"), init, NetPolicy::default()).await;
            assert_eq!(
                sent_header(&rec, "x-http-method-override").as_deref(),
                Some("PATCH")
            );

            // No origin: the embedder's own request, sent as set.
            let rec = recorded(
                client(),
                srv.url("/headers"),
                RequestInit::get(headers("TRACE")),
                NetPolicy::default(),
            )
            .await;
            assert!(changes(&rec).is_empty(), "{:?}", changes(&rec));
            assert_eq!(
                sent_header(&rec, "cookie").as_deref(),
                Some("session=stolen")
            );
        }

        /// `CONNECT`, `TRACE` and `TRACK`, in any case, are refused for a request with an
        /// initiating origin before anything is sent (Fetch §2.2.1). Without an origin the
        /// request is the embedder's and goes out.
        #[tokio::test(flavor = "current_thread")]
        async fn forbidden_methods_are_refused_for_web_content() {
            let srv = TestServer::new()
                .default_route(RouteConfig::ok(b"x"))
                .start()
                .await;
            let origin = Some(srv.url("/").origin());
            for written in ["TRACE", "track", "Connect"] {
                let method = Method::from_bytes(written.as_bytes()).unwrap();
                let init = RequestInit::new(method, HeaderMap::new(), None)
                    .with_mixed_content(origin.clone(), MixedContentPolicy::default());
                let res = super::super::fetch_response_complete(
                    client(),
                    srv.url("/x"),
                    init,
                    CancellationToken::new(),
                    observer(),
                    None,
                    Duration::from_secs(3),
                    Some(Duration::from_secs(5)),
                    NetPolicy::default(),
                )
                .await;
                assert!(
                    matches!(
                        res,
                        Err(NetError::Blocked {
                            reason: BlockReason::ForbiddenMethod,
                            ..
                        })
                    ),
                    "{written}: {res:?}"
                );
            }
            assert_eq!(srv.hit_count("/x"), 0);

            let rec = recorded(
                client(),
                srv.url("/y"),
                RequestInit::new(Method::TRACE, HeaderMap::new(), None),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(rec.requests_sent().len(), 1);
            assert_eq!(srv.hit_count("/y"), 1);
        }

        /// The six methods Fetch normalizes go out uppercased, whatever case the caller wrote
        /// them in (Fetch §2.2.1); any other method is left alone.
        #[tokio::test(flavor = "current_thread")]
        async fn methods_are_normalized() {
            let srv = TestServer::new()
                .default_route(RouteConfig::ok(b"x"))
                .start()
                .await;
            for (written, sent) in [
                ("get", "GET"),
                ("pOsT", "POST"),
                ("Delete", "DELETE"),
                ("patch", "patch"),
            ] {
                let method = Method::from_bytes(written.as_bytes()).unwrap();
                let rec = recorded(
                    client(),
                    srv.url("/"),
                    RequestInit::new(method, HeaderMap::new(), None),
                    NetPolicy::default(),
                )
                .await;
                assert_eq!(rec.requests_sent().pop().unwrap().0.as_str(), sent);
            }
        }

        /// POST and PUT without a body send `Content-Length: 0` (Fetch §4.6); GET sends none.
        #[tokio::test(flavor = "current_thread")]
        async fn a_post_or_put_without_a_body_sends_content_length_zero() {
            let srv = TestServer::new()
                .route("/headers", RouteConfig::echo_request_headers())
                .start()
                .await;
            for (method, expected) in [
                (Method::POST, Some("0")),
                (Method::PUT, Some("0")),
                (Method::GET, None),
            ] {
                let rec = recorded(
                    client(),
                    srv.url("/headers"),
                    RequestInit::new(method.clone(), HeaderMap::new(), None),
                    NetPolicy::default(),
                )
                .await;
                let sent = rec.requests_sent().pop().unwrap().2;
                assert_eq!(
                    sent.get(header::CONTENT_LENGTH)
                        .map(|v| v.to_str().unwrap().to_string())
                        .as_deref(),
                    expected,
                    "{method}"
                );
            }
        }

        /// A caller's `Content-Length` and `Transfer-Encoding` are not sent: the body frames
        /// the message (RFC 9112 §6). A shorter `Content-Length` would cut the body, so the
        /// server echoing what it read gets all of it.
        #[tokio::test(flavor = "current_thread")]
        async fn framing_headers_come_from_the_body() {
            let srv = TestServer::new()
                .route("/echo", RouteConfig::echo_body())
                .route("/headers", RouteConfig::echo_request_headers())
                .start()
                .await;
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_LENGTH, "3".parse().unwrap());
            let rec = Arc::new(RecordingObserver::new());
            let (_, echoed) = super::super::fetch_response_complete(
                client(),
                srv.url("/echo"),
                RequestInit::post(headers, b"0123456789".to_vec()),
                CancellationToken::new(),
                rec.clone(),
                None,
                Duration::from_secs(3),
                Some(Duration::from_secs(5)),
                NetPolicy::default(),
            )
            .await
            .unwrap();
            assert_eq!(&echoed[..], b"0123456789");
            assert_eq!(
                changes(&rec),
                vec![RequestChange::HeadersRemoved {
                    headers: vec![header::CONTENT_LENGTH],
                }]
            );

            let mut headers = HeaderMap::new();
            headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
            let (_, echoed) = super::super::fetch_response_complete(
                client(),
                srv.url("/headers"),
                RequestInit::post(headers, b"0123456789".to_vec()),
                CancellationToken::new(),
                observer(),
                None,
                Duration::from_secs(3),
                Some(Duration::from_secs(5)),
                NetPolicy::default(),
            )
            .await
            .unwrap();
            let echoed = String::from_utf8_lossy(&echoed).to_ascii_lowercase();
            assert!(!echoed.contains("transfer-encoding"), "{echoed}");
            assert!(echoed.contains("content-length: 10"), "{echoed}");
        }

        /// The names of the events from `first` on, with the ones no test here is about
        /// (`DnsResolved`, `Connected`, `BodyPreview`, `Progress`) left out.
        fn stream(rec: &RecordingObserver) -> Vec<String> {
            rec.event_names()
                .into_iter()
                .filter(|n| {
                    !matches!(
                        n.as_str(),
                        "DnsResolved" | "Connected" | "Progress" | "BodyPreview"
                    )
                })
                .collect()
        }

        /// A request with every input set that nothing has to change. It has a same-origin
        /// referrer (its fragment is not a change), a same-origin initiator, same-origin
        /// credentials and a same-origin 307, which keeps the POST. No event.
        #[tokio::test(flavor = "current_thread")]
        async fn nothing_changed_reports_nothing() {
            let srv = TestServer::new()
                .route("/hop", RouteConfig::redirect_307("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let mut referrer = srv.url("/page");
            referrer.set_fragment(Some("frag"));
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, "Bearer t".parse().unwrap());
            let init = RequestInit::post(headers, b"x".to_vec())
                .with_referrer(Some(referrer), ReferrerPolicy::default())
                .with_mixed_content(Some(srv.base_url().origin()), MixedContentPolicy::Upgrade)
                .with_credentials(RequestCredentials::SameOrigin);
            let rec = recorded(client(), srv.url("/hop"), init, NetPolicy::default()).await;

            assert!(rec.upgrades().is_empty(), "{:?}", rec.upgrades());
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
            assert_eq!(rec.requests_sent().len(), 2);
        }

        /// A host with a stored HSTS policy is fetched over https, and the upgrade is reported
        /// before the request goes out.
        #[tokio::test(flavor = "current_thread")]
        async fn hsts_upgrade_is_reported_before_the_request() {
            let (srv, client) = tls_server_and_client(vec![("/", RouteConfig::ok(b"x"))]).await;
            let store = Arc::new(crate::net::hsts::InMemoryHstsStore::new());
            crate::net::hsts::HstsStore::store(
                store.as_ref(),
                "hsts.test",
                crate::net::hsts::HstsEntry {
                    expires_at: chrono::Utc::now() + chrono::TimeDelta::days(1),
                    include_subdomains: false,
                },
            );
            let secure = srv.url("/");
            let mut insecure = secure.clone();
            insecure.set_scheme("http").unwrap();

            let rec = recorded(
                client,
                insecure.clone(),
                RequestInit::get(HeaderMap::new()),
                NetPolicy::default().with_hsts(Some(store)),
            )
            .await;

            assert_eq!(
                rec.upgrades(),
                vec![(
                    insecure.to_string(),
                    secure.to_string(),
                    UpgradeReason::Hsts
                )]
            );
            assert_eq!(rec.requests_sent()[0].1, secure);
            assert_eq!(
                stream(&rec)[..4],
                [
                    "Started",
                    "SecurityUpgraded",
                    "RequestSent",
                    "ResponseHeaders"
                ]
            );
        }

        /// A mixed content upgrade on a redirect hop comes after the `Redirected` for it, and
        /// is not also reported as a warning any more.
        #[tokio::test(flavor = "current_thread")]
        async fn mixed_content_upgrade_follows_the_redirect() {
            let srv = TestServer::new()
                .route(
                    "/hop",
                    RouteConfig::redirect_absolute("http://insecure.invalid/a.js"),
                )
                .start()
                .await;
            let init = RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Upgrade,
            );
            let rec = recorded(client(), srv.url("/hop"), init, NetPolicy::default()).await;

            assert_eq!(
                rec.upgrades(),
                vec![(
                    "http://insecure.invalid/a.js".to_string(),
                    "https://insecure.invalid/a.js".to_string(),
                    UpgradeReason::MixedContent
                )]
            );
            assert!(rec.warnings().is_empty(), "{:?}", rec.warnings());
            let names = stream(&rec);
            let redirected = names.iter().position(|n| n == "Redirected").unwrap();
            assert_eq!(names[redirected + 1], "SecurityUpgraded", "{names:?}");
        }

        /// Credentials in the initial URL: reported once, right after `Started`, against the
        /// URL without them. No warning.
        #[tokio::test(flavor = "current_thread")]
        async fn url_credentials_on_the_initial_url() {
            let srv = TestServer::new()
                .route("/", RouteConfig::ok(b"x"))
                .start()
                .await;
            let mut url = srv.url("/");
            url.set_username("user").unwrap();
            url.set_password(Some("pw")).unwrap();
            let rec = recorded(
                client(),
                url,
                RequestInit::get(HeaderMap::new()),
                NetPolicy::default(),
            )
            .await;

            assert_eq!(
                rec.modifications(),
                vec![(
                    srv.url("/").to_string(),
                    RequestChange::UrlCredentialsRemoved
                )]
            );
            assert!(rec.warnings().is_empty(), "{:?}", rec.warnings());
            assert_eq!(
                stream(&rec)[..3],
                ["Started", "RequestModified", "RequestSent"]
            );
        }

        /// Credentials in a same-origin `Location`: reported after the `Redirected`, against
        /// the target.
        #[tokio::test(flavor = "current_thread")]
        async fn url_credentials_on_a_location() {
            let srv = TestServer::new()
                .route(
                    "/hop",
                    RouteConfig::redirect_to_with_credentials("user:pw", "/end"),
                )
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let rec = recorded(
                client(),
                srv.url("/hop"),
                RequestInit::get(HeaderMap::new()),
                NetPolicy::default(),
            )
            .await;

            assert_eq!(
                rec.modifications(),
                vec![(
                    srv.url("/end").to_string(),
                    RequestChange::UrlCredentialsRemoved
                )]
            );
            let names = stream(&rec);
            let redirected = names.iter().position(|n| n == "Redirected").unwrap();
            assert_eq!(names[redirected + 1], "RequestModified", "{names:?}");
        }

        /// The default policy sends a cross-origin target the bare origin. Reported for each
        /// hop, before that hop's request.
        #[tokio::test(flavor = "current_thread")]
        async fn referrer_reduced_on_each_hop() {
            let srv = TestServer::new()
                .route("/hop", RouteConfig::redirect_to("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let init = RequestInit::get(HeaderMap::new()).with_referrer(
                Some(Url::parse("https://example.com/page?q=1#frag").unwrap()),
                ReferrerPolicy::default(),
            );
            let rec = recorded(client(), srv.url("/hop"), init, NetPolicy::default()).await;

            let change = RequestChange::ReferrerReduced {
                from: Url::parse("https://example.com/page?q=1").unwrap(),
                to: Some(Url::parse("https://example.com/").unwrap()),
                policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            };
            assert_eq!(
                rec.modifications(),
                vec![
                    (srv.url("/hop").to_string(), change.clone()),
                    (srv.url("/end").to_string(), change)
                ]
            );
            assert_eq!(
                stream(&rec),
                [
                    "Started",
                    "RequestModified",
                    "RequestSent",
                    "ResponseHeaders",
                    "Redirected",
                    "RequestModified",
                    "RequestSent",
                    "ResponseHeaders",
                    "Finished"
                ]
            );
        }

        /// `no-referrer` sends nothing, reported as `to: None`.
        #[tokio::test(flavor = "current_thread")]
        async fn referrer_suppressed() {
            let srv = TestServer::new()
                .route("/", RouteConfig::ok(b"x"))
                .start()
                .await;
            let referrer = srv.url("/page");
            let init = RequestInit::get(HeaderMap::new())
                .with_referrer(Some(referrer.clone()), ReferrerPolicy::NoReferrer);
            let rec = recorded(client(), srv.url("/"), init, NetPolicy::default()).await;

            assert_eq!(
                changes(&rec),
                vec![RequestChange::ReferrerReduced {
                    from: referrer,
                    to: None,
                    policy: ReferrerPolicy::NoReferrer,
                }]
            );
        }

        /// The chain goes home, away, home, home. The second hop taints the chain, and `Origin` is
        /// `null` from there on. Reported once, on the first hop that sends the `null`.
        #[tokio::test(flavor = "current_thread")]
        async fn origin_tainted_once_per_chain() {
            let home = TestServer::new()
                .route("/again", RouteConfig::redirect_to("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let away = TestServer::new()
                .route(
                    "/hop",
                    RouteConfig::redirect_absolute(home.url("/again").as_str()),
                )
                .start()
                .await;
            let init = RequestInit::get(HeaderMap::new())
                .with_fetch_metadata(RequestDestination::Empty, RequestMode::Websocket, false)
                .with_mixed_content(
                    Some(home.base_url().origin()),
                    MixedContentPolicy::default(),
                );
            let rec = recorded(client(), away.url("/hop"), init, NetPolicy::default()).await;

            assert_eq!(
                rec.modifications(),
                vec![(home.url("/again").to_string(), RequestChange::OriginTainted)]
            );
            let origins: Vec<_> = rec
                .requests_sent()
                .iter()
                .map(|(_, _, h)| h.get(header::ORIGIN).cloned())
                .collect();
            assert_eq!(origins.len(), 3);
            assert_eq!(origins[1].as_ref().unwrap(), "null");
            assert_eq!(origins[2].as_ref().unwrap(), "null");
        }

        /// A POST under `no-referrer` sends `Origin: null`. Reported with the policy.
        #[tokio::test(flavor = "current_thread")]
        async fn origin_hidden_by_the_referrer_policy() {
            let srv = TestServer::new()
                .route("/", RouteConfig::ok(b"x"))
                .start()
                .await;
            let init = RequestInit::post(HeaderMap::new(), b"x".to_vec())
                .with_referrer(None, ReferrerPolicy::NoReferrer)
                .with_mixed_content(Some(srv.base_url().origin()), MixedContentPolicy::default());
            let rec = recorded(client(), srv.url("/"), init, NetPolicy::default()).await;

            assert_eq!(
                changes(&rec),
                vec![RequestChange::OriginHidden {
                    policy: ReferrerPolicy::NoReferrer
                }]
            );
        }

        /// An opaque initiator has no serialisation other than `null`. Nothing is hidden.
        #[tokio::test(flavor = "current_thread")]
        async fn an_opaque_origin_is_not_reported() {
            let srv = TestServer::new()
                .route("/", RouteConfig::ok(b"x"))
                .start()
                .await;
            let opaque = Url::parse("data:text/html,x").unwrap().origin();
            let init = RequestInit::post(HeaderMap::new(), b"x".to_vec())
                .with_mixed_content(Some(opaque), MixedContentPolicy::default());
            let rec = recorded(client(), srv.url("/"), init, NetPolicy::default()).await;
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
        }

        /// `same-origin` credentials on a cross-origin hop. The jar is not asked, and the
        /// hop reports it. `omit` asked for that on every hop and reports nothing.
        #[tokio::test(flavor = "current_thread")]
        async fn credentials_withheld_from_a_cross_origin_hop() {
            let srv = TestServer::new()
                .route("/", RouteConfig::echo_cookie_header())
                .start()
                .await;
            let jar = || NetPolicy {
                cookies_for: Box::new(|_| Some("session=1".into())),
                ..NetPolicy::default()
            };
            let other = Some(Url::parse("http://other.example/").unwrap().origin());

            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(other.clone(), MixedContentPolicy::default())
                .with_credentials(RequestCredentials::SameOrigin);
            let rec = recorded(client(), srv.url("/"), init, jar()).await;
            assert_eq!(
                rec.modifications(),
                vec![(srv.url("/").to_string(), RequestChange::CredentialsWithheld)]
            );
            assert_eq!(rec.requests_sent()[0].2.get(header::COOKIE), None);

            let init = RequestInit::get(HeaderMap::new())
                .with_mixed_content(other, MixedContentPolicy::default())
                .with_credentials(RequestCredentials::Omit);
            let rec = recorded(client(), srv.url("/"), init, jar()).await;
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
        }

        /// A cross-origin redirect drops the caller's `Authorization`, `Cookie`, `Referer` and
        /// `Proxy-Authorization`. Reported once, after the `Redirected`, listing only what was
        /// there.
        #[tokio::test(flavor = "current_thread")]
        async fn sensitive_headers_stripped_on_a_cross_origin_redirect() {
            let away = TestServer::new()
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let home = TestServer::new()
                .route(
                    "/cross",
                    RouteConfig::redirect_absolute(away.url("/end").as_str()),
                )
                .route("/same", RouteConfig::redirect_to("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let headers = || {
                let mut h = HeaderMap::new();
                h.insert(header::AUTHORIZATION, "Bearer t".parse().unwrap());
                h.insert(header::COOKIE, "a=1".parse().unwrap());
                h.insert(header::REFERER, "http://example.com/".parse().unwrap());
                h.insert(
                    header::PROXY_AUTHORIZATION,
                    "Basic Ym9iOnMz".parse().unwrap(),
                );
                h
            };

            let rec = recorded(
                client(),
                home.url("/cross"),
                RequestInit::get(headers()),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(
                rec.modifications(),
                vec![(
                    away.url("/end").to_string(),
                    RequestChange::SensitiveHeadersStripped {
                        headers: vec![
                            header::AUTHORIZATION,
                            header::COOKIE,
                            header::REFERER,
                            header::PROXY_AUTHORIZATION,
                        ],
                    }
                )]
            );
            let last = rec.requests_sent().pop().unwrap();
            assert_eq!(last.2.get(header::PROXY_AUTHORIZATION), None);
            let names = stream(&rec);
            let redirected = names.iter().position(|n| n == "Redirected").unwrap();
            assert_eq!(names[redirected + 1], "RequestModified", "{names:?}");

            let rec = recorded(
                client(),
                home.url("/same"),
                RequestInit::get(headers()),
                NetPolicy::default(),
            )
            .await;
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
        }

        /// Cookies from the jar and a computed `Referer` are put back for the next hop, so
        /// stripping them changes nothing the caller asked for.
        #[tokio::test(flavor = "current_thread")]
        async fn recomputed_headers_are_not_reported_as_stripped() {
            let away = TestServer::new()
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;
            let home = TestServer::new()
                .route(
                    "/cross",
                    RouteConfig::redirect_absolute(away.url("/end").as_str()),
                )
                .start()
                .await;
            let policy = NetPolicy {
                cookies_for: Box::new(|_| Some("session=1".into())),
                ..NetPolicy::default()
            };
            let init = RequestInit::get(HeaderMap::new())
                .with_referrer(Some(home.url("/page")), ReferrerPolicy::UnsafeUrl);
            let rec = recorded(client(), home.url("/cross"), init, policy).await;
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
            let sent = rec.requests_sent();
            assert_eq!(sent[1].2.get(header::COOKIE).unwrap(), "session=1");
        }

        /// A 302 turns a POST into a GET and drops the body. A 307 keeps both.
        #[tokio::test(flavor = "current_thread")]
        async fn method_downgraded_by_a_redirect() {
            let srv = TestServer::new()
                .route("/302", RouteConfig::redirect_to("/end"))
                .route("/307", RouteConfig::redirect_307("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;

            let rec = recorded(
                client(),
                srv.url("/302"),
                RequestInit::post(HeaderMap::new(), b"a=1".to_vec()),
                NetPolicy::default(),
            )
            .await;
            assert_eq!(
                rec.modifications(),
                vec![(
                    srv.url("/end").to_string(),
                    RequestChange::MethodDowngraded {
                        from: Method::POST,
                        to: Method::GET,
                    }
                )]
            );

            let rec = recorded(
                client(),
                srv.url("/307"),
                RequestInit::post(HeaderMap::new(), b"a=1".to_vec()),
                NetPolicy::default(),
            )
            .await;
            assert!(rec.modifications().is_empty(), "{:?}", rec.modifications());
        }

        /// The cookie hook sees each hop's method as the hop sends it, and the chain before it:
        /// a 307 keeps the POST, the 302 after it turns it into a GET.
        #[tokio::test(flavor = "current_thread")]
        async fn the_cookie_hook_sees_each_hops_method_and_chain() {
            let srv = TestServer::new()
                .route("/307", RouteConfig::redirect_307("/302"))
                .route("/302", RouteConfig::redirect_to("/end"))
                .route("/end", RouteConfig::ok(b"x"))
                .start()
                .await;

            type Seen = Vec<(Method, String, Vec<String>)>;
            let seen: Arc<std::sync::Mutex<Seen>> = Arc::default();
            let record = seen.clone();
            let policy = NetPolicy {
                cookies_for: Box::new(move |hop| {
                    let paths = hop.url_list.iter().map(|u| u.path().to_string()).collect();
                    record.lock().unwrap().push((
                        hop.method.clone(),
                        hop.url.path().to_string(),
                        paths,
                    ));
                    None
                }),
                ..NetPolicy::default()
            };
            recorded(
                client(),
                srv.url("/307"),
                RequestInit::post(HeaderMap::new(), b"a=1".to_vec()),
                policy,
            )
            .await;

            let path = |p: &str| p.to_string();
            assert_eq!(
                *seen.lock().unwrap(),
                vec![
                    (Method::POST, path("/307"), vec![]),
                    (Method::POST, path("/302"), vec![path("/307")]),
                    (Method::GET, path("/end"), vec![path("/307"), path("/302")]),
                ]
            );
        }

        /// A refused hop is a `Blocked`, not an upgrade or a change.
        #[tokio::test(flavor = "current_thread")]
        async fn a_blocked_hop_is_not_a_change() {
            let init = RequestInit::get(HeaderMap::new()).with_mixed_content(
                Some(Url::parse("https://example.com").unwrap().origin()),
                MixedContentPolicy::Block,
            );
            let rec = recorded(
                client(),
                Url::parse("http://insecure.example.com/a.js").unwrap(),
                init,
                NetPolicy::default(),
            )
            .await;
            assert_eq!(rec.blocked_reason(), Some(BlockReason::MixedContent));
            assert!(rec.upgrades().is_empty());
            assert!(rec.modifications().is_empty());
        }

        #[test]
        fn display() {
            assert_eq!(UpgradeReason::Hsts.to_string(), "HSTS");
            assert_eq!(UpgradeReason::MixedContent.to_string(), "mixed content");
            let u = |s: &str| Url::parse(s).unwrap();
            let cases = [
                (
                    RequestChange::UrlCredentialsRemoved,
                    "removed credentials from the URL",
                ),
                (
                    RequestChange::ReferrerReduced {
                        from: u("https://a.example/p"),
                        to: Some(u("https://a.example/")),
                        policy: ReferrerPolicy::StrictOrigin,
                    },
                    "referrer https://a.example/p reduced to https://a.example/ by strict-origin",
                ),
                (
                    RequestChange::ReferrerReduced {
                        from: u("https://a.example/p"),
                        to: None,
                        policy: ReferrerPolicy::NoReferrer,
                    },
                    "referrer https://a.example/p suppressed by no-referrer",
                ),
                (
                    RequestChange::OriginTainted,
                    "origin sent as null after a redirect",
                ),
                (
                    RequestChange::OriginHidden {
                        policy: ReferrerPolicy::SameOrigin,
                    },
                    "origin sent as null by same-origin",
                ),
                (
                    RequestChange::CredentialsWithheld,
                    "credentials withheld from a cross-origin hop",
                ),
                (
                    RequestChange::SensitiveHeadersStripped {
                        headers: vec![header::AUTHORIZATION, header::COOKIE],
                    },
                    "stripped headers on a cross-origin redirect: authorization cookie",
                ),
                (
                    RequestChange::MethodDowngraded {
                        from: Method::POST,
                        to: Method::GET,
                    },
                    "method changed from POST to GET by a redirect",
                ),
            ];
            for (change, text) in cases {
                assert_eq!(change.to_string(), text);
            }
        }
    }
}

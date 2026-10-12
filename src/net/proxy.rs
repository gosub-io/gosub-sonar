//! Programmatic proxy configuration for the [`Fetcher`].
//!
//! Without configuration the fetcher reads the `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` /
//! `NO_PROXY` environment variables -- see [`ProxyConfig::System`]. An embedder that has its own proxy settings (a browser's network
//! preferences, a PAC-derived result, a per-profile override) sets
//! [`FetcherConfig::proxy`] instead, which takes the environment out of the picture entirely.
//!
//! ```no_run
//! use gosub_sonar::{FetcherConfig, ProxyConfig, ProxyRule};
//!
//! let cfg = FetcherConfig {
//!     proxy: ProxyConfig::Rules(vec![
//!         ProxyRule::all("http://proxy.corp:8080")
//!             .with_basic_auth("alice", "hunter2")
//!             .bypassing("localhost, 10.0.0.0/8, .internal.corp"),
//!     ]),
//!     ..FetcherConfig::default()
//! };
//! ```
//!
//! Native-only: on `wasm32` the browser's `fetch()` applies the user's own proxy settings and
//! offers no way to override them, so this module is not compiled there.
//!
//! [`Fetcher`]: crate::net::fetcher::Fetcher
//! [`FetcherConfig::proxy`]: crate::net::fetcher::FetcherConfig::proxy

use anyhow::Context;
use hyper_util::client::proxy::matcher as proxy_matcher;
use url::Url;

/// Which request URLs a [`ProxyRule`] applies to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum ProxyScope {
    /// Only `http://` request URLs.
    Http,
    /// Only `https://` request URLs. Requests are tunnelled through the proxy with `CONNECT`.
    Https,
    /// Every request URL, whatever its scheme. The default.
    #[default]
    All,
}

/// Credentials presented to the proxy itself, sent as `Proxy-Authorization`.
///
/// This is separate from any authentication the *origin server* asks for. Credentials embedded
/// in the proxy URL (`http://user:pass@proxy:8080`) work too, but anything needing escaping is
/// easier to get right here.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProxyAuth {
    /// `Proxy-Authorization: Basic <base64(username:password)>`.
    Basic {
        /// Username presented to the proxy.
        username: String,
        /// Password presented to the proxy.
        password: String,
    },
    /// A verbatim `Proxy-Authorization` header value, for schemes other than Basic
    /// (e.g. `"Bearer <token>"`). Rejected at [`Fetcher::new`](crate::net::fetcher::Fetcher::new)
    /// if it is not a valid header value.
    Custom(String),
}

/// One proxy: where it lives, which requests go through it, and which hosts bypass it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProxyRule {
    /// Which request URLs this rule applies to.
    pub scope: ProxyScope,
    /// The proxy's own URL, e.g. `http://proxy.corp:8080`. `http` and `https` proxies are always
    /// supported; `socks4`, `socks5`, and `socks5h` need the crate's `socks` feature. An
    /// unparseable or unsupported URL is reported by
    /// [`Fetcher::new`](crate::net::fetcher::Fetcher::new).
    pub url: String,
    /// Credentials for the proxy, if it demands any.
    pub auth: Option<ProxyAuth>,
    /// Hosts that bypass this proxy, in `NO_PROXY` syntax: comma-separated entries, each a
    /// domain (matching that domain and its subdomains), an IP address, a CIDR block, or `*` for
    /// everything. An IPv6 address may be in brackets (`[::1]`), a domain may end in a dot, and
    /// an entry may name a port (`localhost:8080`, `[::1]:8080`) to bypass that port only.
    /// `None` sends every in-scope request through the proxy — note that this does
    /// *not* fall back to the `NO_PROXY` environment variable, since configuring a rule
    /// programmatically opts out of the environment entirely.
    pub no_proxy: Option<String>,
}

impl ProxyRule {
    /// A rule routing every request through `url`, whatever the scheme.
    pub fn all(url: impl Into<String>) -> Self {
        Self::new(ProxyScope::All, url)
    }

    /// A rule routing `http://` requests through `url`.
    pub fn http(url: impl Into<String>) -> Self {
        Self::new(ProxyScope::Http, url)
    }

    /// A rule routing `https://` requests through `url`.
    pub fn https(url: impl Into<String>) -> Self {
        Self::new(ProxyScope::Https, url)
    }

    /// A rule with an explicit scope, no credentials, and no bypass list.
    pub fn new(scope: ProxyScope, url: impl Into<String>) -> Self {
        Self {
            scope,
            url: url.into(),
            auth: None,
            no_proxy: None,
        }
    }

    /// Present `username` / `password` to the proxy via `Proxy-Authorization: Basic`.
    #[must_use]
    pub fn with_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.auth = Some(ProxyAuth::Basic {
            username: username.into(),
            password: password.into(),
        });
        self
    }

    /// Present a verbatim `Proxy-Authorization` header value, e.g. `"Bearer <token>"`.
    #[must_use]
    pub fn with_custom_auth(mut self, header_value: impl Into<String>) -> Self {
        self.auth = Some(ProxyAuth::Custom(header_value.into()));
        self
    }

    /// Exempt hosts from this proxy, in `NO_PROXY` syntax — see [`ProxyRule::no_proxy`].
    #[must_use]
    pub fn bypassing(mut self, no_proxy: impl Into<String>) -> Self {
        self.no_proxy = Some(no_proxy.into());
        self
    }

    /// Translate into a `reqwest::Proxy`, failing on an unusable proxy URL or auth header.
    fn to_reqwest(&self) -> anyhow::Result<reqwest::Proxy> {
        // reqwest accepts a socks URL whether or not its own `socks` feature is on, and without
        // it quietly falls back to speaking HTTP at the socks port — a connect-time failure with
        // nothing pointing at the cause. Reject it here, while there is still a URL to name.
        #[cfg(not(feature = "socks"))]
        {
            let scheme = self
                .url
                .split("://")
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            anyhow::ensure!(
                !matches!(scheme.as_str(), "socks4" | "socks4a" | "socks5" | "socks5h"),
                "proxy URL {:?} needs the `socks` cargo feature",
                self.url
            );
        }

        // A bypass entry with a port is beyond the matcher, which only knows hosts: such a rule
        // decides per request itself, with the same answer `intercept_any` gives.
        let mut proxy = if self.port_entries().is_empty() {
            match self.scope {
                ProxyScope::Http => reqwest::Proxy::http(&self.url),
                ProxyScope::Https => reqwest::Proxy::https(&self.url),
                ProxyScope::All => reqwest::Proxy::all(&self.url),
            }
            .with_context(|| format!("unusable proxy URL {:?}", self.url))?
        } else {
            let proxy_url = Url::parse(&self.url)
                .with_context(|| format!("unusable proxy URL {:?}", self.url))?;
            let rule = self.clone();
            reqwest::Proxy::custom(move |url: &Url| {
                let dst: http::Uri = url.as_str().parse().ok()?;
                rule.intercept_any(proxy_url.clone(), &dst)
                    .map(|_| proxy_url.clone())
            })
        };

        match self.auth {
            // `basic_auth` puts the pair in the proxy URL, which the matcher percent-decodes, so
            // it goes in encoded. A rule with a port entry is matched by a closure instead, and
            // reqwest encodes the pair into the header as given.
            Some(ProxyAuth::Basic {
                ref username,
                ref password,
            }) => {
                proxy = if self.port_entries().is_empty() {
                    proxy.basic_auth(&userinfo_encoded(username), &userinfo_encoded(password))
                } else {
                    proxy.basic_auth(username, password)
                }
            }
            Some(ProxyAuth::Custom(ref value)) => {
                let header = value.parse().with_context(|| {
                    format!("proxy {:?}: invalid Proxy-Authorization value", self.url)
                })?;
                proxy = proxy.custom_http_auth(header);
            }
            None => {}
        }

        if let Some(list) = self.bypass_list() {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(&list));
        }

        Ok(proxy)
    }

    /// The `Proxy-Authorization` this rule would put on a plain-`http` request to `dst`, or
    /// `None` when the rule does not apply to it or carries no credentials.
    ///
    /// Matched with `hyper_util`'s proxy matcher, built exactly as `reqwest::Proxy` builds it,
    /// rather than by re-deciding scope and `no_proxy` here: the answer has to be the client's
    /// answer, and a second implementation of CIDR and domain-suffix matching would be a second
    /// chance to disagree with it. Getting it wrong does not merely misreport a header -- it
    /// sends credentials to a host that was never meant to see them.
    fn non_tunnel_authorization(&self, dst: &http::Uri) -> Option<http::HeaderValue> {
        let auth = self.auth.as_ref()?;

        let mut proxy_url = Url::parse(&self.url).ok()?;
        if let ProxyAuth::Basic {
            ref username,
            ref password,
        } = *auth
        {
            // Where `reqwest::Proxy::basic_auth` puts them, encoded as `to_reqwest` encodes
            // them, so the matcher derives the same header from the same place.
            proxy_url.set_username(&userinfo_encoded(username)).ok()?;
            proxy_url
                .set_password(Some(&userinfo_encoded(password)))
                .ok()?;
        }

        let intercept = self.intercept(proxy_url, dst)?;
        match *auth {
            ProxyAuth::Basic { .. } => intercept.basic_auth().cloned(),
            ProxyAuth::Custom(ref value) => value.parse().ok(),
        }
    }

    /// The http(s) proxy this rule routes a plain-`http` request to `dst` through, without
    /// credentials; `None` if the rule does not apply or names a socks proxy.
    fn non_tunnel_proxy(&self, dst: &http::Uri) -> Option<Url> {
        let proxy_url = Url::parse(&self.url).ok()?;
        let intercept = self.intercept(proxy_url, dst)?;
        let mut proxy = Url::parse(&intercept.uri().to_string()).ok()?;
        let _ = proxy.set_username("");
        let _ = proxy.set_password(None);
        Some(proxy)
    }

    /// Match `dst` with `hyper_util`'s matcher, as `reqwest::Proxy` does. Socks proxies are
    /// filtered out: they authenticate in their own handshake and send no header.
    fn intercept(&self, proxy_url: Url, dst: &http::Uri) -> Option<proxy_matcher::Intercept> {
        let intercept = self.intercept_any(proxy_url, dst)?;
        matches!(intercept.uri().scheme_str(), Some("http") | Some("https")).then_some(intercept)
    }

    /// Whether this rule sends a request to `dst` through its proxy, of any kind.
    fn routes(&self, dst: &http::Uri) -> bool {
        Url::parse(&self.url)
            .ok()
            .and_then(|proxy_url| self.intercept_any(proxy_url, dst))
            .is_some()
    }

    /// [`intercept`](Self::intercept) without the filter: socks proxies match too.
    fn intercept_any(&self, proxy_url: Url, dst: &http::Uri) -> Option<proxy_matcher::Intercept> {
        if self.bypassed_by_port(dst) {
            return None;
        }
        let builder = proxy_matcher::Matcher::builder();
        let builder = match self.scope {
            ProxyScope::Http => builder.http(proxy_url.to_string()),
            ProxyScope::Https => builder.https(proxy_url.to_string()),
            ProxyScope::All => builder.all(proxy_url.to_string()),
        };
        builder
            .no(self.bypass_list().unwrap_or_default())
            .build()
            .intercept(dst)
    }

    /// The bypass list as the matcher is given it, by the client and by this module alike, so
    /// the two cannot disagree. Entries are read the way other tools write them:
    ///
    /// - `*` is spelled out to also cover IP addresses: the matcher checks an IP host against IP
    ///   entries only, so a bare `*` let `http://127.0.0.1/` through the proxy though it is
    ///   documented, and curl's `NO_PROXY` has it, as everything.
    /// - an IPv6 address may come in brackets, as in a URL: `[::1]`.
    /// - a name may end in a dot, and covers the name with or without one.
    /// - an entry with a port (`localhost:8080`, `[::1]:8080`) is left out here and checked by
    ///   [`bypassed_by_port`](Self::bypassed_by_port): it bypasses that port only.
    fn bypass_list(&self) -> Option<String> {
        let list = self.no_proxy.as_ref()?;
        let mut entries: Vec<String> = Vec::new();
        for entry in bypass_entries(list) {
            match entry {
                BypassEntry::Everything => {
                    entries.extend(["*", "0.0.0.0/0", "::/0"].map(String::from))
                }
                BypassEntry::Host { host, port: None } => {
                    if host.parse::<std::net::IpAddr>().is_err() {
                        entries.push(format!("{host}."));
                    }
                    entries.push(host);
                }
                BypassEntry::Host { port: Some(_), .. } => {}
                BypassEntry::Verbatim(entry) => entries.push(entry),
            }
        }
        Some(entries.join(","))
    }

    /// The bypass entries that name a port.
    fn port_entries(&self) -> Vec<(String, u16)> {
        self.no_proxy
            .as_deref()
            .map(bypass_entries)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| match entry {
                BypassEntry::Host {
                    host,
                    port: Some(port),
                } => Some((host, port)),
                _ => None,
            })
            .collect()
    }

    /// Whether `dst` is exempt through an entry with a port: the same host, or a subdomain of
    /// it, on that port. A request without a port has its scheme's.
    fn bypassed_by_port(&self, dst: &http::Uri) -> bool {
        let Some(host) = dst.host() else {
            return false;
        };
        let host = normalize_host(host);
        let port = dst.port_u16().unwrap_or(match dst.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
        self.port_entries().iter().any(|(entry, entry_port)| {
            *entry_port == port && {
                let entry = entry.trim_start_matches('.');
                host == entry || host.ends_with(&format!(".{entry}"))
            }
        })
    }
}

/// One entry of a bypass list.
enum BypassEntry {
    /// `*`.
    Everything,
    /// A name or an IP address, without brackets or a trailing dot, perhaps with a port.
    Host { host: String, port: Option<u16> },
    /// Anything else, such as a CIDR block, handed to the matcher as written.
    Verbatim(String),
}

/// Split a `NO_PROXY`-style list into its entries.
fn bypass_entries(list: &str) -> Vec<BypassEntry> {
    list.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|entry| {
            if entry == "*" {
                return BypassEntry::Everything;
            }
            if entry.contains('/') {
                return BypassEntry::Verbatim(entry.to_string());
            }
            // `[v6]` or `[v6]:port`.
            if let Some(rest) = entry.strip_prefix('[') {
                if let Some((host, after)) = rest.split_once(']') {
                    let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
                    return BypassEntry::Host {
                        host: normalize_host(host),
                        port,
                    };
                }
            }
            // `host:port`; a bare IPv6 address has more than one colon and no port.
            if let Some((host, port)) = entry.split_once(':') {
                if !host.contains(':') && !port.contains(':') {
                    if let Ok(port) = port.parse() {
                        return BypassEntry::Host {
                            host: normalize_host(host),
                            port: Some(port),
                        };
                    }
                }
            }
            BypassEntry::Host {
                host: normalize_host(entry),
                port: None,
            }
        })
        .collect()
}

/// `s` percent-encoded for the userinfo of a URL, every byte but the unreserved ones (RFC 3986
/// §2.3), so that decoding it gives `s` back whatever it contains, a `%` included.
fn userinfo_encoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A host as entries and requests are compared: lowercase, without IPv6 brackets or a trailing
/// dot.
fn normalize_host(host: &str) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// How the fetcher chooses a proxy for outgoing requests.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub enum ProxyConfig {
    /// Take the proxy from the environment: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and the
    /// `NO_PROXY` bypass list. The default.
    ///
    /// Each is read as the rules of [`ProxyConfig::Rules`] would be written: `HTTP_PROXY` an
    /// [`ProxyRule::http`], `HTTPS_PROXY` an [`ProxyRule::https`], `ALL_PROXY` an
    /// [`ProxyRule::all`] for whatever the other two leave, each bypassing `NO_PROXY` in the
    /// syntax [`ProxyRule::no_proxy`] describes. The uppercase name wins over the lowercase
    /// one, an empty value counts as unset, and a value without a scheme is an `http` proxy. An
    /// unusable value is skipped with a warning rather than failing the fetcher.
    ///
    /// Under CGI (`REQUEST_METHOD` is set) the environment is ignored and every request goes
    /// direct: a CGI server passes a request's `Proxy` header to its program as `HTTP_PROXY`,
    /// so the client of that server would choose it (httpoxy, CVE-2016-5385).
    ///
    /// When no variable names a proxy, the operating system's settings are used where there
    /// are any (macOS, Windows), as reqwest reads them.
    ///
    /// The environment is read once, when the [`Fetcher`](crate::net::fetcher::Fetcher) is
    /// built.
    #[default]
    System,
    /// Send every request directly, ignoring the environment variables.
    Disabled,
    /// Use exactly these rules and nothing from the environment. Each request URL is matched
    /// against the rules in order and takes the first whose scope matches and whose bypass list
    /// does not exempt it; an empty list therefore behaves like [`ProxyConfig::Disabled`].
    Rules(Vec<ProxyRule>),
}

impl ProxyConfig {
    /// A single proxy for all schemes, with no bypass list — the common case.
    pub fn single(url: impl Into<String>) -> Self {
        ProxyConfig::Rules(vec![ProxyRule::all(url)])
    }

    /// Apply this configuration to a client builder, reading the environment now for
    /// [`ProxyConfig::System`].
    pub(crate) fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> anyhow::Result<reqwest::ClientBuilder> {
        ProxyRoutes::resolve(self).apply(builder)
    }
}

/// The rules [`ProxyConfig::System`] reads from the environment through `var`, or `None` when
/// no variable names a proxy. See [`ProxyConfig::System`] for how each is read.
fn env_rules(var: &dyn Fn(&str) -> Option<String>) -> Option<Vec<ProxyRule>> {
    let first = |names: &[&str]| {
        names
            .iter()
            .filter_map(|name| var(name))
            .map(|value| value.trim().to_string())
            .find(|value| !value.is_empty())
    };
    if var("REQUEST_METHOD").is_some() {
        return Some(Vec::new());
    }
    let http = first(&["HTTP_PROXY", "http_proxy"]);
    let https = first(&["HTTPS_PROXY", "https_proxy"]);
    let all = first(&["ALL_PROXY", "all_proxy"]);
    if http.is_none() && https.is_none() && all.is_none() {
        return None;
    }
    let no_proxy = first(&["NO_PROXY", "no_proxy"]);
    let with_scheme = |url: String| {
        if url.contains("://") {
            url
        } else {
            format!("http://{url}")
        }
    };
    let rules = [
        (ProxyScope::Http, http),
        (ProxyScope::Https, https),
        (ProxyScope::All, all),
    ]
    .into_iter()
    .filter_map(|(scope, url)| {
        let rule = ProxyRule {
            no_proxy: no_proxy.clone(),
            ..ProxyRule::new(scope, with_scheme(url?))
        };
        match rule.to_reqwest() {
            Ok(_) => Some(rule),
            Err(e) => {
                log::warn!("ignoring the proxy from the environment: {e:#}");
                None
            }
        }
    })
    .collect();
    Some(rules)
}

/// A [`ProxyConfig`] resolved once, with the environment read for [`ProxyConfig::System`].
/// The client is built from it and requests are judged by it, so the two cannot disagree;
/// asking the environment again per request would answer for settings the client never saw.
pub(crate) enum ProxyRoutes {
    /// No variable named a proxy: the operating system's settings, as hyper-util reads them for
    /// reqwest (macOS, Windows; nothing elsewhere).
    System(Box<proxy_matcher::Matcher>),
    Disabled,
    Rules(Vec<ProxyRule>),
}

impl ProxyRoutes {
    /// Resolve `config`, reading the environment now for [`ProxyConfig::System`].
    pub(crate) fn resolve(config: &ProxyConfig) -> Self {
        match config {
            ProxyConfig::System => match env_rules(&|name| std::env::var(name).ok()) {
                Some(rules) => ProxyRoutes::Rules(rules),
                None => ProxyRoutes::System(Box::new(proxy_matcher::Matcher::from_system())),
            },
            ProxyConfig::Disabled => ProxyRoutes::Disabled,
            ProxyConfig::Rules(rules) => ProxyRoutes::Rules(rules.clone()),
        }
    }

    /// Apply these routes to a client builder.
    ///
    /// [`ProxyRoutes::System`] leaves the builder as it is: reqwest reads the same operating
    /// system settings itself. The others clear it first so nothing else is appended to them.
    pub(crate) fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> anyhow::Result<reqwest::ClientBuilder> {
        match self {
            ProxyRoutes::System(_) => Ok(builder),
            ProxyRoutes::Disabled => Ok(builder.no_proxy()),
            ProxyRoutes::Rules(rules) => {
                // `no_proxy()` first: with an empty `rules` nothing else would switch the
                // client's own environment lookup off.
                let mut builder = builder.no_proxy();
                for rule in rules {
                    builder = builder.proxy(rule.to_reqwest()?);
                }
                Ok(builder)
            }
        }
    }

    /// The `Proxy-Authorization` the HTTP client will attach to a request for `url`, so that
    /// [`NetEvent::RequestSent`](crate::net::events::NetEvent::RequestSent) reports a header
    /// this crate would otherwise only watch the client add.
    ///
    /// Answers only for an `http` URL, and only for rules:
    ///
    /// - An `https` request is tunnelled, and the client puts the credentials on the `CONNECT`
    ///   request instead. That is a separate exchange no observer sees, and it carries no
    ///   header on the request this reports.
    /// - The operating system's settings are the client's to read.
    ///
    /// The rule that answers is the first one that routes the request, the one whose proxy the
    /// client connects through, and its credentials or none at all: credentials belong to the
    /// proxy that demanded them (RFC 9110 §11.7.2), so a later rule's never go to an earlier
    /// rule's proxy. When that first rule is a socks proxy, the next HTTP recipient is the
    /// origin server, and nothing is sent. The header is written into the request before the
    /// client sees it, and the client then leaves it alone ([reqwest `Client::proxy_auth`]), so
    /// this choice is the one that reaches the wire.
    ///
    /// [reqwest `Client::proxy_auth`]: https://docs.rs/reqwest/0.13.5/src/reqwest/async_impl/client.rs.html
    pub(crate) fn proxy_authorization(&self, url: &Url) -> Option<http::HeaderValue> {
        if url.scheme() != "http" {
            return None;
        }
        let ProxyRoutes::Rules(ref rules) = *self else {
            return None;
        };
        let dst: http::Uri = url.as_str().parse().ok()?;
        rules
            .iter()
            .find(|rule| rule.routes(&dst))?
            .non_tunnel_authorization(&dst)
    }

    /// The http(s) proxy a plain-`http` request to `url` goes through, without credentials;
    /// `None` for https (tunnelled via CONNECT, so no 407 response can come from the proxy),
    /// direct, or socks. Decides whether a 407 counts as a proxy challenge. Only the first rule
    /// that routes the request counts, as for the client: when it is a socks proxy, the 407
    /// came from the origin server behind it.
    pub(crate) fn plain_http_proxy(&self, url: &Url) -> Option<Url> {
        if url.scheme() != "http" {
            return None;
        }
        let dst: http::Uri = url.as_str().parse().ok()?;
        match *self {
            ProxyRoutes::Rules(ref rules) => rules
                .iter()
                .find(|rule| rule.routes(&dst))?
                .non_tunnel_proxy(&dst),
            ProxyRoutes::System(ref matcher) => {
                let intercept = matcher.intercept(&dst)?;
                if !matches!(intercept.uri().scheme_str(), Some("http") | Some("https")) {
                    return None;
                }
                let mut proxy = Url::parse(&intercept.uri().to_string()).ok()?;
                let _ = proxy.set_username("");
                let _ = proxy.set_password(None);
                Some(proxy)
            }
            ProxyRoutes::Disabled => None,
        }
    }

    /// Whether a request to `url` goes through a proxy (http, https or socks) rather than
    /// straight to the host. A URL the matcher cannot take counts as proxied: the answer
    /// decides whether the connection's peer is the host's address, and "unknown" must not
    /// pass for "yes".
    pub(crate) fn routes_through_proxy(&self, url: &Url) -> bool {
        let Ok(dst) = url.as_str().parse::<http::Uri>() else {
            return true;
        };
        match *self {
            ProxyRoutes::Rules(ref rules) => rules.iter().any(|rule| rule.routes(&dst)),
            ProxyRoutes::System(ref matcher) => matcher.intercept(&dst).is_some(),
            ProxyRoutes::Disabled => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind of proxy counts, socks included (a local Tor is the case that matters: its
    /// address is loopback whatever the host's is), and a bypassed host does not.
    #[test]
    fn routes_through_proxy_covers_socks_and_honours_the_bypass_list() {
        let url = |s: &str| Url::parse(s).unwrap();
        let socks = ProxyRoutes::Rules(vec![ProxyRule::all("socks5h://127.0.0.1:9050")]);
        assert!(socks.routes_through_proxy(&url("https://example.com/")));
        assert!(socks.routes_through_proxy(&url("http://example.com/")));

        let http_only = ProxyRoutes::Rules(vec![
            ProxyRule::http("http://127.0.0.1:3128").bypassing("intranet.test")
        ]);
        assert!(http_only.routes_through_proxy(&url("http://example.com/")));
        assert!(!http_only.routes_through_proxy(&url("https://example.com/")));
        assert!(!http_only.routes_through_proxy(&url("http://intranet.test/")));

        assert!(!ProxyRoutes::Disabled.routes_through_proxy(&url("http://example.com/")));
        assert!(!ProxyRoutes::Rules(vec![]).routes_through_proxy(&url("http://example.com/")));
    }

    /// `ProxyRule::no_proxy`: `*` is "for everything", as in curl's `NO_PROXY`: IP hosts too, not
    /// just names.
    #[test]
    fn a_star_bypasses_every_host_ip_addresses_included() {
        let url = |s: &str| Url::parse(s).unwrap();
        let routes =
            ProxyRoutes::Rules(vec![ProxyRule::all("http://127.0.0.1:3128").bypassing("*")]);
        for target in [
            "http://example.com/",
            "https://intranet.test/",
            "http://127.0.0.1:8080/",
            "http://10.1.2.3/",
            "http://[::1]/",
            "http://[2001:db8::1]/",
        ] {
            assert!(!routes.routes_through_proxy(&url(target)), "{target}");
        }
    }

    /// Bypass entries as other tools write them: an IPv6 address in brackets, a name with a
    /// trailing dot (and a request to one), and a host with a port, which bypasses that port only.
    #[test]
    fn bypass_entries_in_the_forms_other_tools_use() {
        let url = |s: &str| Url::parse(s).unwrap();
        let routes = |list: &str| {
            ProxyRoutes::Rules(vec![ProxyRule::all("http://127.0.0.1:3128").bypassing(list)])
        };
        let bypassed = |list: &str, target: &str| !routes(list).routes_through_proxy(&url(target));

        assert!(bypassed("[::1]", "http://[::1]/"));
        assert!(bypassed("[::1]", "http://[::1]:8080/"));
        assert!(bypassed("example.com", "http://example.com./"));
        assert!(bypassed("example.com", "http://a.example.com./"));
        assert!(bypassed("example.com.", "http://example.com/"));
        assert!(bypassed("Example.COM", "http://example.com/"));

        // A port bypasses that port only; a URL without one has its scheme's.
        assert!(bypassed("localhost:8080", "http://localhost:8080/"));
        assert!(!bypassed("localhost:8080", "http://localhost:9090/"));
        assert!(!bypassed("localhost:8080", "http://localhost/"));
        assert!(bypassed("intranet.test:443", "https://intranet.test/"));
        assert!(bypassed("intranet.test:443", "https://a.intranet.test/"));
        assert!(!bypassed("intranet.test:443", "http://intranet.test/"));
        assert!(bypassed("[::1]:8080", "http://[::1]:8080/"));
        assert!(!bypassed("[::1]:8080", "http://[::1]:9090/"));
        assert!(bypassed("10.0.0.5:8080", "http://10.0.0.5:8080/"));
        assert!(!bypassed("10.0.0.5:8080", "http://10.0.0.6:8080/"));

        // Still not a match: a name that only ends in the same letters, a CIDR, a bare IPv6.
        assert!(!bypassed("example.com", "http://notexample.com/"));
        assert!(bypassed("10.0.0.0/8", "http://10.9.9.9/"));
        assert!(bypassed("::1", "http://[::1]/"));
    }

    /// The system routes answer from the matcher they were resolved with, not from whatever
    /// the environment says by the time a request is made.
    #[test]
    fn system_routes_answer_from_their_snapshot() {
        let url = |s: &str| Url::parse(s).unwrap();
        let routes = ProxyRoutes::System(Box::new(
            proxy_matcher::Matcher::builder()
                .all("http://127.0.0.1:3128".to_string())
                .no("intranet.test".to_string())
                .build(),
        ));
        assert!(routes.routes_through_proxy(&url("https://example.com/")));
        assert!(!routes.routes_through_proxy(&url("http://intranet.test/")));
        assert_eq!(
            routes
                .plain_http_proxy(&url("http://example.com/"))
                .map(|u| u.to_string()),
            Some("http://127.0.0.1:3128/".to_string())
        );

        let direct = ProxyRoutes::System(Box::new(proxy_matcher::Matcher::builder().build()));
        assert!(!direct.routes_through_proxy(&url("https://example.com/")));
        assert_eq!(direct.plain_http_proxy(&url("http://example.com/")), None);
    }

    #[test]
    fn builders_set_scope_and_extras() {
        let rule = ProxyRule::https("http://p:8080")
            .with_basic_auth("u", "p")
            .bypassing("localhost");
        assert_eq!(rule.scope, ProxyScope::Https);
        assert_eq!(rule.url, "http://p:8080");
        assert_eq!(
            rule.auth,
            Some(ProxyAuth::Basic {
                username: "u".into(),
                password: "p".into()
            })
        );
        assert_eq!(rule.no_proxy.as_deref(), Some("localhost"));

        assert_eq!(ProxyRule::http("http://p:8080").scope, ProxyScope::Http);
        assert_eq!(ProxyRule::all("http://p:8080").scope, ProxyScope::All);
        assert!(ProxyRule::all("http://p:8080").auth.is_none());
    }

    /// The `Proxy-Authorization` reported for `url` under `cfg`, as a string.
    fn authorization(cfg: &ProxyConfig, url: &str) -> Option<String> {
        ProxyRoutes::resolve(cfg)
            .proxy_authorization(&Url::parse(url).unwrap())
            .map(|v| v.to_str().unwrap().to_string())
    }

    fn credentialed(rule: ProxyRule) -> ProxyConfig {
        ProxyConfig::Rules(vec![rule.with_basic_auth("alice", "hunter2")])
    }

    /// The value the client would attach, computed the same way: `Basic base64(user:password)`.
    /// `tests/e2e.rs` holds this to what a proxy actually receives.
    #[test]
    fn basic_credentials_are_reported_for_a_matching_rule() {
        let cfg = credentialed(ProxyRule::all("http://proxy.corp:8080"));
        assert_eq!(
            authorization(&cfg, "http://target.example/page").as_deref(),
            Some("Basic YWxpY2U6aHVudGVyMg==")
        );
    }

    /// An https request is tunnelled with `CONNECT`, and the credentials go on the tunnel --
    /// a separate exchange, carrying nothing on the request reported here. Reporting the
    /// header anyway would claim the origin server was sent proxy credentials.
    #[test]
    fn an_https_target_reports_nothing_because_it_is_tunnelled() {
        let cfg = credentialed(ProxyRule::all("http://proxy.corp:8080"));
        assert_eq!(authorization(&cfg, "https://target.example/page"), None);
    }

    #[test]
    fn a_rule_that_does_not_apply_reports_nothing() {
        // Scope: an https-only rule never sees a plain-http request.
        let scoped = credentialed(ProxyRule::https("http://proxy.corp:8080"));
        assert_eq!(authorization(&scoped, "http://target.example/"), None);

        // Bypass list, in each of its shapes.
        let bypassing = credentialed(
            ProxyRule::all("http://proxy.corp:8080").bypassing("target.example, 10.0.0.0/8"),
        );
        assert_eq!(authorization(&bypassing, "http://target.example/"), None);
        assert_eq!(authorization(&bypassing, "http://10.1.2.3/"), None);
        assert!(authorization(&bypassing, "http://elsewhere.example/").is_some());

        // No credentials to send.
        let bare = ProxyConfig::single("http://proxy.corp:8080");
        assert_eq!(authorization(&bare, "http://target.example/"), None);
    }

    /// A socks proxy authenticates inside its own handshake, so the client sends no header
    /// however the rule was written -- and neither do we.
    #[test]
    fn a_socks_proxy_reports_no_header() {
        let cfg = credentialed(ProxyRule::all("socks5://proxy.corp:1080"));
        assert_eq!(authorization(&cfg, "http://target.example/"), None);
    }

    /// `with_basic_auth` takes the username and password as they are: a `%` in either is a
    /// `%`, not the start of an escape (RFC 7617 §2). Also for a rule with a port entry, which
    /// the client matches by a closure and encodes differently.
    #[test]
    fn basic_credentials_are_taken_verbatim() {
        // base64("al%40ice:p%41ss: x")
        let expected = Some("Basic YWwlNDBpY2U6cCU0MXNzOiB4");
        for rule in [
            ProxyRule::all("http://proxy.corp:8080"),
            ProxyRule::all("http://proxy.corp:8080").bypassing("intranet.test:8080"),
        ] {
            let cfg = ProxyConfig::Rules(vec![rule.with_basic_auth("al%40ice", "p%41ss: x")]);
            assert_eq!(
                authorization(&cfg, "http://target.example/").as_deref(),
                expected
            );
        }
    }

    #[test]
    fn a_custom_authorization_is_reported_verbatim() {
        let cfg = ProxyConfig::Rules(vec![
            ProxyRule::all("http://proxy.corp:8080").with_custom_auth("Bearer token-value")
        ]);
        assert_eq!(
            authorization(&cfg, "http://target.example/").as_deref(),
            Some("Bearer token-value")
        );
    }

    /// Credentials belong to the proxy that demanded them (RFC 9110 §11.7.2): the first rule
    /// that routes the request is the proxy the client connects through, so its credentials
    /// answer, or none when it has none. A later rule's credentials are never sent to it.
    #[test]
    fn the_first_routing_rule_answers_with_its_own_credentials() {
        let cfg = ProxyConfig::Rules(vec![
            ProxyRule::all("http://first.corp:8080"),
            ProxyRule::all("http://second.corp:8080").with_basic_auth("alice", "hunter2"),
        ]);
        assert_eq!(authorization(&cfg, "http://target.example/"), None);

        // Bypassed by the first rule, the request goes through the second, with its credentials.
        let cfg = ProxyConfig::Rules(vec![
            ProxyRule::all("http://first.corp:8080").bypassing("target.example"),
            ProxyRule::all("http://second.corp:8080").with_basic_auth("alice", "hunter2"),
        ]);
        assert_eq!(
            authorization(&cfg, "http://target.example/").as_deref(),
            Some("Basic YWxpY2U6aHVudGVyMg==")
        );
    }

    /// Behind a socks proxy the next HTTP recipient is the origin server, so an http rule
    /// further down must not put its proxy credentials on the request.
    #[test]
    fn a_socks_rule_first_means_no_proxy_authorization() {
        let cfg = ProxyConfig::Rules(vec![
            ProxyRule::all("socks5h://127.0.0.1:1080"),
            ProxyRule::all("http://proxy.corp:8080").with_basic_auth("alice", "hunter2"),
        ]);
        assert_eq!(authorization(&cfg, "http://target.example/"), None);
    }

    /// The operating system's settings are the client's to read, and a disabled proxy has no
    /// credentials to report.
    #[test]
    fn system_settings_and_disabled_report_nothing() {
        let url = Url::parse("http://target.example/").unwrap();
        let os = ProxyRoutes::System(Box::new(
            proxy_matcher::Matcher::builder()
                .all("http://alice:hunter2@127.0.0.1:3128".to_string())
                .build(),
        ));
        assert_eq!(os.proxy_authorization(&url), None);
        assert_eq!(ProxyRoutes::Disabled.proxy_authorization(&url), None);
    }

    /// The routes [`env_rules`] makes of `vars`, or `None` when it finds no proxy.
    fn env(vars: &[(&str, &str)]) -> Option<ProxyRoutes> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        env_rules(&|name| vars.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()))
            .map(ProxyRoutes::Rules)
    }

    /// The proxy a plain-http request to `target` goes through under `routes`, as a string.
    fn via(routes: &ProxyRoutes, target: &str) -> Option<String> {
        routes
            .plain_http_proxy(&Url::parse(target).unwrap())
            .map(|u| u.to_string())
    }

    /// `NO_PROXY` from the environment means what `ProxyRule::no_proxy` means: `*` covers IP
    /// hosts too, an IPv6 address may be in brackets, a name may end in a dot.
    #[test]
    fn env_no_proxy_is_read_like_a_rules_bypass_list() {
        let url = |s: &str| Url::parse(s).unwrap();
        let star = env(&[("HTTP_PROXY", "http://127.0.0.1:3128"), ("NO_PROXY", "*")]).unwrap();
        for target in [
            "http://example.com/",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
        ] {
            assert!(!star.routes_through_proxy(&url(target)), "{target}");
        }

        let forms = env(&[
            ("ALL_PROXY", "http://127.0.0.1:3128"),
            ("no_proxy", "[::1], intranet.example."),
        ])
        .unwrap();
        assert!(!forms.routes_through_proxy(&url("http://[::1]/")));
        assert!(!forms.routes_through_proxy(&url("https://intranet.example/")));
        assert!(forms.routes_through_proxy(&url("http://example.com/")));
    }

    /// Each variable covers its own scheme, `ALL_PROXY` whatever is left, and an empty value
    /// counts as unset rather than hiding the lowercase spelling.
    #[test]
    fn env_variables_by_scheme_with_empty_values_unset() {
        let routes = env(&[
            ("HTTP_PROXY", ""),
            ("http_proxy", "http://lower.test:3128"),
            ("ALL_PROXY", "http://all.test:3128"),
        ])
        .unwrap();
        assert_eq!(
            via(&routes, "http://example.com/").as_deref(),
            Some("http://lower.test:3128/")
        );
        assert!(routes.routes_through_proxy(&Url::parse("https://example.com/").unwrap()));

        // Uppercase wins when both are set, as in hyper-util and Go.
        let both = env(&[
            ("HTTP_PROXY", "http://upper.test:3128"),
            ("http_proxy", "http://lower.test:3128"),
        ])
        .unwrap();
        assert_eq!(
            via(&both, "http://example.com/").as_deref(),
            Some("http://upper.test:3128/")
        );
        assert!(!both.routes_through_proxy(&Url::parse("https://example.com/").unwrap()));
    }

    /// A value without a scheme is an http proxy, an unusable one is skipped, and no proxy
    /// variable at all leaves the choice to the operating system's settings.
    #[test]
    fn env_values_without_a_scheme_unusable_or_absent() {
        let bare = env(&[("HTTP_PROXY", "proxy.test:3128")]).unwrap();
        assert_eq!(
            via(&bare, "http://example.com/").as_deref(),
            Some("http://proxy.test:3128/")
        );

        let broken = env(&[
            ("HTTP_PROXY", "http://[not-an-address"),
            ("ALL_PROXY", "http://all.test:3128"),
        ])
        .unwrap();
        assert_eq!(
            via(&broken, "http://example.com/").as_deref(),
            Some("http://all.test:3128/")
        );

        assert!(env(&[("NO_PROXY", "*")]).is_none());
        assert!(env(&[("HTTP_PROXY", "  ")]).is_none());
    }

    /// httpoxy (CVE-2016-5385): under CGI a request's `Proxy` header arrives as `HTTP_PROXY`,
    /// so the environment is not trusted for a proxy at all.
    #[test]
    fn under_cgi_the_environment_names_no_proxy() {
        let cgi = env(&[
            ("REQUEST_METHOD", "GET"),
            ("HTTP_PROXY", "http://evil.test:3128"),
        ])
        .unwrap();
        assert!(!cgi.routes_through_proxy(&Url::parse("http://example.com/").unwrap()));
    }

    #[test]
    fn default_is_system() {
        assert_eq!(ProxyConfig::default(), ProxyConfig::System);
    }

    #[test]
    fn single_is_an_all_scheme_rule() {
        assert_eq!(
            ProxyConfig::single("http://p:8080"),
            ProxyConfig::Rules(vec![ProxyRule::all("http://p:8080")])
        );
    }

    #[test]
    fn valid_rules_build() {
        for rule in [
            ProxyRule::all("http://proxy.example:8080"),
            ProxyRule::http("http://user:pass@proxy.example:8080"),
            ProxyRule::https("https://proxy.example:8443").with_basic_auth("u", "p"),
            ProxyRule::all("http://proxy.example:8080").with_custom_auth("Bearer token"),
            ProxyRule::all("http://proxy.example:8080").bypassing("localhost, 10.0.0.0/8"),
        ] {
            assert!(rule.to_reqwest().is_ok(), "should build: {rule:?}");
        }
    }

    /// The `socks` feature is the only thing standing between a `socks5://` URL and a working
    /// proxy, so assert both directions — the docs promise exactly this trade.
    #[test]
    fn socks_urls_need_the_socks_feature() {
        let built = ProxyRule::all("socks5://127.0.0.1:1080")
            .to_reqwest()
            .is_ok();
        assert_eq!(built, cfg!(feature = "socks"));
    }

    #[test]
    fn unusable_proxy_url_is_reported() {
        let err = ProxyRule::all("not a url").to_reqwest().unwrap_err();
        assert!(
            err.to_string().contains("not a url"),
            "error should name the offending URL, got: {err}"
        );
    }

    #[test]
    fn invalid_custom_auth_header_is_reported() {
        let err = ProxyRule::all("http://proxy.example:8080")
            .with_custom_auth("bad\nvalue")
            .to_reqwest()
            .unwrap_err();
        assert!(
            err.to_string().contains("Proxy-Authorization"),
            "error should mention the header, got: {err}"
        );
    }

    #[test]
    fn apply_accepts_every_variant() {
        for cfg in [
            ProxyConfig::System,
            ProxyConfig::Disabled,
            ProxyConfig::Rules(vec![]),
            ProxyConfig::single("http://proxy.example:8080"),
        ] {
            assert!(
                cfg.apply(reqwest::Client::builder()).is_ok(),
                "should apply: {cfg:?}"
            );
        }
    }

    #[test]
    fn apply_propagates_rule_errors() {
        let cfg = ProxyConfig::single("not a url");
        assert!(cfg.apply(reqwest::Client::builder()).is_err());
    }

    #[test]
    fn plain_http_proxy_names_the_proxy_for_http_only() {
        let cfg = ProxyRoutes::Rules(vec![
            ProxyRule::all("http://user:pw@proxy.test:3128").bypassing("internal.test")
        ]);
        let proxy = |u: &str| cfg.plain_http_proxy(&Url::parse(u).unwrap());
        assert_eq!(
            proxy("http://example.test/").map(|u| u.to_string()),
            Some("http://proxy.test:3128/".to_string()),
            "credentials are left out"
        );
        assert_eq!(
            proxy("https://example.test/"),
            None,
            "an https request tunnels"
        );
        assert_eq!(proxy("http://internal.test/"), None, "no_proxy is honoured");

        let socks = ProxyRoutes::Rules(vec![ProxyRule::all("socks5://proxy.test:1080")]);
        assert_eq!(
            socks.plain_http_proxy(&Url::parse("http://example.test/").unwrap()),
            None
        );

        // A socks rule first: the client connects through it, so the http rule after it is
        // not the proxy, and a 407 is the origin's.
        let socks_first = ProxyRoutes::Rules(vec![
            ProxyRule::all("socks5h://proxy.test:1080"),
            ProxyRule::all("http://proxy.test:3128"),
        ]);
        assert_eq!(
            socks_first.plain_http_proxy(&Url::parse("http://example.test/").unwrap()),
            None
        );
        assert_eq!(
            ProxyRoutes::Disabled.plain_http_proxy(&Url::parse("http://example.test/").unwrap()),
            None
        );
    }
}

//! Programmatic proxy configuration for the [`Fetcher`].
//!
//! Without configuration the fetcher keeps reqwest's default behaviour and reads the
//! `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` environment variables — see
//! [`ProxyConfig::System`]. An embedder that has its own proxy settings (a browser's network
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
    /// everything. `None` sends every in-scope request through the proxy — note that this does
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

        let mut proxy = match self.scope {
            ProxyScope::Http => reqwest::Proxy::http(&self.url),
            ProxyScope::Https => reqwest::Proxy::https(&self.url),
            ProxyScope::All => reqwest::Proxy::all(&self.url),
        }
        .with_context(|| format!("unusable proxy URL {:?}", self.url))?;

        match self.auth {
            Some(ProxyAuth::Basic {
                ref username,
                ref password,
            }) => proxy = proxy.basic_auth(username, password),
            Some(ProxyAuth::Custom(ref value)) => {
                let header = value.parse().with_context(|| {
                    format!("proxy {:?}: invalid Proxy-Authorization value", self.url)
                })?;
                proxy = proxy.custom_http_auth(header);
            }
            None => {}
        }

        if let Some(ref list) = self.no_proxy {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(list));
        }

        Ok(proxy)
    }
}

/// How the fetcher chooses a proxy for outgoing requests.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub enum ProxyConfig {
    /// Take the proxy from the environment: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and the
    /// `NO_PROXY` bypass list (lowercase spellings included). The default, and what the fetcher
    /// did before proxies were configurable.
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

    /// Apply this configuration to a client builder.
    ///
    /// [`ProxyConfig::System`] leaves the builder untouched, since reading the environment is
    /// reqwest's own default; the other variants clear it first so no environment proxy leaks in.
    pub(crate) fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> anyhow::Result<reqwest::ClientBuilder> {
        match self {
            ProxyConfig::System => Ok(builder),
            ProxyConfig::Disabled => Ok(builder.no_proxy()),
            ProxyConfig::Rules(rules) => {
                // `no_proxy()` first: with an empty `rules` nothing else would switch the
                // environment lookup off, and a caller that spelled out its rules never wants
                // `HTTP_PROXY` silently appended to them.
                let mut builder = builder.no_proxy();
                for rule in rules {
                    builder = builder.proxy(rule.to_reqwest()?);
                }
                Ok(builder)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

//! Blocking insecure sub-resources loaded by a secure document ([spec]).
//!
//! An `https` page that pulls a script over plain `http` hands anyone on the network the ability
//! to rewrite it, defeating the outer TLS connection.
//!
//! Enforcement is split. Sonar re-checks **every redirect hop** — the part a caller cannot do
//! for itself, since a check made before [`Fetcher::fetch`] cannot see an `https://a` →
//! `http://b` redirect. Classification stays with the embedder: [`ResourceKind`] cannot tell an
//! image from a script, so a caller that wants to permit *optionally-blockable* content (images,
//! video, audio) passes [`MixedContentPolicy::Allow`] on those requests via
//! [`FetchRequest::mixed_content`].
//!
//! To wire it up, set [`FetcherConfig::mixed_content`] for the fetcher-wide default and
//! [`FetchRequest::origin`] to the initiating document. Without an origin the check is inert.
//!
//! On `wasm32` the browser follows redirects itself and cannot be asked not to, so only the
//! initial URL is checked; the browser blocks the hops sonar never sees.
//!
//! [spec]: https://w3c.github.io/webappsec-mixed-content/
//! [`Fetcher::fetch`]: crate::net::fetcher::Fetcher::fetch
//! [`ResourceKind`]: crate::net::types::ResourceKind
//! [`FetcherConfig::mixed_content`]: crate::net::fetcher::FetcherConfig::mixed_content
//! [`FetchRequest::origin`]: crate::net::types::FetchRequest::origin
//! [`FetchRequest::mixed_content`]: crate::net::types::FetchRequest::mixed_content

use url::{Host, Origin, Url};

/// What to do with an insecure sub-resource requested by a secure document.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum MixedContentPolicy {
    /// Send the request unchanged. Use this for optionally-blockable content (images, video,
    /// audio) that the embedder has chosen to permit, or to opt out of mixed content handling.
    Allow,
    /// Rewrite the request URL to `https` before sending it, as `upgrade-insecure-requests` does.
    /// There is no fallback to `http` if the upgraded request fails.
    Upgrade,
    /// Reject the request with
    /// [`NetError::Blocked`](crate::net::types::NetError::Blocked). The default, matching
    /// browser behaviour for blockable content.
    #[default]
    Block,
}

/// The outcome of a mixed content check.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MixedContentAction {
    /// Not mixed content, or explicitly permitted. Send the request as-is.
    Allow,
    /// Send the request to this `https` URL instead of the original `http` one.
    Upgrade(Url),
    /// Refuse to send the request.
    Block,
}

/// Returns `true` if `host` is a loopback address or a `localhost` domain.
///
/// Traffic to these hosts never leaves the machine, so it is trustworthy regardless of scheme
/// (see [secure contexts §3.1][spec]).
///
/// Generic over the domain's string type so it accepts both `Url::host` (`Host<&str>`) and
/// `Origin::Tuple` (`Host<String>`).
///
/// [spec]: https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy
fn is_loopback_host<S: AsRef<str>>(host: &Host<S>) -> bool {
    match host {
        // `Url` lowercases domains during parsing, so an ASCII comparison is enough.
        Host::Domain(d) => {
            let d = d.as_ref();
            d == "localhost" || d.ends_with(".localhost")
        }
        // The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1.
        Host::Ipv4(ip) => ip.octets()[0] == 127,
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Returns `true` if `scheme` is authenticated by construction.
fn is_trustworthy_scheme(scheme: &str) -> bool {
    matches!(scheme, "https" | "wss" | "file")
}

/// Returns `true` if `url` is a *potentially trustworthy URL*.
///
/// `data:`, `blob:`, and `about:blank` are trustworthy per spec but are never fetched over the
/// network, so they are not handled here.
pub fn is_potentially_trustworthy(url: &Url) -> bool {
    is_trustworthy_scheme(url.scheme()) || url.host().is_some_and(|h| is_loopback_host(&h))
}

/// Returns `true` if `origin` is a *potentially trustworthy origin*.
///
/// An opaque (serialised as `"null"`) origin is never trustworthy.
pub fn is_origin_potentially_trustworthy(origin: &Origin) -> bool {
    match origin {
        Origin::Opaque(_) => false,
        Origin::Tuple(scheme, host, _) => is_trustworthy_scheme(scheme) || is_loopback_host(host),
    }
}

/// Rewrite an insecure URL to its `https` equivalent, as the *upgrade a mixed content request*
/// algorithm does. Returns `None` if the scheme cannot be rewritten.
///
/// An explicit non-default port is preserved: the spec only drops port 80, which `Url` has
/// already normalised away as the default for `http`.
fn upgrade(url: &Url) -> Option<Url> {
    let mut upgraded = url.clone();
    upgraded.set_scheme("https").ok()?;
    Some(upgraded)
}

/// Decide what to do with a request for `url` initiated by a document at `origin`.
///
/// Returns [`MixedContentAction::Allow`] unless *all* of the following hold:
///
/// 1. `origin` is `Some` — there is a document context to protect.
/// 2. That origin is potentially trustworthy — an insecure document has nothing to downgrade.
/// 3. `url` is *not* potentially trustworthy — the sub-resource is the insecure part.
///
/// Only then does `policy` decide between allowing, upgrading, and blocking.
pub fn evaluate(
    policy: MixedContentPolicy,
    origin: Option<&Origin>,
    url: &Url,
) -> MixedContentAction {
    let Some(origin) = origin else {
        return MixedContentAction::Allow;
    };
    if !is_origin_potentially_trustworthy(origin) || is_potentially_trustworthy(url) {
        return MixedContentAction::Allow;
    }

    match policy {
        MixedContentPolicy::Allow => MixedContentAction::Allow,
        // A URL we cannot rewrite is one we cannot make safe, so fall through to blocking
        // rather than silently sending the insecure request.
        MixedContentPolicy::Upgrade => upgrade(url).map_or(MixedContentAction::Block, |u| {
            MixedContentAction::Upgrade(u)
        }),
        MixedContentPolicy::Block => MixedContentAction::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn origin(s: &str) -> Origin {
        url(s).origin()
    }

    #[test]
    fn https_origin_blocks_http_subresource() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Block,
                Some(&origin("https://example.com")),
                &url("http://cdn.example.com/a.js"),
            ),
            MixedContentAction::Block
        );
    }

    #[test]
    fn https_origin_upgrades_http_subresource() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Upgrade,
                Some(&origin("https://example.com")),
                &url("http://cdn.example.com:8080/a.js"),
            ),
            MixedContentAction::Upgrade(url("https://cdn.example.com:8080/a.js"))
        );
    }

    #[test]
    fn upgrade_drops_default_http_port() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Upgrade,
                Some(&origin("https://example.com")),
                &url("http://cdn.example.com:80/a.js"),
            ),
            MixedContentAction::Upgrade(url("https://cdn.example.com/a.js"))
        );
    }

    #[test]
    fn allow_policy_permits_mixed_content() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Allow,
                Some(&origin("https://example.com")),
                &url("http://cdn.example.com/cat.png"),
            ),
            MixedContentAction::Allow
        );
    }

    #[test]
    fn https_subresource_is_never_mixed_content() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Block,
                Some(&origin("https://example.com")),
                &url("https://cdn.example.com/a.js"),
            ),
            MixedContentAction::Allow
        );
    }

    #[test]
    fn insecure_origin_is_not_protected() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Block,
                Some(&origin("http://example.com")),
                &url("http://cdn.example.com/a.js"),
            ),
            MixedContentAction::Allow
        );
    }

    #[test]
    fn absent_origin_is_not_protected() {
        assert_eq!(
            evaluate(MixedContentPolicy::Block, None, &url("http://example.com/")),
            MixedContentAction::Allow
        );
    }

    #[test]
    fn loopback_subresource_is_trustworthy() {
        for target in [
            "http://localhost:3000/a.js",
            "http://dev.localhost/a.js",
            "http://127.0.0.1/a.js",
            "http://127.9.9.9/a.js",
            "http://[::1]:8080/a.js",
        ] {
            assert_eq!(
                evaluate(
                    MixedContentPolicy::Block,
                    Some(&origin("https://example.com")),
                    &url(target),
                ),
                MixedContentAction::Allow,
                "{target} should be potentially trustworthy"
            );
        }
    }

    #[test]
    fn loopback_origin_is_trustworthy() {
        assert_eq!(
            evaluate(
                MixedContentPolicy::Block,
                Some(&origin("http://localhost:3000")),
                &url("http://cdn.example.com/a.js"),
            ),
            MixedContentAction::Block,
            "a loopback document is a secure context and must still block mixed content"
        );
    }

    #[test]
    fn opaque_origin_is_not_trustworthy() {
        // `data:` URLs produce an opaque origin.
        assert!(!is_origin_potentially_trustworthy(&origin("data:,hello")));
    }

    #[test]
    fn near_miss_hosts_are_not_loopback() {
        for target in [
            "http://notlocalhost/a.js",
            "http://localhost.evil.com/a.js",
            "http://128.0.0.1/a.js",
            "http://[::2]/a.js",
        ] {
            assert!(
                !is_potentially_trustworthy(&url(target)),
                "{target} must not be treated as loopback"
            );
        }
    }
}

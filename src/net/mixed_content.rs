//! Blocking insecure sub-resources loaded by a secure document ([spec]).
//!
//! An `https` page that pulls a script over plain `http` hands anyone on the network the ability
//! to rewrite it, defeating the outer TLS connection.
//!
//! Sonar checks **every redirect hop**, which a caller cannot do for itself: a check made before
//! [`Fetcher::fetch`] cannot see an `https://a` → `http://b` redirect.
//!
//! The default, [`MixedContentPolicy::Block`], is what browsers do (Mixed Content Level 2), by
//! the request's destination: images, audio and video are *upgradeable*, and are fetched over
//! `https` instead, unless the host is an IP address; everything else is blocked; and a
//! top-level navigation (destination `document`) is not mixed content at all. One difference:
//! Fetch also blocks an image requested for `srcset` or `<picture>` (initiator `imageset`),
//! which sonar cannot tell from another image, so it is upgraded too.
//!
//! To wire it up, set [`FetcherConfig::mixed_content`] for the fetcher-wide default and
//! [`FetchRequest::origin`] to the initiating document. Without an origin the check is inert,
//! and so it is for a document opened from a `file:` URL: its origin is opaque, so nothing it
//! loads is mixed content, as in browsers.
//!
//! On `wasm32` the browser follows redirects itself and cannot be asked not to, so only the
//! initial URL is checked; the browser blocks the hops sonar never sees.
//!
//! [spec]: https://w3c.github.io/webappsec-mixed-content/
//! [`Fetcher::fetch`]: crate::net::fetcher::Fetcher::fetch
//! [`FetcherConfig::mixed_content`]: crate::net::fetcher::FetcherConfig::mixed_content
//! [`FetchRequest::origin`]: crate::net::types::FetchRequest::origin
//! [`FetchRequest::mixed_content`]: crate::net::types::FetchRequest::mixed_content

use crate::net::fetch_metadata::RequestDestination;
use url::{Host, Origin, Url};

/// What to do with an insecure sub-resource requested by a secure document.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum MixedContentPolicy {
    /// Send the request unchanged: the user agent was told to allow mixed content (Mixed
    /// Content §4.4), or the embedder opts out of mixed content handling.
    Allow,
    /// Rewrite the request URL to `https` before sending it, as `upgrade-insecure-requests` does.
    /// There is no fallback to `http` if the upgraded request fails.
    Upgrade,
    /// What browsers do (Mixed Content Level 2), and the default: an image, audio or video
    /// request is upgraded to `https` unless its host is an IP address, any other request is
    /// rejected with [`NetError::Blocked`](crate::net::types::NetError::Blocked), and a top-level
    /// navigation is let through.
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
        // `Url` lowercases domains during parsing, so an ASCII comparison is enough. The fully
        // qualified forms, with one trailing dot, count too (secure contexts §3.1 step 5).
        Host::Domain(d) => {
            let d = d.as_ref();
            let d = d.strip_suffix('.').unwrap_or(d);
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
/// An opaque (serialised as `"null"`) origin is never trustworthy. That includes the origin of
/// a `file:` URL, which the URL standard makes opaque, even though a `file:` *URL* counts as
/// trustworthy in [`is_potentially_trustworthy`].
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
///
/// The request's destination is not known here, so it is judged as a subresource of no
/// particular kind; [`evaluate_for`] takes it into account.
pub fn evaluate(
    policy: MixedContentPolicy,
    origin: Option<&Origin>,
    url: &Url,
) -> MixedContentAction {
    evaluate_for(policy, origin, url, RequestDestination::Empty)
}

/// [`evaluate`] for a request with this destination.
///
/// A top-level navigation (destination `document`) is never mixed content: following a link
/// from an `https` page to an `http` one leaves the secure page rather than loading something
/// into it (Mixed Content §4.4). Nested documents have their own destinations (`iframe`,
/// `frame`), and are checked like any subresource.
pub fn evaluate_for(
    policy: MixedContentPolicy,
    origin: Option<&Origin>,
    url: &Url,
    destination: RequestDestination,
) -> MixedContentAction {
    let Some(origin) = origin else {
        return MixedContentAction::Allow;
    };
    if !is_origin_potentially_trustworthy(origin) || is_potentially_trustworthy(url) {
        return MixedContentAction::Allow;
    }
    if destination == RequestDestination::Document && policy == MixedContentPolicy::Block {
        return MixedContentAction::Allow;
    }

    match policy {
        MixedContentPolicy::Allow => MixedContentAction::Allow,
        // A URL we cannot rewrite is one we cannot make safe, so fall through to blocking
        // rather than silently sending the insecure request.
        MixedContentPolicy::Upgrade => upgrade(url).map_or(MixedContentAction::Block, |u| {
            MixedContentAction::Upgrade(u)
        }),
        // Upgradeable content (Mixed Content §4.1): images, audio and video, except on an IP
        // host, where a certificate is unlikely and the upgrade would only trade a mixed load
        // for a failed one.
        MixedContentPolicy::Block
            if matches!(
                destination,
                RequestDestination::Image | RequestDestination::Audio | RequestDestination::Video
            ) && matches!(url.host(), Some(Host::Domain(_))) =>
        {
            upgrade(url).map_or(MixedContentAction::Block, MixedContentAction::Upgrade)
        }
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
            // Secure contexts §3.1 step 5: "localhost." and ".localhost." count as well.
            "http://localhost./a.js",
            "http://dev.localhost./a.js",
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

    /// A local page is not protected: its subresources are never mixed content.
    #[test]
    fn file_document_is_not_protected() {
        let doc = Url::parse("file:///home/me/index.html").unwrap().origin();
        assert!(!is_origin_potentially_trustworthy(&doc));
        assert_eq!(
            evaluate(
                MixedContentPolicy::Block,
                Some(&doc),
                &Url::parse("http://cdn.test/app.js").unwrap()
            ),
            MixedContentAction::Allow
        );
        assert!(is_potentially_trustworthy(
            &Url::parse("file:///home/me/index.html").unwrap()
        ));
    }

    /// Mixed Content §4.4: a top-level navigation is not mixed content. An `iframe` is, and so
    /// is a request of unknown destination.
    #[test]
    fn a_top_level_navigation_is_not_mixed_content() {
        let doc = origin("https://example.com");
        let target = url("http://insecure.example.com/");
        let verdict =
            |destination| evaluate_for(MixedContentPolicy::Block, Some(&doc), &target, destination);
        assert_eq!(
            verdict(RequestDestination::Document),
            MixedContentAction::Allow
        );
        assert_eq!(
            verdict(RequestDestination::Iframe),
            MixedContentAction::Block
        );
        assert_eq!(
            verdict(RequestDestination::Script),
            MixedContentAction::Block
        );
        assert_eq!(
            evaluate(MixedContentPolicy::Block, Some(&doc), &target),
            MixedContentAction::Block
        );
    }

    /// Mixed Content §4.1: images, audio and video are upgradeable. From a secure document they
    /// are fetched over `https` instead of being blocked, except on an IP host; every other
    /// destination is blocked.
    #[test]
    fn images_audio_and_video_are_upgraded_by_default() {
        let doc = origin("https://example.com");
        let verdict = |target: &str, destination| {
            evaluate_for(
                MixedContentPolicy::Block,
                Some(&doc),
                &url(target),
                destination,
            )
        };
        for destination in [
            RequestDestination::Image,
            RequestDestination::Audio,
            RequestDestination::Video,
        ] {
            assert_eq!(
                verdict("http://cdn.example.com:8080/cat.png", destination),
                MixedContentAction::Upgrade(url("https://cdn.example.com:8080/cat.png")),
                "{destination:?}"
            );
            for ip in [
                "http://93.184.216.34/cat.png",
                "http://[2001:db8::1]/cat.png",
            ] {
                assert_eq!(
                    verdict(ip, destination),
                    MixedContentAction::Block,
                    "{destination:?} {ip}"
                );
            }
        }
        for destination in [
            RequestDestination::Script,
            RequestDestination::Style,
            RequestDestination::Font,
            RequestDestination::Iframe,
            RequestDestination::Empty,
        ] {
            assert_eq!(
                verdict("http://cdn.example.com/x", destination),
                MixedContentAction::Block,
                "{destination:?}"
            );
        }
        // `Allow` still lets an image through as it is.
        assert_eq!(
            evaluate_for(
                MixedContentPolicy::Allow,
                Some(&doc),
                &url("http://cdn.example.com/cat.png"),
                RequestDestination::Image
            ),
            MixedContentAction::Allow
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
            "http://localhost../a.js",
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

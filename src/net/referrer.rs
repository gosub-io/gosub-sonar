//! Computing the `Referer` header from a referrer policy ([spec]).
//!
//! The header says where a request came from, which leaks browsing history, so a policy narrows
//! what is sent. The default is the browsers' — [`StrictOriginWhenCrossOrigin`]: full URL within
//! a site, bare origin when leaving it, nothing on an `https` → `http` downgrade.
//!
//! Set [`FetchRequest::referrer`] to the initiating document's URL and
//! [`FetchRequest::referrer_policy`] to its policy; without a referrer no header is sent. The
//! value is recomputed at every redirect hop, since same-origin and downgrade are properties of
//! the target and change as the chain moves.
//!
//! Inert on `wasm32`: the browser follows redirects itself and `Referer` is a forbidden header
//! name there, so it applies its own policy and ignores ours.
//!
//! [spec]: https://w3c.github.io/webappsec-referrer-policy/
//! [`StrictOriginWhenCrossOrigin`]: ReferrerPolicy::StrictOriginWhenCrossOrigin
//! [`FetchRequest::referrer`]: crate::net::types::FetchRequest::referrer
//! [`FetchRequest::referrer_policy`]: crate::net::types::FetchRequest::referrer_policy

use crate::net::mixed_content::is_potentially_trustworthy;
use url::Url;

/// How much of the initiating document's URL to reveal in the `Referer` header.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum ReferrerPolicy {
    /// Never send a `Referer`.
    NoReferrer,
    /// Send the full URL, except when moving from a trustworthy origin to a non-trustworthy one.
    NoReferrerWhenDowngrade,
    /// Send the full URL to the same origin, nothing to any other.
    SameOrigin,
    /// Send only the origin, to everyone.
    Origin,
    /// Send only the origin, and nothing on a downgrade.
    StrictOrigin,
    /// Send the full URL to the same origin, the origin alone to any other.
    OriginWhenCrossOrigin,
    /// Send the full URL to the same origin, the origin alone cross-origin, and nothing on a
    /// downgrade. The default for modern browsers, and for this crate.
    #[default]
    StrictOriginWhenCrossOrigin,
    /// Send the full URL to every target, downgrade included.
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Parse a single policy token, as it appears in a `Referrer-Policy` header or an HTML
    /// `referrerpolicy` attribute. Matching is case-insensitive; unknown tokens give `None`.
    pub fn parse_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "no-referrer" => Some(Self::NoReferrer),
            "no-referrer-when-downgrade" => Some(Self::NoReferrerWhenDowngrade),
            "same-origin" => Some(Self::SameOrigin),
            "origin" => Some(Self::Origin),
            "strict-origin" => Some(Self::StrictOrigin),
            "origin-when-cross-origin" => Some(Self::OriginWhenCrossOrigin),
            "strict-origin-when-cross-origin" => Some(Self::StrictOriginWhenCrossOrigin),
            "unsafe-url" => Some(Self::UnsafeUrl),
            _ => None,
        }
    }

    /// Parse a whole `Referrer-Policy` header value.
    ///
    /// The header may carry a comma-separated list and **the last token we understand wins**.
    /// That is deliberate in the spec: a site can send `no-referrer, strict-origin` so that old
    /// user agents fall back to the stricter policy they do recognise instead of ignoring the
    /// header entirely. Returns `None` when nothing in the list is recognised, meaning the
    /// current policy stands.
    pub fn parse_header(value: &str) -> Option<Self> {
        value.split(',').filter_map(Self::parse_token).next_back()
    }
}

/// Strip a URL for use as a referrer: drop the fragment and any credentials.
///
/// Returns `None` for schemes that are never sent as a referrer. A `file:`, `data:`, or
/// `about:blank` document produces no `Referer` at all, so those are filtered here rather than
/// leaking a local path to the network.
fn strip(url: &Url) -> Option<Url> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let mut stripped = url.clone();
    stripped.set_fragment(None);
    // These fail only for schemes that cannot carry credentials, which the check above excludes.
    let _ = stripped.set_username("");
    let _ = stripped.set_password(None);
    Some(stripped)
}

/// The referrer reduced to its origin, serialised with a trailing slash (`https://example.com/`).
fn origin_only(url: &Url) -> Option<Url> {
    let mut origin = strip(url)?;
    origin.set_path("/");
    origin.set_query(None);
    Some(origin)
}

/// Would sending `referrer` to `target` move from a trustworthy origin to a non-trustworthy one?
///
/// This is the "downgrade" the strict policies exist to prevent.
fn is_downgrade(referrer: &Url, target: &Url) -> bool {
    is_potentially_trustworthy(referrer) && !is_potentially_trustworthy(target)
}

/// True when this referrer and policy can never produce a header, whatever the target is.
///
/// Used to collapse such requests into one request-coalescing bucket: if no header is ever sent,
/// the referrer source cannot influence the response.
pub(crate) fn never_sends(referrer: &Url, policy: ReferrerPolicy) -> bool {
    policy == ReferrerPolicy::NoReferrer || strip(referrer).is_none()
}

/// A referrer serialising longer than this is reduced to its origin before the policy is applied.
///
/// From the spec, and load-bearing in practice: servers cap total header size (nginx allows 8 KiB
/// by default), so an unbounded `Referer` turns a long URL into a rejected request.
const MAX_REFERRER_LEN: usize = 4096;

/// Compute the `Referer` value to send to `target` for a request initiated by `referrer`.
///
/// Returns `None` when no referrer may be sent — either the policy forbids it for this target, or
/// the source is not an http(s) URL. The header must then be omitted, not sent empty.
pub fn determine(referrer: &Url, policy: ReferrerPolicy, target: &Url) -> Option<Url> {
    let stripped = strip(referrer)?;
    let origin = origin_only(referrer)?;
    let same_origin = referrer.origin() == target.origin();
    let downgrade = is_downgrade(referrer, target);

    // The length cap applies before the policy switch, so an over-long URL degrades to its
    // origin even under a policy that would otherwise reveal the whole thing.
    let full = if stripped.as_str().len() > MAX_REFERRER_LEN {
        origin.clone()
    } else {
        stripped
    };

    match policy {
        ReferrerPolicy::NoReferrer => None,
        ReferrerPolicy::UnsafeUrl => Some(full),
        // Deliberately ignores downgrades — that is what makes it the non-strict variant.
        ReferrerPolicy::Origin => Some(origin),
        ReferrerPolicy::SameOrigin => same_origin.then_some(full),
        ReferrerPolicy::StrictOrigin => (!downgrade).then_some(origin),
        ReferrerPolicy::OriginWhenCrossOrigin => Some(if same_origin { full } else { origin }),
        ReferrerPolicy::StrictOriginWhenCrossOrigin => {
            if same_origin {
                Some(full)
            } else if downgrade {
                None
            } else {
                Some(origin)
            }
        }
        ReferrerPolicy::NoReferrerWhenDowngrade => (!downgrade).then_some(full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// The document every case below is initiated from.
    fn doc() -> Url {
        u("https://example.com/page?q=1#frag")
    }

    fn determined(policy: ReferrerPolicy, target: &str) -> Option<String> {
        determine(&doc(), policy, &u(target)).map(|r| r.to_string())
    }

    #[test]
    fn no_referrer_sends_nothing_anywhere() {
        for target in [
            "https://example.com/a",
            "https://other.com/a",
            "http://other.com/a",
        ] {
            assert_eq!(determined(ReferrerPolicy::NoReferrer, target), None);
        }
    }

    #[test]
    fn unsafe_url_sends_full_url_even_on_downgrade() {
        for target in [
            "https://example.com/a",
            "https://other.com/a",
            "http://other.com/a",
        ] {
            assert_eq!(
                determined(ReferrerPolicy::UnsafeUrl, target).as_deref(),
                Some("https://example.com/page?q=1"),
                "{target}"
            );
        }
    }

    #[test]
    fn origin_sends_origin_even_on_downgrade() {
        for target in [
            "https://example.com/a",
            "https://other.com/a",
            "http://other.com/a",
        ] {
            assert_eq!(
                determined(ReferrerPolicy::Origin, target).as_deref(),
                Some("https://example.com/"),
                "{target}"
            );
        }
    }

    #[test]
    fn same_origin_sends_only_within_the_origin() {
        assert_eq!(
            determined(ReferrerPolicy::SameOrigin, "https://example.com/a").as_deref(),
            Some("https://example.com/page?q=1")
        );
        assert_eq!(
            determined(ReferrerPolicy::SameOrigin, "https://other.com/a"),
            None
        );
    }

    #[test]
    fn strict_origin_drops_the_referrer_on_downgrade() {
        assert_eq!(
            determined(ReferrerPolicy::StrictOrigin, "https://other.com/a").as_deref(),
            Some("https://example.com/")
        );
        assert_eq!(
            determined(ReferrerPolicy::StrictOrigin, "http://other.com/a"),
            None
        );
    }

    #[test]
    fn origin_when_cross_origin_keeps_the_path_only_at_home() {
        assert_eq!(
            determined(
                ReferrerPolicy::OriginWhenCrossOrigin,
                "https://example.com/a"
            )
            .as_deref(),
            Some("https://example.com/page?q=1")
        );
        assert_eq!(
            determined(ReferrerPolicy::OriginWhenCrossOrigin, "https://other.com/a").as_deref(),
            Some("https://example.com/")
        );
        // Non-strict: a downgrade still gets the origin.
        assert_eq!(
            determined(ReferrerPolicy::OriginWhenCrossOrigin, "http://other.com/a").as_deref(),
            Some("https://example.com/")
        );
    }

    #[test]
    fn strict_origin_when_cross_origin_is_the_default() {
        assert_eq!(
            ReferrerPolicy::default(),
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
        assert_eq!(
            determined(
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                "https://example.com/a"
            )
            .as_deref(),
            Some("https://example.com/page?q=1")
        );
        assert_eq!(
            determined(
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                "https://other.com/a"
            )
            .as_deref(),
            Some("https://example.com/")
        );
        assert_eq!(
            determined(
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                "http://other.com/a"
            ),
            None
        );
    }

    #[test]
    fn no_referrer_when_downgrade_keeps_the_full_url_until_it_downgrades() {
        assert_eq!(
            determined(
                ReferrerPolicy::NoReferrerWhenDowngrade,
                "https://other.com/a"
            )
            .as_deref(),
            Some("https://example.com/page?q=1")
        );
        assert_eq!(
            determined(
                ReferrerPolicy::NoReferrerWhenDowngrade,
                "http://other.com/a"
            ),
            None
        );
    }

    #[test]
    fn fragment_and_credentials_are_stripped() {
        let referrer = u("https://user:pw@example.com/page?q=1#secret");
        let sent = determine(
            &referrer,
            ReferrerPolicy::UnsafeUrl,
            &u("https://example.com/a"),
        )
        .unwrap();
        assert_eq!(sent.as_str(), "https://example.com/page?q=1");
        assert!(sent.fragment().is_none());
        assert_eq!(sent.username(), "");
        assert_eq!(sent.password(), None);
    }

    /// A local document must not leak its path onto the network, whatever the policy asks for.
    #[test]
    fn non_network_referrer_sources_send_nothing() {
        for source in ["file:///home/user/secret.html", "data:text/html,hi"] {
            assert_eq!(
                determine(
                    &u(source),
                    ReferrerPolicy::UnsafeUrl,
                    &u("https://example.com/a")
                ),
                None,
                "{source}"
            );
        }
    }

    /// http → http is not a downgrade, so the strict policies still send a referrer.
    #[test]
    fn insecure_to_insecure_is_not_a_downgrade() {
        assert_eq!(
            determine(
                &u("http://example.com/page"),
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                &u("http://other.com/a"),
            )
            .map(|r| r.to_string())
            .as_deref(),
            Some("http://example.com/")
        );
    }

    /// Loopback counts as trustworthy, so localhost → http is a downgrade like any other.
    #[test]
    fn loopback_referrer_downgrades_to_plain_http() {
        assert_eq!(
            determine(
                &u("http://localhost:3000/page"),
                ReferrerPolicy::StrictOrigin,
                &u("http://other.com/a"),
            ),
            None
        );
    }

    #[test]
    fn parses_every_policy_token_case_insensitively() {
        let cases = [
            ("no-referrer", ReferrerPolicy::NoReferrer),
            (
                "no-referrer-when-downgrade",
                ReferrerPolicy::NoReferrerWhenDowngrade,
            ),
            ("same-origin", ReferrerPolicy::SameOrigin),
            ("origin", ReferrerPolicy::Origin),
            ("strict-origin", ReferrerPolicy::StrictOrigin),
            (
                "origin-when-cross-origin",
                ReferrerPolicy::OriginWhenCrossOrigin,
            ),
            (
                "strict-origin-when-cross-origin",
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
            ),
            ("unsafe-url", ReferrerPolicy::UnsafeUrl),
        ];
        for (token, expected) in cases {
            assert_eq!(
                ReferrerPolicy::parse_token(token),
                Some(expected),
                "{token}"
            );
            assert_eq!(
                ReferrerPolicy::parse_token(&token.to_uppercase()),
                Some(expected),
                "{token} uppercased"
            );
        }
        assert_eq!(ReferrerPolicy::parse_token("nonsense"), None);
        assert_eq!(ReferrerPolicy::parse_token(""), None);
    }

    /// The last understood token wins, which is how a site offers a fallback to older agents.
    #[test]
    fn header_list_takes_the_last_understood_token() {
        assert_eq!(
            ReferrerPolicy::parse_header("no-referrer, strict-origin-when-cross-origin"),
            Some(ReferrerPolicy::StrictOriginWhenCrossOrigin)
        );
        // The trailing token is not understood, so the earlier fallback stands.
        assert_eq!(
            ReferrerPolicy::parse_header("no-referrer, some-future-policy"),
            Some(ReferrerPolicy::NoReferrer)
        );
        // Nothing understood at all leaves the caller's policy in force.
        assert_eq!(ReferrerPolicy::parse_header("a, b"), None);
        assert_eq!(ReferrerPolicy::parse_header(""), None);
    }

    /// Over-long referrers degrade to their origin, before the policy is even consulted.
    /// Servers cap header size, so an unbounded value would fail the whole request.
    #[test]
    fn over_long_referrer_degrades_to_origin() {
        let long = u(&format!("https://example.com/{}", "a".repeat(5000)));
        assert!(long.as_str().len() > MAX_REFERRER_LEN);

        // Same-origin under a policy that would otherwise reveal everything.
        for policy in [
            ReferrerPolicy::UnsafeUrl,
            ReferrerPolicy::SameOrigin,
            ReferrerPolicy::StrictOriginWhenCrossOrigin,
        ] {
            assert_eq!(
                determine(&long, policy, &u("https://example.com/a")).map(|r| r.to_string()),
                Some("https://example.com/".to_string()),
                "{policy:?}"
            );
        }

        // A referrer just under the cap is still sent whole.
        let short = u("https://example.com/page");
        assert_eq!(
            determine(
                &short,
                ReferrerPolicy::UnsafeUrl,
                &u("https://example.com/a")
            )
            .map(|r| r.to_string()),
            Some("https://example.com/page".to_string())
        );
    }

    /// A cross-origin target on the same host but a different port is still cross-origin.
    #[test]
    fn different_port_is_cross_origin() {
        assert_eq!(
            determined(ReferrerPolicy::SameOrigin, "https://example.com:8443/a"),
            None
        );
    }
}

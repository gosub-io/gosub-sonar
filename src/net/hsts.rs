//! HTTP Strict Transport Security (RFC 6797).
//!
//! A site declares over HTTPS that it must only ever be reached over HTTPS; later `http://`
//! requests to it are rewritten before any connection is made.
//!
//! This module owns the protocol — header parsing, host matching, expiry, the URL rewrite. An
//! embedder owns only storage, via [`HstsStore`]. [`InMemoryHstsStore`] is the default, so HSTS
//! is enforced without any embedder code.
//!
//! The preload list is out of scope; only the dynamic, header-driven part is implemented.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use http::{header, HeaderMap};
use url::{Host, Url};

/// Ceiling on `max-age`. The value is server-controlled and unbounded in the grammar, so this
/// keeps the conversion to an expiry instant total. A century is far beyond any real policy.
const MAX_AGE_CAP_SECS: u64 = 100 * 365 * 24 * 60 * 60;

/// A host's stored HSTS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsEntry {
    /// When this policy stops applying. Derived from `max-age` at the time the header was seen.
    pub expires_at: DateTime<Utc>,
    /// Whether the policy extends to subdomains. Gates only inherited matches — see
    /// [`should_upgrade`].
    pub include_subdomains: bool,
}

impl HstsEntry {
    /// Whether this entry has expired as of `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Storage for HSTS policies, keyed by host. Implement to persist across restarts.
///
/// The contract is a plain map: `load` returns whatever `store` was last given for that key.
/// Hosts arrive normalised (lowercase, no trailing dot) and should be treated as opaque — the
/// crate handles `max-age`, subdomain matching, and expiry, and ignores entries past
/// `expires_at` even if `load` returns them.
///
/// `load` runs once per host label on every hop of every request, so it must not block: keep an
/// in-memory map and persist asynchronously.
pub trait HstsStore: Send + Sync {
    /// Return the entry stored for exactly `host`, if any.
    fn load(&self, host: &str) -> Option<HstsEntry>;
    /// Store `entry` under exactly `host`, replacing any existing entry.
    fn store(&self, host: &str, entry: HstsEntry);
    /// Remove any entry stored under exactly `host`.
    fn remove(&self, host: &str);
}

/// The default [`HstsStore`]: an in-memory map that does not survive a restart.
#[derive(Debug, Default)]
pub struct InMemoryHstsStore {
    entries: DashMap<String, HstsEntry>,
}

impl InMemoryHstsStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries held, expired ones included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl HstsStore for InMemoryHstsStore {
    fn load(&self, host: &str) -> Option<HstsEntry> {
        self.entries.get(host).map(|e| e.clone())
    }

    fn store(&self, host: &str, entry: HstsEntry) {
        self.entries.insert(host.to_string(), entry);
    }

    fn remove(&self, host: &str) {
        self.entries.remove(host);
    }
}

/// A successfully parsed `Strict-Transport-Security` header value.
#[derive(Debug, PartialEq, Eq)]
struct StsDirectives {
    max_age: u64,
    include_subdomains: bool,
}

/// Strips the root label's trailing dot. `url` already lowercases domain hosts, but
/// `example.org.` and `example.org` must not occupy separate entries.
fn normalize_host(host: &str) -> &str {
    host.trim_end_matches('.')
}

/// The normalised domain host of `url`. IP literals yield `None`: HSTS applies to domain names
/// only (RFC 6797 §8.1).
fn domain_of(url: &Url) -> Option<&str> {
    match url.host() {
        Some(Host::Domain(d)) => Some(normalize_host(d)),
        _ => None,
    }
}

/// Strips the `quoted-string` form permitted for directive values (§6.1): `max-age="31536000"`.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Parses a `Strict-Transport-Security` value, or `None` if it does not conform — §6.1 requires
/// a non-conforming header be ignored whole rather than salvaged in part. `max-age` is required;
/// a repeated directive invalidates the header; unknown directives are ignored.
fn parse_sts(value: &str) -> Option<StsDirectives> {
    let mut max_age: Option<u64> = None;
    let mut include_subdomains = false;
    let mut seen_include_subdomains = false;

    for raw in value.split(';') {
        let token = raw.trim();
        if token.is_empty() {
            // The grammar permits empty directives, e.g. a trailing ';'.
            continue;
        }

        let (name, val) = match token.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (token, None),
        };

        if name.eq_ignore_ascii_case("max-age") {
            if max_age.is_some() {
                return None;
            }
            max_age = Some(unquote(val?).parse::<u64>().ok()?);
        } else if name.eq_ignore_ascii_case("includeSubDomains") {
            if seen_include_subdomains {
                return None;
            }
            seen_include_subdomains = true;
            include_subdomains = true;
        }
    }

    Some(StsDirectives {
        max_age: max_age?,
        include_subdomains,
    })
}

/// Records any policy advertised by the hop at `url`.
///
/// Call for every hop, not just the final one: a `301 http://x → https://x` is the usual way a
/// site first arms HSTS.
///
/// Headers arriving over plaintext are ignored (§8.1) — honouring them would let an on-path
/// attacker pin a host persistently. A successful `https` response also implies a validated
/// chain, since the TLS stack rejects it otherwise.
pub(crate) fn record(store: &dyn HstsStore, url: &Url, headers: &HeaderMap, now: DateTime<Utc>) {
    if url.scheme() != "https" {
        return;
    }
    let Some(host) = domain_of(url) else {
        return;
    };

    // §8.1: process only the first such header field.
    let Some(raw) = headers.get(header::STRICT_TRANSPORT_SECURITY) else {
        return;
    };
    let Ok(raw) = raw.to_str() else {
        return;
    };
    let Some(sts) = parse_sts(raw) else {
        return;
    };

    // §6.1.1: max-age=0 disarms, so delete rather than store an already-expired entry.
    if sts.max_age == 0 {
        store.remove(host);
        return;
    }

    let secs = sts.max_age.min(MAX_AGE_CAP_SECS) as i64;
    let Some(expires_at) =
        ChronoDuration::try_seconds(secs).and_then(|d| now.checked_add_signed(d))
    else {
        return;
    };

    store.store(
        host,
        HstsEntry {
            expires_at,
            include_subdomains: sts.include_subdomains,
        },
    );
}

/// Whether `url` must be upgraded under the policies in `store`.
///
/// §8.2: a host is a Known HSTS Host given a congruent (exact) match, or *any* superdomain match
/// asserting `includeSubDomains`. So the flag gates inherited matches only — an exact match
/// ignores it — and a nearer non-matching entry does not shadow a permissive ancestor.
pub(crate) fn should_upgrade(store: &dyn HstsStore, url: &Url, now: DateTime<Utc>) -> bool {
    if url.scheme() != "http" {
        return false;
    }
    let Some(host) = domain_of(url) else {
        return false;
    };

    let mut candidate = host;
    let mut is_exact = true;

    loop {
        if let Some(entry) = store.load(candidate) {
            if !entry.is_expired(now) && (is_exact || entry.include_subdomains) {
                return true;
            }
        }
        match candidate.split_once('.') {
            // Stop before the final label: a bare TLD cannot serve the header that would create
            // an entry there. A single-label host still matches its own entry above.
            Some((_, parent)) if parent.contains('.') => {
                candidate = parent;
                is_exact = false;
            }
            _ => return false,
        }
    }
}

/// Rewrites `http://` to `https://` per §8.3.
///
/// Only the scheme changes. An implicit port or an explicit `:80` becomes 443, but any other
/// explicit port is preserved (`http://x:8080/` → `https://x:8080/`) — HSTS upgrades the
/// transport, it does not redirect to 443. `url` normalises default ports away, so `set_scheme`
/// covers all three cases; pinned by `upgrade_follows_rfc_port_rules`.
pub(crate) fn upgrade(url: &Url) -> Url {
    let mut upgraded = url.clone();
    if upgraded.set_scheme("https").is_err() {
        return url.clone();
    }
    upgraded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid fixed timestamp")
    }

    fn entry(include_subdomains: bool) -> HstsEntry {
        HstsEntry {
            expires_at: now() + ChronoDuration::days(365),
            include_subdomains,
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url must parse")
    }

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            value.parse().expect("test header value must parse"),
        );
        h
    }

    #[test]
    fn parse_accepts_max_age_alone() {
        assert_eq!(
            parse_sts("max-age=31536000"),
            Some(StsDirectives {
                max_age: 31_536_000,
                include_subdomains: false
            })
        );
    }

    #[test]
    fn parse_accepts_include_subdomains_and_is_case_insensitive() {
        assert_eq!(
            parse_sts("MAX-AGE=100; IncludeSubDomains"),
            Some(StsDirectives {
                max_age: 100,
                include_subdomains: true
            })
        );
    }

    #[test]
    fn parse_accepts_quoted_max_age() {
        assert_eq!(parse_sts(r#"max-age="600""#).map(|d| d.max_age), Some(600));
    }

    #[test]
    fn parse_ignores_unknown_directives() {
        assert_eq!(
            parse_sts("max-age=1; preload; someFutureThing=4"),
            Some(StsDirectives {
                max_age: 1,
                include_subdomains: false
            })
        );
    }

    #[test]
    fn parse_tolerates_whitespace_and_empty_directives() {
        assert_eq!(
            parse_sts("  max-age = 42 ;; includeSubDomains ; "),
            Some(StsDirectives {
                max_age: 42,
                include_subdomains: true
            })
        );
    }

    #[test]
    fn parse_rejects_missing_max_age() {
        assert_eq!(parse_sts("includeSubDomains"), None);
    }

    #[test]
    fn parse_rejects_valueless_or_non_numeric_max_age() {
        assert_eq!(parse_sts("max-age"), None);
        assert_eq!(parse_sts("max-age=soon"), None);
        assert_eq!(parse_sts("max-age=-1"), None);
    }

    #[test]
    fn parse_rejects_repeated_directives() {
        assert_eq!(parse_sts("max-age=1; max-age=2"), None);
        assert_eq!(
            parse_sts("max-age=1; includeSubDomains; includeSubDomains"),
            None
        );
    }

    #[test]
    fn record_stores_policy_from_https_response() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("https://example.org/x"),
            &headers_with("max-age=600; includeSubDomains"),
            now(),
        );
        let e = store.load("example.org").expect("entry must be stored");
        assert!(e.include_subdomains);
        assert_eq!(e.expires_at, now() + ChronoDuration::seconds(600));
    }

    #[test]
    fn record_ignores_header_over_plaintext() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("http://example.org/x"),
            &headers_with("max-age=600"),
            now(),
        );
        assert!(store.is_empty());
    }

    #[test]
    fn record_ignores_ip_literal_hosts() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("https://192.0.2.1/x"),
            &headers_with("max-age=600"),
            now(),
        );
        record(
            &store,
            &url("https://[2001:db8::1]/x"),
            &headers_with("max-age=600"),
            now(),
        );
        assert!(store.is_empty());
    }

    #[test]
    fn record_max_age_zero_removes_entry() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(false));
        record(
            &store,
            &url("https://example.org/"),
            &headers_with("max-age=0"),
            now(),
        );
        assert_eq!(store.load("example.org"), None);
    }

    #[test]
    fn record_ignores_malformed_header_leaving_existing_entry() {
        let store = InMemoryHstsStore::new();
        let existing = entry(true);
        store.store("example.org", existing.clone());
        record(
            &store,
            &url("https://example.org/"),
            &headers_with("max-age=1; max-age=2"),
            now(),
        );
        assert_eq!(store.load("example.org"), Some(existing));
    }

    #[test]
    fn record_caps_absurd_max_age_instead_of_overflowing() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("https://example.org/"),
            &headers_with(&format!("max-age={}", u64::MAX)),
            now(),
        );
        let e = store.load("example.org").expect("entry must be stored");
        assert_eq!(
            e.expires_at,
            now() + ChronoDuration::seconds(MAX_AGE_CAP_SECS as i64)
        );
    }

    #[test]
    fn record_normalizes_trailing_dot_host() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("https://example.org./"),
            &headers_with("max-age=600"),
            now(),
        );
        assert!(store.load("example.org").is_some());
    }

    #[test]
    fn record_without_header_stores_nothing() {
        let store = InMemoryHstsStore::new();
        record(
            &store,
            &url("https://example.org/"),
            &HeaderMap::new(),
            now(),
        );
        assert!(store.is_empty());
    }

    #[test]
    fn exact_match_upgrades_regardless_of_include_subdomains() {
        let store = InMemoryHstsStore::new();
        store.store("foo.example.org", entry(false));
        assert!(should_upgrade(
            &store,
            &url("http://foo.example.org/p"),
            now()
        ));
    }

    #[test]
    fn superdomain_match_requires_include_subdomains() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(false));
        assert!(!should_upgrade(
            &store,
            &url("http://foo.example.org/p"),
            now()
        ));

        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(true));
        assert!(should_upgrade(
            &store,
            &url("http://foo.example.org/p"),
            now()
        ));
    }

    #[test]
    fn superdomain_match_walks_multiple_labels() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(true));
        assert!(should_upgrade(
            &store,
            &url("http://a.b.c.example.org/"),
            now()
        ));
    }

    #[test]
    fn non_inheriting_entry_does_not_shadow_permissive_ancestor() {
        // sub.example.org matches nothing here (not congruent, does not inherit), but example.org
        // still arms the host — the walk must not stop at the first entry it finds.
        let store = InMemoryHstsStore::new();
        store.store("sub.example.org", entry(false));
        store.store("example.org", entry(true));
        assert!(should_upgrade(
            &store,
            &url("http://deep.sub.example.org/"),
            now()
        ));
    }

    #[test]
    fn expired_entry_does_not_shadow_live_ancestor() {
        let store = InMemoryHstsStore::new();
        store.store(
            "sub.example.org",
            HstsEntry {
                expires_at: now() - ChronoDuration::seconds(1),
                include_subdomains: true,
            },
        );
        store.store("example.org", entry(true));
        assert!(should_upgrade(
            &store,
            &url("http://deep.sub.example.org/"),
            now()
        ));
    }

    #[test]
    fn expired_entry_does_not_upgrade() {
        let store = InMemoryHstsStore::new();
        store.store(
            "example.org",
            HstsEntry {
                expires_at: now() - ChronoDuration::seconds(1),
                include_subdomains: false,
            },
        );
        assert!(!should_upgrade(&store, &url("http://example.org/"), now()));
    }

    #[test]
    fn entry_expiring_exactly_now_does_not_upgrade() {
        let store = InMemoryHstsStore::new();
        store.store(
            "example.org",
            HstsEntry {
                expires_at: now(),
                include_subdomains: false,
            },
        );
        assert!(!should_upgrade(&store, &url("http://example.org/"), now()));
    }

    #[test]
    fn unrelated_host_does_not_upgrade() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(true));
        assert!(!should_upgrade(&store, &url("http://example.com/"), now()));
        // A string suffix is not a domain match.
        assert!(!should_upgrade(
            &store,
            &url("http://notexample.org/"),
            now()
        ));
    }

    #[test]
    fn single_label_host_matches_its_own_entry() {
        let store = InMemoryHstsStore::new();
        store.store("intranet", entry(false));
        assert!(should_upgrade(&store, &url("http://intranet/"), now()));
    }

    #[test]
    fn https_url_is_never_upgraded_again() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(true));
        assert!(!should_upgrade(&store, &url("https://example.org/"), now()));
    }

    #[test]
    fn ip_literal_never_upgrades() {
        let store = InMemoryHstsStore::new();
        store.store("192.0.2.1", entry(true));
        assert!(!should_upgrade(&store, &url("http://192.0.2.1/"), now()));
    }

    #[test]
    fn lookup_matches_trailing_dot_host() {
        let store = InMemoryHstsStore::new();
        store.store("example.org", entry(false));
        assert!(should_upgrade(&store, &url("http://example.org./"), now()));
    }

    #[test]
    fn upgrade_follows_rfc_port_rules() {
        // Pins `url`'s default-port normalisation, which is what makes a bare set_scheme correct.
        assert_eq!(upgrade(&url("http://x/p")).as_str(), "https://x/p");
        assert_eq!(upgrade(&url("http://x:80/p")).as_str(), "https://x/p");
        assert_eq!(
            upgrade(&url("http://x:8080/p")).as_str(),
            "https://x:8080/p"
        );
    }

    #[test]
    fn upgrade_preserves_everything_but_the_scheme() {
        assert_eq!(
            upgrade(&url("http://u:pw@x.org/a/b?q=1&r=2#frag")).as_str(),
            "https://u:pw@x.org/a/b?q=1&r=2#frag"
        );
    }
}

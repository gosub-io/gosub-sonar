//! HTTP authentication challenges (RFC 9110 §11).
//!
//! Parses the [`WWW-Authenticate`] and [`Proxy-Authenticate`] challenges of a `401` or `407`
//! response into [`AuthChallenge`]s. The fetch stack re-sends the hop once credentials for one of
//! them are found, so the caller gets the authenticated response instead of the challenge.
//!
//! Credentials are looked up in two places, in this order:
//!
//! 1. [`FetcherConfig::credentials`], a [`CredentialStore`] keyed by [`ProtectionSpace`]
//!    (target + scheme + origin + realm), so a realm is only asked about once.
//! 2. [`FetcherContext::on_auth_challenge`], called for each challenge in the order the server
//!    listed them until one returns [`Credentials`]. What it returns is written to the store when
//!    the retry succeeds and removed again when the server rejects it.
//!
//! The hook is synchronous, like [`FetcherContext::tls_override`], so it must not block on a
//! password dialog. Return `None`, show the dialog, and then either put the answer in the store
//! or re-submit the fetch.
//!
//! Only [`AuthScheme::Basic`] is computed here. Other schemes (`Digest`, `Bearer`, `Negotiate`)
//! use [`Credentials::Raw`], a verbatim header value; the challenge's parsed parameters (`nonce`,
//! `qop`, `realm`) are what the embedder needs to build one.
//!
//! [`FetcherConfig::credentials`]: crate::net::fetcher::FetcherConfig::credentials
//! [`FetcherContext::on_auth_challenge`]: crate::net::fetcher_context::FetcherContext::on_auth_challenge
//! [`FetcherContext::tls_override`]: crate::net::fetcher_context::FetcherContext::tls_override
//! [`WWW-Authenticate`]: http::header::WWW_AUTHENTICATE
//! [`Proxy-Authenticate`]: http::header::PROXY_AUTHENTICATE

use crate::net::utils::split_outside_quotes;
use http::{header, HeaderMap, HeaderValue};
use std::fmt;
use url::Url;

/// How many times a single hop may be re-sent with credentials before the `401`/`407` is
/// returned to the caller.
///
/// Enough for a stale stored password followed by a fresh one, and low enough to terminate when
/// an embedder keeps returning credentials the server refuses.
pub const MAX_AUTH_ATTEMPTS: u32 = 3;

/// Who is asking for credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthTarget {
    /// The origin server: `401` + `WWW-Authenticate`, answered with `Authorization`.
    Server,
    /// A proxy: `407` + `Proxy-Authenticate`, answered with `Proxy-Authorization`.
    Proxy,
}

impl AuthTarget {
    /// The target a status code demands credentials for, or `None` if it isn't a challenge.
    pub fn for_status(status: u16) -> Option<Self> {
        match status {
            401 => Some(Self::Server),
            407 => Some(Self::Proxy),
            _ => None,
        }
    }

    /// The response header carrying this target's challenges.
    pub fn challenge_header(self) -> header::HeaderName {
        match self {
            Self::Server => header::WWW_AUTHENTICATE,
            Self::Proxy => header::PROXY_AUTHENTICATE,
        }
    }

    /// The request header carrying this target's credentials.
    pub fn credentials_header(self) -> header::HeaderName {
        match self {
            Self::Server => header::AUTHORIZATION,
            Self::Proxy => header::PROXY_AUTHORIZATION,
        }
    }
}

/// The authentication scheme of a challenge, matched case-insensitively (RFC 9110 §11.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthScheme {
    /// `Basic` (RFC 7617). The only scheme this crate can answer by itself.
    Basic,
    /// `Digest` (RFC 7616).
    Digest,
    /// `Bearer` (RFC 6750).
    Bearer,
    /// SPNEGO/Kerberos (RFC 4559).
    Negotiate,
    /// Microsoft NTLM.
    Ntlm,
    /// Anything else, holding the scheme name as the server spelled it.
    Other(String),
}

impl AuthScheme {
    /// Classify a scheme name.
    pub fn parse(name: &str) -> Self {
        if name.eq_ignore_ascii_case("basic") {
            Self::Basic
        } else if name.eq_ignore_ascii_case("digest") {
            Self::Digest
        } else if name.eq_ignore_ascii_case("bearer") {
            Self::Bearer
        } else if name.eq_ignore_ascii_case("negotiate") {
            Self::Negotiate
        } else if name.eq_ignore_ascii_case("ntlm") {
            Self::Ntlm
        } else {
            Self::Other(name.to_string())
        }
    }

    /// The scheme name as it goes into the credentials header.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Basic => "Basic",
            Self::Digest => "Digest",
            Self::Bearer => "Bearer",
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
            Self::Other(name) => name,
        }
    }
}

impl fmt::Display for AuthScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One challenge from a `401`/`407` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// The hop that was challenged.
    pub url: Url,
    /// Whether the origin server or a proxy is asking.
    pub target: AuthTarget,
    /// The scheme the server offers.
    pub scheme: AuthScheme,
    /// The `realm` parameter, when present: the name of the protection space, meant to be shown
    /// to the user.
    pub realm: Option<String>,
    /// Every auth-param of the challenge, names lowercased and values unquoted, in the order
    /// they appeared. `realm` is included here too. Digest reads `nonce`, `qop`, `algorithm`,
    /// and `opaque` from this.
    pub params: Vec<(String, String)>,
    /// The token68 form of the challenge (`Negotiate <base64>`), for schemes that use it instead
    /// of parameters.
    pub token68: Option<String>,
    /// How many times this hop was already re-sent with credentials. `0` on the first challenge;
    /// a higher value means the credentials given last time were rejected.
    pub attempt: u32,
}

impl AuthChallenge {
    /// The value of an auth-param, matched case-insensitively.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The protection space this challenge belongs to, i.e. the key credentials for it are
    /// stored under.
    pub fn protection_space(&self) -> ProtectionSpace {
        ProtectionSpace {
            target: self.target,
            scheme: self.scheme.clone(),
            origin: match self.target {
                AuthTarget::Server => Some(self.url.origin().ascii_serialization()),
                // A proxy challenge says nothing about which proxy sent it, and one fetcher has
                // one proxy configuration — see `ProtectionSpace`.
                AuthTarget::Proxy => None,
            },
            realm: self.realm.clone().unwrap_or_default(),
        }
    }
}

/// The set of requests one set of credentials covers (RFC 9110 §11.5).
///
/// For a server challenge that is the challenged origin plus the realm — credentials for
/// `https://example.com` never travel to `http://example.com` or to a sibling host. For a proxy
/// challenge there is no origin: a fetcher has one proxy configuration, so proxy credentials are
/// keyed by realm alone and reused for every request that goes through it.
///
/// The scheme is part of the key: a password encoded for `Basic` is not an answer to a `Digest`
/// challenge of the same realm.
///
/// A challenge without a `realm` parameter maps to the empty realm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtectionSpace {
    /// Server or proxy credentials.
    pub target: AuthTarget,
    /// The scheme the credentials answer.
    pub scheme: AuthScheme,
    /// Serialized origin of the challenging server (`https://example.com:8443`), `None` for a
    /// proxy.
    pub origin: Option<String>,
    /// The challenge's realm, or the empty string when it named none.
    pub realm: String,
}

/// Credentials to answer a challenge with.
///
/// The `Debug` implementation redacts the secret, so these can be logged.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// Username and password, sent as `Basic base64(username:password)` (RFC 7617). The username
    /// may not contain a colon; such credentials are dropped instead of sent ambiguously.
    Basic {
        /// User name, UTF-8 encoded on the wire.
        username: String,
        /// Password, UTF-8 encoded on the wire.
        password: String,
    },
    /// A verbatim credentials header value, e.g. `"Bearer eyJ..."` or a computed
    /// `"Digest username=..., response=..."`. Dropped if it is not a valid header value.
    Raw(String),
}

impl Credentials {
    /// [`Credentials::Basic`] from anything string-shaped.
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// The `Authorization`/`Proxy-Authorization` value for these credentials, marked sensitive
    /// so it stays out of logs. `None` when they cannot be expressed as a header value.
    pub fn header_value(&self) -> Option<HeaderValue> {
        let mut value = match self {
            Self::Basic { username, password } => {
                // RFC 7617 §2: the user-id is everything before the first colon, so a colon in
                // the name would move the password boundary.
                if username.contains(':') {
                    return None;
                }
                let encoded = base64_encode(format!("{username}:{password}").as_bytes());
                HeaderValue::from_str(&format!("Basic {encoded}")).ok()?
            }
            Self::Raw(value) => HeaderValue::from_str(value).ok()?,
        };
        value.set_sensitive(true);
        Some(value)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Raw(_) => f.write_str("Raw(<redacted>)"),
        }
    }
}

/// Credentials remembered per [`ProtectionSpace`], so a realm is only asked about once.
///
/// The in-memory default is not persisted. Implement this to back it with a keychain.
/// [`credentials_for`](Self::credentials_for) is called on the request path and must not block on
/// user interaction.
pub trait CredentialStore: Send + Sync {
    /// Credentials to try for `space`, if any are known.
    fn credentials_for(&self, space: &ProtectionSpace) -> Option<Credentials>;
    /// Remember `credentials` for `space`, after a retry with them succeeded.
    ///
    /// Only called for [`Credentials::Basic`]. A [`Credentials::Raw`] answer was computed for one
    /// challenge (a Digest nonce, a Negotiate token) and is not replayed; pre-seed the store
    /// yourself for a scheme whose value is stable, such as a bearer token.
    fn store(&self, space: ProtectionSpace, credentials: Credentials);
    /// Drop what is known about `space`. Called when the server rejects the stored credentials,
    /// so that the next challenge reaches [`FetcherContext::on_auth_challenge`] again.
    ///
    /// [`FetcherContext::on_auth_challenge`]: crate::net::fetcher_context::FetcherContext::on_auth_challenge
    fn forget(&self, space: &ProtectionSpace);
}

/// In-memory [`CredentialStore`].
#[derive(Default)]
pub struct InMemoryCredentialStore {
    entries: parking_lot::Mutex<std::collections::HashMap<ProtectionSpace, Credentials>>,
}

impl InMemoryCredentialStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of protection spaces with credentials.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// True when nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Forget everything, e.g. when the user logs out or clears their session.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

impl CredentialStore for InMemoryCredentialStore {
    fn credentials_for(&self, space: &ProtectionSpace) -> Option<Credentials> {
        self.entries.lock().get(space).cloned()
    }

    fn store(&self, space: ProtectionSpace, credentials: Credentials) {
        self.entries.lock().insert(space, credentials);
    }

    fn forget(&self, space: &ProtectionSpace) {
        self.entries.lock().remove(space);
    }
}

/// Parse every challenge a `401`/`407` response offers, in the order the server listed them.
///
/// Reads all field lines of the target's challenge header. Unparsable challenges are skipped
/// instead of failing the response, since a malformed header still leaves a usable `401` for the
/// caller. Returns an empty vector when nothing could be parsed.
pub fn parse_challenges(
    headers: &HeaderMap,
    target: AuthTarget,
    url: &Url,
    attempt: u32,
) -> Vec<AuthChallenge> {
    headers
        .get_all(target.challenge_header())
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(parse_challenge_list)
        .map(|raw| AuthChallenge {
            url: url.clone(),
            target,
            scheme: AuthScheme::parse(&raw.scheme),
            realm: raw
                .params
                .iter()
                .find(|(n, _)| n == "realm")
                .map(|(_, v)| v.clone()),
            params: raw.params,
            token68: raw.token68,
            attempt,
        })
        .collect()
}

/// One challenge, still as spelled by the server.
struct RawChallenge {
    scheme: String,
    params: Vec<(String, String)>,
    token68: Option<String>,
}

/// Split a challenge header value into challenges.
///
/// The grammar is ambiguous: a comma separates both the challenges in the list and the
/// auth-params within one challenge. This walks the comma-separated elements and decides per
/// element. An element that is `name=value` (a bare token before the `=`) continues the current
/// challenge; anything else starts a new one whose first word is the scheme. Browsers resolve it
/// the same way. That covers `Basic realm="x"`, `Digest realm="x", qop="auth", nonce="..."`,
/// `Negotiate`, `Negotiate <token68>`, and several challenges side by side.
fn parse_challenge_list(value: &str) -> Vec<RawChallenge> {
    let mut out: Vec<RawChallenge> = Vec::new();

    for element in split_outside_quotes(value) {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }

        // `name=value` continues the challenge before it. Without one it is a stray parameter
        // from a malformed header, with nothing to attach it to.
        if let Some((name, val)) = as_param(element) {
            if let Some(current) = out.last_mut() {
                current.params.push((name, val));
            }
            continue;
        }

        // Otherwise: `scheme`, `scheme token68`, or `scheme first-param`.
        let (scheme, rest) = match element.find(char::is_whitespace) {
            Some(i) => (&element[..i], element[i..].trim()),
            None => (element, ""),
        };
        let mut challenge = RawChallenge {
            scheme: scheme.to_string(),
            params: Vec::new(),
            token68: None,
        };
        if !rest.is_empty() {
            match as_param(rest) {
                Some((name, val)) => challenge.params.push((name, val)),
                None => challenge.token68 = Some(rest.to_string()),
            }
        }
        out.push(challenge);
    }

    out
}

/// Read `name=value`, with optional whitespace around the `=` and a quoted or token value.
/// `None` when the text is not one, including `Basic realm="x"`, where the text before the `=`
/// is two words and so cannot be a parameter name.
fn as_param(text: &str) -> Option<(String, String)> {
    let eq = text.find('=')?;
    let name = text[..eq].trim();
    if name.is_empty() || !name.chars().all(is_token_char) {
        return None;
    }
    let raw = text[eq + 1..].trim();
    let value = if let Some(quoted) = raw.strip_prefix('"') {
        let inner = quoted.strip_suffix('"')?;
        unquote(inner)
    } else if raw.is_empty() || !raw.chars().all(is_token_char) {
        // An empty or non-token value means this is token68 padding (`Negotiate YII=`), not a
        // parameter.
        return None;
    } else {
        raw.to_string()
    };
    Some((name.to_ascii_lowercase(), value))
}

/// Resolve the `\c` escapes of a quoted-string body (RFC 9110 §5.6.4).
fn unquote(inner: &str) -> String {
    if !inner.contains('\\') {
        return inner.to_string();
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// tchar (RFC 9110 §5.6.2).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// Standard base64 with padding (RFC 4648 §4). The only thing this crate encodes is a
/// `user:password` pair, which does not warrant a dependency.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let bits = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(bits >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(bits >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(bits >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(bits & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        Url::parse("https://example.com/protected").unwrap()
    }

    fn challenges(header: &str) -> Vec<AuthChallenge> {
        let mut headers = HeaderMap::new();
        headers.append(header::WWW_AUTHENTICATE, header.parse().unwrap());
        parse_challenges(&headers, AuthTarget::Server, &url(), 0)
    }

    #[test]
    fn parses_a_basic_challenge() {
        let c = challenges(r#"Basic realm="Secure Area""#);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].scheme, AuthScheme::Basic);
        assert_eq!(c[0].realm.as_deref(), Some("Secure Area"));
        assert_eq!(c[0].param("REALM"), Some("Secure Area"));
        assert_eq!(c[0].attempt, 0);
        assert!(c[0].token68.is_none());
    }

    #[test]
    fn parses_a_digest_challenge_with_all_parameters() {
        let c = challenges(
            r#"Digest realm="test", qop="auth,auth-int", nonce="abc123", opaque="xyz", algorithm=SHA-256"#,
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].scheme, AuthScheme::Digest);
        assert_eq!(c[0].param("qop"), Some("auth,auth-int"));
        assert_eq!(c[0].param("nonce"), Some("abc123"));
        assert_eq!(c[0].param("opaque"), Some("xyz"));
        // unquoted token value
        assert_eq!(c[0].param("algorithm"), Some("SHA-256"));
    }

    #[test]
    fn parses_several_challenges_side_by_side() {
        let c = challenges(r#"Digest realm="d", nonce="n", Basic realm="b""#);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].scheme, AuthScheme::Digest);
        assert_eq!(c[0].param("nonce"), Some("n"));
        assert_eq!(c[1].scheme, AuthScheme::Basic);
        assert_eq!(c[1].realm.as_deref(), Some("b"));
    }

    #[test]
    fn parses_schemes_without_parameters_and_with_token68() {
        let c = challenges("Negotiate, NTLM");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].scheme, AuthScheme::Negotiate);
        assert!(c[0].params.is_empty());
        assert_eq!(c[1].scheme, AuthScheme::Ntlm);

        let c = challenges("Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSg==");
        assert_eq!(c.len(), 1);
        assert_eq!(
            c[0].token68.as_deref(),
            Some("YIIFxAYGKwYBBQUCoIIFuDCCBbSg==")
        );
        assert!(c[0].params.is_empty());
    }

    #[test]
    fn a_comma_inside_a_quoted_realm_does_not_split_the_challenge() {
        let c = challenges(r#"Basic realm="one, two""#);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].realm.as_deref(), Some("one, two"));
    }

    #[test]
    fn quoted_escapes_are_resolved() {
        let c = challenges(r#"Basic realm="say \"hi\"""#);
        assert_eq!(c[0].realm.as_deref(), Some(r#"say "hi""#));
    }

    #[test]
    fn whitespace_around_the_equals_sign_is_allowed() {
        let c = challenges(r#"Digest realm = "test" , qop = auth"#);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].realm.as_deref(), Some("test"));
        assert_eq!(c[0].param("qop"), Some("auth"));
    }

    #[test]
    fn scheme_names_are_case_insensitive_but_unknown_ones_are_kept_verbatim() {
        assert_eq!(
            challenges(r#"bAsIc realm="x""#)[0].scheme,
            AuthScheme::Basic
        );
        let c = challenges("Mutual-v1 sid=1");
        assert_eq!(c[0].scheme, AuthScheme::Other("Mutual-v1".into()));
        assert_eq!(c[0].scheme.as_str(), "Mutual-v1");
    }

    #[test]
    fn challenges_from_separate_field_lines_are_all_returned() {
        let mut headers = HeaderMap::new();
        headers.append(header::WWW_AUTHENTICATE, "Negotiate".parse().unwrap());
        headers.append(
            header::WWW_AUTHENTICATE,
            r#"Basic realm="x""#.parse().unwrap(),
        );
        let c = parse_challenges(&headers, AuthTarget::Server, &url(), 1);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].scheme, AuthScheme::Negotiate);
        assert_eq!(c[1].scheme, AuthScheme::Basic);
        assert!(c.iter().all(|c| c.attempt == 1));
    }

    #[test]
    fn a_response_without_a_challenge_header_yields_nothing() {
        assert!(parse_challenges(&HeaderMap::new(), AuthTarget::Server, &url(), 0).is_empty());
        // A stray parameter has no challenge to belong to.
        assert!(challenges(r#"realm="x""#).is_empty());
    }

    #[test]
    fn proxy_challenges_come_from_the_proxy_authenticate_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::PROXY_AUTHENTICATE,
            r#"Basic realm="corp""#.parse().unwrap(),
        );
        assert!(parse_challenges(&headers, AuthTarget::Server, &url(), 0).is_empty());
        let c = parse_challenges(&headers, AuthTarget::Proxy, &url(), 0);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].target, AuthTarget::Proxy);
    }

    #[test]
    fn protection_space_is_per_origin_for_a_server_and_shared_for_a_proxy() {
        let server = challenges(r#"Basic realm="Secure Area""#)[0].protection_space();
        assert_eq!(
            server,
            ProtectionSpace {
                target: AuthTarget::Server,
                scheme: AuthScheme::Basic,
                origin: Some("https://example.com".into()),
                realm: "Secure Area".into(),
            }
        );

        // Same realm, other scheme: a different space.
        let digest = challenges(r#"Digest realm="Secure Area", nonce="n""#)[0].protection_space();
        assert_ne!(digest, server);

        // Same host over plain http is a different space.
        let insecure = AuthChallenge {
            url: Url::parse("http://example.com/protected").unwrap(),
            ..challenges(r#"Basic realm="Secure Area""#).remove(0)
        };
        assert_ne!(insecure.protection_space(), server);

        let mut headers = HeaderMap::new();
        headers.append(header::PROXY_AUTHENTICATE, "Basic".parse().unwrap());
        let proxy = parse_challenges(&headers, AuthTarget::Proxy, &url(), 0)[0].protection_space();
        assert_eq!(proxy.origin, None);
        assert_eq!(proxy.realm, "");
    }

    #[test]
    fn target_maps_status_codes_and_headers() {
        assert_eq!(AuthTarget::for_status(401), Some(AuthTarget::Server));
        assert_eq!(AuthTarget::for_status(407), Some(AuthTarget::Proxy));
        assert_eq!(AuthTarget::for_status(403), None);
        assert_eq!(AuthTarget::for_status(200), None);
        assert_eq!(
            AuthTarget::Proxy.credentials_header(),
            header::PROXY_AUTHORIZATION
        );
        assert_eq!(
            AuthTarget::Server.credentials_header(),
            header::AUTHORIZATION
        );
    }

    #[test]
    fn basic_credentials_are_base64_of_user_colon_password() {
        // RFC 7617 §2 example.
        let value = Credentials::basic("Aladdin", "open sesame")
            .header_value()
            .unwrap();
        assert_eq!(value, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(value.is_sensitive());
    }

    #[test]
    fn base64_matches_the_rfc4648_test_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input}");
        }
        // Non-ASCII passwords go out as UTF-8.
        assert_eq!(base64_encode("é".as_bytes()), "w6k=");
    }

    #[test]
    fn credentials_that_cannot_be_a_header_value_are_dropped() {
        // A colon in the user-id would move the password boundary.
        assert!(Credentials::basic("a:b", "pw").header_value().is_none());
        assert!(Credentials::Raw("Bearer bad\nvalue".into())
            .header_value()
            .is_none());
        assert_eq!(
            Credentials::Raw("Bearer token".into())
                .header_value()
                .unwrap(),
            "Bearer token"
        );
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let debug = format!("{:?}", Credentials::basic("alice", "hunter2"));
        assert!(debug.contains("alice"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!format!("{:?}", Credentials::Raw("Bearer s3cret".into())).contains("s3cret"));
    }

    #[test]
    fn the_in_memory_store_round_trips_and_forgets() {
        let store = InMemoryCredentialStore::new();
        let space = challenges(r#"Basic realm="x""#)[0].protection_space();
        assert!(store.is_empty());
        assert!(store.credentials_for(&space).is_none());

        store.store(space.clone(), Credentials::basic("u", "p"));
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.credentials_for(&space),
            Some(Credentials::basic("u", "p"))
        );

        store.forget(&space);
        assert!(store.credentials_for(&space).is_none());
        store.store(space, Credentials::basic("u", "p"));
        store.clear();
        assert!(store.is_empty());
    }
}

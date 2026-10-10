//! Integration trait for wiring the fetcher into an application.

use crate::net::auth::{AuthChallenge, Credentials};
use crate::net::null_emitter::NullEmitter;
use crate::net::observer::NetObserver;
use crate::net::request_ref::RequestReference;
use crate::net::tls::TlsError;
use crate::net::types::{Initiator, ResourceKind};
use crate::types::RequestId;
use http::Method;
use std::sync::Arc;
use url::Url;

/// One hop of a request, as [`FetcherContext::cookies_for_hop`] sees it: what a jar needs to
/// decide which `SameSite` cookies the hop may carry.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CookieHop<'a> {
    /// The URL this hop goes to.
    pub url: &'a Url,
    /// The hop's method. A redirect may have changed it: a `303`, and a `301` or `302` after a
    /// `POST`, turn it into `GET`; a `307` or `308` keeps it.
    pub method: &'a Method,
    /// The URLs the request went to before this hop, oldest first; empty on the first hop.
    pub url_list: &'a [Url],
}

impl<'a> CookieHop<'a> {
    /// A hop to `url` with `method`, after the hops at `url_list`.
    pub fn new(url: &'a Url, method: &'a Method, url_list: &'a [Url]) -> Self {
        Self {
            url,
            method,
            url_list,
        }
    }
}

/// Abstracts the engine-side plumbing the Fetcher needs: observer creation and reference lifecycle.
/// Implement this in the engine to wire up event routing without the net crate depending on
/// engine-specific types like TabId or EventChannel.
pub trait FetcherContext: Send + Sync {
    /// Return an observer to emit NetEvents for this specific request.
    fn observer_for(
        &self,
        reference: RequestReference,
        req_id: RequestId,
        kind: ResourceKind,
        initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync>;

    /// Called once when the Fetcher becomes the leader for a new unique fetch.
    fn on_ref_active(&self, reference: RequestReference);

    /// Called once when all subscribers for a fetch are done and the entry can be cleaned up.
    fn on_ref_done(&self, reference: RequestReference);

    /// Return `false` to block a URL before it is fetched.
    ///
    /// Called for the initial request URL and for every redirect target. Override to implement
    /// SSRF protection, allowlists, or blocklists. The default allows all URLs.
    fn is_url_allowed(&self, _url: &Url) -> bool {
        true
    }

    /// Return the cookies to send with a request to `url`.
    ///
    /// The returned string must be in `Cookie` header format: `"name=value; name2=value2"`.
    /// Called at the start of every request hop (including redirect targets after cross-origin
    /// cookie stripping). Returning `None` sends no cookie header for that hop.
    ///
    /// `reference` is the request's [`FetchRequest::reference`](crate::net::types::FetchRequest),
    /// so a host with more than one jar (one per tab, profile or partition) can answer from the
    /// right one. Requests share a response while cookies ride along only when
    /// [`cookie_jar_key`](Self::cookie_jar_key) says they use the same jar, so one jar's cookies
    /// cannot reach another's request through coalescing.
    ///
    /// The default returns `None` (no cookies injected).
    fn cookies_for(&self, _reference: RequestReference, _url: &Url) -> Option<String> {
        None
    }

    /// Return the cookies to send with one hop of a request: what the fetcher calls at the
    /// start of every hop.
    ///
    /// Override this rather than [`cookies_for`](Self::cookies_for) to judge `SameSite` the way
    /// RFC 6265bis does: the hop's [`method`](CookieHop::method) decides whether `Lax` cookies
    /// ride on a cross-site navigation (only a safe one), and its
    /// [`url_list`](CookieHop::url_list) is the chain so far, which a redirect through another
    /// site makes cross-site for the rest of it.
    ///
    /// The default asks [`cookies_for`](Self::cookies_for) with the hop's URL.
    fn cookies_for_hop(&self, reference: RequestReference, hop: &CookieHop<'_>) -> Option<String> {
        self.cookies_for(reference, hop.url)
    }

    /// Called for every response carrying `Set-Cookie` headers, redirect hops included, when
    /// the request's credentials mode attached cookies to that hop. A `credentials: omit`
    /// request never reaches this.
    ///
    /// `reference` is the request's, as for [`cookies_for`](Self::cookies_for). `url` is the URL
    /// of the hop that sent them. `values` is the slice of raw `Set-Cookie` header values from
    /// the response — one entry per header line.
    ///
    /// The default implementation does nothing.
    fn on_cookies_received(&self, _reference: RequestReference, _url: &Url, _values: &[&str]) {}

    /// Which jar the cookie hooks answer `reference` from, as far as sharing a response goes:
    /// two requests for the same thing that may carry cookies are coalesced into one fetch only
    /// when this is equal for both. Equal must mean the hooks give both the same answers.
    ///
    /// The default is the reference itself, so no two references share: safe for a host with a
    /// jar per reference that does not override this. A host with one jar, or none, returns a
    /// constant and gets coalescing across references back.
    fn cookie_jar_key(&self, reference: RequestReference) -> String {
        reference.to_string()
    }

    /// Whether to accept a certificate that failed verification.
    ///
    /// Only called when [`FetcherConfig::tls_overrides`] is set and the store doesn't already
    /// accept the certificate. Returning `true` accepts it for `error.host` and adds it to the
    /// store. This is called synchronously during the handshake, so don't block on a dialog
    /// here; for the interactive case return `false`, show the error, and when the user clicks
    /// through call [`TlsOverrideStore::accept`] with `error.fingerprint` and retry.
    ///
    /// Default: `false`.
    ///
    /// [`FetcherConfig::tls_overrides`]: crate::net::fetcher::FetcherConfig::tls_overrides
    /// [`TlsOverrideStore::accept`]: crate::net::tls::TlsOverrideStore::accept
    fn tls_override(&self, _error: &TlsError) -> bool {
        false
    }

    /// Credentials to answer an authentication challenge with, or `None` to let the `401`/`407`
    /// reach the caller.
    ///
    /// Called for each challenge of a challenged hop, in the order the server listed them, until
    /// one returns credentials. Returning `None` for a scheme you cannot answer therefore offers
    /// the next challenge. Only reached after [`FetcherConfig::credentials`] had no entry for the
    /// challenge's [`ProtectionSpace`]; what is returned here is stored there once the retry
    /// succeeds. `challenge.attempt` counts the credentials this hop already had rejected.
    ///
    /// Like [`tls_override`](Self::tls_override) this is called on the request path and must not
    /// block on a password dialog. Return `None`, show the dialog, and then either put the answer
    /// in the credential store or re-submit the fetch.
    ///
    /// Default: `None`, the behaviour of a fetcher without authentication support.
    ///
    /// [`FetcherConfig::credentials`]: crate::net::fetcher::FetcherConfig::credentials
    /// [`ProtectionSpace`]: crate::net::auth::ProtectionSpace
    fn on_auth_challenge(&self, _challenge: &AuthChallenge) -> Option<Credentials> {
        None
    }
}

/// A no-op [`FetcherContext`] for consumers that don't need lifecycle hooks.
///
/// Ignores all events (via [`NullEmitter`]), allows every URL, and has no cookie jar.
/// Use this to get a [`Fetcher`](crate::net::fetcher::Fetcher) running without writing
/// any integration code:
///
/// ```ignore
/// let fetcher = Fetcher::new(FetcherConfig::default(), Arc::new(NullContext))?;
/// ```
pub struct NullContext;

impl FetcherContext for NullContext {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
    // No jar, so every reference gets the same cookies: none.
    fn cookie_jar_key(&self, _: RequestReference) -> String {
        String::new()
    }
}

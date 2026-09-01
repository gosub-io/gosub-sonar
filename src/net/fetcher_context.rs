//! Integration trait for wiring the fetcher into an application.

use crate::net::auth::{AuthChallenge, Credentials};
use crate::net::null_emitter::NullEmitter;
use crate::net::observer::NetObserver;
use crate::net::request_ref::RequestReference;
use crate::net::tls::TlsError;
use crate::net::types::{Initiator, ResourceKind};
use crate::types::RequestId;
use std::sync::Arc;
use url::Url;

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
    /// The default returns `None` (no cookies injected).
    fn cookies_for(&self, _url: &Url) -> Option<String> {
        None
    }

    /// Called once after every successful HTTP response that carries `Set-Cookie` headers.
    ///
    /// `url` is the **final** URL (after redirects). `values` is the slice of raw
    /// `Set-Cookie` header values from the response — one entry per header line.
    ///
    /// The default implementation does nothing.
    fn on_cookies_received(&self, _url: &Url, _values: &[&str]) {}

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
}

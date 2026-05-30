//! Integration trait for wiring the fetcher into an application.

use crate::net::observer::NetObserver;
use crate::net::request_ref::RequestReference;
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
}

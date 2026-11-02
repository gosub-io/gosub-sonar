//! The fetcher on wasm32: the browser's `fetch()` owns proxies, HSTS and its cache, so the
//! items `native.rs` has for those are here and do nothing.

use super::{Fetcher, FetcherConfig};
use crate::net::fetch::NetPolicy;
use crate::net::fetcher_context::FetcherContext;
use crate::net::types::FetchRequest;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// What the client was built with that a request's policy has to agree with, taken when
/// it was built rather than looked up again per request, and where a request's policy leaves
/// the background revalidations it starts.
pub(super) struct ClientsBuilt;

impl ClientsBuilt {
    pub(super) fn new(_cfg: &FetcherConfig) -> Self {
        ClientsBuilt
    }
}

impl Fetcher {
    /// No cache, so no revalidations to queue.
    pub(super) async fn queue_revalidations(&self) {}

    /// Waits until a request is submitted, or `shutdown`.
    pub(super) async fn wait_for_work(&self, shutdown: &CancellationToken) {
        tokio::select! {
            _ = self.wake.notified() => {},
            _ = shutdown.cancelled() => {},
        }
    }

    /// The browser applies HSTS itself.
    pub(super) fn hsts_upgrade(&self, _req: &mut FetchRequest) {}
}

/// The browser's `fetch()` has no separate deadline for headers.
pub(super) const HEADERS_DEADLINE: bool = false;

/// The client the browser's `fetch()` stands behind.
pub(super) fn build_client(
    cfg: &FetcherConfig,
    _ctx: &Arc<dyn FetcherContext>,
    _built: &ClientsBuilt,
) -> anyhow::Result<reqwest::Client> {
    // The browser's fetch() owns TLS, connection management, timeouts, proxying, and transparent
    // decompression; none of the tuning knobs below exist in reqwest's wasm backend.
    //
    // It also owns redirects: there is no way to ask for them un-followed, so on wasm32
    // `get_with_redirects` only ever sees the final response and the per-hop checks run once,
    // on the initial URL. The browser applies its own mixed content blocking to the hops we
    // cannot see, so this is a loss of reporting rather than of enforcement.
    let mut b = reqwest::Client::builder();
    if let Some(ref ua) = cfg.user_agent {
        b = b.user_agent(ua);
    }
    Ok(b.build()?)
}

/// No proxies, resolver, HSTS, TLS overrides or cache to hook in.
pub(super) fn native_policy(
    policy: NetPolicy,
    _req: &FetchRequest,
    _cfg: &FetcherConfig,
    _built: &Arc<ClientsBuilt>,
) -> NetPolicy {
    policy
}

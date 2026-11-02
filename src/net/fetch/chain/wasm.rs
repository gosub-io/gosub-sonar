//! The redirect chain on wasm32: the browser's `fetch()` applies HSTS, CORS, its cache and its
//! proxies itself, so the items `native.rs` has for those are here and do nothing.

use super::HopChain;
use crate::net::fetch::{HopResponse, NetPolicy, PendingStore, RequestInit, Revalidation};
use crate::net::fetch_metadata::SecFetchSite;
use crate::net::observer::NetObserver;
use crate::net::types::NetError;
use http::HeaderMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// What every hop of a chain is fetched with.
pub(super) struct ChainEnv<'a> {
    pub(super) client: &'a reqwest::Client,
    // Without the method, headers, body and revalidation: those went into the `HopChain`.
    pub(super) init: &'a RequestInit,
    pub(super) cancel: &'a CancellationToken,
    pub(super) observer: &'a Arc<dyn NetObserver + Send + Sync>,
    pub(super) policy: &'a NetPolicy,
}

impl<'a> ChainEnv<'a> {
    /// The env for a chain; `resumed` says whether it is a background revalidation.
    pub(super) fn new(
        client: &'a reqwest::Client,
        init: &'a RequestInit,
        cancel: &'a CancellationToken,
        observer: &'a Arc<dyn NetObserver + Send + Sync>,
        policy: &'a NetPolicy,
        _resumed: bool,
    ) -> Self {
        ChainEnv {
            client,
            init,
            cancel,
            observer,
            policy,
        }
    }
}

/// What the stages before a hop's send worked out for it.
pub(super) struct HopPlan {
    pub(super) attach_credentials: bool,
}

/// The response a hop got.
pub(super) struct HopExchange {
    pub(super) response: HopResponse,
}

impl HopExchange {
    pub(super) fn new(response: HopResponse, _timing: Timing) -> Self {
        HopExchange { response }
    }
}

/// When a send was made: only the cache asks, and there is none here.
pub(super) struct Timing;

impl Timing {
    pub(super) fn requested() -> Self {
        Timing
    }

    pub(super) fn received(&mut self) {}
}

impl HopChain {
    pub(super) fn revalidation_start(&self, _env: &ChainEnv<'_>) -> Option<Revalidation> {
        None
    }

    pub(super) fn apply_hsts(&mut self, _env: &ChainEnv<'_>) -> Option<Url> {
        None
    }

    pub(super) async fn check_ip_literal(&self, _env: &ChainEnv<'_>) -> Result<(), NetError> {
        Ok(())
    }

    pub(super) async fn preflight(
        &self,
        _env: &ChainEnv<'_>,
        _hop_site: SecFetchSite,
    ) -> Result<Option<Infallible>, NetError> {
        Ok(None)
    }

    pub(super) fn plan(
        &self,
        _env: &ChainEnv<'_>,
        attach_credentials: bool,
        _preflight: Option<Infallible>,
        _revalidation: Option<Revalidation>,
    ) -> Result<HopPlan, NetError> {
        Ok(HopPlan { attach_credentials })
    }

    /// No cache on wasm32, so every hop goes out as it is.
    pub(super) async fn exchange(
        &self,
        env: &ChainEnv<'_>,
        plan: &mut HopPlan,
    ) -> Result<HopExchange, NetError> {
        self.send(env, plan).await
    }

    pub(super) fn revalidated(
        &self,
        _env: &ChainEnv<'_>,
        _plan: &mut HopPlan,
        _resp: &reqwest::Response,
        _timing: &Timing,
    ) -> Option<ControlFlow<HopResponse>> {
        None
    }

    pub(super) fn challenge_proxy(&self, _env: &ChainEnv<'_>) -> Option<Url> {
        None
    }

    pub(super) fn add_send_headers(
        &self,
        _env: &ChainEnv<'_>,
        _plan: &HopPlan,
        _hop_headers: &mut HeaderMap,
    ) {
    }

    pub(super) fn order_headers(
        &self,
        _env: &ChainEnv<'_>,
        request: reqwest::Request,
    ) -> reqwest::Request {
        request
    }

    pub(super) fn check_response(
        &self,
        _env: &ChainEnv<'_>,
        _plan: &mut HopPlan,
        _resp: &reqwest::Response,
    ) -> Result<(), NetError> {
        Ok(())
    }

    pub(super) fn invalidate_cache(
        &self,
        _env: &ChainEnv<'_>,
        _hop: &HopResponse,
        _plan: &HopPlan,
    ) {
    }

    pub(super) fn pending_store(
        &self,
        _env: &ChainEnv<'_>,
        _plan: &HopPlan,
        _exchange: &HopExchange,
        _peer_addr: Option<SocketAddr>,
    ) -> Option<PendingStore> {
        None
    }
}

pub(super) fn client_deadline(
    _env: &ChainEnv<'_>,
    req_builder: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    req_builder
}

/// reqwest's wasm Response has no version().
pub(super) fn report_protocol(_env: &ChainEnv<'_>, _resp: &reqwest::Response) {}

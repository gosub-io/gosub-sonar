//! The fetch layer on wasm32: the browser's `fetch()` caches, decodes and connects itself, so
//! the items `native.rs` has for those are here and do nothing. `PendingStore` and
//! `CacheCollector` have no values at all: nothing is ever stored.

use super::NetPolicy;
use crate::net::observer::NetObserver;
use crate::net::types::NetError;
use bytes::Bytes;
use futures_util::stream::LocalBoxStream;
use futures_util::{Stream, StreamExt};
use http::HeaderMap;
use std::convert::Infallible;
use std::sync::Arc;
use url::Url;

/// A storable response; there are none without a cache.
pub(crate) enum PendingStore {}

impl PendingStore {
    pub(crate) fn max_bytes(&self) -> usize {
        match *self {}
    }

    pub(crate) fn decoded(self, _decoded: bool) -> Self {
        match self {}
    }

    pub(crate) fn commit(self, _body: Bytes, _observer: &Arc<dyn NetObserver + Send + Sync>) {
        match self {}
    }
}

/// A body copied for the cache; there are none without a cache.
pub(super) enum CacheCollector {}

impl CacheCollector {
    pub(super) fn new(store: PendingStore, _prefix: &[u8]) -> Self {
        match store {}
    }

    pub(super) fn feed(&mut self, _chunk: &[u8]) {
        match *self {}
    }

    pub(super) fn commit(&mut self, _observer: &Arc<dyn NetObserver + Send + Sync>) {
        match *self {}
    }
}

/// A response body as the fetch layer passes it on. reqwest's wasm body stream is `!Send`
/// (single thread), so it is boxed without the `Send` bound.
pub(super) type BodyStream = LocalBoxStream<'static, Result<Bytes, NetError>>;

pub(super) fn boxed<S>(stream: S) -> BodyStream
where
    S: Stream<Item = Result<Bytes, NetError>> + 'static,
{
    stream.boxed_local()
}

/// The browser decodes bodies before they get here.
pub(super) fn decoding(
    _auto_decode: bool,
    _bodiless: bool,
    headers: HeaderMap,
    content_length: Option<u64>,
) -> (Option<Infallible>, HeaderMap, Option<u64>) {
    (None, headers, content_length)
}

pub(super) fn decode<S>(body_stream: S, _codings: Option<Infallible>) -> BodyStream
where
    S: Stream<Item = Result<Bytes, NetError>> + 'static,
{
    body_stream.boxed_local()
}

/// The browser reports TLS and proxy failures as plain network errors.
pub(super) fn classify_send_error(
    _e: &reqwest::Error,
    _url: &Url,
    _observer: &Arc<dyn NetObserver + Send + Sync>,
    _policy: &NetPolicy,
) -> Option<NetError> {
    None
}

/// The browser does not say which peer a response came from.
pub(super) fn origin_peer(
    _resp: &reqwest::Response,
    _url: &Url,
    _policy: &NetPolicy,
) -> Option<std::net::SocketAddr> {
    None
}

//! The simple helpers on wasm32: the browser's `fetch()` owns TLS, timeouts, redirects,
//! proxying and decoding, and there is no filesystem, so the items `native.rs` has for those
//! are here and do nothing.

use super::SimpleOptions;
use anyhow::Result;
use bytes::Bytes;
use futures_util::Stream;
use http::HeaderMap;
use url::Url;

/// The `User-Agent` sent unless one was set by hand: `user_agent`, else the browser's own.
pub(super) fn user_agent(user_agent: Option<&str>) -> Option<&str> {
    user_agent
}

/// The browser sets `Accept-Encoding`, and decodes.
pub(super) fn accept_encoding(_headers: &mut HeaderMap) {}

/// reqwest's wasm backend has headers and nothing else.
pub(super) fn configure(
    _opts: &SimpleOptions,
    b: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    Ok(b)
}

/// No filesystem: `file:` is an unsupported scheme.
pub(super) async fn read_file(_url: &Url, _max_body: u64) -> Result<Bytes> {
    anyhow::bail!("Unsupported URL scheme: file")
}

/// The browser decodes bodies before they get here.
pub(super) fn decoded(
    resp: reqwest::Response,
) -> (
    HeaderMap,
    impl Stream<Item = reqwest::Result<Bytes>> + Unpin,
) {
    (resp.headers().clone(), resp.bytes_stream())
}

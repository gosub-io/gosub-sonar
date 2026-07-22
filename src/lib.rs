//! Browser-agnostic HTTP/HTTPS fetching library.
//!
//! Two APIs are available depending on how much control you need:
//!
//! - [`simple_get`] — one-shot GET, no setup required.
//! - [`Fetcher`] — priority-scheduled fetcher with request coalescing,
//!   per-origin concurrency limits, and fan-out to multiple subscribers.
//!
//! For the full scheduler, implement [`FetcherContext`] to receive lifecycle callbacks,
//! or use [`NullContext`] if you don't need any:
//!
//! ```no_run
//! use std::sync::Arc;
//! use gosub_sonar::{FetchRequest, Fetcher, FetcherConfig, NullContext};
//! use http::Method;
//! use tokio_util::sync::CancellationToken;
//! use url::Url;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), Arc::new(NullContext))?);
//!
//! let shutdown = CancellationToken::new();
//! tokio::spawn({
//!     let f = fetcher.clone();
//!     let cancel = shutdown.clone();
//!     async move { f.run(cancel).await }
//! });
//!
//! let req = FetchRequest::builder(Method::GET, Url::parse("https://example.org")?).build();
//! let result = fetcher.fetch(req).await;
//! # Ok(())
//! # }
//! ```
//!
//! The most common types are re-exported at the crate root; the full API remains
//! available under [`net`].
//!
//! # Examples
//!
//! Runnable examples are in the `examples/` directory:
//!
//! - `simple_fetch` — one-shot GET using [`simple_get`]
//! - `fetcher` — minimal [`Fetcher`] setup with a no-op context
//! - `fetcher_harness` — self-contained harness covering concurrency, coalescing, priority, cancellation, and errors

#![forbid(unsafe_code)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::dbg_macro)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod http;
pub mod net;
pub mod types;

pub use net::events::NetEvent;
pub use net::fetcher::{Fetcher, FetcherConfig};
pub use net::fetcher_context::{FetcherContext, NullContext};
#[cfg(not(target_arch = "wasm32"))]
pub use net::hsts::{HstsEntry, HstsStore, InMemoryHstsStore};
pub use net::mixed_content::MixedContentPolicy;
pub use net::null_emitter::NullEmitter;
pub use net::observer::NetObserver;
#[cfg(not(target_arch = "wasm32"))]
pub use net::proxy::{ProxyAuth, ProxyConfig, ProxyRule, ProxyScope};
pub use net::referrer::ReferrerPolicy;
pub use net::request_ref::RequestReference;
pub use net::shared_body::SharedBody;
pub use net::simple::simple_get;
#[cfg(not(target_arch = "wasm32"))]
pub use net::simple::{sync_fetch, sync_get};
pub use net::types::{
    BlockReason, BoxedAsyncRead, FetchRequest, FetchRequestBuilder, FetchResult, FetchResultMeta,
    Initiator, NetError, Priority, RequestBody, ResourceKind,
};
pub use types::{PeekBuf, RequestId};

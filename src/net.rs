//! Async HTTP/HTTPS fetching stack.
//!
//! See [`simple::simple_get`] for one-shot requests and [`fetcher::Fetcher`] for the
//! full priority scheduler. Implement [`fetcher_context::FetcherContext`] to hook into
//! the fetch lifecycle, or use [`fetcher_context::NullContext`] if you don't need to.

/// In-process mock HTTP server, available to this crate's tests and — behind the
/// `test-support` cargo feature — to downstream integration tests and examples.
/// Native-only: the mock server listens on a real TCP socket.
#[cfg(all(any(test, feature = "test-support"), not(target_arch = "wasm32")))]
pub mod test_support;

pub mod events;
pub mod fetch;
pub mod fetcher;
pub mod fetcher_context;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod fs_utils;
/// HTTP Strict Transport Security. Native-only: on wasm32 the browser's fetch() applies its own
/// HSTS, and CORS filtering hides the `Strict-Transport-Security` response header from us anyway.
#[cfg(not(target_arch = "wasm32"))]
pub mod hsts;
pub mod null_emitter;
pub mod observer;
#[cfg(not(target_arch = "wasm32"))]
pub mod pump;
pub mod request_ref;
pub mod shared_body;
pub mod simple;
pub mod types;
pub(crate) mod utils;

//! Async HTTP/HTTPS fetching stack.
//!
//! See [`simple::simple_get`] for one-shot requests and [`fetcher::Fetcher`] for the
//! full priority scheduler. Implement [`fetcher_context::FetcherContext`] to hook into
//! the fetch lifecycle, or use [`fetcher_context::NullContext`] if you don't need to.

/// In-process mock HTTP server, available to this crate's tests and — behind the
/// `test-support` cargo feature — to downstream integration tests and examples.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub mod events;
pub mod fetch;
pub mod fetcher;
pub mod fetcher_context;
pub(crate) mod fs_utils;
pub mod null_emitter;
pub mod observer;
pub mod pump;
pub mod request_ref;
pub mod shared_body;
pub mod simple;
pub mod types;
pub(crate) mod utils;

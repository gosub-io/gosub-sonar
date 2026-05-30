//! Async HTTP/HTTPS fetching stack.
//!
//! See [`simple::simple_get`] for one-shot requests and [`fetcher::Fetcher`] for the
//! full priority scheduler. Implement [`fetcher_context::FetcherContext`] to hook into
//! the fetch lifecycle, or use [`null_emitter::NullEmitter`] to ignore events.

#[cfg(test)]
pub mod test_support;

pub mod events;
pub mod fetch;
pub mod fetcher;
pub mod fetcher_context;
pub mod fs_utils;
pub mod null_emitter;
pub mod observer;
pub mod pump;
pub mod request_ref;
pub mod shared_body;
pub mod simple;
pub mod types;
pub mod utils;

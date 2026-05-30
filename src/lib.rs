//! Browser-agnostic HTTP/HTTPS fetching library.
//!
//! Two APIs are available depending on how much control you need:
//!
//! - [`net::simple::simple_get`] — one-shot GET, no setup required.
//! - [`net::fetcher::Fetcher`] — priority-scheduled fetcher with request coalescing,
//!   per-origin concurrency limits, and fan-out to multiple subscribers.
//!
//! For the full scheduler, implement [`net::fetcher_context::FetcherContext`] to receive
//! lifecycle callbacks, or use [`net::null_emitter::NullEmitter`] to ignore them.
//!
//! # Examples
//!
//! Runnable examples are in the `examples/` directory:
//!
//! - `simple_fetch` — one-shot GET using [`net::simple::simple_get`]
//! - `fetcher` — minimal [`net::fetcher::Fetcher`] setup with a no-op context
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

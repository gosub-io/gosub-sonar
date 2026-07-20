# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tests/e2e.rs`: integration tests exercising the crate through its public API
  only, as a downstream consumer would — including an externally implemented
  `FetcherContext`. Gated on the `test-support` feature; CI now enables it.
- `NetEvent` is re-exported at the crate root; implementing `NetObserver`
  previously required the `net::events` path.

## [0.1.0] - 2026-07-04

Initial release. gosub-sonar is the network stack of the [Gosub](https://gosub.io)
browser engine, extracted into a standalone, browser-agnostic crate.

### Added

- `Fetcher` — priority-scheduled fetcher with:
  - four priority lanes (`High`, `Normal`, `Low`, `Idle`) dequeued via weighted
    round-robin, so lower priorities never starve
  - request coalescing: identical in-flight GET/HEAD requests share one HTTP
    request, with fan-out of the response to all subscribers
  - global and per-origin concurrency limits (separate HTTP/1.1 and HTTP/2 caps)
  - per-subscriber cancellation (`fetch_with_cancel`); the underlying request is
    aborted once all subscribers cancel
  - buffered and streaming response bodies (`FetchResult::Buffered` / `Stream`),
    with a peek buffer for content-type sniffing and an optional `max_bytes` cap
- `FetcherContext` trait for lifecycle integration: URL filtering (scheme
  allowlist / SSRF policy), cookie jar hooks (`cookies_for`,
  `on_cookies_received`, including on intermediate redirect hops), and observer
  selection per request; `NullContext` for when none of this is needed
- `FetchRequest` builder: method, headers, body, priority, initiator, resource
  kind, streaming, auto-decode, and byte-limit settings
- Request bodies (`RequestBody::bytes` / `json` / `form` / `text`) with redirect
  method semantics per RFC 7231 §6.4
- Content decoding (gzip, brotli, deflate) behind a per-request `auto_decode` flag
- Redirect handling with a hop limit, plus typed `NetError` variants
  (reqwest, redirect, I/O, cancelled, read, timeout)
- `NetObserver` / `NetEvent` — progress, redirect, header, and completion events
  for every request
- Simple one-shot API: async `simple_get`, blocking `sync_get` (bytes), and
  blocking `sync_fetch` (full `Response` with status, headers, and cookies)
- `test-support` cargo feature: in-process mock HTTP server (`TestServer`) with
  configurable per-route behaviours (delays, mid-body stalls, connection drops,
  redirect loops, chunked bodies, gzip) for downstream integration tests
- Runnable examples: `simple_fetch`, `fetcher`, and `fetcher_harness`
- No unsafe code (`#![forbid(unsafe_code)]`); full public-API documentation

[Unreleased]: https://github.com/gosub-io/gosub-sonar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gosub-io/gosub-sonar/releases/tag/v0.1.0

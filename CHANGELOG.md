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
- HTTP Strict Transport Security (RFC 6797, dynamic part): a `Strict-Transport-Security`
  header received over HTTPS is recorded, and later `http://` requests to that host are
  rewritten to `https://` before any connection is opened. Enabled by default via
  `FetcherConfig::hsts`, which holds an `InMemoryHstsStore` unless you supply your own
  `HstsStore`; set it to `None` to disable HSTS (e.g. for private browsing). The crate owns
  the protocol — header parsing, `includeSubDomains` matching, expiry, and the URL rewrite —
  so a store only has to behave like a map. No preload list. Native-only: on wasm32 the
  browser's `fetch()` applies its own HSTS.
- `NetPolicy::with_hsts` for callers using the low-level `fetch` API directly.
- Streaming uploads: `RequestBody::stream` takes a reader factory (opened once
  per send attempt, so 307/308 redirects can replay the body), and
  `RequestBody::file` streams a file from disk without buffering it. Native
  targets only.
- Connection-pool tuning in `FetcherConfig`: `pool_max_idle_per_host`
  (default 6), `pool_idle_timeout` (default 90s), and `tcp_keepalive`
  (default 60s). Previously reqwest's defaults applied: an unbounded idle
  pool and no keepalive.
- `test-support`: the mock server can now serve HTTPS — `TestServer::tls(domain)` with
  `TestServerHandle::{cert_pem, socket_addr, tls_domain}` — `RouteConfig::ok_with_headers`
  responds 200 with arbitrary extra response headers, and `RouteConfig::redirect_307`
  issues a 307 that preserves the method and body.
- Mixed content blocking (#5) — insecure sub-resources requested by a secure
  document are blocked, or upgraded to `https`, at every redirect hop:
  - `net::mixed_content` — `MixedContentPolicy` (`Allow` / `Upgrade` / `Block`)
    and the secure-context predicates
  - `FetcherConfig::mixed_content` — fetcher-wide default (`Block`)
  - `FetchRequest::origin` — the initiating document's origin; unset leaves the
    check inert
  - `FetchRequest::mixed_content` — per-request override, to permit images
    while still blocking scripts
- Referrer policy (#6) — a `Referer` header computed per the Referrer Policy
  spec, recomputed at every redirect hop and retargeted mid-chain by a
  `Referrer-Policy` response header:
  - `net::referrer` — all eight `ReferrerPolicy` values, defaulting to
    `strict-origin-when-cross-origin`
  - `FetchRequest::referrer` — the initiating document's URL; unset sends no header
  - `FetchRequest::referrer_policy` — how much of it to reveal
- `NetError::Blocked` / `NetEvent::Blocked`, with a typed `BlockReason`
- `test_support`: `RouteConfig::RedirectAbsolute`, `EchoRefererHeader`,
  `RedirectWithReferrerPolicy`, and `RecordingObserver`

### Changed

- `RequestBody`'s `bytes` field is private; use `RequestBody::as_bytes()`.
  `len()` now returns `Option<u64>` (`None` for a stream without a declared
  length).
- **Breaking:** scheme and `is_url_allowed` rejections now return
  `NetError::Blocked` instead of `NetError::Redirect` / `NetError::Other`
- **Breaking:** `NetError` and `NetEvent` gain a `Blocked` variant, and
  `FetchRequest` and `RequestInit` gain public fields — exhaustive `match`es and
  struct-literal construction need updating
- Request coalescing now also keys on the mixed content verdict and the
  referrer, so fewer requests share a response
- `FetchRequest::builder()` now defaults to `auto_decode: true`, matching the
  simple API and the wasm32 build. Use `.with_auto_decode(false)` for raw bytes.
- With decoding on, `max_bytes` caps the decompressed size, and the early
  `Content-Length` rejection no longer applies (reqwest strips the header
  when it decodes).

### Fixed

- **The URL policy is now applied to redirect targets.** `build_client` never disabled reqwest's
  own redirect following, so reqwest resolved each 3xx internally and the manual
  `get_with_redirects` loop only ever saw the final response. `FetcherContext::is_url_allowed`
  was therefore consulted for the initial URL but **not** for any redirect target, contrary to
  its documentation — a redirect to an internal address bypassed an embedder's SSRF guard. The
  `Set-Cookie`-on-3xx jar reporting and the cross-origin `Authorization`/`Cookie` stripping were
  inert for the same reason and are now live.
- `Referer` is now stripped on cross-origin redirects, alongside `Authorization`
  and `Cookie`, so a hand-set one cannot leak to a third-party host

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

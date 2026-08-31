# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Connection timing is reported to the request's observer, so an embedder can attribute
  the time before the first byte instead of guessing at it:
  - `NetEvent::DnsResolved { host, elapsed, addr_count }` times a hostname lookup. It
    requires a `FetcherConfig::dns_resolver` to be set — reqwest's built-in resolution
    happens below this crate's level and cannot be timed.
  - `NetEvent::Connected { elapsed }` times connection establishment. Note that it *encloses*
    the resolution above: name resolution happens inside reqwest's connector, and the timing
    wraps that connector, so `Connected` covers dns + TCP + (for https) TLS. The phases nest
    rather than tile, and their durations deliberately do not add up to the elapsed total.
    Always reported; it carries no host because reqwest's connector request type is opaque.
  - Both are emitted only when a connection was actually opened. A request served from the
    connection pool reports neither, which is the honest answer rather than a zero.
  - `dns::SystemResolver` is a `DnsResolver` that goes through the system resolver and
    refuses nothing — behaviourally what reqwest already does, for embedders who want the
    timing without a resolution policy of their own. It applies no SSRF or DNS-rebinding
    protection; anything facing untrusted URLs still wants a resolver that classifies
    addresses.
  - `test-support`: `RecordingObserver::connects()` and `RecordingObserver::dns_lookups()`
  - native-only; on wasm32 the browser owns both resolution and connection setup
- `NetEvent::CorsPreflightDone { url, elapsed }` closes the pair that `NetEvent::CorsPreflight`
  opened. A preflight is a blocking extra round-trip whose cost was invisible before — it
  looked like server think-time in the gap before the response. Emitted whenever the
  `OPTIONS` got a response, including one that fails validation: the round-trip was paid for
  either way, and the refusal is separately reported as `Blocked`. A preflight that never got
  a response reports nothing here; the resulting `Failed` or `Cancelled` covers it, and a hop
  served from the grant cache sends no `OPTIONS` and reports neither event.
  `test-support` gains `RecordingObserver::cors_preflights()`.

### Fixed

- `NetEvent::ResponseHeaders` was declared but never emitted by anything, so there was no
  time-to-first-byte signal. It is now emitted per hop, which also accounts for each hop of
  a redirect chain. `test-support` gains `RecordingObserver::response_headers()`.

### Changed

- **Breaking:** `NetEvent` is now `#[non_exhaustive]`. A `match` over it needs a catch-all
  arm — but from here on, a new event is no longer a breaking change. Done in the same
  release as three new variants, when it costs one adjustment rather than two.

## [0.4.0] - 2026-08-29

### Changed

- `SharedBody`: a subscriber dropped for falling behind the producer now receives
  `Err(NetError::Read(..))` before its stream ends, instead of the same clean end a
  finished body gives. A consumer that missed chunks could not tell the difference
  before and would deliver a truncated body as complete.

## [0.3.0] - 2026-08-20

### Added

- TLS errors and certificate overrides (#4):
  - a failed handshake now returns `NetError::Tls(TlsError)` instead of an opaque client
    error. `TlsError` has a `TlsErrorKind` (`Expired`, `NotYetValid`, `UnknownIssuer`,
    `HostnameMismatch`, `Revoked`, `InvalidCertificate`, `Handshake`, `Other`), the host and
    the rustls message. Observers get `NetEvent::TlsFailed`.
  - `FetcherConfig::tls_overrides` takes a `TlsOverrideStore` (in-memory default:
    `InMemoryTlsOverrideStore`) and enables browser-style "proceed anyway": the error then
    carries the certificate and its fingerprint, `store.accept(host, fingerprint)` lets the
    next connection through, and `FetcherContext::tls_override` can accept on the spot.
    Per (host, certificate); refused for HSTS hosts and for non-certificate failures.
  - `test-support`: `TestServer::tls_validity` sets the certificate's validity window, to
    test expired and not-yet-valid certificates
  - native-only; on wasm32 the browser does TLS
- CORS per WHATWG Fetch (#2), enforced per redirect hop whenever a request carries
  `FetchRequest::origin`; without one CORS is entirely inert, like mixed content:
  - `RequestMode` is now enforced: `SameOrigin` refuses cross-origin targets, `NoCors` (the
    default) only allows cross-origin loads in the shape markup can produce and marks the
    response opaque, `Cors` runs the CORS check on every response of the chain — redirect
    hops included
  - preflights: an `OPTIONS` round-trip when the method or headers need server approval,
    re-run per hop after redirects; grants cached per (origin, URL, credentials) honoring
    `Access-Control-Max-Age` via `FetcherConfig::cors_preflight_cache` (`CorsPreflightCache`
    trait, in-memory default)
  - `FetchRequest::credentials` (`RequestCredentials`, default `Include` — the old behaviour)
    gates cookie-jar injection per hop and selects the credentialed CORS rules
  - response tainting is annotated, not enforced: `FetchResultMeta::tainting` +
    `readable_headers()` compute the script-visible view; the embedder owns the boundary
  - failures surface as `BlockReason::Cors(CorsError)`, preflights as
    `NetEvent::CorsPreflight`; redirect `Location`s with embedded credentials are refused
  - inert on wasm32; `test-support` gains `RouteConfig::Cors` and separate `OPTIONS` hit
    counts
- `Origin` and `Sec-Fetch-*` fetch metadata headers (#47):
  - `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, and `Sec-Fetch-Site` are sent on every request,
    driven by the new `FetchRequest::destination` and `FetchRequest::mode` fields
    (`RequestDestination` / `RequestMode`, re-exported at the crate root);
    `Sec-Fetch-User: ?1` is sent on user-activated navigations (`Initiator::User`)
  - `Origin` is sent on non-GET/HEAD requests and on cross-origin CORS/WebSocket
    requests, computed from the existing `FetchRequest::origin` field
  - like `Referer`, the values are recomputed at every redirect hop and only sent to
    potentially trustworthy targets; `Sec-Fetch-Site` can only degrade across a chain,
    and `Origin` becomes `null` after a tainting cross-origin redirect
  - `same-site` compares registrable domains using the public suffix list (`psl` crate,
    native only) (#60); same host on another port reports `same-site`
  - inert on wasm32, where the browser owns these headers
- Runnable examples: `document_fetch`, `fetcher_context`, `streaming`, and `tls_override`

### Changed

- Per-origin concurrency limits now follow the negotiated protocol (#49): every origin
  starts at the HTTP/1.1 limit (`h1_per_origin`, default 6) and is raised to the HTTP/2
  limit (`h2_per_origin`, default 16) once an HTTP/2 or HTTP/3 response has been seen from
  it, redirect hops included. Previously every `https` origin was assumed to speak HTTP/2,
  giving HTTP/1.1-only servers 16 connections instead of 6.

- **Breaking:** `FetchRequest` gains the `credentials` field, `FetchResultMeta` gains
  `tainting`, `BlockReason` gains `Cors(CorsError)`, `NetEvent` gains `CorsPreflight` and
  `TlsFailed`, and `NetError` gains `Tls` — struct-literal construction and exhaustive
  `match`es need updating. Requests built through
  `FetchRequest::builder()` keep their previous behaviour (mode `NoCors` restrictions aside)
- Request coalescing now also keys on the credentials mode, so requests that would attach
  different cookies never share a response
- The default `User-Agent` is now `gosub-sonar/<crate version>` instead of no header at all
  (#38). The value is available as `DEFAULT_USER_AGENT`; set `FetcherConfig::user_agent` to
  override it, or to `None` to send no `User-Agent` header.

### Fixed

- Streamed bodies lost data when the subscriber attached after bytes had already been read:
  the first chunk beyond the peek buffer, and everything the server sent before the caller got
  around to `subscribe_stream()`, was pushed to nobody. `SharedBody::from_reader` now waits for
  the first subscriber before it starts reading (bounded by the idle/total timeouts and
  cancellation), and subscribing after the body ended with an error yields that error instead
  of an empty stream.

## [0.2.0] - 2026-08-01

### Added

- wasm32 support: the crate now compiles for `wasm32-unknown-unknown`, where the
  browser's `fetch()` provides the transport. The async API (`Fetcher`,
  `simple_get`) is available there; native-only pieces — the blocking helpers
  (`sync_get`, `sync_fetch`), `file://` URLs, HSTS, proxy configuration, the
  DNS resolver, and streaming uploads — are compiled out, with the browser
  applying its own equivalents where they exist. CI builds the wasm32 target.
- Pluggable DNS resolution — `FetcherConfig::dns_resolver` takes a
  `DnsResolver` implementation which becomes the *only* resolver the underlying
  client consults: every lookup, including each redirect hop, goes through it,
  and connections go to exactly the addresses it returns. Lookups happen per
  connection, not per request, so a rebound DNS name cannot redirect a pooled
  connection (DNS rebinding). Return `Err` to refuse a host — the shape of an
  SSRF policy that classifies resolved addresses rather than URLs.
  `DnsResolver`, `DnsError`, and `Resolving` are re-exported at the crate root.
  Native-only: on wasm32 the browser owns name resolution.
- Proxy configuration (#12) — `FetcherConfig::proxy` takes a `ProxyConfig`, so an embedder
  can point the fetcher at a proxy from its own settings instead of the process environment:
  - `ProxyConfig::System` (the default) keeps the previous behaviour, reading `HTTP_PROXY`,
    `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`
  - `ProxyConfig::Disabled` connects directly and ignores those variables
  - `ProxyConfig::Rules` uses only the rules given. A `ProxyRule` carries a `ProxyScope`
    (`Http` / `Https` / `All`), the proxy URL, optional `ProxyAuth` (`Basic` or a verbatim
    `Proxy-Authorization` value), and an optional `NO_PROXY`-syntax bypass list
  - an unusable proxy URL or auth header is reported by `Fetcher::new`
  - new `socks` cargo feature to accept `socks4`/`socks5`/`socks5h` proxy URLs
  - native-only: on wasm32 the browser's `fetch()` applies the user's own proxy settings

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

### Removed

- **Breaking:** `FetchHandle` and `FetchKeyData` are no longer part of the
  public API. The request-coalescing key is an internal detail of the fetcher,
  and everything the handle carried is available from `FetchResult` /
  `FetchResultMeta`.

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

[Unreleased]: https://github.com/gosub-io/gosub-sonar/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/gosub-io/gosub-sonar/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gosub-io/gosub-sonar/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gosub-io/gosub-sonar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gosub-io/gosub-sonar/releases/tag/v0.1.0

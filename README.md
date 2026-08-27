# gosub-sonar

[![Crates.io](https://img.shields.io/crates/v/gosub-sonar.svg)](https://crates.io/crates/gosub-sonar)
[![Documentation](https://docs.rs/gosub-sonar/badge.svg)](https://docs.rs/gosub-sonar)
[![CI](https://github.com/gosub-io/gosub-sonar/actions/workflows/ci.yml/badge.svg)](https://github.com/gosub-io/gosub-sonar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/gosub-io/gosub-sonar/blob/main/LICENSE)

Browser-agnostic priority-scheduled HTTP/HTTPS fetching library.

## Overview

gosub-sonar provides two fetching APIs:

- **`simple_get`** — one-shot GET for tools and scripts that just need bytes.
- **`Fetcher`** — full priority scheduler with request coalescing, per-origin concurrency limits, and fan-out to multiple subscribers.

The library has no dependency on any browser engine and can be used standalone.

## Features

- Scheduling: four priority lanes, global and per-origin connection limits (h1/h2 aware),
  coalescing of identical in-flight requests with fan-out to all subscribers, per-subscriber
  cancellation.
- Bodies: buffered or streamed (`SharedBody`), automatic decompression, `max_bytes`, idle and
  total-body timeouts, request bodies for POST/PUT.
- Web platform policies, applied on every redirect hop: CORS (preflights, response tainting),
  referrer policy, mixed content, `Origin` and `Sec-Fetch-*` headers, HSTS, cookie hooks,
  `Authorization`/`Cookie` stripped on cross-origin redirects.
- Transport: TLS errors with user overrides, pluggable DNS (for SSRF policies), proxy
  configuration, default `User-Agent` of `gosub-sonar/<version>` (`FetcherConfig::user_agent`).
- Authentication: `401`/`407` challenges answered from a credential store or a context hook and
  the request retried; `Basic` is computed for you.
- `NetEvent`s per request (started, redirected, headers, progress, blocked, preflight, TLS
  failure, auth challenge, finished) via `NetObserver`; typed `NetError` / `BlockReason`.
- Compiles for `wasm32-unknown-unknown` on top of the browser's `fetch()`. HSTS, DNS, proxies,
  TLS, the blocking helpers and `file://` are native only.

The policies are documented in their modules on [docs.rs](https://docs.rs/gosub-sonar)
(`net::cors`, `net::referrer`, `net::mixed_content`, `net::fetch_metadata`, `net::hsts`,
`net::tls`, `net::auth`, `net::dns`, `net::proxy`);
[docs/architecture.md](https://github.com/gosub-io/gosub-sonar/blob/main/docs/architecture.md)
has the overall picture.

## Usage

Add to your `Cargo.toml` (the scheduler API also uses these companion crates directly):

```toml
[dependencies]
gosub-sonar = "0.3"
http = "1"
tokio = { version = "1", features = ["rt", "macros"] }
tokio-util = "0.7"
url = "2"
```

### One-shot GET

```rust,ignore
use gosub_sonar::net::simple::simple_get;
use url::Url;

let bytes = simple_get(&Url::parse("https://example.org")?).await?;
```

### Priority scheduler

```rust,ignore
use std::sync::Arc;
use gosub_sonar::{FetchRequest, FetchResult, Fetcher, FetcherConfig, NullContext, Priority};
use http::Method;
use tokio_util::sync::CancellationToken;
use url::Url;

// NullContext ignores all lifecycle events; implement FetcherContext to receive them.
let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), Arc::new(NullContext))?);

let shutdown = CancellationToken::new();
let f = fetcher.clone();
let cancel = shutdown.clone();
tokio::spawn(async move { f.run(cancel).await });

let req = FetchRequest::builder(Method::GET, Url::parse("https://example.org")?)
    .with_priority(Priority::Normal)
    .with_auto_decode(true)
    .build();

match fetcher.fetch(req).await {
    FetchResult::Buffered { meta, body } => println!("{} — {} bytes", meta.status, body.len()),
    FetchResult::Stream { .. } => println!("streaming"),
    FetchResult::Error(e) => eprintln!("error: {e}"),
}

shutdown.cancel();
```

For per-subscriber cancellation use `fetcher.fetch_with_cancel(req, token)`; for full control
over the reply channel use `fetcher.submit(req, cancel, reply_tx)`.

See the `examples/` directory for runnable versions.

### Hooking into the fetcher

`FetcherContext` is how the host plugs in: it hands out a `NetObserver` per request (a devtools
panel, a progress bar), tracks outstanding work per `RequestReference` (a tab), and answers the
policy questions the fetcher asks on every hop:

```rust
use std::sync::Arc;
use gosub_sonar::{
    FetcherContext, Initiator, NetEvent, NetObserver, RequestId, RequestReference, ResourceKind,
    TlsError,
};
use url::Url;

struct Log;
impl NetObserver for Log {
    fn on_event(&self, ev: NetEvent) {
        println!("{ev:?}");
    }
}

struct MyContext;
impl FetcherContext for MyContext {
    fn observer_for(&self, _: RequestReference, _: RequestId, _: ResourceKind, _: Initiator)
        -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(Log)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}

    // All optional; the defaults allow everything, send no cookies and refuse bad certificates.
    fn is_url_allowed(&self, url: &Url) -> bool { url.host_str() != Some("ads.example") }
    fn cookies_for(&self, _url: &Url) -> Option<String> { None }
    fn on_cookies_received(&self, _url: &Url, _set_cookie: &[&str]) {}
    fn tls_override(&self, _error: &TlsError) -> bool { false }
}
```

`is_url_allowed`, `cookies_for` and `on_cookies_received` are called for the initial URL and
for every redirect target, so a blocklist or cookie jar can't be bypassed by a redirect. See
`examples/fetcher_context.rs` for a complete one with a cookie jar and an event log.

### HSTS

HTTP Strict Transport Security (RFC 6797) is on by default: a site that sends
`Strict-Transport-Security` over HTTPS is recorded, and later `http://` requests to it are
rewritten to `https://` before any connection is opened. The default store is in-memory, so
policies last for the life of the process and need no setup.

To persist across restarts, implement `HstsStore` — a host-keyed map. The crate handles `max-age`,
`includeSubDomains` matching, and expiry, so the store interprets nothing:

```rust,ignore
use gosub_sonar::{HstsEntry, HstsStore, FetcherConfig};

struct ProfileStore { /* in-memory map + async write-through to disk */ }

impl HstsStore for ProfileStore {
    fn load(&self, host: &str) -> Option<HstsEntry> { /* ... */ }
    fn store(&self, host: &str, entry: HstsEntry) { /* ... */ }
    fn remove(&self, host: &str) { /* ... */ }
}

let cfg = FetcherConfig {
    hsts: Some(Arc::new(ProfileStore::open(&profile_dir)?)),
    ..Default::default()
};
```

`load` runs on every hop of every request, so it must not block — keep an in-memory map and
persist in the background.

Set `hsts: None` to disable HSTS: nothing consulted, nothing recorded. This is what a
private-browsing session wants.

There is no preload list. On wasm32 the browser's `fetch()` applies its own HSTS, so the field does
not exist there.

### TLS errors and certificate overrides

A failed handshake comes back as `NetError::Tls(TlsError)` with a `kind` (`Expired`,
`UnknownIssuer`, `HostnameMismatch`, ...) so you can show the right warning. To let the user
proceed anyway, give the fetcher a `TlsOverrideStore`; the error then also carries the
certificate and its fingerprint:

```rust,ignore
use gosub_sonar::{FetcherConfig, InMemoryTlsOverrideStore, NetError, FetchResult};

let overrides = Arc::new(InMemoryTlsOverrideStore::new());
let cfg = FetcherConfig {
    tls_overrides: Some(overrides.clone()),
    ..Default::default()
};

// ...
if let FetchResult::Error(NetError::Tls(err)) = fetcher.fetch(req).await {
    if err.kind.is_certificate_error() && user_clicked_proceed(&err) {
        overrides.accept(&err.host, err.fingerprint.unwrap());
        // retry the request; the next connection is let through
    }
}
```

Overrides are per (host, certificate): a different bad certificate for the same host is a new
error. Known HSTS hosts can't be overridden, nor can handshake failures that aren't about the
certificate. For a policy rather than a dialog (say, trust self-signed certificates on your dev
hosts) implement `FetcherContext::tls_override`; it is asked synchronously during the handshake,
after the store. See `examples/tls_override.rs`. Native only.

### Authentication challenges

A `401` (or a proxy's `407`) is answered rather than returned: the challenges are parsed, the
credentials are looked up, and the hop is re-sent with an `Authorization` header. After
`MAX_AUTH_ATTEMPTS` tries the challenge is handed to the caller as before.

Credentials come from `FetcherConfig::credentials` (a `CredentialStore` keyed by protection
space — target, scheme, origin, realm — with an in-memory default) and otherwise from your
context:

```rust,ignore
use gosub_sonar::{AuthChallenge, AuthScheme, Credentials, FetcherContext};

impl FetcherContext for MyApp {
    // ... observer_for / on_ref_active / on_ref_done ...

    fn on_auth_challenge(&self, challenge: &AuthChallenge) -> Option<Credentials> {
        match challenge.scheme {
            // Basic is encoded for you; `challenge.realm` is what to show the user.
            AuthScheme::Basic => self.passwords.lookup(&challenge.url, challenge.realm.as_deref()),
            // Any other scheme: build the header value yourself from `challenge.params`.
            AuthScheme::Bearer => Some(Credentials::Raw(format!("Bearer {}", self.token))),
            _ => None,
        }
    }
}
```

The hook is called once per challenge, in the order the server listed them, so returning `None`
for a scheme you cannot compute lets the next one through. It runs on the request path and must
not block on a password dialog: return `None`, prompt, and then either put the answer in the store
or re-submit the fetch. A password that works is remembered; credentials the server refuses are
dropped, and `challenge.attempt` tells you it is being asked again. A `Raw` value is used but not
remembered, since it was computed for that one challenge, so pre-seed the store yourself for a
stable one such as a bearer token.

Server credentials follow `FetchRequest::credentials` and are not attached to CORS-tainted
requests (`Authorization` is not a CORS-safelisted header). Proxy challenges are native only.

### DNS and SSRF

`FetcherConfig::dns_resolver` replaces the system resolver. It is used for every connection,
redirect hops included, and the connection goes to exactly the addresses it returns. Return `Err`
to refuse a host, e.g. for an SSRF policy on resolved addresses:

```rust
use std::sync::Arc;
use gosub_sonar::{DnsResolver, FetcherConfig, Resolving};

struct PublicOnly;

impl DnsResolver for PublicOnly {
    fn resolve(&self, host: &str) -> Resolving {
        let host = host.to_owned();
        Box::pin(async move {
            let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addrs.iter().any(|a| a.ip().is_loopback()) {
                return Err(format!("{host} resolves to loopback").into());
            }
            Ok(addrs)
        })
    }
}

let cfg = FetcherConfig {
    dns_resolver: Some(Arc::new(PublicOnly)),
    ..Default::default()
};
```

`FetcherContext::is_url_allowed` is the URL-level counterpart; it sees the initial URL and every
redirect target before they are fetched. Native only.

### Proxies

By default the fetcher reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` from the
environment. `FetcherConfig::proxy` replaces that with your own settings:

```rust
use gosub_sonar::{FetcherConfig, ProxyConfig, ProxyRule};

let cfg = FetcherConfig {
    proxy: ProxyConfig::Rules(vec![
        ProxyRule::all("http://proxy.corp:8080")
            .with_basic_auth("alice", "hunter2")
            .bypassing("localhost, 10.0.0.0/8, .internal.corp"),
    ]),
    ..Default::default()
};
```

Rules are matched in order; each carries a scope (`http`, `https`, or all), optional credentials,
and an optional `NO_PROXY`-syntax bypass list. Anything other than `ProxyConfig::System` ignores
the environment entirely, so `ProxyConfig::Disabled` guarantees a direct connection. `socks4`,
`socks5`, and `socks5h` proxy URLs need the `socks` feature. On wasm32 the browser's `fetch()`
uses the user's own proxy settings, so the field does not exist there.

### wasm32

The crate compiles for `wasm32-unknown-unknown`, where reqwest's `fetch()` backend is the
transport. The async API (`Fetcher`, `simple_get`) works there; the browser owns TLS,
connections, redirects, cookies, proxies and DNS, so those knobs don't exist on that target and
the per-hop policies (CORS, referrer, mixed content, fetch metadata, HSTS) are applied by the
browser instead of by sonar. `sync_get` / `sync_fetch`, `file://` URLs and streaming uploads are
native only.

## Cargo features

- `test-support` — the in-process mock HTTP/HTTPS server (`net::test_support`) for downstream
  integration tests. Native only.
- `socks` — `socks4://`, `socks5://` and `socks5h://` proxy URLs.

Minimum supported Rust version: 1.88.

## Examples

```text
cargo run --example simple_fetch -- https://example.org
cargo run --example fetcher -- https://example.org
cargo run --example tls_override -- https://self-signed.badssl.com/
cargo run --example fetcher_context --features test-support
cargo run --example streaming --features test-support
cargo run --example document_fetch --features test-support
cargo run --example auth --features test-support
cargo run --example fetcher_harness --features test-support
```

- `simple_fetch` — one-shot GET
- `fetcher` — minimal `Fetcher` setup with a no-op context
- `tls_override` — certificate errors and "proceed anyway" (needs network)
- `fetcher_context` — a `FetcherContext` with an event log, a cookie jar and a URL blocklist
- `streaming` — a streamed body, and two subscribers sharing one fetch
- `document_fetch` — requests as a page makes them: `Referer`, `Sec-Fetch-*`, `Origin`, CORS with
  preflight, mixed content
- `auth` — answering `401` challenges: from the context, from the credential store, and not at all
- `fetcher_harness` — concurrency, coalescing, priority, cancellation and error scenarios

The last five run against the mock server, no network needed.

## Documentation

API documentation is on [docs.rs](https://docs.rs/gosub-sonar). Design notes:

- [architecture.md](https://github.com/gosub-io/gosub-sonar/blob/main/docs/architecture.md) — overall structure of the fetch stack
- [net-design.md](https://github.com/gosub-io/gosub-sonar/blob/main/docs/net-design.md) — scheduler design (coalescing, priorities, fan-out)
- [pump.md](https://github.com/gosub-io/gosub-sonar/blob/main/docs/pump.md) — how streamed bodies are pumped to subscribers

## License

MIT — see [LICENSE](https://github.com/gosub-io/gosub-sonar/blob/main/LICENSE).

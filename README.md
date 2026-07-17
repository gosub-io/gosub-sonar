# gosub-sonar

[![Crates.io](https://img.shields.io/crates/v/gosub-sonar.svg)](https://crates.io/crates/gosub-sonar)
[![Documentation](https://docs.rs/gosub-sonar/badge.svg)](https://docs.rs/gosub-sonar)
[![CI](https://github.com/gosub-io/gosub-sonar/actions/workflows/ci.yml/badge.svg)](https://github.com/gosub-io/gosub-sonar/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Browser-agnostic priority-scheduled HTTP/HTTPS fetching library.

## Overview

gosub-sonar provides two fetching APIs:

- **`simple_get`** — one-shot GET for tools and scripts that just need bytes.
- **`Fetcher`** — full priority scheduler with request coalescing, per-origin concurrency limits, and fan-out to multiple subscribers.

The library has no dependency on any browser engine and can be used standalone.

## Usage

Add to your `Cargo.toml` (the scheduler API also uses these companion crates directly):

```toml
[dependencies]
gosub-sonar = "0.1"
http = "1"
tokio = { version = "1", features = ["rt", "macros"] }
tokio-util = "0.7"
url = "2"
```

### One-shot GET

```rust
use gosub_sonar::net::simple::simple_get;
use url::Url;

let bytes = simple_get(&Url::parse("https://example.org")?).await?;
```

### Priority scheduler

```rust
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
over the reply channel and request handle use `fetcher.submit(req, handle, tx)`.

See the `examples/` directory for runnable versions.

### HSTS

HTTP Strict Transport Security (RFC 6797) is on by default: a site that sends
`Strict-Transport-Security` over HTTPS is recorded, and later `http://` requests to it are
rewritten to `https://` before any connection is opened. The default store is in-memory, so
policies last for the life of the process and need no setup.

To persist across restarts, implement `HstsStore` — a host-keyed map. The crate handles `max-age`,
`includeSubDomains` matching, and expiry, so the store interprets nothing:

```rust
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

## Examples

```text
cargo run --example simple_fetch -- https://example.org
cargo run --example fetcher -- https://example.org
cargo run --example fetcher_harness --features test-support
```

## Documentation

API documentation is available on [docs.rs](https://docs.rs/gosub-sonar). Design notes live
in the [`docs/`](docs/) directory:

- [architecture.md](docs/architecture.md) — overall structure of the fetch stack
- [net-design.md](docs/net-design.md) — scheduler design (coalescing, priorities, fan-out)
- [pump.md](docs/pump.md) — how streamed bodies are pumped to subscribers

## License

MIT — see [LICENSE](LICENSE).

# gosub-sonar

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

## Examples

```text
cargo run --example simple_fetch -- https://example.org
cargo run --example fetcher -- https://example.org
cargo run --example fetcher_harness
```

## License

MIT — see [LICENSE](LICENSE).

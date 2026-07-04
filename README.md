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
use gosub_sonar::net::fetcher::{Fetcher, FetcherConfig};
use gosub_sonar::net::fetcher_context::FetcherContext;
use gosub_sonar::net::null_emitter::NullEmitter;
use gosub_sonar::net::observer::NetObserver;
use gosub_sonar::net::request_ref::RequestReference;
use gosub_sonar::net::types::{FetchHandle, FetchRequest, FetchResult, Initiator, Priority, ResourceKind};
use gosub_sonar::types::RequestId;
use http::Method;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use url::Url;

struct MyContext;

impl FetcherContext for MyContext {
    fn observer_for(&self, _: RequestReference, _: RequestId, _: ResourceKind, _: Initiator)
        -> Arc<dyn NetObserver + Send + Sync> { Arc::new(NullEmitter) }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

let shutdown = CancellationToken::new();
let fetcher = Arc::new(Fetcher::new(FetcherConfig::default(), Arc::new(MyContext))?);

let f = fetcher.clone();
let cancel = shutdown.clone();
tokio::spawn(async move { f.run(cancel).await });

let req = FetchRequest::builder(Method::GET, Url::parse("https://example.org")?)
    .with_priority(Priority::Normal)
    .with_kind(ResourceKind::Primary)
    .with_auto_decode(true)
    .build();
// The handle shares the request's id and key so the fetcher can correlate them.
let handle = FetchHandle {
    req_id: req.req_id,
    key: req.key_data.clone(),
    cancel: CancellationToken::new(),
};
let (tx, rx) = oneshot::channel();
fetcher.submit(req, handle, tx).await;

match rx.await? {
    FetchResult::Buffered { meta, body } => println!("{} — {} bytes", meta.status, body.len()),
    FetchResult::Stream { .. } => println!("streaming"),
    FetchResult::Error(e) => eprintln!("error: {e}"),
}

shutdown.cancel();
```

See the `examples/` directory for runnable versions.

## Examples

```text
cargo run --example simple_fetch -- https://example.org
cargo run --example fetcher -- https://example.org
cargo run --example fetcher_harness
```

## License

MIT — see [LICENSE](LICENSE).

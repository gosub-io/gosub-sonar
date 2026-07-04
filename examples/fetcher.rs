//! Demonstrates the priority-scheduling `Fetcher`.
//!
//! The `Fetcher` is the full network scheduler used by the Gosub engine: it coalesces
//! identical in-flight requests, enforces per-origin and global concurrency limits,
//! and fans out results to multiple subscribers.
//!
//! Callers that don't need the scheduler (tools, renderers) should use `simple_get`
//! instead. This example shows how to wire up the `Fetcher` standalone, outside of
//! the engine, using the no-op `NullContext`. Implement your own `FetcherContext`
//! to receive per-request events and lifecycle callbacks instead.
//!
//! Run with:
//! ```text
//! cargo run -p gosub_sonar --example fetcher -- https://example.org
//! ```

use gosub_sonar::{FetchRequest, FetchResult, Fetcher, FetcherConfig, NullContext, SharedBody};
use http::Method;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let raw = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.org".to_string());
    let url = Url::parse(&raw)?;

    // Build the fetcher with default config and the no-op context, and start its run loop.
    let fetcher = Arc::new(Fetcher::new(
        FetcherConfig::default(),
        Arc::new(NullContext),
    )?);

    let shutdown = CancellationToken::new();
    let fetcher_task = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move {
        fetcher_task.run(cancel).await;
    });

    // Build the request and fetch. `fetch` handles the reply channel and request handle
    // internally; use `submit` directly if you need to manage those yourself.
    let req = FetchRequest::builder(Method::GET, url.clone())
        .with_auto_decode(true)
        .build();

    println!("Fetching {url} ...");

    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            println!(
                "Buffered response: HTTP {} — {} bytes",
                meta.status,
                body.len()
            );
            if let Ok(text) = std::str::from_utf8(&body[..body.len().min(512)]) {
                println!("{text}");
            }
        }
        FetchResult::Stream {
            meta,
            peek_buf,
            shared,
        } => {
            println!("Streamed response: HTTP {}", meta.status);
            let mut reader = SharedBody::combined_reader(peek_buf, shared);
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            println!("Read {} bytes total", buf.len());
            if let Ok(text) = std::str::from_utf8(&buf[..buf.len().min(512)]) {
                println!("{text}");
            }
        }
        FetchResult::Error(e) => {
            eprintln!("Fetch error: {e}");
        }
    }

    shutdown.cancel();

    Ok(())
}

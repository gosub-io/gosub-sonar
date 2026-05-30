//! Demonstrates the priority-scheduling `Fetcher`.
//!
//! The `Fetcher` is the full network scheduler used by the Gosub engine: it coalesces
//! identical in-flight requests, enforces per-origin and global concurrency limits,
//! and fans out results to multiple subscribers.
//!
//! Callers that don't need the scheduler (tools, renderers) should use `simple_get`
//! instead. This example shows how to wire up the `Fetcher` standalone, outside of
//! the engine, using a minimal no-op `FetcherContext`.
//!
//! Run with:
//! ```text
//! cargo run -p gosub_sonar --example fetcher -- https://example.org
//! ```

use gosub_sonar::net::fetcher::{Fetcher, FetcherConfig};
use gosub_sonar::net::fetcher_context::FetcherContext;
use gosub_sonar::net::null_emitter::NullEmitter;
use gosub_sonar::net::observer::NetObserver;
use gosub_sonar::net::request_ref::RequestReference;
use gosub_sonar::net::types::{
    FetchHandle, FetchKeyData, FetchRequest, FetchResult, Initiator, Priority, ResourceKind,
};
use gosub_sonar::types::RequestId;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use url::Url;

struct StandaloneContext;

impl FetcherContext for StandaloneContext {
    fn observer_for(
        &self,
        _reference: RequestReference,
        _req_id: RequestId,
        _kind: ResourceKind,
        _initiator: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }

    fn on_ref_active(&self, _reference: RequestReference) {}
    fn on_ref_done(&self, _reference: RequestReference) {}
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let raw = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.org".to_string());
    let url = Url::parse(&raw)?;

    // Build the fetcher with default config and our no-op context.
    let config = FetcherConfig::default();
    let fetcher = Arc::new(Fetcher::new(config, Arc::new(StandaloneContext))?);

    let shutdown = CancellationToken::new();

    let fetcher_task = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move {
        fetcher_task.run(cancel).await;
    });

    // Build the request.
    let key_data = FetchKeyData::new(url.clone());
    let req_id = RequestId::new();

    let req = FetchRequest {
        reference: RequestReference::Background(0),
        req_id,
        key_data: key_data.clone(),
        priority: Priority::Normal,
        initiator: Initiator::Other,
        kind: ResourceKind::Primary,
        streaming: false,
        auto_decode: true,
        body: None,
        max_bytes: None,
    };

    let handle = FetchHandle {
        req_id,
        key: key_data,
        cancel: CancellationToken::new(),
    };

    // Submit the request and wait for the result.
    let (reply_tx, reply_rx) = oneshot::channel();
    fetcher.submit(req, handle, reply_tx).await;

    println!("Fetching {url} ...");

    match reply_rx.await? {
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
            let mut reader =
                gosub_sonar::net::shared_body::SharedBody::combined_reader(peek_buf, shared);
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

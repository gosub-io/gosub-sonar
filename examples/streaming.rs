#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Streaming bodies, and one fetch feeding several subscribers.
//!
//! A streamed request returns `FetchResult::Stream` as soon as the headers and the first few KB
//! (the peek buffer) are in, and the rest of the body arrives through a `SharedBody`. Submitting
//! the same URL twice while it is in flight does not open a second connection: both callers get
//! the same stream (coalescing + fan-out), and the server sees one request.
//!
//! Runs against the in-process mock server, which sends the body in slow chunks so the streaming
//! is visible.
//!
//! Run with:
//! ```text
//! cargo run --example streaming --features test-support
//! ```

use gosub_sonar::net::test_support::{RouteConfig, TestServer};
use gosub_sonar::{FetchRequest, FetchResult, Fetcher, FetcherConfig, NullContext, SharedBody};
use http::Method;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Read a streamed result to the end, reporting progress.
async fn consume(name: &'static str, result: FetchResult, started: Instant) {
    match result {
        FetchResult::Stream {
            meta,
            peek_buf,
            shared,
        } => {
            println!(
                "[{name}] headers: HTTP {}, content-type {:?}, {} bytes peeked",
                meta.status,
                meta.content_type,
                peek_buf.len()
            );
            let mut reader = SharedBody::combined_reader(peek_buf, shared);
            let mut buf = vec![0u8; 8192];
            let mut total = 0usize;
            loop {
                let n = reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if total.is_multiple_of(8192) {
                    println!("[{name}] {total:>6} bytes after {:?}", started.elapsed());
                }
            }
            println!("[{name}] done: {total} bytes");
        }
        FetchResult::Buffered { meta, body } => {
            println!(
                "[{name}] buffered: HTTP {} {} bytes",
                meta.status,
                body.len()
            )
        }
        FetchResult::Error(e) => println!("[{name}] error: {e}"),
    }
}

fn request(url: Url) -> FetchRequest {
    FetchRequest::builder(Method::GET, url)
        .with_streaming(true)
        .build()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // 64 chunks of 1 KB, 20 ms apart.
    let chunk = vec![b'x'; 1024];
    let srv = TestServer::new()
        .route(
            "/big",
            RouteConfig::chunked_with_delay(vec![&chunk; 64], Duration::from_millis(20)),
        )
        .start()
        .await;

    let fetcher = Arc::new(Fetcher::new(
        FetcherConfig::default(),
        Arc::new(NullContext),
    )?);
    let shutdown = CancellationToken::new();
    let run = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move { run.run(cancel).await });

    let started = Instant::now();

    // Two subscribers for the same URL, submitted back to back. The second one is coalesced
    // onto the first: same connection, same SharedBody.
    let a = fetcher.fetch(request(srv.url("/big")));
    let b = fetcher.fetch(request(srv.url("/big")));
    let (a, b) = tokio::join!(a, b);

    tokio::join!(consume("a", a, started), consume("b", b, started));

    println!("server saw {} request(s) for /big", srv.hit_count("/big"));

    shutdown.cancel();
    Ok(())
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Fetches URLs and prints where the time went, as a waterfall.
//!
//! The fetch stack reports the phases that happen below the request - name resolution,
//! connection setup, and the CORS preflight round-trip - as [`NetEvent`]s carrying an
//! `elapsed`. This example collects them per request and lays them out against the total.
//!
//! Two things it makes visible that are easy to misread as bugs:
//!
//! - a phase that did not happen reports nothing rather than zero. Fetch the same host
//!   twice and the second request shows no dns and no connect: it reused a pooled
//!   connection, so it spent no time on either.
//! - `DnsResolved` needs a [`DnsResolver`] to be configured. reqwest's built-in resolution
//!   happens below this crate and cannot be timed, so this example installs
//!   [`SystemResolver`], which resolves exactly like reqwest would but through a seam that
//!   can be measured.
//!
//! The phases nest rather than tile: resolution happens inside reqwest's connector, and the
//! connect timing wraps that connector, so `connect` contains `dns`. The bars show the
//! overlap, and the durations deliberately do not add up to the total.
//!
//! Run with:
//! ```text
//! cargo run --example timings -- https://example.org
//! cargo run --example timings -- https://example.org https://example.org/  # 2nd is pooled
//! ```

use gosub_sonar::net::dns::SystemResolver;
use gosub_sonar::{
    FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, Initiator, NetEvent,
    NetObserver, RequestId, RequestReference, ResourceKind, SharedBody,
};
use http::Method;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

/// One thing the fetch stack reported, and when it reported it.
enum Mark {
    Started,
    Dns {
        host: String,
        addrs: usize,
        elapsed: Duration,
    },
    Connected {
        elapsed: Duration,
    },
    PreflightStart,
    PreflightDone {
        elapsed: Duration,
    },
    Headers {
        status: u16,
    },
    Redirected {
        status: u16,
        to: Url,
    },
    Finished {
        bytes: u64,
        elapsed: Duration,
    },
    Note(String),
    Failed(String),
}

/// Records every event with the offset at which it arrived. The offset is measured from
/// just before the request is handed to the fetcher, so it includes any time the request
/// spent queued behind the scheduler's concurrency limits.
struct Timeline {
    start: Instant,
    marks: Mutex<Vec<(Duration, Mark)>>,
}

impl Timeline {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            marks: Mutex::new(Vec::new()),
        }
    }

    fn push(&self, mark: Mark) {
        self.marks
            .lock()
            .unwrap()
            .push((self.start.elapsed(), mark));
    }
}

impl NetObserver for Timeline {
    fn on_event(&self, ev: NetEvent) {
        match ev {
            NetEvent::Started { .. } => self.push(Mark::Started),
            NetEvent::DnsResolved {
                host,
                elapsed,
                addr_count,
            } => self.push(Mark::Dns {
                host,
                addrs: addr_count,
                elapsed,
            }),
            NetEvent::Connected { elapsed } => self.push(Mark::Connected { elapsed }),
            NetEvent::CorsPreflight { .. } => self.push(Mark::PreflightStart),
            NetEvent::CorsPreflightDone { elapsed, .. } => {
                self.push(Mark::PreflightDone { elapsed })
            }
            NetEvent::ResponseHeaders { status, .. } => self.push(Mark::Headers { status }),
            NetEvent::Redirected { status, to, .. } => self.push(Mark::Redirected { status, to }),
            NetEvent::Finished {
                received_bytes,
                elapsed,
                ..
            } => self.push(Mark::Finished {
                bytes: received_bytes,
                elapsed,
            }),
            NetEvent::Blocked { reason, .. } => self.push(Mark::Note(format!("blocked: {reason}"))),
            NetEvent::Failed { error, .. } => self.push(Mark::Failed(format!("failed: {error}"))),
            NetEvent::Cancelled { reason, .. } => {
                self.push(Mark::Note(format!("cancelled: {reason}")))
            }
            NetEvent::TlsFailed { error, .. } => self.push(Mark::Note(format!("tls: {error}"))),
            _ => {}
        }
    }
}

/// Hands the timeline for the request currently being made to whoever asks. An engine
/// would key this per tab or per resource instead.
struct Ctx {
    current: Mutex<Arc<Timeline>>,
}

impl FetcherContext for Ctx {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        self.current.lock().unwrap().clone()
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

/// A phase with a measured duration, positioned against the start of the request.
struct Phase {
    label: &'static str,
    start: Duration,
    dur: Duration,
    note: String,
}

const BAR: usize = 34;

fn ms(d: Duration) -> String {
    format!("{:.1}ms", d.as_secs_f64() * 1000.0)
}

/// A `BAR`-wide row with the phase's span filled in. Always at least one cell, so a phase
/// too short to scale to a full cell is still visible.
fn draw(start: Duration, dur: Duration, total: Duration) -> String {
    if total.is_zero() {
        return " ".repeat(BAR);
    }
    let scale = |d: Duration| (d.as_secs_f64() / total.as_secs_f64() * BAR as f64).round() as usize;
    let from = scale(start).min(BAR - 1);
    let len = scale(dur).max(1).min(BAR - from);
    format!(
        "{}{}{}",
        " ".repeat(from),
        "\u{2588}".repeat(len),
        " ".repeat(BAR - from - len)
    )
}

fn report(url: &Url, tl: &Timeline, error: Option<String>) {
    let marks = tl.marks.lock().unwrap();
    let mut phases: Vec<Phase> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut total = Duration::ZERO;
    let mut bytes = 0u64;
    let mut pf_start: Option<Duration> = None;
    let mut headers: Vec<(Duration, u16)> = Vec::new();
    let mut saw_failure = false;

    for (at, mark) in marks.iter() {
        match mark {
            // Everything before this was the scheduler, not the network.
            Mark::Started => phases.push(Phase {
                label: "queued",
                start: Duration::ZERO,
                dur: *at,
                note: "waiting for a scheduler slot".into(),
            }),
            // These arrive when the phase ends, so its start is the arrival less its own
            // duration.
            Mark::Dns {
                host,
                addrs,
                elapsed,
            } => phases.push(Phase {
                label: "dns",
                start: at.saturating_sub(*elapsed),
                dur: *elapsed,
                note: format!("{host} -> {addrs} address(es)"),
            }),
            Mark::Connected { elapsed } => phases.push(Phase {
                label: "connect",
                start: at.saturating_sub(*elapsed),
                dur: *elapsed,
                // Resolution happens inside reqwest's connector, and the timing layer
                // wraps the connector, so this span encloses the dns one above it.
                note: if url.scheme() == "https" {
                    "dns + tcp + tls handshake".into()
                } else {
                    "dns + tcp handshake".into()
                },
            }),
            Mark::PreflightStart => pf_start = Some(*at),
            Mark::PreflightDone { elapsed } => phases.push(Phase {
                label: "preflight",
                start: pf_start.take().unwrap_or(at.saturating_sub(*elapsed)),
                dur: *elapsed,
                note: "CORS OPTIONS round-trip".into(),
            }),
            Mark::Headers { status } => headers.push((*at, *status)),
            Mark::Redirected { status, to } => {
                notes.push(format!("{} redirect {status} -> {to}", ms(*at)))
            }
            Mark::Finished {
                bytes: b,
                elapsed: e,
            } => {
                total = *e;
                bytes = *b;
            }
            Mark::Note(n) => notes.push(format!("{} {n}", ms(*at))),
            Mark::Failed(n) => {
                saw_failure = true;
                notes.push(format!("{} {n}", ms(*at)));
            }
        }
    }

    println!("\n{url}");
    if total.is_zero() {
        // No `Finished`, so there is no measured total to lay phases out against. The
        // request reports its own failure, so the notes below say why.
        for n in &notes {
            println!("  {n}");
        }
        // The stack reports its own failures now, so the returned error is only printed
        // when nothing reported one.
        match error {
            Some(e) if !saw_failure => println!("  failed: {e}"),
            None if !saw_failure => println!("  no timing: the request did not complete"),
            _ => {}
        }
        return;
    }

    // Measured from the end of the last phase rather than by subtracting durations,
    // because the phases nest - `connect` contains `dns` - so they do not add up to
    // elapsed time.
    let last_end = phases
        .iter()
        .map(|p| p.start + p.dur)
        .max()
        .unwrap_or(Duration::ZERO);

    match (headers.first(), headers.last()) {
        (Some((first, status)), Some((last, _))) => {
            phases.push(Phase {
                label: "waiting",
                start: last_end,
                dur: first.saturating_sub(last_end),
                note: format!("request sent -> {status} response headers"),
            });
            // More than one set of headers means the chain waited on a redirect hop too.
            if headers.len() > 1 {
                phases.push(Phase {
                    label: "redirects",
                    start: *first,
                    dur: last.saturating_sub(*first),
                    note: format!("{} further hop(s)", headers.len() - 1),
                });
            }
            phases.push(Phase {
                label: "transfer",
                start: *last,
                dur: total.saturating_sub(*last),
                note: format!("{bytes} bytes of body"),
            });
        }
        // No headers event: fall back to one bar for everything after the connection.
        _ => phases.push(Phase {
            label: "req+resp",
            start: last_end,
            dur: total.saturating_sub(last_end),
            note: format!("request sent, server, {bytes} bytes back"),
        }),
    }

    println!("  {:<9} {:>8} {:>8}", "phase", "start", "dur");
    for p in &phases {
        println!(
            "  {:<9} {:>8} {:>8}  {}  {}",
            p.label,
            ms(p.start),
            ms(p.dur),
            draw(p.start, p.dur, total),
            p.note
        );
    }
    println!("  {:<9} {:>8} {:>8}", "total", "", ms(total));

    for n in &notes {
        println!("  {n}");
    }
    // An absent phase is a real answer, not a gap in the instrumentation.
    if !phases.iter().any(|p| p.label == "dns") {
        println!("  (no dns: served from the connection pool, nothing was resolved)");
    }
    if !phases.iter().any(|p| p.label == "connect") {
        println!("  (no connect: served from the connection pool, nothing was opened)");
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let urls: Vec<Url> = if raw.is_empty() {
        vec![Url::parse("https://example.org")?]
    } else {
        raw.iter()
            .map(|u| Url::parse(u))
            .collect::<Result<_, _>>()?
    };

    let ctx = Arc::new(Ctx {
        current: Mutex::new(Arc::new(Timeline::new())),
    });

    // `SystemResolver` resolves exactly like reqwest's built-in resolution does, but through
    // `DnsResolver`, which is the seam the timing is taken at. Without it there is no
    // `DnsResolved` event at all.
    let config = FetcherConfig {
        dns_resolver: Some(Arc::new(SystemResolver)),
        ..FetcherConfig::default()
    };
    let fetcher = Arc::new(Fetcher::new(config, ctx.clone())?);
    let shutdown = CancellationToken::new();
    let run = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move { run.run(cancel).await });

    for url in &urls {
        let timeline = Arc::new(Timeline::new());
        *ctx.current.lock().unwrap() = timeline.clone();

        let req = FetchRequest::builder(Method::GET, url.clone())
            .with_auto_decode(true)
            .build();

        let mut failure = None;
        match fetcher.fetch(req).await {
            FetchResult::Buffered { .. } => {}
            // The body must be drained before the timing is complete: `Finished` is emitted
            // by the reader when the stream ends.
            FetchResult::Stream {
                peek_buf, shared, ..
            } => {
                let mut reader = SharedBody::combined_reader(peek_buf, shared);
                let mut sink = Vec::new();
                reader.read_to_end(&mut sink).await?;
            }
            FetchResult::Error(e) => failure = Some(e.to_string()),
        }

        report(url, &timeline, failure);
    }

    shutdown.cancel();
    Ok(())
}

//! Certificate overrides: letting the user proceed past a TLS error.
//!
//! Fetches a URL whose certificate doesn't verify (default: `https://self-signed.badssl.com/`).
//! The first attempt fails with `NetError::Tls`, which carries the certificate and its
//! fingerprint. We print it, ask on stdin whether to accept, and if so put the fingerprint in the
//! `TlsOverrideStore` and retry. The retry succeeds.
//!
//! With `--auto` the decision is made in `FetcherContext::tls_override` instead: the hook accepts
//! unknown-issuer errors for the requested host, so the first request already goes through. Use
//! that shape for a policy ("trust self-signed on my dev hosts"), not for a dialog: the hook runs
//! inside the handshake and must not block.
//!
//! Other hosts to try: expired.badssl.com, wrong.host.badssl.com, untrusted-root.badssl.com.
//!
//! Run with:
//! ```text
//! cargo run --example tls_override -- https://self-signed.badssl.com/
//! cargo run --example tls_override -- --auto https://self-signed.badssl.com/
//! ```

use gosub_sonar::{
    FetchRequest, FetchResult, Fetcher, FetcherConfig, FetcherContext, InMemoryTlsOverrideStore,
    Initiator, NetError, NetObserver, NullEmitter, RequestId, RequestReference, ResourceKind,
    TlsError, TlsErrorKind, TlsOverrideStore,
};
use http::Method;
use std::io::{BufRead, Write};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Accepts unknown-issuer certificates for one host, refuses everything else.
struct TrustSelfSignedOn {
    host: String,
}

impl FetcherContext for TrustSelfSignedOn {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}

    fn tls_override(&self, error: &TlsError) -> bool {
        let ok = error.host == self.host && error.kind == TlsErrorKind::UnknownIssuer;
        println!(
            "tls_override({}, {}) -> {}",
            error.host,
            error.kind,
            if ok { "accept" } else { "refuse" }
        );
        ok
    }
}

/// Default hook (refuse); the user decides after the fact.
struct AskTheUser;

impl FetcherContext for AskTheUser {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(NullEmitter)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ask(question: &str) -> bool {
    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok();
    matches!(line.trim(), "y" | "Y" | "yes")
}

async fn fetch(fetcher: &Fetcher, url: &Url) -> FetchResult {
    let req = FetchRequest::builder(Method::GET, url.clone())
        .with_auto_decode(true)
        .build();
    fetcher.fetch(req).await
}

fn describe(result: &FetchResult) {
    match result {
        FetchResult::Buffered { meta, body } => {
            println!("HTTP {} - {} bytes", meta.status, body.len());
        }
        FetchResult::Stream { meta, .. } => println!("HTTP {} (streamed)", meta.status),
        FetchResult::Error(e) => println!("error: {e}"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let auto = args.iter().any(|a| a == "--auto");
    let url = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "https://self-signed.badssl.com/".to_string());
    let url = Url::parse(&url)?;
    let host = url.host_str().unwrap_or_default().to_string();

    // Setting the store enables overrides. Keep a handle: the user's decision goes in there.
    let overrides = Arc::new(InMemoryTlsOverrideStore::new());
    let config = FetcherConfig {
        tls_overrides: Some(overrides.clone()),
        ..FetcherConfig::default()
    };
    let ctx: Arc<dyn FetcherContext> = if auto {
        Arc::new(TrustSelfSignedOn { host })
    } else {
        Arc::new(AskTheUser)
    };

    let fetcher = Arc::new(Fetcher::new(config, ctx)?);
    let shutdown = CancellationToken::new();
    let run = fetcher.clone();
    let cancel = shutdown.clone();
    tokio::spawn(async move { run.run(cancel).await });

    println!("Fetching {url} ...");
    let result = fetch(&fetcher, &url).await;
    describe(&result);

    if let FetchResult::Error(NetError::Tls(err)) = result {
        println!();
        println!("Certificate problem: {}", err.kind);
        println!("  host:        {}", err.host);
        println!("  detail:      {}", err.message);
        if let Some(fp) = &err.fingerprint {
            println!("  fingerprint: {}", hex(fp));
        }
        if let Some(der) = &err.certificate {
            println!("  certificate: {} bytes DER", der.len());
        }

        // Only certificate errors can be overridden. The fingerprint is there whenever the
        // override store is configured (our verifier saw the certificate).
        match err.fingerprint {
            Some(fp) if err.kind.is_certificate_error() => {
                if ask("Accept this certificate and retry?") {
                    // The "proceed anyway" click. Next connection to this host with this exact
                    // certificate goes through; a different certificate fails again.
                    overrides.accept(&err.host, fp);
                    println!("Retrying ...");
                    describe(&fetch(&fetcher, &url).await);
                }
            }
            _ => println!("This error cannot be overridden."),
        }
    }

    shutdown.cancel();
    Ok(())
}

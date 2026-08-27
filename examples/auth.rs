#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Answering `401` authentication challenges.
//!
//! A protected route challenges with `WWW-Authenticate`; the fetcher parses the challenge, looks
//! for credentials, and re-sends the request with them. Three cases:
//!
//! 1. A context that knows the password. `FetcherContext::on_auth_challenge` answers on the spot
//!    and the fetch returns 200. The credentials land in the store, so the second request for the
//!    same realm does not ask again.
//! 2. A context that does not. Without credentials the `401` is the result of the fetch,
//!    `WWW-Authenticate` intact. That is how an asynchronous password dialog works: refuse,
//!    prompt, then seed the store or re-submit.
//! 3. A scheme we cannot compute. The server offers `Digest` first and `Basic` second; the hook
//!    declines the `Digest` challenge and answers the `Basic` one.
//!
//! Run with:
//! ```text
//! cargo run --example auth --features test-support
//! ```

use gosub_sonar::net::test_support::{RouteConfig, TestServer};
use gosub_sonar::{
    AuthChallenge, AuthScheme, Credentials, FetchRequest, FetchResult, Fetcher, FetcherConfig,
    FetcherContext, InMemoryCredentialStore, Initiator, NetEvent, NetObserver, RequestId,
    RequestReference, ResourceKind,
};
use http::Method;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Prints every challenge the fetcher ran into and what it did about it.
struct AuthLog;

impl NetObserver for AuthLog {
    fn on_event(&self, ev: NetEvent) {
        if let NetEvent::AuthRequired {
            challenges,
            retried,
            ..
        } = ev
        {
            let offered: Vec<String> = challenges
                .iter()
                .map(|c| match c.realm.as_deref() {
                    Some(realm) => format!("{} realm={realm:?}", c.scheme),
                    None => c.scheme.to_string(),
                })
                .collect();
            println!(
                "    challenged with [{}] -> {}",
                offered.join(", "),
                if retried { "retrying" } else { "giving up" }
            );
        }
    }
}

/// Knows one password, and only for `Basic`.
struct Passwords {
    password: Option<&'static str>,
}

impl FetcherContext for Passwords {
    fn observer_for(
        &self,
        _: RequestReference,
        _: RequestId,
        _: ResourceKind,
        _: Initiator,
    ) -> Arc<dyn NetObserver + Send + Sync> {
        Arc::new(AuthLog)
    }
    fn on_ref_active(&self, _: RequestReference) {}
    fn on_ref_done(&self, _: RequestReference) {}

    fn on_auth_challenge(&self, challenge: &AuthChallenge) -> Option<Credentials> {
        println!(
            "    on_auth_challenge: {} realm={:?} attempt={}",
            challenge.scheme, challenge.realm, challenge.attempt
        );
        match challenge.scheme {
            // Basic is encoded for us. Another scheme means building the header value from
            // `challenge.params` (nonce, qop, algorithm) and returning `Credentials::Raw`.
            AuthScheme::Basic => Some(Credentials::basic("alice", self.password?)),
            _ => None,
        }
    }
}

async fn show(label: &str, fetcher: &Fetcher, req: FetchRequest) {
    println!("{label}");
    match fetcher.fetch(req).await {
        FetchResult::Buffered { meta, body } => {
            println!(
                "    {} — {}",
                meta.status,
                String::from_utf8_lossy(&body[..body.len().min(40)])
            );
            if let Some(challenge) = meta.headers.get(http::header::WWW_AUTHENTICATE) {
                println!("    www-authenticate: {}", challenge.to_str().unwrap_or(""));
            }
        }
        FetchResult::Error(err) => println!("    error: {err}"),
        other => println!("    {other:?}"),
    }
}

/// A fetcher with the given context and a fresh credential store.
fn fetcher_with(ctx: Arc<dyn FetcherContext>) -> (Arc<Fetcher>, CancellationToken) {
    let cfg = FetcherConfig {
        credentials: Some(Arc::new(InMemoryCredentialStore::new())),
        ..FetcherConfig::default()
    };
    let fetcher = Arc::new(Fetcher::new(cfg, ctx).unwrap());
    let shutdown = CancellationToken::new();
    let (f, c) = (fetcher.clone(), shutdown.clone());
    tokio::spawn(async move { f.run(c).await });
    (fetcher, shutdown)
}

#[tokio::main]
async fn main() {
    // base64("alice:hunter2") — what the server accepts.
    const EXPECTED: &str = "Basic YWxpY2U6aHVudGVyMg==";

    let srv = TestServer::new()
        .route(
            "/protected",
            RouteConfig::require_auth(
                r#"Basic realm="Members Only""#,
                EXPECTED,
                b"the secret document".to_vec(),
            ),
        )
        .route(
            "/digest-first",
            RouteConfig::require_auth(
                r#"Digest realm="Members Only", nonce="41cd2f", qop="auth", Basic realm="Members Only""#,
                EXPECTED,
                b"the secret document".to_vec(),
            ),
        )
        .start()
        .await;

    let (fetcher, shutdown) = fetcher_with(Arc::new(Passwords {
        password: Some("hunter2"),
    }));

    show(
        "1a. a context that knows the password",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/protected")).build(),
    )
    .await;
    println!("    server saw {} requests\n", srv.hit_count("/protected"));

    show(
        "1b. same realm again: answered from the credential store, the hook is not asked",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/protected")).build(),
    )
    .await;
    println!(
        "    server saw {} requests in total\n",
        srv.hit_count("/protected")
    );

    show(
        "3. Digest offered first, Basic second: the hook declines one and answers the other",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/digest-first")).build(),
    )
    .await;
    println!();
    shutdown.cancel();

    let (fetcher, shutdown) = fetcher_with(Arc::new(Passwords { password: None }));
    show(
        "2. a context without credentials: the 401 is the result, ready for a dialog",
        &fetcher,
        FetchRequest::builder(Method::GET, srv.url("/protected")).build(),
    )
    .await;
    shutdown.cancel();
}

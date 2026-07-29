//! Pluggable DNS resolution for the [`Fetcher`].
//!
//! Without configuration the fetcher delegates hostname lookups to reqwest's built-in
//! resolver (the system's `getaddrinfo`), which gives an embedder no way to (a) reject
//! internal, link-local, or otherwise off-limits address ranges, or (b) pin the resolved
//! addresses to the connection so a subsequent re-resolution cannot swap in different ones
//! (DNS rebinding). Set [`FetcherConfig::dns_resolver`] to make classification-and-pinning
//! part of resolution itself: when configured, the resolver is the *only* one the
//! underlying client consults, so every lookup — including each redirect hop the fetcher
//! follows — passes through it, and connections go to exactly the addresses it returns.
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use gosub_sonar::net::dns::{DnsResolver, Resolving};
//! use gosub_sonar::FetcherConfig;
//!
//! /// Resolves through the system resolver but refuses loopback and private ranges.
//! struct PublicOnly;
//!
//! impl DnsResolver for PublicOnly {
//!     fn resolve(&self, host: &str) -> Resolving {
//!         let host = host.to_owned();
//!         Box::pin(async move {
//!             let addrs: Vec<SocketAddr> =
//!                 tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
//!             let internal = |ip: std::net::IpAddr| match ip {
//!                 std::net::IpAddr::V4(v4) => {
//!                     v4.is_loopback() || v4.is_private() || v4.is_link_local()
//!                 }
//!                 std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
//!             };
//!             if addrs.iter().any(|a| internal(a.ip())) {
//!                 return Err(format!("{host} resolves to an internal address").into());
//!             }
//!             Ok(addrs)
//!         })
//!     }
//! }
//!
//! let cfg = FetcherConfig {
//!     dns_resolver: Some(Arc::new(PublicOnly)),
//!     ..FetcherConfig::default()
//! };
//! ```
//!
//! Native-only: on `wasm32` the browser's `fetch()` owns name resolution and offers no way
//! to override it, so this module is not compiled there.
//!
//! [`Fetcher`]: crate::net::fetcher::Fetcher
//! [`FetcherConfig::dns_resolver`]: crate::net::fetcher::FetcherConfig::dns_resolver

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

/// Error returned by [`DnsResolver::resolve`]. Surfaces to the caller as a connection
/// failure carrying this error's message, so make refusals descriptive
/// (`"10.0.0.5 is in a private range"`).
pub type DnsError = Box<dyn std::error::Error + Send + Sync>;

/// Future returned by [`DnsResolver::resolve`].
pub type Resolving = Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, DnsError>> + Send>>;

/// Resolves hostnames for the [`Fetcher`](crate::net::fetcher::Fetcher)'s outgoing
/// connections.
///
/// `host` is the bare hostname from the URL being connected to — no port, no scheme. The
/// port on the returned addresses is ignored when the URL names one explicitly; otherwise
/// a port of `0` is replaced by the scheme's default (80/443), so resolvers that don't
/// carry port information should return `0`.
///
/// To refuse a connection (an SSRF policy rejecting an internal range, say) return `Err`
/// rather than `Ok(vec![])`: both fail the connect, but the error's message is what the
/// caller sees.
///
/// Lookups happen per *connection*, not per request: a request served from a pooled
/// connection performs no lookup, which is exactly the pinning behaviour that defeats
/// DNS rebinding — a rebound name cannot redirect an existing connection.
pub trait DnsResolver: Send + Sync {
    /// Resolve `host` to the socket addresses the client may connect to.
    fn resolve(&self, host: &str) -> Resolving;
}

/// Adapts a [`DnsResolver`] to reqwest's `Resolve` trait so the fetcher's client builder
/// can hand it to `ClientBuilder::dns_resolver`.
pub(crate) struct ReqwestResolver(pub(crate) Arc<dyn DnsResolver>);

impl reqwest::dns::Resolve for ReqwestResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.0.clone();
        Box::pin(async move {
            let addrs = resolver.resolve(name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fetcher::{Fetcher, FetcherConfig};
    use crate::net::fetcher_context::NullContext;
    use crate::net::test_support::{RouteConfig, TestServer};
    use crate::net::types::{FetchRequest, FetchResult};
    use http::Method;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    /// Resolves only the hostnames in `map`, records every hostname it is asked about,
    /// and refuses everything else — the shape of an SSRF allow-list resolver.
    struct MapResolver {
        map: HashMap<String, SocketAddr>,
        seen: Mutex<Vec<String>>,
    }

    impl MapResolver {
        fn new(entries: &[(&str, SocketAddr)]) -> Arc<Self> {
            Arc::new(Self {
                map: entries.iter().map(|(h, a)| (h.to_string(), *a)).collect(),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().clone()
        }
    }

    impl DnsResolver for MapResolver {
        fn resolve(&self, host: &str) -> Resolving {
            self.seen.lock().push(host.to_string());
            let result = match self.map.get(host) {
                Some(addr) => Ok(vec![*addr]),
                None => Err(format!("resolver policy refuses host {host}").into()),
            };
            Box::pin(async move { result })
        }
    }

    fn config_with(resolver: Arc<MapResolver>) -> FetcherConfig {
        FetcherConfig {
            connect_timeout: Duration::from_secs(2),
            req_timeout: Duration::from_secs(5),
            dns_resolver: Some(resolver),
            ..FetcherConfig::default()
        }
    }

    fn spawn_fetcher(cfg: FetcherConfig) -> (Arc<Fetcher>, CancellationToken) {
        let fetcher = Arc::new(Fetcher::new(cfg, Arc::new(NullContext)).unwrap());
        let shutdown = CancellationToken::new();
        let f = fetcher.clone();
        let s = shutdown.clone();
        tokio::spawn(async move { f.run(s).await });
        (fetcher, shutdown)
    }

    async fn fetch(fetcher: &Fetcher, url: Url) -> FetchResult {
        let req = FetchRequest::builder(Method::GET, url).build();
        tokio::time::timeout(Duration::from_secs(5), fetcher.fetch(req))
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_resolver_handles_the_lookup() {
        let srv = TestServer::new()
            .route("/fast", RouteConfig::ok(b"x"))
            .start()
            .await;
        let addr = srv.socket_addr();

        let resolver = MapResolver::new(&[("sonar-dns.test", addr)]);
        let (fetcher, shutdown) = spawn_fetcher(config_with(resolver.clone()));

        let url = Url::parse(&format!("http://sonar-dns.test:{}/fast", addr.port())).unwrap();
        match fetch(&fetcher, url).await {
            FetchResult::Buffered { meta, body } => {
                assert_eq!(meta.status, 200);
                assert_eq!(&body[..], b"x");
            }
            other => panic!("expected Buffered, got {other:?}"),
        }
        assert_eq!(resolver.seen(), vec!["sonar-dns.test"]);
        shutdown.cancel();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolver_rejection_blocks_the_request() {
        let resolver = MapResolver::new(&[]);
        let (fetcher, shutdown) = spawn_fetcher(config_with(resolver.clone()));

        let url = Url::parse("http://sonar-refused.test/").unwrap();
        let result = fetch(&fetcher, url).await;
        assert!(result.is_error(), "expected an error, got {result:?}");
        assert_eq!(resolver.seen(), vec!["sonar-refused.test"]);
        shutdown.cancel();
    }

    /// The resolver must see the hostname of every redirect hop, not just the initial
    /// URL — that is what makes a rejection enforceable rather than best-effort.
    /// Both hostnames point at the same server; what matters is that the hop's
    /// hostname is looked up through the hook at all.
    #[tokio::test(flavor = "current_thread")]
    async fn resolver_covers_redirect_hops() {
        let target_srv = TestServer::new()
            .route("/fast", RouteConfig::ok(b"x"))
            .start()
            .await;
        let target_addr = target_srv.socket_addr();
        let hop_srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::RedirectAbsolute(format!(
                    "http://sonar-hop.test:{}/fast",
                    target_addr.port()
                )),
            )
            .start()
            .await;
        let hop_addr = hop_srv.socket_addr();

        let resolver = MapResolver::new(&[
            ("sonar-dns.test", hop_addr),
            ("sonar-hop.test", target_addr),
        ]);
        let (fetcher, shutdown) = spawn_fetcher(config_with(resolver.clone()));

        let url = Url::parse(&format!("http://sonar-dns.test:{}/hop", hop_addr.port())).unwrap();
        match fetch(&fetcher, url).await {
            FetchResult::Buffered { meta, body } => {
                assert_eq!(meta.status, 200);
                assert_eq!(&body[..], b"x");
            }
            other => panic!("expected Buffered, got {other:?}"),
        }
        assert_eq!(resolver.seen(), vec!["sonar-dns.test", "sonar-hop.test"]);
        shutdown.cancel();
    }

    /// A hop whose hostname the resolver refuses must fail the whole fetch — the redirect
    /// target cannot slip past the policy that vetted the initial URL.
    #[tokio::test(flavor = "current_thread")]
    async fn resolver_rejection_blocks_a_redirect_hop() {
        let srv = TestServer::new()
            .route(
                "/hop",
                RouteConfig::RedirectAbsolute("http://sonar-internal.test/".to_string()),
            )
            .start()
            .await;
        let addr = srv.socket_addr();

        let resolver = MapResolver::new(&[("sonar-dns.test", addr)]);
        let (fetcher, shutdown) = spawn_fetcher(config_with(resolver.clone()));

        let url = Url::parse(&format!("http://sonar-dns.test:{}/hop", addr.port())).unwrap();
        let result = fetch(&fetcher, url).await;
        assert!(result.is_error(), "expected an error, got {result:?}");
        assert_eq!(
            resolver.seen(),
            vec!["sonar-dns.test", "sonar-internal.test"]
        );
        shutdown.cancel();
    }
}

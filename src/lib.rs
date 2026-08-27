#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::dbg_macro)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod http;
pub mod net;
pub mod types;

pub use net::auth::{
    AuthChallenge, AuthScheme, AuthTarget, CredentialStore, Credentials, InMemoryCredentialStore,
    ProtectionSpace, MAX_AUTH_ATTEMPTS,
};
pub use net::cors::{CorsError, ResponseTainting};
#[cfg(not(target_arch = "wasm32"))]
pub use net::cors::{CorsPreflightCache, InMemoryPreflightCache, PreflightAllows};
#[cfg(not(target_arch = "wasm32"))]
pub use net::dns::{DnsError, DnsResolver, Resolving};
pub use net::events::NetEvent;
pub use net::fetch_metadata::{RequestDestination, RequestMode, SecFetchSite};
pub use net::fetcher::{Fetcher, FetcherConfig, DEFAULT_USER_AGENT};
pub use net::fetcher_context::{FetcherContext, NullContext};
#[cfg(not(target_arch = "wasm32"))]
pub use net::hsts::{HstsEntry, HstsStore, InMemoryHstsStore};
pub use net::mixed_content::MixedContentPolicy;
pub use net::null_emitter::NullEmitter;
pub use net::observer::NetObserver;
#[cfg(not(target_arch = "wasm32"))]
pub use net::proxy::{ProxyAuth, ProxyConfig, ProxyRule, ProxyScope};
pub use net::referrer::ReferrerPolicy;
pub use net::request_ref::RequestReference;
pub use net::shared_body::SharedBody;
pub use net::simple::simple_get;
#[cfg(not(target_arch = "wasm32"))]
pub use net::simple::{sync_fetch, sync_get};
pub use net::tls::{
    Fingerprint, InMemoryTlsOverrideStore, TlsError, TlsErrorKind, TlsOverrideStore,
};
pub use net::types::{
    BlockReason, BoxedAsyncRead, FetchRequest, FetchRequestBuilder, FetchResult, FetchResultMeta,
    Initiator, NetError, Priority, RequestBody, RequestCredentials, ResourceKind,
};
pub use types::{PeekBuf, RequestId};

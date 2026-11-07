//! `Fetcher::new` with `ProxyConfig::System` reading the process environment. A test binary of
//! its own with a single test, so nothing else runs while the variables are set.

use gosub_sonar::{simple_get, Fetcher, FetcherConfig, NullContext};
use std::sync::Arc;
use url::Url;

const VARS: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

fn clear() {
    for name in VARS {
        std::env::remove_var(name);
    }
}

fn new_fetcher() -> anyhow::Result<Fetcher> {
    Fetcher::new(FetcherConfig::default(), Arc::new(NullContext))
}

#[tokio::test]
async fn an_unusable_env_proxy_fails_the_fetcher() {
    clear();
    assert!(new_fetcher().is_ok(), "no proxy in the environment");

    std::env::set_var("ALL_PROXY", "http://127.0.0.1:3128");
    assert!(new_fetcher().is_ok(), "a usable proxy");

    std::env::set_var("ALL_PROXY", "http://alice:hunter2@[not-an-address");
    let e = format!("{:#}", new_fetcher().err().expect("an unusable proxy"));
    assert!(e.contains("ALL_PROXY"), "{e}");
    assert!(!e.contains("hunter2"), "{e}");

    // The simple API reads the environment the same way.
    let url = Url::parse("http://127.0.0.1:1080/").unwrap();
    let e = format!("{:#}", simple_get(&url).await.unwrap_err());
    assert!(e.contains("ALL_PROXY") && !e.contains("hunter2"), "{e}");

    if !cfg!(feature = "socks") {
        std::env::set_var("ALL_PROXY", "socks5h://127.0.0.1:9050");
        assert!(new_fetcher().is_err(), "socks without the `socks` feature");
    }

    clear();
}

//! One-shot GET helpers for callers that don't need the full scheduler.

use crate::http::response::Response;
use anyhow::Result;
use bytes::Bytes;
use cookie::Cookie;
use cow_utils::CowUtils;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// Maximum body size accepted by the simple API (10 MiB).
const MAX_SIMPLE_BODY: u64 = 10 * 1024 * 1024;

/// Perform a simple one-shot GET request and return the body as bytes.
/// Handles http, https, and file:// URLs.
/// Use this for standalone callers (renderer, tools) that don't need the full
/// priority-scheduler Fetcher.
///
/// The body is capped at 10 MiB. No SSRF protection is applied;
/// callers are responsible for validating the URL before passing it here.
pub async fn simple_get(url: &Url) -> Result<Bytes> {
    match url.scheme() {
        "file" => {
            use std::io::Read as _;
            let path = url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL: {url}"))?;
            // Open and read in one step with a hard byte cap to eliminate the TOCTOU
            // window that a separate metadata() + read() would create.
            let mut body = Vec::new();
            std::fs::File::open(&path)?
                .take(MAX_SIMPLE_BODY + 1)
                .read_to_end(&mut body)?;
            if body.len() as u64 > MAX_SIMPLE_BODY {
                anyhow::bail!("file too large (exceeds {} bytes)", MAX_SIMPLE_BODY);
            }
            Ok(Bytes::from(body))
        }
        "http" | "https" => {
            let client = reqwest::Client::builder()
                .use_rustls_tls()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .build()?;
            let resp = client.get(url.as_str()).send().await?;
            let status = resp.status();
            if !status.is_success() {
                anyhow::bail!("HTTP {status} fetching {url}");
            }
            if let Some(len) = resp.content_length() {
                if len > MAX_SIMPLE_BODY {
                    anyhow::bail!(
                        "response too large ({len} bytes, limit {MAX_SIMPLE_BODY} bytes)"
                    );
                }
            }
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                body.extend_from_slice(&chunk);
                if body.len() as u64 > MAX_SIMPLE_BODY {
                    anyhow::bail!("response body exceeds {MAX_SIMPLE_BODY} bytes");
                }
            }
            Ok(Bytes::from(body))
        }
        scheme => anyhow::bail!("Unsupported URL scheme: {scheme}"),
    }
}

/// Perform a one-shot synchronous GET and return the body as bytes.
///
/// Like [`simple_get`] but sync and safe to call from any context (including inside a Tokio
/// runtime). Errors on non-2xx status codes.
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_get(url: &Url) -> Result<Bytes> {
    let url = url.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(simple_get(&url))
    })
    .join()
    .map_err(|_| anyhow::anyhow!("sync_get: HTTP thread panicked"))?
}

/// Perform a one-shot synchronous GET, returning the full response (status, headers, body).
///
/// Safe to call from **any** context — including from within a Tokio async runtime.
/// The request always runs on a dedicated OS thread with its own Tokio runtime, so it
/// never conflicts with an already-active runtime on the calling thread.
///
/// Use this for engine-internal code that must issue an HTTP request synchronously
/// (e.g. the HTML parser loading an external stylesheet mid-parse).
#[cfg(not(target_arch = "wasm32"))]
pub fn sync_fetch(url: &Url) -> Result<Response> {
    let url = url.clone();
    std::thread::spawn(move || do_sync_fetch(url))
        .join()
        .map_err(|_| anyhow::anyhow!("sync_fetch: HTTP thread panicked"))?
}

#[cfg(not(target_arch = "wasm32"))]
fn do_sync_fetch(url: Url) -> Result<Response> {
    use std::io::Read as _;

    const MAX_BODY: u64 = 10 * 1024 * 1024;

    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid file URL: {}", url))?;
        let mut body = Vec::new();
        std::fs::File::open(&path)?
            .take(MAX_BODY + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_BODY {
            anyhow::bail!("File too large (> {} bytes)", MAX_BODY);
        }
        return Ok(Response::from(body));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;

    rt.block_on(async move {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        let resp = client.get(url.as_str()).send().await?;

        let status = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();
        let version = match resp.version() {
            reqwest::Version::HTTP_10 => "HTTP/1.0",
            reqwest::Version::HTTP_11 => "HTTP/1.1",
            reqwest::Version::HTTP_2 => "HTTP/2",
            reqwest::Version::HTTP_3 => "HTTP/3",
            _ => "HTTP/1.1",
        }
        .to_string();

        if let Some(cl) = resp.headers().get("content-length") {
            if let Ok(size) = cl.to_str().unwrap_or("").parse::<u64>() {
                if size > MAX_BODY {
                    anyhow::bail!("Response body exceeds maximum size of {} bytes", MAX_BODY);
                }
            }
        }

        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().cow_to_lowercase().into_owned(), v.to_string()))
            })
            .collect();

        let cookies: HashMap<String, String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| {
                let s = v.to_str().ok()?;
                Cookie::parse(s.to_owned())
                    .ok()
                    .map(|c| (c.name().to_owned(), c.value().to_owned()))
            })
            .collect();

        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
            if body.len() as u64 > MAX_BODY {
                anyhow::bail!("Response body exceeds maximum size of {} bytes", MAX_BODY);
            }
        }

        Ok(Response {
            status,
            status_text,
            version,
            headers,
            cookies,
            body,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test(flavor = "current_thread")]
    async fn simple_get_reads_file_url() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"file content").unwrap();
        let url = Url::from_file_path(f.path()).unwrap();
        let bytes = simple_get(&url).await.unwrap();
        assert_eq!(&bytes[..], b"file content");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sync_get_fetches_from_http_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                );
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        let bytes = sync_get(&url).unwrap();
        assert_eq!(&bytes[..], b"hello");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sync_fetch_returns_full_response() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                );
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        let resp = sync_fetch(&url).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body[..], b"hello");
        assert!(resp.headers.contains_key("content-type"));
    }
}

//! The simple helpers' native side: the tuned client, its redirect policy, body decoding,
//! `file:` reads and the blocking fetch. On wasm32 the browser's `fetch()` does the network
//! part itself and there is no filesystem, and `wasm.rs` stands in with the same items.

use super::{content_length, refuse_bad_port, SimpleOptions};
use crate::http::response::Response;
use crate::net::fetcher::DEFAULT_USER_AGENT;
use crate::net::transport::TransportError;
use crate::net::types::NetError;
use anyhow::Result;
use bytes::Bytes;
use cookie::Cookie;
use cow_utils::CowUtils;
use futures_util::StreamExt;
use http::{header, HeaderMap};
use std::collections::HashMap;
use url::Url;

/// Most redirect hops followed.
pub(super) const MAX_SIMPLE_REDIRECTS: usize = 10;

/// Whether a redirect from `previous` (every hop so far) to `next` is followed.
///
/// `previous` starts with the URL first asked for, so it holds one URL more than the redirects
/// followed so far.
pub(super) fn allow_redirect(
    previous: &[Url],
    next: &Url,
    allowed_bad_ports: &[u16],
) -> Result<(), &'static str> {
    if previous.len() > MAX_SIMPLE_REDIRECTS {
        return Err("too many redirects");
    }
    if crate::net::port_blocking::should_block(next, allowed_bad_ports) {
        return Err("redirect to a bad port refused");
    }
    match next.scheme() {
        "https" => Ok(()),
        "http" if previous.iter().any(|u| u.scheme() == "https") => {
            Err("redirect from https to http refused")
        }
        "http" => Ok(()),
        _ => Err("redirect to an unsupported scheme"),
    }
}

/// The `User-Agent` sent unless one was set by hand: `user_agent`, else [`DEFAULT_USER_AGENT`].
pub(super) fn user_agent(user_agent: Option<&str>) -> Option<&str> {
    Some(user_agent.unwrap_or(DEFAULT_USER_AGENT))
}

/// The codings `decoded` undoes; the client is built without a decoder of its own.
pub(super) fn accept_encoding(headers: &mut HeaderMap) {
    if !headers.contains_key(header::ACCEPT_ENCODING) {
        headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("gzip, br, deflate"),
        );
    }
}

/// `b` with TLS, timeouts, the redirect policy and the proxy from `opts`.
pub(super) fn configure(
    opts: &SimpleOptions,
    b: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    let allowed_bad_ports = opts.allowed_bad_ports.clone();
    let b = opts.proxy.apply(
        b.use_rustls_tls()
            // Bodies are decoded by `decoded`, never by the client; off explicitly, as a
            // crate that enables reqwest's decompression features would turn it on.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(opts.connect_timeout)
            .timeout(opts.timeout)
            .redirect(reqwest::redirect::Policy::custom(
                move |attempt| match allow_redirect(
                    attempt.previous(),
                    attempt.url(),
                    &allowed_bad_ports,
                ) {
                    Ok(()) => attempt.follow(),
                    Err(why) => attempt.error(why),
                },
            )),
    )?;
    Ok(b)
}

/// Fail for anything but a regular file: a FIFO or device has no end to read to.
fn require_regular_file(meta: &std::fs::Metadata) -> Result<()> {
    if meta.is_file() {
        Ok(())
    } else {
        anyhow::bail!("not a regular file")
    }
}

/// The body of the file at `url`, at most `max_body` bytes.
pub(super) async fn read_file(url: &Url, max_body: u64) -> Result<Bytes> {
    use tokio::io::AsyncReadExt as _;
    let path = url
        .to_file_path()
        .map_err(|_| anyhow::anyhow!("invalid file URL: {url}"))?;
    // Checked on the opened handle and read with a hard cap, so there is no window
    // between the check and the read.
    let file = tokio::fs::File::open(&path).await?;
    require_regular_file(&file.metadata().await?)?;
    let mut body = Vec::new();
    file.take(max_body.saturating_add(1))
        .read_to_end(&mut body)
        .await?;
    if body.len() as u64 > max_body {
        anyhow::bail!("file too large (exceeds {} bytes)", max_body);
    }
    Ok(Bytes::from(body))
}

/// The headers and body of `resp` as the caller gets them: a body in content codings decoded
/// by [`decode`](crate::net::decode), without the `Content-Encoding` and `Content-Length` that
/// described the coded bytes, the way the fetcher hands one on.
pub(super) fn decoded(
    resp: reqwest::Response,
) -> (
    HeaderMap,
    futures_util::stream::BoxStream<'static, std::result::Result<Bytes, NetError>>,
) {
    use futures_util::TryStreamExt;
    let mut headers = resp.headers().clone();
    let body = resp
        .bytes_stream()
        .map_err(|e| NetError::Transport(TransportError::from_client(&e)))
        .boxed();
    match crate::net::decode::codings(&headers).filter(|c| !c.is_empty()) {
        Some(codings) => {
            headers.remove(header::CONTENT_ENCODING);
            headers.remove(header::CONTENT_LENGTH);
            (headers, crate::net::decode::decode(body, codings))
        }
        None => (headers, body),
    }
}

pub(super) fn do_sync_fetch(url: Url, opts: SimpleOptions) -> Result<Response> {
    use std::io::Read as _;

    let max_body = opts.max_body;

    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid file URL: {}", url))?;
        // Blocking is fine: this runs on its own thread.
        let file = std::fs::File::open(&path)?;
        require_regular_file(&file.metadata()?)?;
        let mut body = Vec::new();
        file.take(max_body.saturating_add(1))
            .read_to_end(&mut body)?;
        if body.len() as u64 > max_body {
            anyhow::bail!("File too large (> {} bytes)", max_body);
        }
        return Ok(Response::from(body));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;

    rt.block_on(async move {
        refuse_bad_port(&url, &opts.allowed_bad_ports)?;
        let client = opts.build_client()?;
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

        let (response_headers, mut stream) = decoded(resp);
        if let Some(size) = content_length(&response_headers) {
            if size > max_body {
                anyhow::bail!("Response body exceeds maximum size of {} bytes", max_body);
            }
        }

        let headers: HashMap<String, String> = response_headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().cow_to_lowercase().into_owned(), v.to_string()))
            })
            .collect();

        let cookies: HashMap<String, String> = response_headers
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
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            body.extend_from_slice(&chunk);
            if body.len() as u64 > max_body {
                anyhow::bail!("Response body exceeds maximum size of {} bytes", max_body);
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

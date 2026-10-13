//! Content codings: undoing the `Content-Encoding` of a response body (RFC 9110 §8.4).
//!
//! The fetcher decodes bodies itself rather than leaving it to the HTTP client, which reads only
//! the first `Content-Encoding` field line and compares it case-sensitively: `GZIP` went through
//! undecoded, and `gzip` on two lines was decoded once with both lines dropped, handing the
//! caller gzip bytes labelled as plain ones.
//!
//! [`codings`] reads the codings in the order they were applied, every field line and every
//! list member of one, case-insensitively. [`decode`] undoes them, last applied first. A list
//! with a coding this module cannot undo is not decoded at all: the body and its header reach
//! the caller as they came, so the caller can tell.

use crate::net::transport::{TransportError, TransportErrorKind};
use crate::net::types::NetError;
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder};
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt, TryStreamExt};
use http::{header, HeaderMap};
use tokio::io::{AsyncBufRead, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

/// A content coding [`decode`] can undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coding {
    /// `gzip`, or its alias `x-gzip` (RFC 9110 §8.4.1.3).
    Gzip,
    /// `deflate`: the zlib format (RFC 9110 §8.4.1.2).
    Deflate,
    /// `br` (RFC 7932).
    Brotli,
}

/// The codings applied to a body, in the order they were applied, read from every
/// `Content-Encoding` field line (RFC 9110 §5.3, §8.4) and compared case-insensitively
/// (§8.4.1). `identity` is no coding. `None` when one of them is not a coding [`decode`] can
/// undo, or a line is not text: such a body cannot be decoded, and is passed on as it is.
pub(crate) fn codings(headers: &HeaderMap) -> Option<Vec<Coding>> {
    let mut out = Vec::new();
    for line in headers.get_all(header::CONTENT_ENCODING) {
        for member in line.to_str().ok()?.split(',') {
            let member = member.trim();
            if member.is_empty() || member.eq_ignore_ascii_case("identity") {
                continue;
            }
            out.push(
                if member.eq_ignore_ascii_case("gzip") || member.eq_ignore_ascii_case("x-gzip") {
                    Coding::Gzip
                } else if member.eq_ignore_ascii_case("deflate") {
                    Coding::Deflate
                } else if member.eq_ignore_ascii_case("br") {
                    Coding::Brotli
                } else {
                    return None;
                },
            );
        }
    }
    Some(out)
}

/// `body` with `codings` undone, last applied first. A body with no bytes at all is left empty:
/// there is nothing to decode, and a decoder would take it for a truncated stream. A body the
/// decoders reject ends in a [`TransportErrorKind::Decode`] error; an error of the body itself
/// comes through as it was.
pub(crate) fn decode(
    body: BoxStream<'static, Result<Bytes, NetError>>,
    codings: Vec<Coding>,
) -> BoxStream<'static, Result<Bytes, NetError>> {
    if codings.is_empty() {
        return body;
    }
    stream::once(async move {
        let mut body = body;
        // Wait for the first bytes, so an empty body never reaches a decoder.
        let first = loop {
            match body.next().await {
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                other => break other,
            }
        };
        let body = match first {
            None => return stream::empty().boxed(),
            Some(Err(e)) => return stream::iter([Err(e)]).boxed(),
            Some(Ok(chunk)) => stream::iter([Ok(chunk)]).chain(body),
        };
        let mut reader: Box<dyn AsyncBufRead + Send + Unpin> =
            Box::new(StreamReader::new(body.map_err(|e| e.to_io())));
        for coding in codings.into_iter().rev() {
            reader = match coding {
                Coding::Gzip => {
                    let mut decoder = GzipDecoder::new(reader);
                    // A gzip body may be several members back to back (RFC 1952 §2.2).
                    decoder.multiple_members(true);
                    Box::new(BufReader::new(decoder))
                }
                Coding::Deflate => Box::new(BufReader::new(ZlibDecoder::new(reader))),
                Coding::Brotli => Box::new(BufReader::new(BrotliDecoder::new(reader))),
            };
        }
        ReaderStream::new(reader).map_err(decode_error).boxed()
    })
    .flatten()
    .boxed()
}

/// An error out of the decoders: the body's own error when it carries one, and otherwise the
/// decoders' rejection of the bytes.
fn decode_error(e: std::io::Error) -> NetError {
    match NetError::from(e) {
        NetError::Io(e) => NetError::Transport(TransportError {
            kind: TransportErrorKind::Decode,
            message: e.to_string(),
        }),
        carried => carried,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn headers(lines: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for line in lines {
            h.append(header::CONTENT_ENCODING, line.parse().unwrap());
        }
        h
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    async fn run(chunks: Vec<Vec<u8>>, codings: Vec<Coding>) -> Result<Vec<u8>, NetError> {
        let body = stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from(c)))).boxed();
        let mut out = Vec::new();
        let mut decoded = decode(body, codings);
        while let Some(chunk) = decoded.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    /// RFC 9110 §8.4: the codings in the order they were applied, over every field line and
    /// every list member; §8.4.1: case-insensitive, `x-gzip` is `gzip`, `identity` is none.
    #[test]
    fn codings_are_read_from_every_line_in_order() {
        use Coding::*;
        assert_eq!(codings(&headers(&[])), Some(vec![]));
        assert_eq!(codings(&headers(&["GZIP"])), Some(vec![Gzip]));
        assert_eq!(codings(&headers(&["gzip, br"])), Some(vec![Gzip, Brotli]));
        assert_eq!(
            codings(&headers(&["deflate", "X-Gzip"])),
            Some(vec![Deflate, Gzip])
        );
        assert_eq!(
            codings(&headers(&["identity", " gzip ,"])),
            Some(vec![Gzip])
        );
    }

    /// RFC 9110 §8.4: a coding that cannot be undone leaves the body as it is, whatever else
    /// the list holds.
    #[test]
    fn an_unknown_coding_is_not_decoded() {
        assert_eq!(codings(&headers(&["gzip, x-frob"])), None);
        assert_eq!(codings(&headers(&["zstd"])), None);
    }

    /// The last coding applied is undone first: `gzip` over `deflate`, on two lines.
    #[tokio::test]
    async fn codings_are_undone_last_applied_first() {
        let plain = b"twice coded".to_vec();
        let coded = gz(&zlib(&plain));
        let half = coded.len() / 2;
        let chunks = vec![coded[..half].to_vec(), coded[half..].to_vec()];
        let codings = codings(&headers(&["deflate", "gzip"])).unwrap();
        assert_eq!(run(chunks, codings).await.unwrap(), plain);
    }

    /// An empty body stays empty; a decoder would take it for a cut-off stream.
    #[tokio::test]
    async fn an_empty_body_is_not_decoded() {
        let chunks = vec![Vec::new(), Vec::new()];
        assert_eq!(run(chunks, vec![Coding::Gzip]).await.unwrap(), b"");
    }

    /// Bytes the decoder rejects are a `Decode` transport error; the body's own error is kept.
    #[tokio::test]
    async fn errors_are_told_apart() {
        let err = run(vec![b"not gzip".to_vec()], vec![Coding::Gzip])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, NetError::Transport(t) if t.kind == TransportErrorKind::Decode),
            "{err:?}"
        );
        let body = stream::iter([
            Ok(Bytes::from(gz(b"abc")[..4].to_vec())),
            Err(NetError::Timeout("idle".into())),
        ])
        .boxed();
        let mut decoded = decode(body, vec![Coding::Gzip]);
        let mut last = None;
        while let Some(item) = decoded.next().await {
            if let Err(e) = item {
                last = Some(e);
            }
        }
        assert!(matches!(last, Some(NetError::Timeout(_))), "{last:?}");
    }
}

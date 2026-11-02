//! Request bodies' native side: bodies streamed from a reader or from a file, opened at each
//! send. On wasm32 reqwest's body takes bytes only and there is no filesystem, and `wasm.rs`
//! stands in with a `NativePayload` that has no values.

use super::{BodyStreamFactory, BoxedAsyncRead};
use std::fmt::DebugStruct;

/// A request body that is not buffered bytes.
#[derive(Clone)]
pub(super) enum NativePayload {
    Stream {
        open: BodyStreamFactory,
        len: Option<u64>,
    },
    /// A file on disk, opened and measured at each send.
    File(std::path::PathBuf),
}

impl NativePayload {
    pub(super) fn debug_field<'a, 'b, 'c>(
        &self,
        d: &'a mut DebugStruct<'b, 'c>,
    ) -> &'a mut DebugStruct<'b, 'c> {
        match self {
            NativePayload::Stream { len, .. } => d.field("stream", len),
            NativePayload::File(path) => d.field("file", path),
        }
    }

    pub(super) fn len(&self) -> Option<u64> {
        match self {
            NativePayload::Stream { len, .. } => *len,
            NativePayload::File(path) => std::fs::metadata(path).ok().map(|m| m.len()),
        }
    }

    pub(super) fn to_reqwest_body(&self) -> std::io::Result<(reqwest::Body, Option<u64>)> {
        match self {
            NativePayload::Stream { open, len } => {
                let reader = open()?;
                let stream = tokio_util::io::ReaderStream::new(reader);
                Ok((reqwest::Body::wrap_stream(stream), *len))
            }
            // Length from the handle that is sent, so it matches what is read.
            NativePayload::File(path) => {
                let f = std::fs::File::open(path)?;
                let len = regular_file(&f.metadata()?)?;
                let reader = Box::pin(tokio::fs::File::from_std(f)) as BoxedAsyncRead;
                let stream = tokio_util::io::ReaderStream::new(reader);
                Ok((reqwest::Body::wrap_stream(stream), Some(len)))
            }
        }
    }
}

/// The length of a regular file, or an error for anything else (a FIFO or device has no
/// length and may never end).
pub(super) fn regular_file(meta: &std::fs::Metadata) -> std::io::Result<u64> {
    if meta.is_file() {
        Ok(meta.len())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request body must be a regular file",
        ))
    }
}

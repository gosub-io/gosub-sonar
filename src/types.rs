//! Shared primitive types used across the crate.

use bytes::Bytes;
use std::fmt::Display;
use std::ops::Deref;
use uuid::Uuid;

/// A small buffer that contains the first bytes of a stream.
/// This is used to "peek" into the stream, to determine the content type
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeekBuf(Bytes);

impl PeekBuf {
    /// Creates a peek buffer that takes ownership of the given vector
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self(Bytes::from(vec))
    }

    /// Creates a peek buffer by copying the given slice
    pub fn from_slice(s: &[u8]) -> Self {
        Self(Bytes::copy_from_slice(s))
    }

    /// Creates an empty peek buffer
    pub fn empty() -> Self {
        Self(Bytes::new())
    }

    /// Returns the number of bytes in the buffer
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the buffer contains no bytes
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the buffer contents as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a reference to the underlying [`Bytes`]
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Consumes the buffer and returns the underlying [`Bytes`]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl AsRef<[u8]> for PeekBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for PeekBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// One logical request chain (stable across redirects)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct RequestId(pub Uuid);

impl RequestId {
    /// Creates a new random request ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_buf_as_bytes_roundtrip() {
        let buf = PeekBuf::from_slice(b"hello");
        assert_eq!(buf.as_bytes().as_ref(), b"hello");
    }

    #[test]
    fn peek_buf_into_bytes() {
        let buf = PeekBuf::from_slice(b"world");
        assert_eq!(&buf.into_bytes()[..], b"world");
    }

    #[test]
    fn request_id_default_produces_unique_ids() {
        let a = RequestId::default();
        let b = RequestId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn request_id_display_is_uuid_format() {
        let id = RequestId::new();
        let s = format!("{}", id);
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|&c| c == '-').count(), 4);
    }
}

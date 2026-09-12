//! Transport failures, described without naming the HTTP client underneath.
//!
//! An embedder needs to tell a host that never answered from a body that stopped part way, and
//! only the client knows which it was. Asking it directly means depending on reqwest, at the
//! version sonar happened to resolve, so sonar asks and reports the answer as a
//! [`TransportError`] on [`NetError::Transport`].
//!
//! [`NetError::Transport`]: crate::net::types::NetError::Transport

use std::fmt;

/// Which part of a request the transport failed in.
///
/// Non-exhaustive: a client can learn to tell apart failures it used to lump together, so a
/// `match` over this needs a catch-all arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// Nothing connected: the name did not resolve, the address refused, or the host was
    /// unreachable. Nothing was sent.
    Connect,
    /// The client's own deadline (connect or request) expired first.
    Timeout,
    /// The client could not follow the redirect chain.
    Redirect,
    /// The transfer started and then stopped part way.
    Body,
    /// The body arrived but would not decode, e.g. a `Content-Encoding` that does not
    /// decompress.
    Decode,
    /// The request could not be sent.
    Request,
    /// The request or the client could not be built from what it was given.
    Builder,
    /// The client reported a failure it did not classify further.
    Other,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connection failed",
            Self::Timeout => "timed out",
            Self::Redirect => "redirect could not be followed",
            Self::Body => "transfer failed",
            Self::Decode => "body could not be decoded",
            Self::Request => "request could not be sent",
            Self::Builder => "request could not be built",
            Self::Other => "transport error",
        })
    }
}

/// A failure reported by the HTTP transport beneath the fetch stack.
///
/// Match on `kind`. `message` is the client's own wording, flattened from its error chain, and
/// is for logs and error pages only: it belongs to the client and changes between its releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    /// What failed.
    pub kind: TransportErrorKind,
    /// The client's description of it, source chain included.
    pub message: String,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for TransportError {}

impl TransportError {
    /// Classify the client's error.
    ///
    /// Order matters: a timeout and a connect failure are both a failed send, and the timeout is
    /// the more specific answer.
    pub(crate) fn from_client(e: &reqwest::Error) -> Self {
        // `is_connect` is native-only: on wasm32 the browser's fetch() owns the connection and
        // never tells us that it was the part that failed.
        #[cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))]
        let is_connect = e.is_connect();
        #[cfg(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none")))]
        let is_connect = false;

        let kind = if e.is_timeout() {
            TransportErrorKind::Timeout
        } else if is_connect {
            TransportErrorKind::Connect
        } else if e.is_redirect() {
            TransportErrorKind::Redirect
        } else if e.is_decode() {
            TransportErrorKind::Decode
        } else if e.is_body() {
            TransportErrorKind::Body
        } else if e.is_builder() {
            TransportErrorKind::Builder
        } else if e.is_request() {
            TransportErrorKind::Request
        } else {
            TransportErrorKind::Other
        };

        Self {
            kind,
            message: flatten(e),
        }
    }
}

/// Join an error with its source chain into one line.
///
/// The client's own `Display` is terse ("error sending request"); what went wrong sits in the
/// sources below it, which a plain `to_string()` throws away.
fn flatten(e: &reqwest::Error) -> String {
    use std::error::Error as _;

    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(err) = source {
        let next = err.to_string();
        // A layer repeating its source's message verbatim is common enough that the
        // unflattened string would read "connection refused: connection refused".
        if !out.ends_with(&next) {
            out.push_str(": ");
            out.push_str(&next);
        }
        source = err.source();
    }
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A host nothing is listening on. Without the classification it is indistinguishable from a
    /// body that stopped mid-transfer, which sends you looking at the server when the problem is
    /// the address.
    #[tokio::test]
    async fn a_host_that_never_answers_is_a_connect_failure() {
        // Port 1 on loopback: nothing listens there, and nothing leaves the machine.
        let e = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err();

        let err = TransportError::from_client(&e);
        assert_eq!(err.kind, TransportErrorKind::Connect);
        // The client's own Display says only "error sending request"; the reason lives in the
        // source chain, and dropping it is what makes these errors useless in a log.
        assert!(
            err.message.len() > e.to_string().len(),
            "source chain was not flattened into the message: {:?}",
            err.message
        );
    }

    /// A deadline that expires before anything connects is a timeout, not a connect failure.
    #[tokio::test]
    async fn an_expired_deadline_outranks_the_connect_failure_underneath_it() {
        // 203.0.113.0/24 is TEST-NET-3: reserved for documentation, so it routes nowhere and
        // the connect attempt hangs until the timeout fires rather than being refused.
        let e = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(50))
            .build()
            .unwrap()
            .get("http://203.0.113.1/")
            .send()
            .await
            .unwrap_err();

        assert_eq!(
            TransportError::from_client(&e).kind,
            TransportErrorKind::Timeout
        );
    }
}

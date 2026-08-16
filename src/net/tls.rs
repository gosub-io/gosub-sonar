//! Structured TLS errors.
//!
//! A failed TLS handshake comes out of reqwest as a chain of wrapped errors with a
//! `rustls::Error` at the bottom. [`TlsError`] pulls out the part callers care about — did the
//! certificate expire, is it for another host, is the issuer unknown — so an embedder can show
//! the right warning instead of a generic connection error. The fetch layer returns it as
//! [`NetError::Tls`](crate::net::types::NetError::Tls).
//!
//! Only the classification runs on native targets; on wasm32 the browser does TLS and never
//! hands us the details, so `NetError::Tls` is never produced there.

use std::fmt;

/// What went wrong in the TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsErrorKind {
    /// The certificate's validity period has ended.
    Expired,
    /// The certificate's validity period has not started yet.
    NotYetValid,
    /// The chain does not lead to a trusted root. Self-signed certificates end up here.
    UnknownIssuer,
    /// The certificate is not valid for the host name we connected to.
    HostnameMismatch,
    /// The certificate has been revoked.
    Revoked,
    /// The certificate could not be parsed or verified for some other reason (bad encoding,
    /// bad signature, unsupported algorithm, wrong purpose, ...).
    InvalidCertificate,
    /// The handshake failed before or without a certificate problem: alert from the peer,
    /// no protocol version or cipher suite in common, malformed messages.
    Handshake,
    /// A TLS error we could not classify further.
    Other,
}

impl TlsErrorKind {
    /// Whether this is a certificate verification failure, as opposed to a protocol-level
    /// handshake failure. Only these make sense to offer a "proceed anyway" override for.
    pub fn is_certificate_error(self) -> bool {
        matches!(
            self,
            Self::Expired
                | Self::NotYetValid
                | Self::UnknownIssuer
                | Self::HostnameMismatch
                | Self::Revoked
                | Self::InvalidCertificate
        )
    }
}

impl fmt::Display for TlsErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Expired => "certificate expired",
            Self::NotYetValid => "certificate not yet valid",
            Self::UnknownIssuer => "unknown certificate issuer",
            Self::HostnameMismatch => "certificate not valid for host name",
            Self::Revoked => "certificate revoked",
            Self::InvalidCertificate => "invalid certificate",
            Self::Handshake => "handshake failed",
            Self::Other => "TLS error",
        })
    }
}

/// A TLS handshake failure against one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError {
    /// What went wrong.
    pub kind: TlsErrorKind,
    /// Host we were connecting to (the URL host, i.e. the name the certificate was checked
    /// against).
    pub host: String,
    /// Port we were connecting to.
    pub port: u16,
    /// The underlying error, as reported by the TLS library.
    pub message: String,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}:{}): {}",
            self.kind, self.host, self.port, self.message
        )
    }
}

impl std::error::Error for TlsError {}

/// Find the `rustls::Error` behind a request error, if there is one, and classify it.
///
/// Walks the `source()` chain. `std::io::Error::source()` skips the io error's own payload,
/// so those are stepped into with `get_ref()`; that is where hyper hides the rustls error.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn classify(
    err: &(dyn std::error::Error + 'static),
    url: &url::Url,
) -> Option<TlsError> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(tls) = e.downcast_ref::<rustls::Error>() {
            return Some(TlsError {
                kind: kind_of(tls),
                host: url.host_str().unwrap_or("").to_string(),
                port: url.port_or_known_default().unwrap_or(0),
                message: tls.to_string(),
            });
        }
        cur = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn kind_of(err: &rustls::Error) -> TlsErrorKind {
    use rustls::CertificateError as C;
    use rustls::Error as E;
    match err {
        E::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => TlsErrorKind::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => TlsErrorKind::NotYetValid,
            C::UnknownIssuer => TlsErrorKind::UnknownIssuer,
            C::NotValidForName | C::NotValidForNameContext { .. } => TlsErrorKind::HostnameMismatch,
            C::Revoked => TlsErrorKind::Revoked,
            _ => TlsErrorKind::InvalidCertificate,
        },
        E::InvalidCertRevocationList(_) => TlsErrorKind::InvalidCertificate,
        E::AlertReceived(_)
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::NoCertificatesPresented
        | E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::DecryptError
        | E::EncryptError => TlsErrorKind::Handshake,
        _ => TlsErrorKind::Other,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rustls::{AlertDescription, CertificateError};
    use url::Url;

    /// Wrap a rustls error the way hyper/reqwest deliver it: io::Error(Other) around
    /// io::Error(InvalidData) around the rustls error, behind a plain error on top.
    fn wrapped(e: rustls::Error) -> anyhow::Error {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        let outer = std::io::Error::other(inner);
        anyhow::Error::from(outer).context("request failed")
    }

    fn classify_wrapped(e: rustls::Error) -> TlsError {
        let url = Url::parse("https://example.test:8443/x").unwrap();
        classify(wrapped(e).as_ref(), &url).unwrap()
    }

    #[test]
    fn classifies_certificate_errors() {
        let cases = [
            (CertificateError::Expired, TlsErrorKind::Expired),
            (CertificateError::NotValidYet, TlsErrorKind::NotYetValid),
            (CertificateError::UnknownIssuer, TlsErrorKind::UnknownIssuer),
            (
                CertificateError::NotValidForName,
                TlsErrorKind::HostnameMismatch,
            ),
            (CertificateError::Revoked, TlsErrorKind::Revoked),
            (
                CertificateError::BadEncoding,
                TlsErrorKind::InvalidCertificate,
            ),
            (
                CertificateError::BadSignature,
                TlsErrorKind::InvalidCertificate,
            ),
        ];
        for (cert_err, kind) in cases {
            let e = classify_wrapped(rustls::Error::InvalidCertificate(cert_err));
            assert_eq!(e.kind, kind, "{e}");
            assert!(e.kind.is_certificate_error());
            assert_eq!(e.host, "example.test");
            assert_eq!(e.port, 8443);
        }
    }

    #[test]
    fn classifies_handshake_errors() {
        let e = classify_wrapped(rustls::Error::AlertReceived(
            AlertDescription::HandshakeFailure,
        ));
        assert_eq!(e.kind, TlsErrorKind::Handshake);
        assert!(!e.kind.is_certificate_error());
        assert!(e.message.contains("HandshakeFailure"), "{}", e.message);
    }

    #[test]
    fn non_tls_errors_are_not_classified() {
        let url = Url::parse("https://example.test/").unwrap();
        let e = anyhow::Error::from(std::io::Error::other("connection refused"));
        assert!(classify(e.as_ref(), &url).is_none());
    }

    #[test]
    fn default_port_is_filled_in() {
        let url = Url::parse("https://example.test/").unwrap();
        let e = classify(
            wrapped(rustls::Error::InvalidCertificate(CertificateError::Expired)).as_ref(),
            &url,
        )
        .unwrap();
        assert_eq!(e.port, 443);
    }
}

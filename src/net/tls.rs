//! TLS errors and certificate overrides.
//!
//! reqwest reports a failed handshake as a chain of wrapped errors with a `rustls::Error` at
//! the bottom. [`TlsError`] extracts the useful part (expired, unknown issuer, wrong host name,
//! ...) so a caller can show a proper certificate warning. Returned as
//! [`NetError::Tls`](crate::net::types::NetError::Tls).
//!
//! Set [`FetcherConfig::tls_overrides`] to a [`TlsOverrideStore`] to allow "proceed anyway"
//! on certificate errors. Verification then goes through our own verifier (wrapping the
//! platform one). On failure it checks the store for an accepted (host, certificate) pair and
//! then asks [`FetcherContext::tls_override`]. The [`TlsError`] from this path includes the
//! certificate and its fingerprint, so the embedder can show it and call
//! [`TlsOverrideStore::accept`] when the user clicks through, then retry. Overrides are per
//! (host, certificate). Not allowed for HSTS hosts (RFC 6797 §12.1) or for handshake failures
//! that aren't about the certificate.
//!
//! Native only. On wasm32 the browser does TLS and we never see the error details.
//!
//! [`FetcherConfig::tls_overrides`]: crate::net::fetcher::FetcherConfig::tls_overrides
//! [`FetcherContext::tls_override`]: crate::net::fetcher_context::FetcherContext::tls_override

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

/// Why the TLS handshake failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsErrorKind {
    /// Certificate has expired.
    Expired,
    /// Certificate is not valid yet.
    NotYetValid,
    /// Chain does not lead to a trusted root (includes self-signed certificates).
    UnknownIssuer,
    /// Certificate is not valid for the host name we connected to.
    HostnameMismatch,
    /// Certificate has been revoked.
    Revoked,
    /// Certificate is invalid for another reason (bad encoding, bad signature, unsupported
    /// algorithm, wrong purpose, ...).
    InvalidCertificate,
    /// Handshake failed without a certificate problem: alert from the peer, no common
    /// protocol version or cipher suite, malformed messages.
    Handshake,
    /// Anything else.
    Other,
}

impl TlsErrorKind {
    /// True for certificate verification failures, i.e. the ones a user could choose to
    /// override; false for protocol-level handshake failures.
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

/// SHA-256 over a certificate's DER encoding.
pub type Fingerprint = [u8; 32];

/// A failed TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError {
    /// Why it failed.
    pub kind: TlsErrorKind,
    /// Host name from the URL, which is what the certificate was checked against.
    pub host: String,
    /// The underlying rustls error message.
    pub message: String,
    /// The server's certificate (DER). Only set when
    /// [`FetcherConfig::tls_overrides`](crate::net::fetcher::FetcherConfig::tls_overrides) is
    /// configured; otherwise reqwest verifies and we never see it.
    pub certificate: Option<Vec<u8>>,
    /// Fingerprint of `certificate`, to pass to [`TlsOverrideStore::accept`].
    pub fingerprint: Option<Fingerprint>,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.kind, self.host, self.message)
    }
}

impl std::error::Error for TlsError {}

/// Certificates the user accepted despite a verification error, keyed by (host, fingerprint).
///
/// The in-memory default is not persisted; implement this to remember overrides across
/// restarts. Revoking only affects new connections, an already verified pooled connection stays
/// open.
pub trait TlsOverrideStore: Send + Sync {
    /// Whether `fingerprint` is accepted for `host`.
    fn is_accepted(&self, host: &str, fingerprint: &Fingerprint) -> bool;
    /// Accept `fingerprint` for `host`.
    fn accept(&self, host: &str, fingerprint: Fingerprint);
    /// Forget all overrides for `host`.
    fn revoke(&self, host: &str);
}

/// In-memory [`TlsOverrideStore`].
#[derive(Default)]
pub struct InMemoryTlsOverrideStore {
    accepted: parking_lot::Mutex<std::collections::HashSet<(String, Fingerprint)>>,
}

impl InMemoryTlsOverrideStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of accepted (host, fingerprint) pairs.
    pub fn len(&self) -> usize {
        self.accepted.lock().len()
    }

    /// True when nothing is accepted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl TlsOverrideStore for InMemoryTlsOverrideStore {
    fn is_accepted(&self, host: &str, fingerprint: &Fingerprint) -> bool {
        self.accepted
            .lock()
            .contains(&(host.to_ascii_lowercase(), *fingerprint))
    }

    fn accept(&self, host: &str, fingerprint: Fingerprint) {
        self.accepted
            .lock()
            .insert((host.to_ascii_lowercase(), fingerprint));
    }

    fn revoke(&self, host: &str) {
        let host = host.to_ascii_lowercase();
        self.accepted.lock().retain(|(h, _)| *h != host);
    }
}

/// SHA-256 fingerprint of a DER certificate.
#[cfg(not(target_arch = "wasm32"))]
pub fn fingerprint(der: &[u8]) -> Fingerprint {
    use sha2::Digest;
    sha2::Sha256::digest(der).into()
}

/// rustls client config for when overrides are enabled: reqwest's usual setup (platform
/// verifier, default provider and versions, h2 + http/1.1 ALPN) but with the verifier wrapped
/// in [`OverridableVerifier`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn client_config(
    store: Arc<dyn TlsOverrideStore>,
    ctx: Arc<dyn crate::net::fetcher_context::FetcherContext>,
    hsts: Option<Arc<dyn crate::net::hsts::HstsStore>>,
) -> anyhow::Result<rustls::ClientConfig> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let inner = rustls_platform_verifier::Verifier::new(provider.clone())?;
    let verifier = OverridableVerifier {
        inner: Arc::new(inner),
        store,
        ctx,
        hsts,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Wraps the platform verifier and lets accepted certificates through. See module docs.
#[cfg(not(target_arch = "wasm32"))]
struct OverridableVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    store: Arc<dyn TlsOverrideStore>,
    ctx: Arc<dyn crate::net::fetcher_context::FetcherContext>,
    hsts: Option<Arc<dyn crate::net::hsts::HstsStore>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for OverridableVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverridableVerifier")
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl rustls::client::danger::ServerCertVerifier for OverridableVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let err = match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(ok) => return Ok(ok),
            Err(err) => err,
        };

        let host = server_name.to_str().into_owned();
        let tls = TlsError {
            kind: kind_of(&err),
            host: host.clone(),
            message: err.to_string(),
            certificate: Some(end_entity.to_vec()),
            fingerprint: Some(fingerprint(end_entity)),
        };
        // stash our TlsError (with the cert) in the rustls error so classify() can find it
        let denied = rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
            rustls::OtherError(Arc::new(tls.clone())),
        ));

        if !tls.kind.is_certificate_error() {
            return Err(denied);
        }
        // no click-through on HSTS hosts (RFC 6797 §12.1)
        if let Some(store) = &self.hsts {
            if crate::net::hsts::is_known_host(store.as_ref(), &host, chrono::Utc::now()) {
                return Err(denied);
            }
        }
        let fp = fingerprint(end_entity);
        if self.store.is_accepted(&host, &fp) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        if self.ctx.tls_override(&tls) {
            self.store.accept(&host, fp);
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        Err(denied)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Find the `rustls::Error` behind a request error, if there is one.
///
/// Walks the `source()` chain. Note that `io::Error::source()` skips the io error's own
/// payload, so we step into those with `get_ref()`; that's where hyper puts the rustls error.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn classify(
    err: &(dyn std::error::Error + 'static),
    url: &url::Url,
) -> Option<TlsError> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(tls) = e.downcast_ref::<rustls::Error>() {
            // stashed by OverridableVerifier
            if let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)) = tls {
                if let Some(ours) = other.0.downcast_ref::<TlsError>() {
                    return Some(ours.clone());
                }
            }
            return Some(TlsError {
                kind: kind_of(tls),
                host: url.host_str().unwrap_or("").to_string(),
                message: tls.to_string(),
                certificate: None,
                fingerprint: None,
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
            C::Other(other) => {
                apple_kind(&other.to_string()).unwrap_or(TlsErrorKind::InvalidCertificate)
            }
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

/// On macOS the platform verifier only maps a few Security.framework codes to rustls variants
/// and passes the rest through as `CertificateError::Other("<description>: <OSStatus>")`. Pick
/// out the ones we care about by their code.
#[cfg(not(target_arch = "wasm32"))]
fn apple_kind(msg: &str) -> Option<TlsErrorKind> {
    let code: i32 = msg
        .rsplit(": ")
        .next()?
        .trim_end_matches('"')
        .parse()
        .ok()?;
    match code {
        -67843 => Some(TlsErrorKind::UnknownIssuer), // errSecNotTrusted
        -67818 => Some(TlsErrorKind::Expired),       // errSecCertificateExpired
        -67819 => Some(TlsErrorKind::NotYetValid),   // errSecCertificateNotValidYet
        -67820 => Some(TlsErrorKind::Revoked),       // errSecCertificateRevoked
        _ => None,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rustls::{AlertDescription, CertificateError};
    use url::Url;

    // Same nesting as hyper/reqwest produce: io::Error(Other) > io::Error(InvalidData) > rustls
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
            assert!(e.certificate.is_none());
        }
    }

    #[test]
    fn classifies_unmapped_macos_codes() {
        // What rustls-platform-verifier produces on macOS for a self-signed certificate.
        let e = classify_wrapped(rustls::Error::InvalidCertificate(CertificateError::Other(
            rustls::OtherError(Arc::from(Box::<dyn std::error::Error + Send + Sync>::from(
                "“rcgen self signed cert” certificate is not trusted: -67843",
            ))),
        )));
        assert_eq!(e.kind, TlsErrorKind::UnknownIssuer);

        let e = classify_wrapped(rustls::Error::InvalidCertificate(CertificateError::Other(
            rustls::OtherError(Arc::from(Box::<dyn std::error::Error + Send + Sync>::from(
                "“x” certificate is expired: -67818",
            ))),
        )));
        assert_eq!(e.kind, TlsErrorKind::Expired);

        let e = classify_wrapped(rustls::Error::InvalidCertificate(CertificateError::Other(
            rustls::OtherError(Arc::from(Box::<dyn std::error::Error + Send + Sync>::from(
                "something else entirely",
            ))),
        )));
        assert_eq!(e.kind, TlsErrorKind::InvalidCertificate);
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
    fn stashed_error_from_our_verifier_is_returned_as_is() {
        let ours = TlsError {
            kind: TlsErrorKind::UnknownIssuer,
            host: "example.test".into(),
            message: "nope".into(),
            certificate: Some(vec![1, 2, 3]),
            fingerprint: Some(fingerprint(&[1, 2, 3])),
        };
        let e = classify_wrapped(rustls::Error::InvalidCertificate(CertificateError::Other(
            rustls::OtherError(Arc::new(ours.clone())),
        )));
        assert_eq!(e, ours);
    }

    #[test]
    fn in_memory_store_is_per_host_and_certificate() {
        let store = InMemoryTlsOverrideStore::new();
        let a = fingerprint(b"a");
        let b = fingerprint(b"b");
        assert!(!store.is_accepted("x.test", &a));
        store.accept("X.test", a);
        assert!(store.is_accepted("x.test", &a));
        assert!(!store.is_accepted("x.test", &b));
        assert!(!store.is_accepted("y.test", &a));
        store.accept("x.test", b);
        assert_eq!(store.len(), 2);
        store.revoke("x.test");
        assert!(store.is_empty());
    }
}

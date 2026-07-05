//! HTTP response type returned by [`crate::net::simple::sync_fetch`].

use core::fmt::{Display, Formatter};
use std::collections::HashMap;

/// A complete HTTP response including status, headers, cookies, and body.
#[derive(Debug, Default)]
pub struct Response {
    /// HTTP status code (e.g. 200, 404)
    pub status: u16,
    /// HTTP reason phrase (e.g. "OK", "Not Found")
    pub status_text: String,
    /// HTTP version string (e.g. "HTTP/1.1", "HTTP/2")
    pub version: String,
    /// Response headers, keyed by lowercase header name.
    /// Repeated headers collapse to a single entry (last one wins) — notably multiple
    /// `Set-Cookie` lines; use the scheduler API if you need every raw header value.
    pub headers: HashMap<String, String>,
    /// Cookies parsed from `Set-Cookie` headers, keyed by cookie name.
    /// Only the `name=value` pair is kept; attributes (`Path`, `Expires`, …) are dropped,
    /// and duplicate cookie names collapse to the last one received.
    pub cookies: HashMap<String, String>,
    /// Raw response body bytes
    pub body: Vec<u8>,
}

impl Response {
    /// Creates an empty response with version `HTTP/1.1` and status 0
    #[must_use]
    pub fn new() -> Response {
        Self {
            version: "HTTP/1.1".to_string(),
            ..Default::default()
        }
    }

    /// Returns true when the status code is in the 2xx range
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

impl From<Vec<u8>> for Response {
    fn from(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            status_text: "OK".to_string(),
            version: "HTTP/1.1".to_string(),
            body,
            ..Default::default()
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "{} {}", self.version, self.status)?;
        writeln!(f, "Headers:")?;
        for (key, value) in &self.headers {
            writeln!(f, "  {key}: {value}")?;
        }
        writeln!(f, "Cookies:")?;
        for (key, value) in &self.cookies {
            writeln!(f, "  {key}: {value}")?;
        }
        writeln!(f, "Body: {} bytes", self.body.len())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response() {
        let response = Response::new();
        let s = format!("{response}");
        assert_eq!(s, "HTTP/1.1 0\nHeaders:\nCookies:\nBody: 0 bytes\n");
    }

    /// Display must use the actual negotiated version, not a hardcoded "HTTP/1.1".
    #[test]
    fn display_uses_actual_version() {
        let mut r = Response::new();
        r.status = 200;
        r.version = "HTTP/2.0".to_string();
        let s = format!("{r}");
        assert!(s.starts_with("HTTP/2.0 200\n"), "got: {s}");
    }

    #[test]
    fn is_ok_covers_2xx_range() {
        let mut r = Response::new();
        r.status = 200;
        assert!(r.is_ok());
        r.status = 201;
        assert!(r.is_ok());
        r.status = 299;
        assert!(r.is_ok());
        r.status = 300;
        assert!(!r.is_ok());
        r.status = 404;
        assert!(!r.is_ok());
        r.status = 500;
        assert!(!r.is_ok());
    }

    #[test]
    fn from_vec_u8_sets_200_status_and_body() {
        let r = Response::from(b"hello".to_vec());
        assert_eq!(r.status, 200);
        assert_eq!(r.status_text, "OK");
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(&r.body[..], b"hello");
    }

    #[test]
    fn display_includes_headers_cookies_and_body_size() {
        let mut r = Response::new();
        r.status = 200;
        r.headers
            .insert("content-type".to_string(), "text/html".to_string());
        r.cookies.insert("sid".to_string(), "abc".to_string());
        r.body = b"hi".to_vec();
        let s = format!("{r}");
        assert!(s.contains("content-type: text/html"));
        assert!(s.contains("sid: abc"));
        assert!(s.contains("2 bytes"));
    }
}

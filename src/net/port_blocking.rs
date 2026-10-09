//! Port blocking (Fetch, "Port blocking").
//!
//! A web page names the URLs it makes the browser fetch, ports included, and a request is
//! bytes the page chose sent to whatever listens there. Pointed at a mail, IRC or FTP server,
//! an HTTP request can be read as that protocol's commands, so the ports those services live
//! on are refused outright. Checked on every hop, redirects included, after a mixed-content
//! upgrade has settled the URL that would be sent.
//!
//! An embedder can let named ports through, as browsers let their users do (Chromium's
//! `--explicitly-allowed-ports`, Firefox's `network.security.ports.banned.override`):
//! [`FetcherConfig::allowed_bad_ports`](crate::net::fetcher::FetcherConfig::allowed_bad_ports)
//! and [`SimpleOptions::allowed_bad_ports`](crate::net::simple::SimpleOptions::allowed_bad_ports).
//! A list rather than a switch, so reaching one service never opens the rest.

use url::Url;

/// The spec's bad ports, in ascending order (Fetch, "bad port").
const BAD_PORTS: [u16; 83] = [
    0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101,
    102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427,
    465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990,
    993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667,
    6668, 6669, 6679, 6697, 10080,
];

/// Whether `port` is one the spec refuses to fetch from.
pub fn is_bad_port(port: u16) -> bool {
    BAD_PORTS.binary_search(&port).is_ok()
}

/// Whether fetching `url` should be blocked due to a bad port: an `http`/`https` URL whose
/// port is one, and not one of the `allowed` exceptions. A URL without a port uses its
/// scheme's default (80/443), which is not.
pub fn should_block(url: &Url, allowed: &[u16]) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url
            .port()
            .is_some_and(|port| is_bad_port(port) && !allowed.contains(&port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_sorted_and_without_duplicates() {
        assert!(BAD_PORTS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn bad_ports_are_refused_and_others_are_not() {
        for port in [0, 1, 21, 22, 25, 110, 143, 587, 993, 6000, 6667, 10080] {
            assert!(is_bad_port(port), "{port}");
        }
        for port in [
            80,
            443,
            8000,
            8080,
            8443,
            3000,
            5000,
            9090,
            10079,
            10081,
            u16::MAX,
        ] {
            assert!(!is_bad_port(port), "{port}");
        }
    }

    #[test]
    fn only_http_urls_with_a_bad_port_are_blocked() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(should_block(&u("http://example.test:25/"), &[]));
        assert!(should_block(&u("https://example.test:6667/"), &[]));
        assert!(should_block(&u("http://127.0.0.1:0/"), &[]));
        assert!(!should_block(&u("http://example.test/"), &[]));
        assert!(!should_block(&u("https://example.test/"), &[]));
        assert!(!should_block(&u("http://example.test:8080/"), &[]));
        // Not an HTTP(S) scheme: the check does not apply.
        assert!(!should_block(&u("ftp://example.test:21/"), &[]));
    }

    /// An allowed port goes through; the others stay blocked.
    #[test]
    fn an_allowed_port_is_let_through_and_only_that_one() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(!should_block(&u("http://example.test:25/"), &[25]));
        assert!(should_block(&u("http://example.test:587/"), &[25]));
    }
}

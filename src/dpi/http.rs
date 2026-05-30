//! HTTP/1.x classifier — TCP, cleartext only (TLS is handled by `tls.rs`).
//!
//! Recognizes either side of a connection:
//!   - **Request**: `METHOD SP request-target SP HTTP/1.x CRLF`, followed by
//!     header lines. We pull the method and, if present, the `Host:` header.
//!   - **Response**: `HTTP/1.x SP status CRLF`. No method/host to extract, so
//!     we report `method = "RESPONSE"` — enough to label the flow as HTTP when
//!     we only ever observe the server side.
//!
//! The request line is validated to contain ` HTTP/1.` before we accept it, so
//! arbitrary text payloads that happen to start with an uppercase word aren't
//! misclassified.

use super::{AppProtocol, Classifier};

/// Methods per RFC 7231 plus PATCH (RFC 5789). Upper-case, as on the wire.
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// Cap how far we scan for the `Host:` header. HTTP header blocks are small;
/// the upstream classify path already truncates payload to a few KB. 2 KiB is
/// plenty for the request line + early headers (Host is conventionally first).
const MAX_SCAN: usize = 2048;

pub struct HttpClassifier;

impl Classifier for HttpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp {
            return None;
        }
        let slice = &payload[..payload.len().min(MAX_SCAN)];

        // Server response: `HTTP/1.x ...`.
        if slice.starts_with(b"HTTP/1.") {
            return Some(AppProtocol::Http {
                method: "RESPONSE".into(),
                host: None,
            });
        }

        // Client request: `METHOD target HTTP/1.x`.
        let request_line = first_line(slice)?;
        if !request_line.contains(" HTTP/1.") {
            return None;
        }
        let method = request_line.split(' ').next()?;
        if !METHODS.contains(&method) {
            return None;
        }

        let host = find_host_header(slice);
        Some(AppProtocol::Http {
            method: method.to_string(),
            host,
        })
    }
}

/// First CRLF/LF-delimited line as UTF-8, or None if it isn't valid text.
fn first_line(slice: &[u8]) -> Option<&str> {
    let end = slice
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).ok()
}

/// Scan header lines for `Host:` (case-insensitive). Returns the trimmed
/// value (may include `:port`), or None if absent / unreadable.
fn find_host_header(slice: &[u8]) -> Option<String> {
    // Walk lines after the request line.
    let mut rest = match slice.iter().position(|&b| b == b'\n') {
        Some(i) => &slice[i + 1..],
        None => return None,
    };
    loop {
        let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        let line = &rest[..end];
        // Blank line (just CR or empty) marks end of headers.
        if line.is_empty() || line == b"\r" {
            return None;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (name, value) = line.split_at(colon);
            if name.eq_ignore_ascii_case(b"host") {
                let value = &value[1..]; // skip ':'
                return std::str::from_utf8(value)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
            }
        }
        if end >= rest.len() {
            return None;
        }
        rest = &rest[end + 1..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_request_with_host() {
        let p = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "GET".into(),
                host: Some("example.com".into()),
            }
        );
    }

    #[test]
    fn post_request_host_with_port() {
        let p = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "POST".into(),
                host: Some("api.example.com:8080".into()),
            }
        );
    }

    #[test]
    fn host_header_case_insensitive() {
        let p = b"GET / HTTP/1.1\r\nhOsT:    lower.example\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "GET".into(),
                host: Some("lower.example".into()),
            }
        );
    }

    #[test]
    fn request_without_host() {
        let p = b"GET / HTTP/1.0\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "GET".into(),
                host: None,
            }
        );
    }

    #[test]
    fn server_response() {
        let p = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "RESPONSE".into(),
                host: None,
            }
        );
    }

    #[test]
    fn connect_method() {
        let p = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let r = HttpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Http {
                method: "CONNECT".into(),
                host: Some("example.com:443".into()),
            }
        );
    }

    #[test]
    fn not_http_random_text() {
        let p = b"HELLO there this is not http\r\n";
        assert!(HttpClassifier.classify(p, true).is_none());
    }

    #[test]
    fn lowercase_method_rejected() {
        // Methods are case-sensitive on the wire; a lowercase "get" is not HTTP.
        let p = b"get / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(HttpClassifier.classify(p, true).is_none());
    }

    #[test]
    fn udp_returns_none() {
        let p = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(HttpClassifier.classify(p, false).is_none());
    }
}

//! SSDP — Simple Service Discovery Protocol (UPnP, port 1900).
//!
//! SSDP uses an HTTP-like text wire format over UDP. Two methods
//! dominate: `M-SEARCH * HTTP/1.1` (clients looking for services) and
//! `NOTIFY * HTTP/1.1` (services advertising themselves). The
//! interesting field is the search target (`ST:` for queries, `NT:` for
//! notifications) — that's the service the message is about.

use super::{AppProtocol, Classifier};

pub struct SsdpClassifier;

impl Classifier for SsdpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None;
        }
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?;

        let method = if first_line.starts_with("M-SEARCH ") {
            "M-SEARCH"
        } else if first_line.starts_with("NOTIFY ") {
            "NOTIFY"
        } else if first_line.starts_with("HTTP/1.1 200") {
            // Response to an M-SEARCH from a service. We classify those
            // too so a single SSDP-aware filter (`app:ssdp`) catches the
            // full exchange, not just one direction.
            "RESPONSE"
        } else {
            return None;
        };

        // First header value of ST (search target) or NT (notification
        // target) — both name the service.
        let target = text.lines().find_map(|l| {
            let lower = l.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("st:") {
                Some(v.trim().to_string())
            } else if let Some(v) = lower.strip_prefix("nt:") {
                Some(v.trim().to_string())
            } else {
                None
            }
        });

        Some(AppProtocol::Ssdp {
            method: method.to_string(),
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m_search_with_st() {
        let p = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n";
        let r = SsdpClassifier.classify(p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssdp {
                method: "M-SEARCH".into(),
                target: Some("ssdp:all".into()),
            }
        );
    }

    #[test]
    fn notify_with_nt() {
        let p = b"NOTIFY * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n";
        let r = SsdpClassifier.classify(p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssdp {
                method: "NOTIFY".into(),
                target: Some("upnp:rootdevice".into()),
            }
        );
    }

    #[test]
    fn not_ssdp_returns_none() {
        let p = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(SsdpClassifier.classify(p, false).is_none());
    }

    #[test]
    fn tcp_returns_none() {
        let p = b"M-SEARCH * HTTP/1.1\r\n";
        assert!(SsdpClassifier.classify(p, true).is_none());
    }
}

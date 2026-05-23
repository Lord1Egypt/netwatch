//! NetBIOS over TCP/IP — RFC 1001/1002.
//!
//! Three transport flavours:
//!   - Name service     (NBNS) — UDP/137
//!   - Datagram service (NBDS) — UDP/138
//!   - Session service  (NBSS) — TCP/139 (also carries SMB sessions)
//!
//! We don't decode the full protocol; we just identify which flavour
//! is on the wire so the operator can see it. Port-based dispatch in
//! `classify_once` does most of the disambiguation; the classifier
//! here adds a minimal sanity check on the header so we don't slap a
//! `NetBios` tag on truncated nonsense.

use super::{AppProtocol, Classifier};

pub struct NetBiosClassifier;

impl Classifier for NetBiosClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            classify_session(payload)
        } else {
            classify_udp(payload)
        }
    }
}

fn classify_session(payload: &[u8]) -> Option<AppProtocol> {
    // NBSS / SMB session header is 4 bytes: type, flags, length (2).
    // type field values: 0x00=SESSION MESSAGE, 0x81=SESSION REQUEST,
    // 0x82=POSITIVE SESSION RESPONSE, 0x83=NEGATIVE SESSION RESPONSE,
    // 0x84=RETARGET SESSION RESPONSE, 0x85=SESSION KEEPALIVE.
    if payload.len() < 4 {
        return None;
    }
    let svc = match payload[0] {
        0x00 => "Session Message",
        0x81 => "Session Request",
        0x82 => "Positive Session Response",
        0x83 => "Negative Session Response",
        0x84 => "Retarget Session Response",
        0x85 => "Session Keepalive",
        _ => return None,
    };
    Some(AppProtocol::NetBios {
        service: format!("Session {}", svc),
    })
}

fn classify_udp(payload: &[u8]) -> Option<AppProtocol> {
    // Name service header is 12 bytes — same shape as a DNS header
    // (transaction id, flags, qd/an/ns/ar counts). Sanity-check by
    // requiring at least one question or answer.
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 && ancount == 0 {
        // Could be a datagram-service packet (type field is byte 0:
        // 0x10=Direct Unique, 0x11=Direct Group, 0x12=Broadcast,
        // 0x13=Datagram Error, 0x14=Datagram Query Request, ...).
        let svc = match payload[0] {
            0x10 => "Datagram Direct Unique",
            0x11 => "Datagram Direct Group",
            0x12 => "Datagram Broadcast",
            0x13 => "Datagram Error",
            0x14 => "Datagram Query Request",
            0x15 => "Datagram Positive Query Response",
            0x16 => "Datagram Negative Query Response",
            _ => return None,
        };
        return Some(AppProtocol::NetBios {
            service: svc.to_string(),
        });
    }
    let svc = if (payload[2] & 0x80) == 0 {
        "Name Query"
    } else {
        "Name Response"
    };
    Some(AppProtocol::NetBios {
        service: svc.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbss_session_request() {
        // type 0x81, flags 0, length 0x0044.
        let p = [0x81, 0x00, 0x00, 0x44];
        let r = NetBiosClassifier.classify(&p, true).unwrap();
        assert!(matches!(
            r,
            AppProtocol::NetBios { ref service } if service.contains("Session Request"),
        ));
    }

    #[test]
    fn nbss_unknown_type_returns_none() {
        let p = [0x77, 0x00, 0x00, 0x00];
        assert!(NetBiosClassifier.classify(&p, true).is_none());
    }

    #[test]
    fn nbns_name_query() {
        let mut p = vec![0u8; 12];
        // qdcount = 1
        p[4] = 0;
        p[5] = 1;
        let r = NetBiosClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::NetBios {
                service: "Name Query".into(),
            }
        );
    }

    #[test]
    fn nbns_name_response() {
        let mut p = vec![0u8; 12];
        p[2] = 0x80; // QR bit set
        p[6] = 0;
        p[7] = 1; // ancount = 1
        let r = NetBiosClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::NetBios {
                service: "Name Response".into(),
            }
        );
    }

    #[test]
    fn nbds_direct_unique() {
        let mut p = vec![0u8; 12];
        p[0] = 0x10;
        let r = NetBiosClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::NetBios {
                service: "Datagram Direct Unique".into(),
            }
        );
    }

    #[test]
    fn udp_too_short_returns_none() {
        let p = vec![0u8; 11];
        assert!(NetBiosClassifier.classify(&p, false).is_none());
    }
}

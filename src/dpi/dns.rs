//! DNS classifier — extracts the first question's qname + qtype.
//!
//! Matches both queries and responses since they share the same header
//! shape and the question section comes first in both. Works for plain
//! DNS-over-UDP (port 53), mDNS (5353), LLMNR (5355) — all use the
//! same wire format. DNS-over-TCP and DoH / DoT are not handled here;
//! the TLS classifier covers DoT/DoH at the TLS layer.
//!
//! Wire format (RFC 1035):
//! ```text
//! Header (12 bytes): id(2) flags(2) qd(2) an(2) ns(2) ar(2)
//! Question:          qname (labels, null-terminated) qtype(2) qclass(2)
//! Label:             length(1) bytes(length)
//! ```
//!
//! Limits:
//! - We deliberately reject compression pointers (`0xC0`+ prefix) in
//!   the qname. They're legal in *responses* but our use case is "what
//!   was being looked up," which is the question-section qname — and
//!   that should never compress. Rejecting pointers also keeps the
//!   parser linear-time with no recursion.
//! - We cap qname at 253 bytes (RFC 1035 max).

use super::{AppProtocol, Classifier};

const MAX_QNAME_LEN: usize = 253;
const HEADER_LEN: usize = 12;

pub struct DnsClassifier;

impl Classifier for DnsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None; // DNS-over-TCP exists; skip for now.
        }
        if payload.len() < HEADER_LEN + 1 + 4 {
            return None; // minimum: header + root qname(1) + qtype+qclass(4)
        }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 {
            return None;
        }

        // Header flags: QR is the high bit of byte 2; RCODE is the low
        // nibble of byte 3 (RFC 1035 §4.1.1). We surface the response code
        // only on responses (QR=1); queries report `None`.
        let is_response = payload[2] & 0x80 != 0;
        let rcode = if is_response {
            Some(payload[3] & 0x0F)
        } else {
            None
        };

        // Parse the first question's qname starting right after the
        // 12-byte header. Refuse compression pointers — see module
        // doc. Reject malformed lengths (would walk past the buffer).
        let mut pos = HEADER_LEN;
        let mut name = String::new();
        loop {
            if pos >= payload.len() {
                return None;
            }
            let len = payload[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            // High two bits set → compression pointer (0xC0+). Refuse.
            if len & 0xC0 != 0 {
                return None;
            }
            if pos + 1 + len > payload.len() {
                return None;
            }
            if name.len() + len + 1 > MAX_QNAME_LEN {
                return None;
            }
            // Label bytes must be ASCII-ish. We don't strictly validate
            // hostnames here — utf8 conversion will fail for binary
            // junk and we'll bail.
            let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(label);
            pos += 1 + len;
        }

        if pos + 4 > payload.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        // Skip qclass; not surfaced.

        // Drop trailing dot if present; root queries show as empty.
        if name.is_empty() {
            return None;
        }
        Some(AppProtocol::Dns {
            qname: name,
            qtype,
            rcode,
        })
    }
}

/// Short label for a DNS RCODE (RFC 1035 §4.1.1 + common extensions).
pub fn rcode_label(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard DNS query for `example.com` type A. Hand-built per
    /// RFC 1035: id=0xABCD, flags=RD (0x0100), qdcount=1.
    #[rustfmt::skip]
    const QUERY_EXAMPLE_COM_A: &[u8] = &[
        // Header
        0xAB, 0xCD, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // qname: 7 "example" 3 "com" 0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        // qtype = A (0x0001), qclass = IN (0x0001)
        0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn extracts_qname_and_qtype() {
        let result = DnsClassifier.classify(QUERY_EXAMPLE_COM_A, false);
        match result {
            Some(AppProtocol::Dns {
                qname,
                qtype,
                rcode,
            }) => {
                assert_eq!(qname, "example.com");
                assert_eq!(qtype, 1); // A
                assert_eq!(rcode, None, "queries carry no rcode");
            }
            other => panic!("expected Dns{{..}}, got {:?}", other),
        }
    }

    #[test]
    fn extracts_rcode_from_response() {
        // Same question, but flags = response (QR=1) with RCODE=3 (NXDOMAIN):
        // byte 2 = 0x81 (QR + RD), byte 3 = 0x83 (RA + NXDOMAIN).
        #[rustfmt::skip]
        let response: &[u8] = &[
            0xAB, 0xCD, 0x81, 0x83,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        match DnsClassifier.classify(response, false) {
            Some(AppProtocol::Dns {
                qname,
                rcode: Some(rc),
                ..
            }) => {
                assert_eq!(qname, "example.com");
                assert_eq!(rc, 3); // NXDOMAIN
                assert_eq!(rcode_label(rc), "NXDOMAIN");
            }
            other => panic!("expected Dns response with rcode, got {:?}", other),
        }
    }

    #[test]
    fn rejects_tcp_path() {
        assert!(DnsClassifier.classify(QUERY_EXAMPLE_COM_A, true).is_none());
    }

    #[test]
    fn rejects_compression_pointer_in_qname() {
        // Header (qdcount=1), then a label whose length byte starts
        // with 0xC0 (compression pointer marker). Our parser refuses
        // this in the question section.
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C, // pointer back to header — illegal here
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_zero_qdcount() {
        // Same shape but qdcount=0 → no question to classify.
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        // Header + label-length byte but no label bytes.
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }

    #[test]
    fn rejects_non_utf8_labels() {
        // Header + label of length 3 containing high-bit bytes — fails
        // utf8 parsing and we bail. (Real DNS labels are ASCII-only.)
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0xff, 0xfe, 0xfd,
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(DnsClassifier.classify(payload, false).is_none());
    }
}

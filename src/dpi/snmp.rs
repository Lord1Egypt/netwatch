//! SNMP v1 / v2c / v3 — UDP/161 (gets/sets) and UDP/162 (traps).
//!
//! Wire format is ASN.1 BER. The minimum we decode:
//!
//!   SEQUENCE {
//!     version       INTEGER {0=v1, 1=v2c, 3=v3},
//!     community     OCTET STRING (for v1/v2c) — *the SNMP community*,
//!                                   visible plaintext, useful to surface
//!     ...
//!   }
//!
//! v3 uses a different structure (msgVersion=3 → msgGlobalData ...) so
//! we skip community extraction for it.

use super::{AppProtocol, Classifier};

pub struct SnmpClassifier;

impl Classifier for SnmpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None;
        }
        // SEQUENCE tag = 0x30
        let (body, _rest) = read_tlv(payload, 0x30)?;
        // version: INTEGER (tag 0x02), 1 byte
        let (version_bytes, after_version) = read_tlv(body, 0x02)?;
        if version_bytes.is_empty() {
            return None;
        }
        let v = version_bytes[0];
        let version_str = match v {
            0 => "v1",
            1 => "v2c",
            3 => "v3",
            _ => return None,
        };

        // For v1/v2c the community is the next field (OCTET STRING).
        let community = if v == 0 || v == 1 {
            let (s, _) = read_tlv(after_version, 0x04)?;
            std::str::from_utf8(s).ok().map(|s| s.to_string())
        } else {
            None
        };

        Some(AppProtocol::Snmp {
            version: version_str.to_string(),
            community,
        })
    }
}

/// Read one ASN.1 BER TLV element of the expected tag, returning (value
/// bytes, remaining bytes after this element). Returns None if the tag
/// doesn't match or the encoded length is malformed / exceeds the
/// buffer.
fn read_tlv(buf: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 || buf[0] != expected_tag {
        return None;
    }
    let first_len_byte = buf[1];
    let (len, header_len) = if first_len_byte & 0x80 == 0 {
        // Short form: single byte length 0..127.
        (first_len_byte as usize, 2)
    } else {
        // Long form: top bit set, low 7 bits = number of length bytes.
        let n = (first_len_byte & 0x7F) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..n {
            len = (len << 8) | buf[2 + i] as usize;
        }
        (len, 2 + n)
    };
    if buf.len() < header_len + len {
        return None;
    }
    Some((&buf[header_len..header_len + len], &buf[header_len + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v2c_get(community: &[u8]) -> Vec<u8> {
        // SEQUENCE { INTEGER 1, OCTET STRING <community>, ... padding }
        let mut inner = vec![];
        // version = 1 (v2c)
        inner.extend_from_slice(&[0x02, 0x01, 0x01]);
        // community
        inner.push(0x04);
        inner.push(community.len() as u8);
        inner.extend_from_slice(community);
        // placeholder for remaining PDU
        inner.extend_from_slice(&[0xA0, 0x00]);

        let mut p = vec![0x30, inner.len() as u8];
        p.extend_from_slice(&inner);
        p
    }

    #[test]
    fn v2c_with_public_community() {
        let p = build_v2c_get(b"public");
        let r = SnmpClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Snmp {
                version: "v2c".into(),
                community: Some("public".into()),
            }
        );
    }

    #[test]
    fn v1_with_private_community() {
        let mut inner = vec![0x02, 0x01, 0x00]; // version=0 (v1)
        inner.extend_from_slice(&[0x04, 0x07]);
        inner.extend_from_slice(b"private");
        inner.extend_from_slice(&[0xA0, 0x00]);
        let mut p = vec![0x30, inner.len() as u8];
        p.extend_from_slice(&inner);

        let r = SnmpClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Snmp {
                version: "v1".into(),
                community: Some("private".into()),
            }
        );
    }

    #[test]
    fn invalid_sequence_tag_returns_none() {
        let p = vec![0x31, 0x03, 0x02, 0x01, 0x01];
        assert!(SnmpClassifier.classify(&p, false).is_none());
    }

    #[test]
    fn unsupported_version_returns_none() {
        let mut inner = vec![0x02, 0x01, 0x05];
        let mut p = vec![0x30, inner.len() as u8];
        p.append(&mut inner);
        assert!(SnmpClassifier.classify(&p, false).is_none());
    }

    #[test]
    fn tcp_returns_none() {
        let p = build_v2c_get(b"public");
        assert!(SnmpClassifier.classify(&p, true).is_none());
    }
}

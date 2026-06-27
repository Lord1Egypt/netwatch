//! LLMNR — Link-Local Multicast Name Resolution (RFC 4795).
//!
//! Wire format is identical to DNS, which means our DNS classifier
//! would happily report `AppProtocol::Dns` if we ran it indiscriminately.
//! We disambiguate by port (5355) in `classify_once` and re-use the DNS
//! parser here to extract qname / qtype, just rebadged as `Llmnr`.

use super::dns::DnsClassifier;
use super::{AppProtocol, Classifier};

pub struct LlmnrClassifier;

impl Classifier for LlmnrClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None;
        }
        match DnsClassifier.classify(payload, is_tcp)? {
            AppProtocol::Dns { qname, qtype, .. } => Some(AppProtocol::Llmnr { qname, qtype }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query(qname_labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        // qdcount = 1
        p[5] = 1;
        for label in qname_labels {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0); // qname terminator
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01]); // qclass = IN
        p
    }

    #[test]
    fn llmnr_query_for_wpad() {
        let p = build_dns_query(&["wpad"], 1); // A record
        let r = LlmnrClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Llmnr {
                qname: "wpad".into(),
                qtype: 1,
            }
        );
    }

    #[test]
    fn tcp_returns_none() {
        let p = build_dns_query(&["wpad"], 1);
        assert!(LlmnrClassifier.classify(&p, true).is_none());
    }

    #[test]
    fn garbage_returns_none() {
        let p = vec![0u8; 8];
        assert!(LlmnrClassifier.classify(&p, false).is_none());
    }
}

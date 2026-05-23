//! BitTorrent peer-wire protocol — BEP 3 handshake.
//!
//! The handshake is the only message with a fixed shape we can match on:
//!
//!   <1-byte pstrlen=19>
//!   <19-byte pstr "BitTorrent protocol">
//!   <8 reserved bytes>
//!   <20-byte info_hash>
//!   <20-byte peer_id>
//!
//! Subsequent messages are length-prefixed and lack a distinguishing
//! signature, so we classify on the handshake only. Once a stream is
//! marked, the classifier won't run again (see `Stream::app_protocol_attempted`).

use super::{AppProtocol, Classifier};

const HANDSHAKE_MIN: usize = 1 + 19 + 8 + 20 + 20;
const PROTOCOL_STRING: &[u8] = b"BitTorrent protocol";

pub struct BitTorrentClassifier;

impl Classifier for BitTorrentClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp || payload.len() < HANDSHAKE_MIN {
            return None;
        }
        if payload[0] != 19 {
            return None;
        }
        if &payload[1..20] != PROTOCOL_STRING {
            return None;
        }
        let info_hash = &payload[28..48];
        Some(AppProtocol::BitTorrent {
            info_hash: Some(hex_encode(info_hash)),
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble_to_hex(b >> 4));
        out.push(nibble_to_hex(b & 0x0F));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_handshake(info_hash: [u8; 20]) -> Vec<u8> {
        let mut p = vec![19];
        p.extend_from_slice(PROTOCOL_STRING);
        p.extend_from_slice(&[0u8; 8]); // reserved
        p.extend_from_slice(&info_hash);
        p.extend_from_slice(&[0u8; 20]); // peer_id
        p
    }

    #[test]
    fn handshake_with_info_hash() {
        let ih = [0xDEu8; 20];
        let p = build_handshake(ih);
        let r = BitTorrentClassifier.classify(&p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::BitTorrent {
                info_hash: Some("de".repeat(20)),
            }
        );
    }

    #[test]
    fn wrong_pstrlen_returns_none() {
        let mut p = build_handshake([0u8; 20]);
        p[0] = 18;
        assert!(BitTorrentClassifier.classify(&p, true).is_none());
    }

    #[test]
    fn wrong_protocol_string_returns_none() {
        let mut p = build_handshake([0u8; 20]);
        p[1] = b'X';
        assert!(BitTorrentClassifier.classify(&p, true).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let p = vec![19u8; 10];
        assert!(BitTorrentClassifier.classify(&p, true).is_none());
    }
}

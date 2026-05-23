//! STUN — RFC 5389 (used by WebRTC, VoIP NAT traversal).
//!
//! STUN messages start with a 20-byte header:
//!   bytes 0..2  : message type (first two bits zero; bits 13/9 = class,
//!                 remaining = method)
//!   bytes 2..4  : message length (must be a multiple of 4)
//!   bytes 4..8  : magic cookie 0x2112A442 (RFC 5389)
//!   bytes 8..20 : transaction ID (96 bits)
//!
//! The magic cookie is unambiguous — any 20+ byte UDP payload with the
//! cookie at offset 4 is STUN. We surface the message-type as a string
//! (e.g. `BindingRequest`, `BindingSuccessResponse`).

use super::{AppProtocol, Classifier};

const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

pub struct StunClassifier;

impl Classifier for StunClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp || payload.len() < 20 {
            return None;
        }
        if payload[4..8] != STUN_MAGIC {
            return None;
        }
        // Top 2 bits MUST be zero per RFC 5389.
        if payload[0] & 0xC0 != 0 {
            return None;
        }
        let mt = u16::from_be_bytes([payload[0], payload[1]]);
        let class = ((mt >> 8) & 0x01) << 1 | ((mt >> 4) & 0x01);
        let method = (mt & 0xF) | ((mt & 0xE0) >> 1) | ((mt & 0x3E00) >> 2);

        let class_name = match class {
            0 => "Request",
            1 => "Indication",
            2 => "SuccessResponse",
            3 => "ErrorResponse",
            _ => "Unknown",
        };
        let method_name = match method {
            0x001 => "Binding",
            0x002 => "SharedSecret",
            0x003 => "Allocate",
            0x004 => "Refresh",
            0x006 => "Send",
            0x007 => "Data",
            0x008 => "CreatePermission",
            0x009 => "ChannelBind",
            0x00A => "Connect",
            0x00B => "ConnectionBind",
            0x00C => "ConnectionAttempt",
            _ => "Unknown",
        };

        Some(AppProtocol::Stun {
            message_type: format!("{}{}", method_name, class_name),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_stun(message_type: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0..2].copy_from_slice(&message_type.to_be_bytes());
        // length = 0
        p[4..8].copy_from_slice(&STUN_MAGIC);
        // transaction ID stays zero
        p
    }

    #[test]
    fn binding_request_recognized() {
        let p = build_stun(0x0001);
        let r = StunClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Stun {
                message_type: "BindingRequest".into(),
            }
        );
    }

    #[test]
    fn binding_success_response() {
        // class = 0b10 (success) → bit 8 set; method 0x001 (Binding).
        // 0x0101 = method bits | success class encoding.
        let p = build_stun(0x0101);
        let r = StunClassifier.classify(&p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Stun {
                message_type: "BindingSuccessResponse".into(),
            }
        );
    }

    #[test]
    fn missing_magic_cookie_returns_none() {
        let mut p = build_stun(0x0001);
        p[4] = 0;
        assert!(StunClassifier.classify(&p, false).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let p = vec![0u8; 19];
        assert!(StunClassifier.classify(&p, false).is_none());
    }

    #[test]
    fn tcp_returns_none() {
        let p = build_stun(0x0001);
        assert!(StunClassifier.classify(&p, true).is_none());
    }
}

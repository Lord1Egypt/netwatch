//! MQTT 3.1.1 / 5.0 — IoT pub/sub on TCP/1883 (cleartext) and /8883 (TLS).
//!
//! Every MQTT control packet starts with a 1-byte fixed header whose
//! upper nibble is the packet type (CONNECT=1, CONNACK=2, PUBLISH=3,
//! etc.) and a variable-length remaining-length encoding. CONNECT
//! payloads include the protocol name ("MQTT" for 3.1.1 / 5.0, "MQIsdp"
//! for 3.1) and a client ID string — both useful to surface.

use super::{AppProtocol, Classifier};

pub struct MqttClassifier;

impl Classifier for MqttClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp || payload.is_empty() {
            return None;
        }
        let pkt_type = (payload[0] >> 4) & 0x0F;
        // Skip rare/invalid types (0 = reserved, 15 = reserved in 3.1.1).
        if pkt_type == 0 || pkt_type == 15 {
            return None;
        }
        // Decode remaining length (variable-length int, up to 4 bytes).
        let (_rem_len, header_len) = decode_remaining_length(&payload[1..])?;
        let body = &payload[1 + header_len..];

        match pkt_type {
            1 => parse_connect(body),
            // Any other type is plausibly MQTT but carries no extractable
            // string we want to surface — return the variant with no
            // client_id so the operator at least sees "MQTT" classification.
            2..=14 => Some(AppProtocol::Mqtt { client_id: None }),
            _ => None,
        }
    }
}

fn decode_remaining_length(buf: &[u8]) -> Option<(u32, usize)> {
    let mut multiplier: u32 = 1;
    let mut value: u32 = 0;
    let mut bytes_used = 0;
    for &b in buf.iter().take(4) {
        value += (b as u32 & 0x7F) * multiplier;
        bytes_used += 1;
        if b & 0x80 == 0 {
            return Some((value, bytes_used));
        }
        multiplier *= 128;
    }
    None
}

fn parse_connect(body: &[u8]) -> Option<AppProtocol> {
    // CONNECT variable header starts with protocol name length-prefixed
    // string. Match the known protocol names so we don't pull a
    // hostname-shaped pattern out of arbitrary binary that happens to
    // have the right packet-type nibble.
    let (proto_name, rest) = read_string(body)?;
    if proto_name != "MQTT" && proto_name != "MQIsdp" {
        return None;
    }
    // Skip protocol level (1) + connect flags (1) + keepalive (2).
    if rest.len() < 4 {
        return None;
    }
    let after_flags = &rest[4..];
    let (client_id, _) = read_string(after_flags)?;
    Some(AppProtocol::Mqtt {
        client_id: if client_id.is_empty() {
            None
        } else {
            Some(client_id.to_string())
        },
    })
}

fn read_string(buf: &[u8]) -> Option<(&str, &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    let s = std::str::from_utf8(&buf[2..2 + len]).ok()?;
    Some((s, &buf[2 + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_with_client_id() {
        // CONNECT packet: type=1, flags=0, remaining_length, then:
        // proto name "MQTT" (length-prefixed), level=4, flags=0,
        // keepalive=60, client_id "my-client" (length-prefixed).
        let mut payload = vec![0x10]; // CONNECT
        let body: Vec<u8> = {
            let mut b = vec![];
            b.extend_from_slice(&(4u16).to_be_bytes());
            b.extend_from_slice(b"MQTT");
            b.push(4); // protocol level (3.1.1)
            b.push(0); // connect flags
            b.extend_from_slice(&60u16.to_be_bytes());
            let cid = b"my-client";
            b.extend_from_slice(&(cid.len() as u16).to_be_bytes());
            b.extend_from_slice(cid);
            b
        };
        payload.push(body.len() as u8); // remaining length (single byte)
        payload.extend_from_slice(&body);

        let r = MqttClassifier.classify(&payload, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Mqtt {
                client_id: Some("my-client".into()),
            }
        );
    }

    #[test]
    fn non_connect_returns_mqtt_with_no_id() {
        // PUBLISH packet: type=3, remaining_length=0.
        let payload = vec![0x30, 0x00];
        let r = MqttClassifier.classify(&payload, true).unwrap();
        assert_eq!(r, AppProtocol::Mqtt { client_id: None });
    }

    #[test]
    fn random_binary_with_zero_nibble_returns_none() {
        // type=0 is reserved/invalid — we reject so SSH banners and
        // other arbitrary TCP traffic don't get misclassified.
        let payload = vec![0x00, 0x00];
        assert!(MqttClassifier.classify(&payload, true).is_none());
    }

    #[test]
    fn udp_returns_none() {
        let payload = vec![0x30, 0x00];
        assert!(MqttClassifier.classify(&payload, false).is_none());
    }
}

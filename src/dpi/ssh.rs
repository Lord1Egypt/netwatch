//! SSH classifier — protocol-version exchange banner (RFC 4253 §4.2).
//!
//! Both client and server open an SSH connection by sending an identification
//! string of the form `SSH-protoversion-softwareversion SP comments CR LF`,
//! e.g. `SSH-2.0-OpenSSH_9.0`. It's the first thing on the wire, in cleartext,
//! before the binary packet protocol begins — so a single classify pass on the
//! first segment catches it. We require the `SSH-` prefix followed by a digit
//! (the protoversion) to avoid matching arbitrary text that starts with "SSH".

use super::{AppProtocol, Classifier};

/// RFC 4253 caps the identification string at 255 bytes including CRLF.
const MAX_BANNER: usize = 255;

pub struct SshClassifier;

impl Classifier for SshClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp {
            return None;
        }
        // Must start with `SSH-` and a digit (protoversion like 2.0 / 1.99).
        if !payload.starts_with(b"SSH-") {
            return None;
        }
        if payload.get(4).map(|b| b.is_ascii_digit()) != Some(true) {
            return None;
        }

        let slice = &payload[..payload.len().min(MAX_BANNER)];
        let end = slice
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(slice.len());
        let version = std::str::from_utf8(&slice[..end]).ok()?.trim();
        if version.len() < 6 {
            // Shortest plausible is "SSH-2.0" (7); guard against truncation.
            return None;
        }
        Some(AppProtocol::Ssh {
            version: version.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_server_banner() {
        let p = b"SSH-2.0-OpenSSH_9.0\r\n";
        let r = SshClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssh {
                version: "SSH-2.0-OpenSSH_9.0".into()
            }
        );
    }

    #[test]
    fn banner_with_comment() {
        let p = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n";
        let r = SshClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssh {
                version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4".into()
            }
        );
    }

    #[test]
    fn legacy_1_99_protoversion() {
        let p = b"SSH-1.99-OpenSSH_3.9p1\r\n";
        let r = SshClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssh {
                version: "SSH-1.99-OpenSSH_3.9p1".into()
            }
        );
    }

    #[test]
    fn no_trailing_crlf_still_parses() {
        let p = b"SSH-2.0-libssh_0.10.4";
        let r = SshClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssh {
                version: "SSH-2.0-libssh_0.10.4".into()
            }
        );
    }

    #[test]
    fn ssh_prefix_without_digit_rejected() {
        // "SSH-foo" isn't a valid protoversion banner.
        let p = b"SSHFS mount in progress\r\n";
        assert!(SshClassifier.classify(p, true).is_none());
    }

    #[test]
    fn random_text_rejected() {
        let p = b"hello world\r\n";
        assert!(SshClassifier.classify(p, true).is_none());
    }

    #[test]
    fn udp_returns_none() {
        let p = b"SSH-2.0-OpenSSH_9.0\r\n";
        assert!(SshClassifier.classify(p, false).is_none());
    }
}

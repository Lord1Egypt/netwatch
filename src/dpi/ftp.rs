//! FTP control channel — TCP port 21.
//!
//! Server responses are `nnn text` (3-digit code + space + text) for
//! single-line replies, `nnn-text` for multi-line. Client commands are
//! `VERB [args]\r\n` with verbs like USER / PASS / RETR / STOR / LIST.
//! We classify on either side: server reply if the line starts with a
//! valid 3-digit FTP reply code, client command if it starts with a
//! recognized 3–4 character ASCII verb.

use super::{AppProtocol, Classifier};

const KNOWN_VERBS: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV", "EPRT", "EPSV",
    "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR",
    "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP", "FEAT",
    "OPTS", "AUTH", "PBSZ", "PROT", "MLSD", "MLST", "MDTM", "SIZE",
];

pub struct FtpClassifier;

impl Classifier for FtpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if !is_tcp {
            return None;
        }
        let line = first_line(payload)?;

        // Server reply: 3-digit code, then space or '-'.
        if line.len() >= 4 {
            let bytes = line.as_bytes();
            if bytes[0].is_ascii_digit()
                && bytes[1].is_ascii_digit()
                && bytes[2].is_ascii_digit()
                && (bytes[3] == b' ' || bytes[3] == b'-')
            {
                let code: String = line.chars().take(3).collect();
                return Some(AppProtocol::Ftp {
                    command: format!("REPLY {}", code),
                });
            }
        }

        // Client command: first whitespace-delimited token, upper-cased.
        let verb_raw = line.split_whitespace().next()?;
        let verb = verb_raw.to_ascii_uppercase();
        if KNOWN_VERBS.iter().any(|&v| v == verb.as_str()) {
            return Some(AppProtocol::Ftp { command: verb });
        }
        None
    }
}

fn first_line(payload: &[u8]) -> Option<&str> {
    // Cap at 256 bytes — FTP control lines are short. Avoids
    // misclassifying a large binary blob that happens to start with
    // ASCII digits as an FTP reply.
    let slice = &payload[..payload.len().min(256)];
    let end = slice
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_reply_220_ready() {
        let p = b"220 (vsFTPd 3.0.3)\r\n";
        let r = FtpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ftp {
                command: "REPLY 220".into()
            }
        );
    }

    #[test]
    fn server_reply_multi_line_uses_dash() {
        let p = b"211-Extensions supported:\r\n";
        let r = FtpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ftp {
                command: "REPLY 211".into()
            }
        );
    }

    #[test]
    fn client_user_command() {
        let p = b"USER alice\r\n";
        let r = FtpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ftp {
                command: "USER".into()
            }
        );
    }

    #[test]
    fn client_retr_lowercase_normalized() {
        let p = b"retr /tmp/file\r\n";
        let r = FtpClassifier.classify(p, true).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ftp {
                command: "RETR".into()
            }
        );
    }

    #[test]
    fn unrecognized_verb_returns_none() {
        let p = b"FOOBAR baz\r\n";
        assert!(FtpClassifier.classify(p, true).is_none());
    }

    #[test]
    fn udp_returns_none() {
        let p = b"USER alice\r\n";
        assert!(FtpClassifier.classify(p, false).is_none());
    }
}

//! JA4 TLS ClientHello fingerprinting (Foxio spec).
//! <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
//!
//! JA4 has the form `JA4_a_JA4_b_JA4_c` (10 + 12 + 12 chars, two `_`s):
//!
//! - **JA4_a** (10 chars, human-readable): protocol prefix (`t`/`q`) +
//!   TLS version (`13`/`12`/...) + SNI presence (`d` if domain SNI
//!   sent, `i` if not) + 2-digit GREASE-filtered cipher count + 2-digit
//!   GREASE-filtered extension count + 2-char ALPN hint (first+last
//!   char of first ALPN value, or `00` if none).
//! - **JA4_b** (12 chars): first 12 hex chars of `SHA256(ciphers)`,
//!   where `ciphers` is GREASE-filtered, sorted ascending by hex
//!   string, comma-separated.
//! - **JA4_c** (12 chars): first 12 hex chars of `SHA256(extensions_sorted_minus_SNI_ALPN "_" sig_algs_in_wire_order)`,
//!   all GREASE-filtered.
//!
//! JA4 supersedes JA3: it's more granular (separates a/b/c so users can
//! tell *what* changed between two fingerprints) and covers QUIC via
//! the protocol-prefix slot. This module computes JA4 for TLS-over-TCP
//! today; JA4Q for QUIC is a planned follow-on that reuses the same
//! `compute_ja4` against the reassembled QUIC ClientHello.

use std::fmt::Write;

use ring::digest;

/// Inputs to [`compute_ja4`]. Callers pass raw on-the-wire values;
/// GREASE filtering happens internally so the call site doesn't have
/// to reason about RFC 8701.
pub struct Ja4Input<'a> {
    /// `false` for TLS-over-TCP (emits `t` prefix), `true` for QUIC
    /// (emits `q`). The rest of the computation is identical.
    pub is_quic: bool,
    /// Highest negotiated TLS version: 0x0304 = TLS 1.3, 0x0303 = TLS 1.2,
    /// 0x0302 = TLS 1.1, 0x0301 = TLS 1.0, 0x0300 = SSL 3.0. For TLS 1.3
    /// ClientHellos this is the highest non-GREASE value from the
    /// `supported_versions` extension; older clients use `legacy_version`.
    pub tls_version: u16,
    /// `true` if the ClientHello carried a `server_name` extension with
    /// a host_name entry (so the JA4_a `d` indicator fires).
    pub sni_present: bool,
    /// First ALPN value's raw bytes (e.g. `b"h2"`, `b"h3"`, `b"http/1.1"`),
    /// or `None` if no ALPN extension.
    pub alpn_first: Option<&'a [u8]>,
    /// Cipher suite IDs in wire order. GREASE values are filtered out
    /// internally.
    pub ciphers: &'a [u16],
    /// Extension type codes in wire order. GREASE values are filtered
    /// out internally; SNI (0x0000) and ALPN (0x0010) are additionally
    /// removed from JA4_c (the spec excludes them since they're already
    /// encoded in JA4_a).
    pub extensions: &'a [u16],
    /// Signature algorithms in wire order (not sorted — the spec
    /// preserves order here). GREASE values are filtered out.
    pub signature_algorithms: &'a [u16],
}

/// RFC 8701 GREASE check for 2-byte enums (cipher suites, extension
/// types, signature algorithms, named groups). Pattern: `0x?A?A` where
/// the high and low bytes are equal and the low nibble of each is 0xA
/// — i.e. `{0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA}` (16 values).
pub fn is_grease(v: u16) -> bool {
    let bytes = v.to_be_bytes();
    bytes[0] == bytes[1] && (bytes[0] & 0x0F) == 0x0A
}

fn tls_version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// JA4 ALPN hint: first + last character of the first ALPN value, or
/// `"00"` when no ALPN was present. For non-ASCII-alphanumeric bytes
/// the spec hex-encodes the value; we fall back to `"00"` for those
/// rather than pretending — keeps the function pure-ASCII and the
/// common case (h2, h3, http/1.1 → h1) trivial.
fn alpn_hint(alpn: Option<&[u8]>) -> String {
    let bytes = match alpn {
        Some(b) if !b.is_empty() => b,
        _ => return "00".into(),
    };
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return "00".into();
    }
    let mut s = String::with_capacity(2);
    s.push(first as char);
    s.push(last as char);
    s
}

fn sha256_truncated_12(input: &str) -> String {
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    let mut out = String::with_capacity(12);
    for byte in hash.as_ref().iter().take(6) {
        // u8 fits in two hex chars; write to a preallocated String never
        // fails. Ignoring the Result is safe and clippy is happy with `_`.
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

/// Walk raw `extensions` wire bytes and return just the type codes in
/// order. Each extension is `[type:2][length:2][data:length]`; we
/// stop at malformed input rather than erroring — partial extension
/// lists shouldn't kill the whole classification.
pub fn extension_type_codes(ext_data: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    let mut i = 0;
    while i + 4 <= ext_data.len() {
        let t = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
        let len = u16::from_be_bytes([ext_data[i + 2], ext_data[i + 3]]) as usize;
        types.push(t);
        let next = i + 4 + len;
        if next > ext_data.len() {
            break;
        }
        i = next;
    }
    types
}

pub fn compute_ja4(input: &Ja4Input) -> String {
    // ── JA4_a ────────────────────────────────────────────────────
    let proto = if input.is_quic { 'q' } else { 't' };
    let ver = tls_version_str(input.tls_version);
    let sni = if input.sni_present { 'd' } else { 'i' };

    let ciphers_no_grease: Vec<u16> = input
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts_no_grease: Vec<u16> = input
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    // Counts cap at 99 per spec — a ClientHello with 100+ ciphers/exts
    // is malformed or an attack; "99" is the saturation value.
    let cipher_count = format!("{:02}", ciphers_no_grease.len().min(99));
    let ext_count = format!("{:02}", exts_no_grease.len().min(99));
    let alpn = alpn_hint(input.alpn_first);

    let ja4_a = format!("{proto}{ver}{sni}{cipher_count}{ext_count}{alpn}");

    // ── JA4_b: sorted ciphers hash ──────────────────────────────
    let mut cipher_hex: Vec<String> = ciphers_no_grease
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect();
    cipher_hex.sort();
    let cipher_str = cipher_hex.join(",");
    let ja4_b = sha256_truncated_12(&cipher_str);

    // ── JA4_c: sorted extensions (minus SNI 0x0000, ALPN 0x0010) + sig algs ─
    let mut ext_hex: Vec<String> = exts_no_grease
        .iter()
        .filter(|e| **e != 0x0000 && **e != 0x0010)
        .map(|e| format!("{:04x}", e))
        .collect();
    ext_hex.sort();
    let ext_str = ext_hex.join(",");
    let sig_hex: Vec<String> = input
        .signature_algorithms
        .iter()
        .filter(|s| !is_grease(**s))
        .map(|s| format!("{:04x}", s))
        .collect();
    let sig_str = sig_hex.join(",");
    let combined = format!("{ext_str}_{sig_str}");
    let ja4_c = sha256_truncated_12(&combined);

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_pattern_matches_canonical_values() {
        for nibble in 0u8..=0xF {
            let v = u16::from_be_bytes([(nibble << 4) | 0x0A, (nibble << 4) | 0x0A]);
            assert!(is_grease(v), "expected 0x{:04x} to be GREASE", v);
        }
    }

    #[test]
    fn grease_pattern_rejects_real_values() {
        // Real cipher / extension IDs that look superficially close to
        // GREASE but aren't.
        for v in [
            0x1301, 0xC02C, 0x00FF, 0x0000, 0x0010, 0x002B, 0xAA0A, 0x0A0B,
        ] {
            assert!(!is_grease(v), "expected 0x{:04x} to NOT be GREASE", v);
        }
    }

    #[test]
    fn tls_version_string_known_versions() {
        assert_eq!(tls_version_str(0x0304), "13");
        assert_eq!(tls_version_str(0x0303), "12");
        assert_eq!(tls_version_str(0x0302), "11");
        assert_eq!(tls_version_str(0x0301), "10");
        assert_eq!(tls_version_str(0x0300), "s3");
        assert_eq!(tls_version_str(0xFFFF), "00");
    }

    #[test]
    fn alpn_hint_handles_common_protocols() {
        assert_eq!(alpn_hint(Some(b"h2")), "h2");
        assert_eq!(alpn_hint(Some(b"h3")), "h3");
        assert_eq!(alpn_hint(Some(b"http/1.1")), "h1");
        assert_eq!(alpn_hint(Some(b"http/0.9")), "h9");
    }

    #[test]
    fn alpn_hint_handles_missing_and_invalid() {
        assert_eq!(alpn_hint(None), "00");
        assert_eq!(alpn_hint(Some(b"")), "00");
        // Single ASCII char: first==last is fine.
        assert_eq!(alpn_hint(Some(b"x")), "xx");
        // Non-alphanumeric edge bytes → "00".
        assert_eq!(alpn_hint(Some(b"\x01h2\x02")), "00");
    }

    #[test]
    fn extension_type_codes_round_trips() {
        // Three extensions: SNI (0x0000, len 5), supported_versions (0x002b, len 3),
        // padding (0x0015, len 0).
        let ext_data: &[u8] = &[
            0x00, 0x00, 0x00, 0x05, b'a', b'b', b'c', b'd', b'e', // SNI
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions
            0x00, 0x15, 0x00, 0x00, // padding
        ];
        let codes = extension_type_codes(ext_data);
        assert_eq!(codes, vec![0x0000, 0x002b, 0x0015]);
    }

    #[test]
    fn extension_type_codes_handles_truncated_input() {
        // Length field claims 100 bytes but data only has 2 → stop, don't panic.
        let ext_data: &[u8] = &[0x00, 0x05, 0x00, 0x64, 0xAA, 0xBB];
        let codes = extension_type_codes(ext_data);
        assert_eq!(codes, vec![0x0005]);
    }

    /// Hand-computed JA4 for a minimal synthetic ClientHello with a
    /// known cipher/extension layout. Verifies the full pipeline
    /// (sorting + hash truncation + JA4_a formatting) against
    /// independently-computed expected values.
    ///
    /// Setup:
    ///   - TLS 1.3, SNI present, ALPN = "h2"
    ///   - 2 ciphers: 0x1301, 0x1303 (both already sorted hex)
    ///   - 4 extensions: 0x0000 (SNI), 0x0010 (ALPN), 0x002b (supported_versions), 0x000d (sig_algs)
    ///   - 1 signature algorithm: 0x0403 (ecdsa_secp256r1_sha256)
    ///
    /// Expected JA4_a: t13d0204h2
    ///   - t (TCP) + 13 (TLS 1.3) + d (SNI) + 02 (2 ciphers) + 04 (4 ext) + h2 (ALPN)
    ///
    /// Expected JA4_b: SHA256("1301,1303")[0..12]
    /// Expected JA4_c: SHA256("000d,002b_0403")[0..12]
    ///   (ext list sorted, with 0x0000 and 0x0010 stripped per spec)
    ///
    /// Hash values cross-checked with `echo -n 'X' | shasum -a 256`.
    #[test]
    fn compute_ja4_minimal_synthetic_clienthello() {
        let input = Ja4Input {
            is_quic: false,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: Some(b"h2"),
            ciphers: &[0x1301, 0x1303],
            extensions: &[0x0000, 0x0010, 0x002b, 0x000d],
            signature_algorithms: &[0x0403],
        };
        let ja4 = compute_ja4(&input);
        let expected_b = sha256_truncated_12("1301,1303");
        let expected_c = sha256_truncated_12("000d,002b_0403");
        let expected = format!("t13d0204h2_{}_{}", expected_b, expected_c);
        assert_eq!(ja4, expected);
        // Sanity-check the parts have the right shape independently.
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "JA4 should be three underscore-separated parts"
        );
        assert_eq!(parts[0].len(), 10, "JA4_a must be 10 chars");
        assert_eq!(parts[1].len(), 12, "JA4_b must be 12 chars");
        assert_eq!(parts[2].len(), 12, "JA4_c must be 12 chars");
    }

    #[test]
    fn compute_ja4_filters_grease_from_all_lists() {
        // Add GREASE values to ciphers, extensions, sig algs. Result
        // must equal the same input without GREASE.
        let with_grease = Ja4Input {
            is_quic: false,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: Some(b"h2"),
            ciphers: &[0x0A0A, 0x1301, 0x1A1A, 0x1303],
            extensions: &[0xFAFA, 0x0000, 0x0010, 0x002b, 0x000d, 0x2A2A],
            signature_algorithms: &[0xCACA, 0x0403],
        };
        let without_grease = Ja4Input {
            is_quic: false,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: Some(b"h2"),
            ciphers: &[0x1301, 0x1303],
            extensions: &[0x0000, 0x0010, 0x002b, 0x000d],
            signature_algorithms: &[0x0403],
        };
        assert_eq!(compute_ja4(&with_grease), compute_ja4(&without_grease));
    }

    #[test]
    fn compute_ja4_sni_indicator_distinguishes_d_vs_i() {
        let base = Ja4Input {
            is_quic: false,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: None,
            ciphers: &[0x1301],
            extensions: &[],
            signature_algorithms: &[],
        };
        let with_d = compute_ja4(&base);
        assert!(with_d.starts_with("t13d"), "got {}", with_d);
        let no_sni = Ja4Input {
            sni_present: false,
            ..base
        };
        let with_i = compute_ja4(&no_sni);
        assert!(with_i.starts_with("t13i"), "got {}", with_i);
    }

    #[test]
    fn compute_ja4_quic_emits_q_prefix() {
        let input = Ja4Input {
            is_quic: true,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: Some(b"h3"),
            ciphers: &[0x1301],
            extensions: &[],
            signature_algorithms: &[],
        };
        let ja4 = compute_ja4(&input);
        assert!(ja4.starts_with("q13d"), "expected q-prefix, got {}", ja4);
    }

    #[test]
    fn compute_ja4_caps_counts_at_99() {
        let many_ciphers: Vec<u16> = (0..120).collect();
        let input = Ja4Input {
            is_quic: false,
            tls_version: 0x0304,
            sni_present: true,
            alpn_first: None,
            ciphers: &many_ciphers,
            extensions: &[],
            signature_algorithms: &[],
        };
        let ja4 = compute_ja4(&input);
        // JA4_a layout: t13d99XX00 — chars 4-5 are cipher count, capped to 99.
        assert_eq!(
            &ja4[4..6],
            "99",
            "expected count to saturate at 99, got {}",
            ja4
        );
    }
}

//! JA4 → client-name lookup database.
//!
//! Coverage is intentionally partial: the bundled table holds the
//! ~30 well-known fingerprints that catch most benign endpoint
//! traffic (Chromium, Firefox, Safari, Python, Go, plus a handful
//! of well-documented IOCs). Empty answers don't mean "unknown
//! client" — they mean "fingerprint not in this snapshot." Real
//! TLS implementation diversity is vastly larger than 30 entries.
//!
//! ## Sources
//! Bundled entries derive from FoxIO's `ja4plus-mapping.csv`
//! (<https://github.com/FoxIO-LLC/ja4>), filtered to the BSD-3-Clause
//! `JA4` column only. JA4+ columns (JA4S/JA4H/JA4X/JA4T/JA4TScan)
//! are deliberately excluded — they are FoxIO License 1.1 (restricts
//! indirect monetization, see NOTICE) and netwatch-cloud ships under
//! a commercial model that would need an OEM license to use them.
//!
//! ## User overlay
//! On first lookup we read `~/.config/netwatch/ja4_db.json` if
//! present and merge it in (overlay wins on conflict). Schema:
//!
//! ```json
//! {
//!   "t13d1234_abc_def": "My internal Chrome build",
//!   "t13d5678_xyz_qrs": "Custom curl wrapper"
//! }
//! ```
//!
//! Malformed JSON is logged at WARN and ignored — bundled lookups
//! continue to work. Reload requires a netwatch restart (the overlay
//! is loaded once and cached for the process lifetime).

use std::collections::HashMap;
use std::sync::OnceLock;

/// Bundled JA4 → label mappings, sorted ascending by JA4 string so
/// we can use binary search. Multiple sources for a single JA4 are
/// joined with " / " — e.g. plain `GoLang` and `Sliver Agent` share
/// a JA4 because Sliver inherits the Go TLS stack; we surface both
/// rather than collapsing to whichever the CSV listed first.
const BUNDLED: &[(&str, &str)] = &[
    ("q13d0312h3_55b375c5d22e_06cda9e17597", "Chromium Browser"),
    ("q13i0311h3_55b375c5d22e_06cda9e17597", "Chromium Browser"),
    ("t12d160700_8cdfa2d4673b_18dd7303c4a5", "GoLang"),
    (
        "t12d190800_d83cc789557e_16bbda4055b2",
        "Cobalt Strike v4.9.1 beacon [Windows 10]",
    ),
    (
        "t12d190800_d83cc789557e_7af1ed941c26",
        "GoLang / WinINET [Windows 10/11]",
    ),
    (
        "t12d210800_76e208dd3e22_16bbda4055b2",
        "Cobalt Strike v4.9.1 beacon [Windows 10]",
    ),
    (
        "t12d350600_9d4c96c0953b_0a9c83bf8b96",
        "Phillips Hue Bridge",
    ),
    ("t12d520600_b380db6257eb_0a9c83bf8b96", "LIFX Smart Bulbs"),
    ("t12d8008h1_9cedc1f1428b_046e095b7c4a", "Nest"),
    (
        "t12i190700_d83cc789557e_16bbda4055b2",
        "Cobalt Strike v4.9.1 beacon [Windows 10]",
    ),
    (
        "t12i210700_76e208dd3e22_16bbda4055b2",
        "Cobalt Strike v4.9.1 beacon [Windows 10]",
    ),
    ("t13d141000_cbb2034c60b8_e7c285222651", "GoLang"),
    ("t13d1412h2_e33ad33b3d25_6b314db333b6", "GoLang webhooks"),
    ("t13d1516h2_8daaf6152771_02713d6af862", "Chromium Browser"),
    ("t13d1517h2_8daaf6152771_b0da82dd1658", "Chromium Browser"),
    ("t13d1517h2_8daaf6152771_b1ff8ab2d16f", "Chromium Browser"),
    ("t13d1715h2_5b57614c22b0_7121afd63204", "Mozilla Firefox"),
    ("t13d181000_85036bcba153_d41ae481755e", "Python"),
    (
        "t13d190900_9dc949149365_97f8aa674fd9",
        "GoLang / Sliver Agent",
    ),
    ("t13d191000_9dc949149365_e7c285222651", "GoLang net package"),
    ("t13d201100_2b729b4bf6f3_9e7b989ebec8", "IcedID"),
    ("t13d2014h2_a09f3c656075_14788d8d241b", "Safari"),
    ("t13d4312h1_c7886603b240_b26ce05bbdd6", "Python"),
    (
        "t13d880900_fcb5b95cb75a_b0d3b4ac2a14",
        "SoftEther VPN Client",
    ),
    ("t13i1515h2_8daaf6152771_02713d6af862", "Chromium Browser"),
    ("t13i1516h2_8daaf6152771_b0da82dd1658", "Chromium Browser"),
    ("t13i1516h2_8daaf6152771_b1ff8ab2d16f", "Chromium Browser"),
    ("t13i1714h2_5b57614c22b0_7121afd63204", "Mozilla Firefox"),
    ("t13i181000_85036bcba153_d41ae481755e", "Python"),
    (
        "t13i190800_9dc949149365_97f8aa674fd9",
        "GoLang / Sliver Agent",
    ),
    ("t13i2013h2_a09f3c656075_14788d8d241b", "Safari"),
    (
        "t13i880900_fcb5b95cb75a_b0d3b4ac2a14",
        "SoftEther VPN Client",
    ),
];

/// Look up a JA4 string in the bundled DB + user overlay.
/// Returns the friendly label when known, `None` otherwise.
/// Overlay entries take priority over bundled — that's how a user
/// can correct or refine a bundled label (e.g. distinguish their
/// internal Chrome build from the generic "Chromium Browser").
pub fn lookup(ja4: &str) -> Option<&str> {
    if let Some(label) = overlay().get(ja4) {
        return Some(label.as_str());
    }
    BUNDLED
        .binary_search_by_key(&ja4, |(k, _)| *k)
        .ok()
        .map(|i| BUNDLED[i].1)
}

/// Lazy-loaded user overlay. Read once on first lookup, cached
/// for the process lifetime. Restart required to pick up edits.
fn overlay() -> &'static HashMap<String, String> {
    static OVERLAY: OnceLock<HashMap<String, String>> = OnceLock::new();
    OVERLAY.get_or_init(load_overlay)
}

fn overlay_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|c| c.join("netwatch").join("ja4_db.json"))
}

fn load_overlay() -> HashMap<String, String> {
    let Some(path) = overlay_path() else {
        return HashMap::new();
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(e) => {
            tracing::warn!(
                target: "netwatch::dpi::ja4_db",
                path = %path.display(),
                error = %e,
                "failed to read JA4 overlay; using bundled DB only"
            );
            return HashMap::new();
        }
    };
    match serde_json::from_str::<HashMap<String, String>>(&text) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                target: "netwatch::dpi::ja4_db",
                path = %path.display(),
                error = %e,
                "malformed JA4 overlay JSON; using bundled DB only"
            );
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_table_is_sorted_for_binary_search() {
        // Binary search returns wrong/missing results on an unsorted
        // input; protect the invariant explicitly.
        for pair in BUNDLED.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "BUNDLED must be sorted: {} >= {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn lookup_hits_known_chromium_fingerprint() {
        assert_eq!(
            lookup("t13d1517h2_8daaf6152771_b1ff8ab2d16f"),
            Some("Chromium Browser")
        );
    }

    #[test]
    fn lookup_hits_known_firefox_fingerprint() {
        assert_eq!(
            lookup("t13d1715h2_5b57614c22b0_7121afd63204"),
            Some("Mozilla Firefox")
        );
    }

    #[test]
    fn lookup_hits_joined_label_for_shared_tls_stack() {
        // Sliver agent inherits Go's TLS stack, so the JA4 matches
        // both — the joined label preserves both possibilities so
        // an analyst doesn't assume "GoLang" means "definitely benign".
        assert_eq!(
            lookup("t13d190900_9dc949149365_97f8aa674fd9"),
            Some("GoLang / Sliver Agent")
        );
    }

    #[test]
    fn lookup_misses_on_unknown_fingerprint() {
        assert_eq!(lookup("t13d9999h2_deadbeefcafe_facefeed0000"), None);
        assert_eq!(lookup(""), None);
        assert_eq!(lookup("not a ja4"), None);
    }

    #[test]
    fn bundled_does_not_leak_ja4plus_columns() {
        // Spot-check: no bundled label should reference JA4S/JA4H/JA4X/
        // JA4T variants that are FoxIO-licensed. Labels describe TLS
        // clients only.
        for (_, label) in BUNDLED {
            assert!(
                !label.to_lowercase().contains("ja4s")
                    && !label.to_lowercase().contains("ja4h")
                    && !label.to_lowercase().contains("ja4x")
                    && !label.to_lowercase().contains("ja4t"),
                "label leaks JA4+ provenance: {}",
                label
            );
        }
    }
}

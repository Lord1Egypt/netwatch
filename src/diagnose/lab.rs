//! The headless lab driver's testable half: where it may write, what it
//! seeds, and the line it prints each tick.
//!
//! `examples/diagnose_lab.rs` runs the real `App::tick` inside the namespace
//! lab (`tests/diagnose/health_lab.py`). `diagnose run` cannot stand in for
//! it: its loop learns no baselines and starts no periodic traces, and it
//! prints only open issues, so it can never show one closing. The fault lab's
//! `diagnose_probe` calls single probes and never reaches the engine at all.
//!
//! Nothing here needs a namespace, so the refusal to touch a real home and
//! the shape of each JSON line are pinned by unit tests rather than by
//! whatever the lab happens to exercise.

use super::baseline::BaselineStore;
use super::coverage::RuleCoverage;
use super::engine::{Engine, Verdict};
use super::issue::{Confidence, Issue, IssueState, Severity};
use crate::collectors::health::HealthStatus;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Written by the lab at the root of the home it creates. A temp directory
/// without it was not made by the lab, and may belong to anything.
pub const HOME_MARKER: &str = ".netwatch-lab";

/// Variables that must be set, and point inside the lab's home, before the
/// driver builds an `App`. The lab sets all three, so one that is unset means
/// the environment is not the lab's, even where `dirs` would fall back to a
/// directory under `HOME`.
pub const HOME_VARS: [&str; 3] = ["HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"];

/// The rules whose coverage each line carries: link, gateway, internet and
/// DNS, failing and slow. These are what the lab scenarios assert on; the
/// rest of the catalogue has no fault the lab can stage yet.
pub const CORE_RULES: &[&str] = &[
    "link.down",
    "gateway.unreachable",
    "gateway.rtt_spike",
    "path.rtt_spike",
    "dns.failing",
    "dns.slow_resolver",
];

/// Metrics a seed file may name. Their subjects are only known once the
/// driver has seen the network, so the file gives values, not subjects.
pub const SEED_METRICS: [&str; 3] = ["gateway.rtt", "dns.rtt_p50", "path.rtt"];

/// Samples credited to a seeded baseline: well past the store's readiness
/// bar, as the fixture's baselines are.
const SEED_SAMPLES: u32 = 2_400;

/// Refuse to start unless every place the App writes resolves inside a home
/// the lab created.
///
/// `var` reads the environment; `temp` is the system temp directory; `writes`
/// are the directories netwatch would resolve for its cache, config and state,
/// named for the error. The resolved directories are checked as well as the
/// variables because episodes and the recovery journal live under the state
/// directory, which none of [`HOME_VARS`] controls when `XDG_STATE_HOME` is
/// set. Returns the canonical home.
pub fn check_home(
    var: impl Fn(&str) -> Option<PathBuf>,
    temp: &Path,
    writes: &[(&str, Option<PathBuf>)],
) -> Result<PathBuf, String> {
    let home = var("HOME").ok_or("HOME is not set")?;
    let home = resolve(&home).ok_or_else(|| format!("HOME {} is not usable", home.display()))?;
    let temp = resolve(temp).ok_or("the temp directory is not usable")?;
    if home == temp || !home.starts_with(&temp) {
        return Err(format!(
            "HOME {} is not inside the temp directory {}; run the lab, not the driver",
            home.display(),
            temp.display()
        ));
    }
    if !home.join(HOME_MARKER).is_file() {
        return Err(format!(
            "HOME {} has no {HOME_MARKER}; the lab did not create it",
            home.display()
        ));
    }
    for name in &HOME_VARS[1..] {
        let value = var(name).ok_or_else(|| format!("{name} is not set"))?;
        inside(&home, name, &value)?;
    }
    for (name, dir) in writes {
        let dir = dir
            .as_ref()
            .ok_or_else(|| format!("the {name} directory cannot be resolved"))?;
        inside(&home, name, dir)?;
    }
    Ok(home)
}

fn inside(home: &Path, name: &str, path: &Path) -> Result<(), String> {
    match resolve(path) {
        Some(p) if p.starts_with(home) => Ok(()),
        _ => Err(format!(
            "{name} {} is outside the lab home {}",
            path.display(),
            home.display()
        )),
    }
}

/// Absolute, with no `..`, and with symlinks resolved as far as the path
/// exists. The rest is appended as written, so a directory the App has yet
/// to create is judged by where it would land.
fn resolve(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    let mut existing = path;
    let mut rest = Vec::new();
    loop {
        if let Ok(canonical) = existing.canonicalize() {
            return Some(rest.iter().rev().fold(canonical, |p, c| p.join(c)));
        }
        rest.push(existing.file_name()?);
        existing = existing.parent()?;
    }
}

/// One seeded baseline's value, in the metric's own unit (ms for all three).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedValue {
    pub mean: f64,
    pub sigma: f64,
}

/// `--seed FILE`: `{"gateway.rtt": {"mean": 1.0, "sigma": 2.0}, ...}`.
///
/// A seeded baseline is ready from the first tick, which is what lets a
/// scenario fault a σ rule within minutes instead of after the store's
/// half-hour learning window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Seed(pub BTreeMap<String, SeedValue>);

impl Seed {
    pub fn parse(text: &str) -> Result<Self, String> {
        let values: BTreeMap<String, SeedValue> =
            serde_json::from_str(text).map_err(|e| format!("seed file: {e}"))?;
        for (metric, v) in &values {
            if !SEED_METRICS.contains(&metric.as_str()) {
                // A typo would otherwise seed nothing, and the scenario that
                // relied on it would wait out the learning window and fail
                // for a reason no line of its output names.
                return Err(format!(
                    "seed file: {metric} is not one of {}",
                    SEED_METRICS.join(", ")
                ));
            }
            if !(v.mean.is_finite() && v.mean >= 0.0 && v.sigma.is_finite() && v.sigma > 0.0) {
                return Err(format!("seed file: {metric} needs mean >= 0 and sigma > 0"));
            }
        }
        Ok(Self(values))
    }

    /// Seed the current network's baselines, each under the subject the live
    /// sampler records it under. Returns `metric@subject` for each one.
    pub fn apply(&self, base: &mut BaselineStore, gateway: &str, resolver: &str) -> Vec<String> {
        let mut seeded = Vec::new();
        for (metric, v) in &self.0 {
            let subject = match metric.as_str() {
                "gateway.rtt" => gateway,
                "dns.rtt_p50" => resolver,
                _ => "internet",
            };
            base.seed(subject, metric, v.mean, v.sigma, SEED_SAMPLES);
            seeded.push(format!("{metric}@{subject}"));
        }
        seeded
    }
}

/// One line of the driver's output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snapshot {
    /// Seconds since the driver started.
    pub t: u64,
    pub ts: String,
    pub verdict: VerdictLine,
    pub probes: Probes,
    /// Every issue the engine tracks, closed ones included: a scenario that
    /// asserts a close has to see the issue after it stops being open.
    pub issues: Vec<IssueRow>,
    /// [`CORE_RULES`], in that order.
    pub coverage: Vec<RuleCoverage>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerdictLine {
    pub chip: &'static str,
    pub line: String,
}

/// What the health prober last measured, and against which address. The
/// targets are how a lab run proves the probes reached its namespaces and
/// not the host's network.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Probes {
    pub gateway_target: Option<String>,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: Option<f64>,
    pub dns_target: Option<String>,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: Option<f64>,
    pub internet_rtt_ms: Option<f64>,
    pub internet_loss_pct: Option<f64>,
}

impl Probes {
    fn from_health(h: &HealthStatus) -> Self {
        Self {
            gateway_target: h.completed.gateway_target.clone(),
            gateway_rtt_ms: h.gateway_rtt_ms,
            gateway_loss_pct: h.gateway_loss.pct(),
            dns_target: h.completed.dns_target.clone(),
            dns_rtt_ms: h.dns_rtt_ms,
            dns_loss_pct: h.dns_loss.pct(),
            internet_rtt_ms: h.internet_rtt_ms,
            internet_loss_pct: h.internet_loss.pct(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IssueRow {
    /// `rule|subject`, the key episodes and engine events use. Issue ids are
    /// numbered per session and mean nothing across runs.
    pub key: String,
    pub rule: String,
    pub state: &'static str,
    pub severity: Severity,
    /// The suppressing issue's key, not its id, for the same reason.
    pub suppressed_by: Option<String>,
    /// `rule/cause`, as labels and model classes name it.
    pub top_cause: Option<String>,
    pub confidence: Option<Confidence>,
}

/// The state as a word a script can compare, in the serde spelling the
/// episode files use.
fn state_name(state: &IssueState) -> &'static str {
    match state {
        IssueState::Open => "open",
        IssueState::Acked => "acked",
        IssueState::Muted { .. } => "muted",
        IssueState::Resolved { .. } => "resolved",
        IssueState::AutoClosed { .. } => "auto_closed",
        IssueState::Expired { .. } => "expired",
    }
}

fn issue_row(engine: &Engine, issue: &Issue) -> IssueRow {
    let top = issue.top_cause();
    IssueRow {
        key: super::episode::issue_key(issue),
        rule: issue.rule.clone(),
        state: state_name(&issue.state),
        severity: issue.severity,
        suppressed_by: issue.suppressed_by.as_ref().map(|id| {
            engine
                .get(id)
                .map_or_else(|| id.clone(), super::episode::issue_key)
        }),
        top_cause: top.map(|c| c.key(&issue.rule)),
        confidence: top.map(|c| c.confidence()),
    }
}

/// This tick, as the driver prints it.
pub fn snapshot(
    engine: &Engine,
    base: &BaselineStore,
    health: &HealthStatus,
    t: u64,
    ts: String,
) -> Snapshot {
    let verdict: Verdict = engine.verdict(base);
    let rows = &engine.coverage().rules;
    Snapshot {
        t,
        ts,
        verdict: VerdictLine {
            chip: verdict.chip(),
            line: verdict.line(),
        },
        probes: Probes::from_health(health),
        issues: engine
            .issues()
            .iter()
            .map(|i| issue_row(engine, i))
            .collect(),
        coverage: CORE_RULES
            .iter()
            .filter_map(|rule| rows.iter().find(|r| r.rule == *rule).cloned())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::engine::FixedClock;
    use crate::diagnose::fixture;

    /// A home the lab would have made: under the temp directory, marked, with
    /// the XDG directories inside it.
    fn lab_home(name: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("nw-lab-{name}-{}", std::process::id()));
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(HOME_MARKER), b"").unwrap();
        home
    }

    fn env(pairs: Vec<(&'static str, PathBuf)>) -> impl Fn(&str) -> Option<PathBuf> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        }
    }

    fn writes(home: &Path) -> Vec<(&'static str, Option<PathBuf>)> {
        vec![
            ("cache", Some(home.join(".cache"))),
            ("config", Some(home.join(".config"))),
            ("state", Some(home.join(".local/state"))),
        ]
    }

    #[test]
    fn lab_refuses_the_real_home() {
        let temp = std::env::temp_dir();
        let real = dirs::home_dir().expect("the test runner has a home");
        let refused = check_home(
            env(vec![
                ("HOME", real.clone()),
                ("XDG_CACHE_HOME", real.join(".cache")),
                ("XDG_CONFIG_HOME", real.join(".config")),
            ]),
            &temp,
            &writes(&real),
        );
        assert!(
            refused.is_err(),
            "the driver ran against {}",
            real.display()
        );

        let home = lab_home("real");
        let lab_env = |cache: PathBuf| {
            env(vec![
                ("HOME", home.clone()),
                ("XDG_CACHE_HOME", cache),
                ("XDG_CONFIG_HOME", home.join(".config")),
            ])
        };
        assert_eq!(
            check_home(lab_env(home.join(".cache")), &temp, &writes(&home)),
            Ok(home.canonicalize().unwrap())
        );

        // Seeded baselines land in the cache directory, so a lab home with a
        // real cache is still the real baselines.json.
        let err = check_home(lab_env(real.join(".cache")), &temp, &writes(&home)).unwrap_err();
        assert!(err.contains("XDG_CACHE_HOME"), "{err}");

        // Episodes go to the state directory, which none of the variables
        // above controls when XDG_STATE_HOME is set.
        let mut leaky = writes(&home);
        leaky[2].1 = Some(real.join(".local/state"));
        let err = check_home(lab_env(home.join(".cache")), &temp, &leaky).unwrap_err();
        assert!(err.contains("state"), "{err}");

        // `..` could walk out of the home after the prefix check passed.
        let err = check_home(
            lab_env(home.join("..").join("..").join(".cache")),
            &temp,
            &writes(&home),
        )
        .unwrap_err();
        assert!(err.contains("XDG_CACHE_HOME"), "{err}");

        // A temp directory the lab did not mark is someone else's.
        std::fs::remove_file(home.join(HOME_MARKER)).unwrap();
        let err = check_home(lab_env(home.join(".cache")), &temp, &writes(&home)).unwrap_err();
        assert!(err.contains(HOME_MARKER), "{err}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn unset_xdg_variables_are_refused() {
        let temp = std::env::temp_dir();
        let home = lab_home("unset");
        let err = check_home(
            env(vec![
                ("HOME", home.clone()),
                ("XDG_CACHE_HOME", home.join(".cache")),
            ]),
            &temp,
            &writes(&home),
        )
        .unwrap_err();
        assert_eq!(err, "XDG_CONFIG_HOME is not set");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn seed_files_name_known_metrics_only() {
        let seed = Seed::parse(
            r#"{"gateway.rtt": {"mean": 1.0, "sigma": 2.0},
                "dns.rtt_p50": {"mean": 2.0, "sigma": 3.0},
                "path.rtt": {"mean": 2.0, "sigma": 3.0}}"#,
        )
        .unwrap();
        assert_eq!(seed.0.len(), 3);
        assert!(Seed::parse(r#"{"gateway.rtt_ms": {"mean": 1, "sigma": 1}}"#).is_err());
        assert!(Seed::parse(r#"{"path.rtt": {"mean": 1, "sigma": 0}}"#).is_err());
        assert!(Seed::parse(r#"{"path.rtt": {"mean": 1, "sd": 1}}"#).is_err());
    }

    #[test]
    fn seeding_uses_the_subjects_the_sampler_records() {
        let seed = Seed::parse(
            r#"{"gateway.rtt": {"mean": 1.0, "sigma": 2.0},
                "dns.rtt_p50": {"mean": 2.0, "sigma": 3.0},
                "path.rtt": {"mean": 4.0, "sigma": 5.0}}"#,
        )
        .unwrap();
        let mut base = BaselineStore::new(fixture::baselines().fingerprint().clone());
        let seeded = seed.apply(&mut base, "192.0.2.2", "192.0.2.53");
        assert_eq!(
            seeded,
            [
                "dns.rtt_p50@192.0.2.53",
                "gateway.rtt@192.0.2.2",
                "path.rtt@internet"
            ]
        );
        // Ready at once: that is the point of seeding.
        assert_eq!(base.get("192.0.2.2", "gateway.rtt").unwrap().mean, 1.0);
        assert_eq!(base.get("192.0.2.53", "dns.rtt_p50").unwrap().mean, 2.0);
        assert_eq!(base.get("internet", "path.rtt").unwrap().mean, 4.0);

        // A seedable metric the sampler never feeds would sit at its seed
        // while the rule judged something else. The subjects need the live
        // sampler, so the lab smoke checks those: each seeded entry must
        // have learned past its seed by the end of the run.
        let baselined: Vec<&str> = crate::diagnose::live::BASELINED_METRICS
            .iter()
            .map(|(metric, _)| *metric)
            .collect();
        for metric in SEED_METRICS {
            assert!(baselined.contains(&metric), "{metric} is never sampled");
        }
    }

    #[test]
    fn lab_snapshot_lists_closed_issues_with_their_state() {
        let clock = std::sync::Arc::new(FixedClock::at(fixture::WINDOW_START));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let base = fixture::baselines();
        // Into the incident, then the same resolver answers at its baseline
        // again and dns.slow_resolver closes on its own verify condition.
        for t in 0..=300 {
            engine.observe(&fixture::observations_at(t), &base);
            clock.advance_secs(1);
        }
        let healthy_dns = fixture::observations_at(0).dns;
        for t in 301..=380 {
            let mut obs = fixture::observations_at(t);
            obs.dns = healthy_dns.clone();
            engine.observe(&obs, &base);
            clock.advance_secs(1);
        }
        let health = crate::collectors::health::HealthProber::new().status();
        let snap = snapshot(&engine, &base, &health, 381, "ts".into());

        let dns = snap
            .issues
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .expect("a closed issue is still listed");
        assert_eq!(dns.state, "auto_closed");
        assert_eq!(dns.key, format!("dns.slow_resolver|{}", fixture::RESOLVER));
        assert!(dns
            .top_cause
            .as_deref()
            .unwrap()
            .starts_with("dns.slow_resolver/"));
        assert!(dns.confidence.is_some());
        assert!(
            snap.issues.iter().any(|i| i.state == "open"),
            "the path and socket issues are still open"
        );
        assert_eq!(snap.issues.len(), engine.issues().len());
        assert_eq!(snap.verdict.chip, engine.verdict(&base).chip());

        // Coverage is every core rule and nothing else, in their order. The
        // engine rates the whole catalogue, so a core rule missing here is a
        // misspelt id that `snapshot` would otherwise drop without a word.
        let rules: Vec<&str> = snap.coverage.iter().map(|r| r.rule.as_str()).collect();
        assert_eq!(rules, CORE_RULES);

        // A script reads these names; pin the spelling.
        let line = serde_json::to_value(&snap).unwrap();
        let row = &line["issues"].as_array().unwrap()[0];
        for field in [
            "key",
            "rule",
            "state",
            "severity",
            "suppressed_by",
            "top_cause",
            "confidence",
        ] {
            assert!(row.get(field).is_some(), "{field} missing from {row}");
        }
        assert!(line["probes"].get("gateway_target").is_some());
        assert!(line["probes"].get("dns_target").is_some());
    }

    #[test]
    fn suppressed_by_names_the_suppressing_issue_by_key() {
        let (engine, base) = fixture::run();
        let health = crate::collectors::health::HealthProber::new().status();
        let snap = snapshot(&engine, &base, &health, 0, String::new());
        assert!(
            snap.issues.iter().any(|r| r.suppressed_by.is_some()),
            "the fixture suppresses one issue under another"
        );
        for (row, issue) in snap.issues.iter().zip(engine.issues()) {
            let expected = issue
                .suppressed_by
                .as_ref()
                .map(|id| super::super::episode::issue_key(engine.get(id).unwrap()));
            assert_eq!(row.suppressed_by, expected, "{}", row.key);
        }
    }
}

//! Read-only bridge from the egress profiler to deterministic Diagnose rules.
//! Baselines describe observed public destinations of a process name, not
//! executable identity, every container, or an authorization decision.
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{
    coverage::Availability,
    detectors::Detection,
    issue::{Cause, CheckResult, Evidence, Step, Subject},
};
use crate::collectors::egress::{AlertMode, EgressProfiler, Verdict};

const LEARN_SECS: f64 = 600.0;
const MAX_FLOWS: usize = 128;
const MAX_BASELINE_DESTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Missing,
    Invalid,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Allowed,
    /// Matched an explicit block entry. The only verdict that alerts by default.
    Blocked,
    Denied,
    Undeclared,
    Unchecked,
    Encrypted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub process: String,
    pub destination: String,
    pub port: u16,
    pub baseline_ready: bool,
    pub baseline_seconds: f64,
    pub novel: bool,
    pub verdict: PolicyVerdict,
}
impl Flow {
    pub fn subject(&self) -> Subject {
        Subject::Egress {
            process: self.process.clone(),
            destination: self.destination.clone(),
            port: self.port,
        }
    }
    /// Whether this flow raises a policy alert. Blocked always does; an
    /// allowlist miss or undeclared process only when the policy opted in.
    pub fn alerts(&self, alert_all: bool) -> bool {
        match self.verdict {
            PolicyVerdict::Blocked => true,
            PolicyVerdict::Denied | PolicyVerdict::Undeclared => alert_all,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub policy: PolicyState,
    pub policy_revision: Option<String>,
    /// The policy's `alert = "all"`: alert on allowlist misses and new
    /// destinations, not only on blocked ones. Recordings made before the
    /// setting existed alerted on everything, so they replay as `true`.
    #[serde(default = "recorded_before_alert_mode")]
    pub alert_all: bool,
    /// False if attribution is incomplete or the bounded flow list overflowed.
    /// Absence from such a snapshot must never verify recovery.
    pub complete: bool,
    pub flows: Vec<Flow>,
}
fn recorded_before_alert_mode() -> bool {
    true
}

impl Observation {
    pub fn coverage(&self, rule: &str) -> (Availability, &'static str) {
        if rule == "egress.drift" && !self.alert_all {
            return (
                Availability::NotConfigured,
                "off by default; set alert = \"all\" in egress-policy.toml to alert on new destinations",
            );
        }
        if rule == "egress.policy_violation" {
            match self.policy {
                PolicyState::Missing => {
                    return (
                        Availability::NotConfigured,
                        "no egress policy loaded; observe mode does not authorize traffic",
                    )
                }
                PolicyState::Invalid => {
                    return (
                        Availability::CollectorFailed,
                        "egress policy is unreadable, invalid, or has unsafe permissions",
                    )
                }
                PolicyState::Loaded => {}
            }
        }
        if self.flows.is_empty() {
            return if self.complete {
                (
                    Availability::NoSubjects,
                    "no attributed public destinations in the completed connection snapshot",
                )
            } else {
                (
                    Availability::NotMeasured,
                    "connection attribution is incomplete",
                )
            };
        }
        if rule == "egress.drift" && !self.flows.iter().any(|f| f.baseline_ready) {
            return (
                Availability::Learning,
                "learning public destinations; needs 10 minutes of observed process activity",
            );
        }
        if rule == "egress.policy_violation"
            && self.alert_all
            && self.flows.iter().all(|f| {
                matches!(
                    f.verdict,
                    PolicyVerdict::Unchecked | PolicyVerdict::Encrypted
                )
            })
        {
            return (
                Availability::NotMeasured,
                "observed destinations have no applicable rule or an encrypted name",
            );
        }
        (
            Availability::Available,
            "observed public destinations only; process identity is scoped to its name",
        )
    }

    /// Subject-specific verification. Unobserved/unchecked traffic is not an allow.
    pub fn recovered(&self, subject: &Subject, rule: &str) -> Option<bool> {
        if !self.complete {
            return None;
        }
        if rule == "egress.policy_violation" && self.policy != PolicyState::Loaded {
            return None;
        }
        let flow = self.flows.iter().find(|f| &f.subject() == subject);
        match flow {
            None => {
                // Loss of a readable hostname can change the displayed subject
                // while the underlying connection remains. Do not call that a fix.
                let ambiguous = if let Subject::Egress { process, port, .. } = subject {
                    self.flows.iter().any(|f| {
                        &f.process == process
                            && f.port == *port
                            && (f.verdict == PolicyVerdict::Encrypted
                                || (rule == "egress.policy_violation"
                                    && f.verdict == PolicyVerdict::Unchecked))
                    })
                } else {
                    true
                };
                (!ambiguous).then_some(true)
            }
            Some(f) if rule == "egress.drift" => f.baseline_ready.then_some(!f.novel),
            Some(f) if f.alerts(self.alert_all) => Some(false),
            Some(f) => match f.verdict {
                PolicyVerdict::Allowed => Some(true),
                // Not blocked, and allowlist misses are not alerting: this
                // subject no longer meets the rule.
                PolicyVerdict::Denied | PolicyVerdict::Undeclared | PolicyVerdict::Unchecked
                    if !self.alert_all =>
                {
                    Some(true)
                }
                _ => None,
            },
        }
    }
}

#[derive(Default)]
struct Learned {
    known: BTreeSet<(String, u16)>,
    seconds: f64,
    last: Option<Instant>,
    ready: bool,
    overflow: bool,
}
#[derive(Default)]
pub struct Tracker {
    baselines: BTreeMap<String, Learned>,
    cached: Option<(Instant, Observation)>,
}
impl Tracker {
    pub fn sample(
        &mut self,
        profiler: &EgressProfiler,
        at: Instant,
        complete: bool,
    ) -> Observation {
        if let Some((old, snapshot)) = &self.cached {
            if *old == at {
                return snapshot.clone();
            }
        }
        let profiles = profiler.profiles_ref();
        self.baselines
            .retain(|name, _| profiles.iter().any(|p| &p.process == name));
        let mut flows = Vec::new();
        let mut complete = complete && profiles.len() < crate::collectors::egress::MAX_PROCESSES;
        for profile in profiles {
            if profile.dests.len() >= MAX_BASELINE_DESTS {
                complete = false;
            }
            let baseline = self
                .baselines
                .entry(profile.process.clone())
                .or_insert_with(|| {
                    // Existing persisted observations can seed a mature baseline.
                    // A just-seen destination is excluded even on a mature process.
                    let known: BTreeSet<_> = profile
                        .dests
                        .values()
                        .filter(|d| {
                            d.count >= 600
                                && d.last_seen
                                    .duration_since(d.first_seen)
                                    .unwrap_or_default()
                                    .as_secs()
                                    >= 600
                        })
                        .map(|d| (d.sni.clone().unwrap_or_else(|| d.last_ip.clone()), d.port))
                        .collect();
                    let ready = !known.is_empty();
                    Learned {
                        known,
                        ready,
                        seconds: if ready { LEARN_SECS } else { 0.0 },
                        ..Default::default()
                    }
                });
            let active: Vec<_> = profile
                .dests
                .values()
                .filter(|d| Some(d.last_seen) == profiler.last_observation_wall())
                .collect();
            if active.is_empty() {
                continue;
            }
            if !baseline.ready {
                if let Some(last) = baseline.last {
                    let elapsed = at.saturating_duration_since(last);
                    if elapsed <= Duration::from_secs(30) {
                        baseline.seconds += elapsed.as_secs_f64();
                    }
                }
                for d in &active {
                    let key = (d.sni.clone().unwrap_or_else(|| d.last_ip.clone()), d.port);
                    if baseline.known.len() < MAX_BASELINE_DESTS || baseline.known.contains(&key) {
                        baseline.known.insert(key);
                    } else {
                        baseline.overflow = true;
                    }
                }
                baseline.ready = baseline.seconds >= LEARN_SECS && !baseline.overflow;
            }
            baseline.last = Some(at);
            for d in active {
                if flows.len() >= MAX_FLOWS {
                    complete = false;
                    break;
                }
                let destination = d.sni.clone().unwrap_or_else(|| d.last_ip.clone());
                let verdict = match profiler.verdict(&profile.process, d) {
                    Verdict::Blocked(_) => PolicyVerdict::Blocked,
                    Verdict::Drift => PolicyVerdict::Denied,
                    Verdict::Undeclared if d.count >= 3 => PolicyVerdict::Undeclared,
                    Verdict::Undeclared | Verdict::NoRule | Verdict::NoPolicy => {
                        PolicyVerdict::Unchecked
                    }
                    Verdict::Ech => PolicyVerdict::Encrypted,
                    _ => PolicyVerdict::Allowed,
                };
                flows.push(Flow {
                    process: profile.process.clone(),
                    novel: baseline.ready
                        && !baseline.known.contains(&(destination.clone(), d.port)),
                    destination,
                    port: d.port,
                    baseline_ready: baseline.ready,
                    baseline_seconds: baseline.seconds,
                    verdict,
                });
            }
        }
        flows.sort_by(|a, b| {
            (&a.process, &a.destination, a.port).cmp(&(&b.process, &b.destination, b.port))
        });
        let observation = Observation {
            policy: if profiler.policy_error().is_some() {
                PolicyState::Invalid
            } else if profiler.has_policy() {
                PolicyState::Loaded
            } else {
                PolicyState::Missing
            },
            policy_revision: profiler.policy_revision().map(str::to_owned),
            alert_all: profiler.alert_mode() == AlertMode::All,
            complete,
            flows,
        };
        self.cached = Some((at, observation.clone()));
        observation
    }
}

pub fn detect(obs: Option<&Observation>) -> Vec<Detection> {
    let Some(obs) = obs else {
        return vec![];
    };
    let mut out = Vec::new();
    for flow in &obs.flows {
        for rule in ["egress.drift", "egress.policy_violation"] {
            let firing = if rule == "egress.drift" {
                obs.alert_all && flow.baseline_ready && flow.novel
            } else {
                obs.policy == PolicyState::Loaded && flow.alerts(obs.alert_all)
            };
            if !firing {
                continue;
            }
            let mut d = Detection::new(rule, flow.subject());
            let policy = rule == "egress.policy_violation";
            d.causes = vec![if policy && flow.verdict == PolicyVerdict::Blocked {
                Cause::new(
                    "blocked_by_policy",
                    "observed destination is explicitly blocked by the policy",
                    vec![CheckResult::pass(
                        "policy_blocks_destination",
                        "loaded policy blocks this destination",
                        "read-only comparison of observed egress metadata",
                    )],
                )
            } else if policy {
                Cause::new(
                    "outside_declared_policy",
                    "observed destination falls outside the declared policy",
                    vec![CheckResult::pass(
                        "policy_rejects_destination",
                        "loaded policy rejects this destination",
                        "read-only comparison of observed egress metadata",
                    )],
                )
            } else {
                Cause::new(
                    "new_public_destination",
                    "a public destination is new for this process name",
                    vec![CheckResult::pass(
                        "outside_learned_baseline",
                        "destination is outside the learned baseline",
                        "read-only comparison of observed egress metadata",
                    )],
                )
            }];
            d.evidence.push(Evidence::new(
                if policy {
                    "egress.denied_flows"
                } else {
                    "egress.new_destinations"
                },
                1.0,
                "observed destination",
            ));
            d.scope.processes = vec![flow.process.clone()];
            d.scope.destinations = 1;
            d.scope.note = Some(if policy {
                format!("policy revision {}; warning only, traffic was not blocked; closure means no violation observed for five minutes", obs.policy_revision.as_deref().unwrap_or("unknown"))
            } else {
                "process-name baseline of public destinations; new does not mean malicious; closure means this destination is no longer observed".into()
            });
            d.remediation = vec![Step::instruct("review this destination in Egress", "Check the owning program and destination. Review policy separately if the traffic is intended; Diagnose does not change permissions.")];
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::{
        baseline::{BaselineStore, NetworkFingerprint},
        detectors::Observations,
        engine::{Clock, Engine, FixedClock, ObservationTimes},
        episode, export,
    };
    use std::sync::Arc;

    fn observation() -> Observation {
        Observation {
            policy: PolicyState::Loaded,
            policy_revision: Some("revision-a".into()),
            alert_all: true,
            complete: true,
            flows: vec![Flow {
                process: "private-tool".into(),
                destination: "secret-service.internal".into(),
                port: 443,
                baseline_ready: true,
                baseline_seconds: 600.0,
                novel: true,
                verdict: PolicyVerdict::Denied,
            }],
        }
    }
    fn base() -> BaselineStore {
        BaselineStore::new(NetworkFingerprint::new("test", None, vec![], None))
    }

    #[test]
    fn default_mode_alerts_only_on_blocked_flows() {
        let mut o = observation();
        o.alert_all = false;
        // Novel and outside the allowlist, but not blocked: nothing fires.
        assert!(detect(Some(&o)).is_empty());
        assert_eq!(o.coverage("egress.drift").0, Availability::NotConfigured);
        let subject = o.flows[0].subject();
        assert_eq!(o.recovered(&subject, "egress.policy_violation"), Some(true));

        o.flows[0].verdict = PolicyVerdict::Blocked;
        let fired = detect(Some(&o));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "egress.policy_violation");
        assert_eq!(fired[0].causes[0].id, "blocked_by_policy");
        assert_eq!(
            o.recovered(&subject, "egress.policy_violation"),
            Some(false)
        );
    }

    #[test]
    fn positive_and_matched_negative_coverage_and_detection() {
        let mut o = observation();
        assert_eq!(detect(Some(&o)).len(), 2);
        o.flows[0].novel = false;
        o.flows[0].verdict = PolicyVerdict::Allowed;
        assert!(detect(Some(&o)).is_empty());
        o.flows[0].novel = true;
        o.flows[0].baseline_ready = false;
        assert!(detect(Some(&o)).is_empty());
        assert_eq!(o.coverage("egress.drift").0, Availability::Learning);
        for (policy, coverage) in [
            (PolicyState::Missing, Availability::NotConfigured),
            (PolicyState::Invalid, Availability::CollectorFailed),
        ] {
            o.policy = policy;
            o.flows[0].verdict = PolicyVerdict::Denied;
            assert!(detect(Some(&o)).is_empty());
            assert_eq!(o.coverage("egress.policy_violation").0, coverage);
        }
        o.policy = PolicyState::Loaded;
        for verdict in [PolicyVerdict::Encrypted, PolicyVerdict::Unchecked] {
            o.flows[0].verdict = verdict;
            assert!(detect(Some(&o)).is_empty());
            assert_eq!(
                o.recovered(&o.flows[0].subject(), "egress.policy_violation"),
                None
            );
        }
    }

    #[test]
    fn missing_attribution_is_not_recovery_and_subjects_stay_separate() {
        let mut o = observation();
        let subject = o.flows[0].subject();
        o.flows.clear();
        o.complete = false;
        assert_eq!(o.recovered(&subject, "egress.policy_violation"), None);
        o.complete = true;
        assert_eq!(o.recovered(&subject, "egress.policy_violation"), Some(true));
        o.policy = PolicyState::Missing;
        assert_eq!(o.recovered(&subject, "egress.policy_violation"), None);
        assert_eq!(o.recovered(&subject, "egress.drift"), Some(true));
    }

    #[test]
    fn lost_hostname_is_not_evidence_that_the_connection_disappeared() {
        let mut o = observation();
        let original = o.flows[0].subject();
        o.flows[0].destination = "8.8.8.8".into();
        o.flows[0].verdict = PolicyVerdict::Encrypted;
        assert_eq!(o.recovered(&original, "egress.policy_violation"), None);
        assert_eq!(o.recovered(&original, "egress.drift"), None);
        o.flows[0].verdict = PolicyVerdict::Unchecked;
        assert_eq!(o.recovered(&original, "egress.policy_violation"), None);
        o.flows[0].verdict = PolicyVerdict::Allowed;
        assert_eq!(
            o.recovered(&original, "egress.policy_violation"),
            Some(true)
        );
    }

    #[test]
    fn cached_and_stale_observations_cannot_open_issues() {
        let clock = Arc::new(FixedClock::at("2026-09-16 10:00:00"));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let origin = Instant::now();
        let obs = Observations {
            egress: Some(observation()),
            ..Default::default()
        };
        let times = ObservationTimes {
            egress: Some(origin),
            ..Default::default()
        };
        for t in 0..10 {
            engine.observe_live_at(&obs, &base(), &times, origin + Duration::from_secs(t));
            clock.advance_secs(1);
        }
        assert_eq!(engine.open_count(), 0);
        engine.observe_live_at(&obs, &base(), &times, origin + Duration::from_secs(31));
        assert_eq!(
            engine
                .coverage()
                .rules
                .iter()
                .find(|r| r.rule == "egress.drift")
                .unwrap()
                .status,
            Availability::Stale
        );
        assert_eq!(engine.open_count(), 0);
    }

    #[test]
    fn policy_suppression_never_hides_a_different_destination() {
        let clock = Arc::new(FixedClock::at("2026-09-16 10:00:00"));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let mut o = observation();
        let mut another = o.flows[0].clone();
        another.destination = "different.example".into();
        another.verdict = PolicyVerdict::Allowed;
        o.flows.push(another);
        let obs = Observations {
            egress: Some(o),
            ..Default::default()
        };
        for _ in 0..5 {
            engine.observe(&obs, &base());
            clock.advance_secs(1);
        }
        let different = engine
            .issues()
            .iter()
            .find(|i| i.subject.label().contains("different.example"))
            .unwrap();
        assert_eq!(different.rule, "egress.drift");
        assert!(different.suppressed_by.is_none());
    }

    #[test]
    fn old_recordings_without_egress_stay_unmeasured() {
        let obs: Observations = serde_json::from_str("{}").unwrap();
        assert!(obs.egress.is_none());
        assert!(detect(obs.egress.as_ref()).is_empty());
        let coverage =
            super::super::coverage::Coverage::from_observations(&obs, &base(), Default::default());
        assert!(coverage
            .rules
            .iter()
            .filter(|r| r.rule.starts_with("egress."))
            .all(|r| r.status == Availability::NotMeasured));
    }

    #[test]
    fn lifecycle_reload_recurrence_suppression_and_redacted_replay() {
        let clock = Arc::new(FixedClock::at("2026-09-16 10:00:00"));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let baseline = base();
        let origin = Instant::now();
        let mut recorder =
            episode::Recorder::new(episode::EnvProfile::detect("user", 1000), 1_800_000_000.0);
        recorder.schedule_quiet_sample(f64::MAX);
        for t in 0..=720 {
            let mut egress = observation();
            if (15..31).contains(&t) {
                egress.policy = PolicyState::Invalid;
            }
            if (31..360).contains(&t) {
                egress.policy_revision = Some("revision-b".into());
                egress.flows[0].verdict = PolicyVerdict::Allowed;
                egress.flows[0].novel = false;
            }
            if t >= 400 {
                egress.flows.clear();
            }
            let now = origin + Duration::from_secs(t);
            let obs = Observations {
                now: super::super::engine::format_ts(clock.now()),
                egress: Some(egress),
                ..Default::default()
            };
            let times = ObservationTimes {
                egress: Some(now),
                ..Default::default()
            };
            engine.observe_live_at(&obs, &baseline, &times, now);
            if t == 14 {
                assert_eq!(
                    engine.issues().len(),
                    2,
                    "one persistent issue per rule, not one per tick"
                );
                assert!(engine
                    .issues()
                    .iter()
                    .find(|i| i.rule == "egress.drift")
                    .unwrap()
                    .suppressed_by
                    .is_some());
            }
            if t == 30 {
                assert!(engine.issues().iter().all(|i| i.state.is_open()));
            }
            if t == 350 {
                assert_eq!(engine.open_count(), 0);
            }
            if t == 390 {
                assert_eq!(
                    engine.issues().len(),
                    2,
                    "recurrence keeps stable identities"
                );
                assert!(engine.open_count() > 0);
            }
            let _ = recorder.record(episode::Tick {
                at: 1_800_000_000.0 + t as f64,
                ts: obs.now.clone(),
                now,
                obs: &obs,
                times: &times,
                readings: &[],
                engine: &engine,
                baselines: &baseline,
                events: vec![],
            });
            clock.advance_secs(1);
        }
        assert_eq!(
            engine.open_count(),
            0,
            "vanished flows close after the hold, including no-subject coverage"
        );
        let ep = recorder
            .flush(&engine, &super::super::engine::format_ts(clock.now()))
            .unwrap();
        let replay = episode::replay(&ep);
        assert!(replay.matches(), "{:?}", replay.divergences);
        let safe = export::Redactor::new(b"test").episode(&ep);
        let text = serde_json::to_string(&safe).unwrap();
        for secret in ["private-tool", "secret-service.internal"] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
        let replay = episode::replay(&safe);
        assert!(replay.matches(), "{:?}", replay.divergences);
        assert!(safe.frames.iter().any(|f| f
            .obs
            .egress
            .as_ref()
            .is_some_and(|o| o.policy_revision.as_deref() == Some("revision-a"))));
        assert!(safe.frames.iter().any(|f| f
            .obs
            .egress
            .as_ref()
            .is_some_and(|o| o.policy_revision.as_deref() == Some("revision-b"))));
    }
}

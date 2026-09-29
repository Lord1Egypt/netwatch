//! `report.md` and `report.json`, generated from the same `Vec<Issue>` the
//! screen renders.
//!
//! The constraint that makes the report trustworthy: **no metric appears in
//! the report that the screen did not show.** Every number here comes from an
//! [`Evidence`] entry via the same accessor the TUI calls, so the report
//! cannot claim a multiple, a baseline or a σ that the Diagnose tab wasn't
//! also showing. A test asserts it.
//!
//! [`Evidence`]: super::issue::Evidence

use serde::{Deserialize, Serialize};

use super::issue::{Applied, Issue, IssueState, Severity, StepKind};
use super::rules;

/// Host and session facts that belong in every report's environment section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    pub host: String,
    pub iface: String,
    pub driver: Option<String>,
    pub kernel: Option<String>,
    pub qdisc: Option<String>,
    pub resolvers: Vec<String>,
    pub gateway: Option<String>,
    pub netwatch_version: String,
    pub ruleset_version: String,
    /// What the baseline store had to work with, so a reader can weigh the
    /// σ figures. A report from a host still learning says so.
    pub baseline_state: String,
}

/// One thing that happened in the window, for the report's timeline section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub at: String,
    /// `issue` | `fix` | `path` | `iface` | `close`
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub coverage: super::coverage::Coverage,
    pub generated_at: String,
    pub window_start: String,
    pub window_end: String,
    pub environment: Environment,
    pub issues: Vec<Issue>,
    pub timeline: Vec<TimelineEvent>,
    /// File names in the incident bundle, referenced by the evidence index.
    pub artifacts: Vec<String>,
}

impl Report {
    /// Issues that are findings in their own right, worst first.
    pub fn primary(&self) -> Vec<&Issue> {
        rules::primary_findings(&self.issues)
    }

    fn find(&self, id: &str) -> Option<&Issue> {
        self.issues.iter().find(|i| i.id == id)
    }

    /// The one-line verdict. Same shape as the toast and the verdict line.
    pub fn summary_line(&self) -> String {
        let primary = self.primary();
        if primary.is_empty() {
            let closed = self.issues.iter().filter(|i| !i.state.is_open()).count();
            let mut line = format!("no open findings · {}", self.coverage.label());
            if closed > 0 {
                line.push_str(&format!(
                    " · {closed} retained closed finding{}",
                    if closed == 1 { "" } else { "s" }
                ));
            }
            return line;
        }
        let worst = primary
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Info);
        let state = match worst {
            Severity::Critical => "down",
            Severity::High => "degraded",
            Severity::Medium => "impaired",
            Severity::Info => "nominal with notes",
        };
        let counts = severity_counts(&primary);
        format!("{state} — {} ({counts})", plural(primary.len(), "issue"))
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// The markdown report. Sections in the order the spec sets out: summary,
    /// one section per open issue in severity order, suppressed consequences
    /// under their root cause, timeline, environment, evidence index.
    pub fn to_markdown(&self) -> String {
        let mut m = String::new();
        let env = &self.environment;

        // Built from the parts that exist. The Diagnose tab renders this
        // same markdown as a live preview, where the environment and window
        // aren't known yet — and "# netwatch report —  ·  to" reads as a
        // broken renderer rather than an incomplete one.
        let mut title = String::from("# netwatch report");
        let where_ = [env.host.as_str(), env.iface.as_str()]
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !where_.is_empty() {
            title.push_str(&format!(" — {where_}"));
        }
        if !self.window_start.is_empty() && !self.window_end.is_empty() {
            let sep = if where_.is_empty() { " —" } else { " ·" };
            let (start, end) = (time_of(&self.window_start), time_of(&self.window_end));
            // A snapshot has no window; "13:35:06 to 13:35:06" reads as a bug.
            if start == end {
                title.push_str(&format!("{sep} {start}"));
            } else {
                title.push_str(&format!("{sep} {start} to {end}"));
            }
        }
        m.push_str(&format!("{title}\n\n"));
        let primary = self.primary();
        let total = self.coverage.rules.len();
        let ready = self
            .coverage
            .rules
            .iter()
            .filter(|r| r.status == super::coverage::Availability::Available)
            .count();

        if primary.is_empty() {
            m.push_str("**Summary:** No findings are currently open.");
            if total == 0 {
                m.push_str(" Coverage was not recorded, so this does not establish health.");
            } else if ready < total {
                m.push_str(&format!(
                    " {ready} of {total} checks had their inputs; this does not establish health for the other {}, listed below.",
                    total - ready
                ));
            } else {
                m.push_str(&format!(" All {total} checks had their inputs."));
            }
            m.push_str("\n\n");
            let closed = self.issues.iter().filter(|i| !i.state.is_open()).count();
            if closed > 0 {
                m.push_str(&format!(
                    "{} closed during this session; see Retained closed findings.\n\n",
                    plural(closed, "finding")
                ));
            }
        } else {
            m.push_str(&format!("**Summary:** {}.\n\n", self.summary_line()));
            m.push_str(&format!("**Coverage:** {}.\n\n", self.coverage.label()));
            let rows: Vec<Vec<String>> = primary
                .iter()
                .enumerate()
                .map(|(n, i)| {
                    vec![
                        (n + 1).to_string(),
                        i.title.clone(),
                        i.severity.long_label().to_string(),
                        time_of(&i.since).to_string(),
                        i.subject.label(),
                        i.state.label().to_string(),
                    ]
                })
                .collect();
            m.push_str(&md_table(
                &["#", "Issue", "Severity", "Since", "Subject", "State"],
                &rows,
            ));
        }

        for (n, issue) in primary.iter().enumerate() {
            m.push_str(&self.issue_section(n + 1, issue));
        }

        if !self.timeline.is_empty() {
            m.push_str("## Timeline\n\n");
            let rows: Vec<Vec<String>> = self
                .timeline
                .iter()
                .map(|e| vec![time_of(&e.at).to_string(), e.kind.clone(), e.text.clone()])
                .collect();
            m.push_str(&md_table(&["Time", "Event", "Detail"], &rows));
        }

        let closed: Vec<Vec<String>> = self
            .issues
            .iter()
            .filter(|i| !i.state.is_open())
            .map(|i| {
                // An expiry says what went away, so it cannot pass for one
                // more close that netwatch watched clear.
                let state = match &i.state {
                    IssueState::Expired { reason, .. } => {
                        format!("expired, evidence gone: {reason}")
                    }
                    s => s.label().to_string(),
                };
                vec![format!("`{}`", i.id), i.title.clone(), state]
            })
            .collect();
        if !closed.is_empty() {
            m.push_str("## Retained closed findings\n\n");
            m.push_str(&md_table(&["ID", "Issue", "State"], &closed));
        }

        // Only the checks that could not run: a table of thirty "ready" rows
        // buries the few that matter. The ready count stands in for the rest.
        if total > 0 && ready < total {
            m.push_str("## Checks not running\n\n");
            m.push_str("These could not run, so their silence is not a result.\n\n");
            let mut previous = "";
            let rows: Vec<Vec<String>> = self
                .coverage
                .rules
                .iter()
                .filter(|r| r.status != super::coverage::Availability::Available)
                .map(|row| {
                    let area = row.rule.split('.').next().unwrap_or("");
                    // Name each area once so the groups read as groups.
                    let shown = if area == previous { "" } else { area };
                    previous = area;
                    vec![
                        shown.to_string(),
                        format!("`{}`", row.rule),
                        row.status.label().to_string(),
                        row.reason.clone(),
                    ]
                })
                .collect();
            m.push_str(&md_table(&["Area", "Check", "Status", "Why"], &rows));
        }

        m.push_str("## Environment\n\n");
        let mut rows = vec![vec!["host".to_string(), env.host.clone()]];
        rows.push(vec![
            "interface".into(),
            match &env.driver {
                Some(d) => format!("{} ({d})", env.iface),
                None => env.iface.clone(),
            },
        ]);
        for (k, v) in [
            ("kernel", &env.kernel),
            ("qdisc", &env.qdisc),
            ("gateway", &env.gateway),
        ] {
            if let Some(v) = v {
                rows.push(vec![k.into(), v.clone()]);
            }
        }
        if !env.resolvers.is_empty() {
            rows.push(vec!["resolvers".into(), env.resolvers.join(", ")]);
        }
        rows.push(vec!["baselines".into(), env.baseline_state.clone()]);
        rows.push(vec!["netwatch".into(), env.netwatch_version.clone()]);
        rows.push(vec![
            "ruleset".into(),
            format!("{} ({})", env.ruleset_version, rules::catalogue_label()),
        ]);
        m.push_str(&md_table(&["Field", "Value"], &rows));

        // The report's own files sit next to it; listing them is noise.
        let artifacts: Vec<&String> = self
            .artifacts
            .iter()
            .filter(|a| !matches!(a.as_str(), "report.json" | "report.md"))
            .collect();
        if !artifacts.is_empty() {
            m.push_str("## Evidence files\n\n");
            for a in artifacts {
                m.push_str(&format!("- `{a}`\n"));
            }
            m.push('\n');
        }

        m
    }

    fn issue_section(&self, n: usize, issue: &Issue) -> String {
        let mut m = String::new();
        m.push_str(&format!(
            "## {n}. {} — {} · since {}",
            issue.title,
            issue.severity.long_label(),
            time_of(&issue.since)
        ));
        if issue.recurrence > 0 {
            m.push_str(&format!(" · recurred {}×", issue.recurrence));
        }
        m.push_str(&format!(" · `{}`\n\n", issue.id));

        // --- subject and scope
        m.push_str(&format!("**Subject:** {}", issue.subject.label()));
        let scope = issue.scope.label();
        if !scope.is_empty() {
            m.push_str(&format!("  \n**Scope:** {scope}"));
        }
        m.push_str("\n\n");

        // --- evidence, rendered by the same accessors the TUI uses
        if !issue.evidence.is_empty() {
            let rows: Vec<Vec<String>> = issue
                .evidence
                .iter()
                .map(|e| {
                    vec![
                        format!("`{}`", e.metric),
                        e.value_label(),
                        e.baseline_label().unwrap_or_else(|| "—".into()),
                        e.baseline_label()
                            .and(e.multiple_label())
                            .unwrap_or_else(|| "—".into()),
                    ]
                })
                .collect();
            m.push_str(&md_table(
                &["Metric", "Value", "Baseline", "vs baseline"],
                &rows,
            ));
            if let Some(e) = issue.headline() {
                if e.samples > 0 {
                    m.push_str(&format!(
                        "{} over {}.\n\n",
                        plural(e.samples as usize, "sample"),
                        super::issue::format_duration(e.window_secs)
                    ));
                }
            }
        }

        // --- probable cause
        if let Some(top) = issue.top_cause() {
            m.push_str(&format!(
                "**Probable cause:** {} ({}, {}).\n\n",
                top.label,
                top.confidence().label(),
                top.checks_label()
            ));
            // A strong claim has to say what made it sufficient, and a
            // qualified one has to say what is still missing. Neither is
            // recoverable from the pass fraction alone.
            match (
                top.confidence(),
                top.sufficient_evidence(),
                top.missing_discriminator(),
            ) {
                (super::issue::Confidence::Strong, evidence, _) if !evidence.is_empty() => {
                    m.push_str(&format!(
                        "Sufficient evidence: {}.\n\n",
                        evidence.join(", ")
                    ));
                }
                (_, _, Some(missing)) => {
                    // Why it is missing, in the words of its `why_not`: a
                    // test nobody has run is not a probe that failed to report.
                    let why = missing
                        .why_not
                        .as_ref()
                        .map_or("not measured", super::issue::Availability::label);
                    m.push_str(&format!(
                        "{}{}: {} — {}.\n\n",
                        why[..1].to_uppercase(),
                        &why[1..],
                        missing.name,
                        missing.detail
                    ));
                }
                _ => {}
            }
            if !top.checks.is_empty() {
                let rows: Vec<Vec<String>> = top
                    .checks
                    .iter()
                    .map(|c| vec![c.glyph().to_string(), c.name.clone(), c.detail.clone()])
                    .collect();
                m.push_str(&md_table(&["", "Check", "Result"], &rows));
            }
            if issue.causes.len() > 1 {
                m.push_str("**Ruled out or ranked lower:** ");
                let rest: Vec<String> = issue.causes[1..]
                    .iter()
                    .map(|c| format!("{} ({})", c.label, c.confidence().label()))
                    .collect();
                m.push_str(&rest.join("; "));
                m.push_str(".\n\n");
            }
        }

        // --- remediation, with what was actually done
        if !issue.remediation.is_empty() {
            m.push_str("**Remediation**\n\n");
            for step in &issue.remediation {
                let marker = match step.kind {
                    StepKind::Apply => "apply",
                    StepKind::Instruct => "run",
                    StepKind::Escalate => "escalate",
                };
                m.push_str(&format!("- _{marker}_ {} — {}", step.text, step.detail));
                match &step.applied {
                    Some(Applied::Yes { at, before, after }) => {
                        m.push_str(&format!(
                            "\n  - applied {} — `{before}` → `{after}`",
                            time_of(at)
                        ));
                    }
                    Some(outcome @ Applied::RecoveryRequired { .. }) => {
                        m.push_str(&format!("\n  - {}", outcome.recovery_summary().unwrap()));
                    }
                    Some(Applied::No { reason }) => {
                        m.push_str(&format!("\n  - not applied: {reason}"));
                    }
                    Some(Applied::Reverted { at, reason }) => {
                        m.push_str(&format!("\n  - reverted {} ({reason})", time_of(at)));
                    }
                    None if step.kind == StepKind::Apply => {
                        m.push_str("\n  - not applied");
                    }
                    None => {}
                }
                m.push('\n');
            }
            m.push('\n');
        }

        m.push_str(&format!("**Verify:** {}", issue.verify.label()));
        match &issue.state {
            IssueState::AutoClosed { at } => {
                m.push_str(&format!(" · held; auto-closed {}", time_of(at)))
            }
            IssueState::Resolved { at } => {
                m.push_str(&format!(" · marked resolved {}", time_of(at)))
            }
            IssueState::Expired { at, reason } => m.push_str(&format!(
                " · expired {}, evidence gone: {reason}",
                time_of(at)
            )),
            IssueState::Acked => m.push_str(" · acknowledged, still open"),
            IssueState::Muted { until } => {
                m.push_str(&format!(" · muted until {}", time_of(until)))
            }
            IssueState::Open => m.push_str(" · not yet met"),
        }
        m.push_str("\n\n");

        // --- consequences: symptoms that were this issue all along
        let consequences: Vec<Vec<String>> = issue
            .consequences
            .iter()
            .filter_map(|cid| self.find(cid))
            .map(|c| {
                vec![
                    c.title.clone(),
                    c.severity.long_label().to_string(),
                    c.subject.label(),
                    format!("`{}`", c.id),
                ]
            })
            .collect();
        if !consequences.is_empty() {
            m.push_str(
                "**Consequences of this issue** (reported here rather than as separate findings):\n\n",
            );
            m.push_str(&md_table(
                &["Issue", "Severity", "Subject", "ID"],
                &consequences,
            ));
        }

        if !issue.artifacts.is_empty() {
            m.push_str(&format!(
                "**Evidence files:** {}\n\n",
                issue.artifacts.join(", ")
            ));
        }

        m
    }
}

/// A GitHub-flavoured markdown table, padded so the raw text lines up too —
/// the Diagnose tab previews this file as plain text. Pipes in cells are
/// escaped, and newlines flattened, so a detail string can't break the table.
fn md_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let clean = |s: &str| s.replace('|', "\\|").replace('\n', " ");
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| clean(c)).collect())
        .collect();
    let widths: Vec<usize> = (0..headers.len())
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .chain([headers[i].chars().count(), 3])
                .max()
                .unwrap_or(3)
        })
        .collect();
    let line = |cells: Vec<String>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c}{}", " ".repeat(w - c.chars().count())))
            .collect();
        format!("| {} |\n", padded.join(" | "))
    };
    let mut out = line(headers.iter().map(|h| h.to_string()).collect());
    out.push_str(&line(widths.iter().map(|w| "-".repeat(*w)).collect()));
    for r in rows {
        let mut r = r;
        r.resize(headers.len(), String::new());
        out.push_str(&line(r));
    }
    out.push('\n');
    out
}

fn severity_counts(issues: &[&Issue]) -> String {
    let mut parts = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Info,
    ] {
        let n = issues.iter().filter(|i| i.severity == sev).count();
        if n > 0 {
            parts.push(format!("{n} {}", sev.long_label()));
        }
    }
    parts.join(", ")
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// `"2026-09-03 06:48:10"` → `"06:48:10"`.
fn time_of(ts: &str) -> &str {
    ts.split(' ').next_back().unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::fixture;

    fn report() -> Report {
        fixture::report()
    }

    #[test]
    fn recovery_outcome_survives_json_and_markdown_export() {
        let mut report = report();
        let step = report
            .issues
            .iter_mut()
            .flat_map(|i| &mut i.remediation)
            .find(|s| s.kind == StepKind::Apply)
            .unwrap();
        step.applied = Some(Applied::RecoveryRequired {
            operation_id: "operation-42".into(),
            reason: "completion journal write failed; target may have changed".into(),
            backup: "/recovery/original.bak".into(),
        });
        let json = report.to_json().unwrap();
        let restored: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, report);
        let md = restored.to_markdown();
        for expected in [
            "recovery required",
            "operation-42",
            "target may have changed",
            "/recovery/original.bak",
        ] {
            assert!(md.contains(expected), "missing {expected}: {md}");
        }
    }

    #[test]
    fn legacy_report_without_coverage_is_explicitly_unknown() {
        let mut value = serde_json::to_value(report()).unwrap();
        value.as_object_mut().unwrap().remove("coverage");
        value["issues"] = serde_json::json!([]);
        let old: Report = serde_json::from_value(value).unwrap();
        assert!(old.summary_line().contains("coverage not recorded"));
        assert!(!old.summary_line().contains("healthy"));
    }

    #[test]
    fn closed_findings_are_retained_in_markdown_and_not_described_as_absent() {
        let mut report = report();
        for i in &mut report.issues {
            i.state = IssueState::Resolved {
                at: "2026-09-03 07:00:00".into(),
            };
        }
        let md = report.to_markdown();
        assert!(report.summary_line().contains("retained closed findings"));
        assert!(md.contains("## Retained closed findings"));
        assert!(!md.contains("No issues were open in this window"));
        for issue in &report.issues {
            assert!(md.contains(&issue.id));
        }
    }

    #[test]
    fn an_expired_finding_says_its_evidence_went() {
        let mut report = report();
        report.issues[0].state = IssueState::Expired {
            at: "2026-09-03 07:00:00".into(),
            reason: "socket closed".into(),
        };
        let json = report.to_json().unwrap();
        assert!(
            json.contains(r#""state": "expired""#) && json.contains(r#""reason": "socket closed""#),
            "{json}"
        );
        let restored: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, report);

        let md = restored.to_markdown();
        let closed = md
            .split("## Retained closed findings")
            .nth(1)
            .expect("an expired finding is retained");
        let row = closed
            .lines()
            .find(|l| l.contains(&report.issues[0].id))
            .unwrap();
        assert!(
            row.contains("expired, evidence gone: socket closed"),
            "{row}"
        );
        assert!(!row.contains("auto-closed"), "{row}");
    }

    #[test]
    fn tables_are_well_formed_and_coverage_uses_readable_labels() {
        let mut r = report();
        let base = crate::diagnose::baseline::BaselineStore::new(
            crate::diagnose::baseline::NetworkFingerprint::new("test", None, vec![], None),
        );
        r.coverage = crate::diagnose::coverage::Coverage::from_observations(
            &crate::diagnose::detectors::Observations::default(),
            &base,
        );
        let md = r.to_markdown();
        assert!(md.contains("| Area "), "{md}");
        assert!(md.contains("## Checks not running"), "{md}");
        assert!(md.contains("not measured"), "{md}");
        assert!(!md.contains("NotMeasured"), "enum debug names leaked: {md}");
        // Every row of a table has the same number of unescaped pipes as its header.
        let mut expected = None;
        for line in md.lines() {
            if !line.starts_with('|') {
                expected = None;
                continue;
            }
            let pipes = line.replace("\\|", "").matches('|').count();
            let want = *expected.get_or_insert(pipes);
            assert_eq!(pipes, want, "ragged table row: {line}");
        }
    }

    #[test]
    fn markdown_summary_states_the_verdict() {
        let md = report().to_markdown();
        let first = md.lines().find(|l| l.starts_with("**Summary:**")).unwrap();
        assert!(first.contains("degraded"), "{first}");
        assert!(first.contains("1 high"), "{first}");
    }

    #[test]
    fn the_report_never_prints_a_multiple_the_evidence_does_not_support() {
        let r = report();
        let md = r.to_markdown();
        assert!(
            md.contains("33× baseline"),
            "the computed multiple should appear:\n{md}"
        );
        assert!(
            !md.contains("100×"),
            "the report must not restate a number the evidence contradicts"
        );
    }

    /// The load-bearing invariant: every number in the markdown can be traced
    /// to an Evidence field on some issue. If a renderer ever hard-codes a
    /// figure, this catches it.
    #[test]
    fn every_metric_in_the_report_comes_from_evidence() {
        let r = report();
        let md = r.to_markdown();

        // Collect every value/baseline/multiple string the evidence can justify.
        let mut allowed: Vec<String> = Vec::new();
        for issue in &r.issues {
            for e in &issue.evidence {
                allowed.push(e.value_label());
                if let Some(b) = e.baseline_label() {
                    allowed.push(b);
                }
                if let Some(m) = e.multiple_label() {
                    allowed.push(m);
                }
            }
        }
        // Each evidence table row must quote one of those.
        let metrics: Vec<String> = r
            .issues
            .iter()
            .flat_map(|i| i.evidence.iter().map(|e| format!("| `{}`", e.metric)))
            .collect();
        let rows: Vec<&str> = md
            .lines()
            .filter(|l| metrics.iter().any(|m| l.starts_with(m.as_str())))
            .collect();
        assert!(!rows.is_empty(), "no evidence rows rendered:\n{md}");
        for line in rows {
            assert!(
                allowed.iter().any(|a| line.contains(a.as_str())),
                "evidence row quotes a number no evidence supports:\n{line}"
            );
        }
    }

    #[test]
    fn a_preview_with_no_environment_still_has_a_sane_heading() {
        // What the Diagnose tab's `o` preview renders.
        let r = Report {
            coverage: Default::default(),
            generated_at: String::new(),
            window_start: String::new(),
            window_end: String::new(),
            environment: Environment::default(),
            issues: fixture::report().issues,
            timeline: vec![],
            artifacts: vec![],
        };
        let first = r.to_markdown().lines().next().unwrap().to_string();
        assert_eq!(first, "# netwatch report", "{first}");
        assert!(!first.contains(" ·  to"), "{first}");
    }

    #[test]
    fn the_report_renders_windows_the_way_the_screen_does() {
        let md = report().to_markdown();
        assert!(md.contains("38 samples over 3m 9s"), "{md}");
    }

    #[test]
    fn json_round_trips_into_the_same_object() {
        let r = report();
        let json = r.to_json().unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn consequences_are_listed_under_their_root_not_as_findings() {
        let mut r = report();
        // Make the dns issue a consequence of a gateway failure.
        let dns_id = r.issues[0].id.clone();
        let mut gw = r.issues[0].clone();
        gw.id = "2026-0903-99".into();
        gw.rule = "gateway.unreachable".into();
        gw.title = "gateway unreachable".into();
        gw.severity = Severity::Critical;
        gw.subject = crate::diagnose::issue::Subject::Host;
        r.issues.push(gw);
        rules::apply_suppression(&mut r.issues);

        let md = r.to_markdown();
        assert!(md.contains("Consequences of this issue"), "{md}");
        // The suppressed issue must not get its own numbered section.
        let sections = md
            .lines()
            .filter(|l| l.starts_with("## ") && l.contains(" — "))
            .count();
        assert_eq!(
            r.primary().len(),
            sections,
            "one section per primary issue, no more"
        );
        assert!(!r.primary().iter().any(|i| i.id == dns_id));
    }

    #[test]
    fn an_unapplied_apply_step_says_so() {
        let md = report().to_markdown();
        assert!(md.contains("not applied"), "{md}");
    }

    #[test]
    fn an_empty_report_does_not_claim_health() {
        let mut r = report();
        r.issues.clear();
        let md = r.to_markdown();
        assert!(md.contains("No findings are currently open"), "{md}");
        assert!(
            r.summary_line().starts_with("no open findings"),
            "{}",
            r.summary_line()
        );
    }

    #[test]
    fn a_qualified_cause_names_the_measurement_it_is_missing() {
        use crate::diagnose::issue::{Availability, Cause, CheckResult};
        let mut report = report();
        report.issues.truncate(1);
        let issue = &mut report.issues[0];
        issue.causes = vec![Cause::new(
            "receiver_queueing",
            "the receiver is queueing",
            vec![
                CheckResult::pass("symptom", "rtt tracks our own tx", "3 MB/s in flight"),
                CheckResult::not_run(
                    "discriminator",
                    "link-level bufferbloat test passed",
                    Availability::AwaitingTest,
                    "no loaded-rtt test has run",
                )
                .weighted(2.0),
            ],
        )];
        let md = report.to_markdown();
        assert!(
            md.contains("Awaiting test: link-level bufferbloat test passed"),
            "{md}"
        );
        assert!(
            !md.contains("Not measured:"),
            "a test nobody has run is not a measurement that failed: {md}"
        );
        assert!(
            !md.contains("Sufficient evidence: link-level bufferbloat test passed"),
            "a skipped check cannot be cited as what made the claim sufficient"
        );

        report.issues[0].causes[0].checks[1] = CheckResult::pass(
            "discriminator",
            "link-level bufferbloat test passed",
            "our uplink stays responsive",
        )
        .weighted(2.0);
        let md = report.to_markdown();
        assert!(
            md.contains("Sufficient evidence: link-level bufferbloat test passed"),
            "{md}"
        );
    }

    #[test]
    fn the_environment_section_states_baseline_confidence() {
        let md = report().to_markdown();
        assert!(md.contains("| baselines "), "{md}");
        assert!(md.contains("ruleset"), "{md}");
    }

    #[test]
    fn confidence_is_never_printed_as_a_percentage() {
        let md = report().to_markdown();
        for line in md.lines().filter(|l| l.contains("Probable cause")) {
            assert!(
                !line.contains('%'),
                "confidence must be a word, not a fake probability: {line}"
            );
        }
    }
}

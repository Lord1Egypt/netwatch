//! `netwatch diagnose run` — one bounded diagnosis, for a script or a ticket.
//!
//! The TUI answers "what is wrong with my network right now" interactively.
//! This answers it once, within a budget, and says so in an exit status a
//! shell can branch on. The distinction that matters is between *no finding*
//! and *not enough evidence*: a run that could not gather what it needed must
//! never be read as a healthy host, which is why those are different exits.

use crate::diagnose::coverage::Coverage;
use crate::diagnose::detectors::Observations;
use crate::diagnose::issue::{Availability, CheckResult, Issue, Kind};
use serde::Serialize;
use std::time::{Duration, Instant};

/// What a run concluded, and the exit status it reports.
///
/// Documented and stable: scripts branch on these, so the numbers are part of
/// the interface, not an implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The run completed and found no Issue. Not a claim that the host is
    /// healthy — only that the rules that could be evaluated did not fire.
    /// Observations may still be listed.
    NoFinding = 0,
    /// The run completed and found at least one open Issue. An Observation,
    /// such as a symmetric NAT, never sets this.
    Finding = 1,
    /// The budget ran out before enough evidence existed to decide. The
    /// caller should retry with a longer budget rather than read this as
    /// health.
    Incomplete = 2,
    /// Bad arguments, or the session could not start.
    Error = 3,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::NoFinding => "no_finding",
            Outcome::Finding => "finding",
            Outcome::Incomplete => "incomplete",
            Outcome::Error => "error",
        }
    }
}

/// Decide the outcome of a finished run.
///
/// Only an Issue is a finding. An Observation says something worth knowing,
/// not something wrong, so a host whose only finding is a symmetric NAT
/// exits 0. `evidence` is whether the run ever saw a usable observation for
/// what it was asked about. Without one there is nothing to conclude,
/// however quiet the issue list looks.
pub fn outcome(findings: &[&Issue], evidence: bool) -> Outcome {
    if findings.iter().any(|f| f.kind() == Kind::Issue) {
        Outcome::Finding
    } else if evidence {
        Outcome::NoFinding
    } else {
        Outcome::Incomplete
    }
}

/// Whether one sample gave the run something to conclude from.
///
/// Asked about one target, only that target's own probe counts: another
/// target completing says nothing about this one. Otherwise a gateway or
/// resolver observation counts, or any completed target probe. The sampler
/// gives no gateway observation until a probe cycle measured loss, so a
/// gateway that answers neither ICMP nor any TCP port is no evidence. The
/// prober's completion stamp, which it sets after that cycle too, used to
/// count, and such a host exited 0.
fn evidence(observations: &Observations, target: Option<&str>) -> bool {
    match target {
        Some(name) => observations.targets.iter().any(|t| t.name == name),
        None => {
            observations.gateway.is_some()
                || observations.dns.is_some()
                || !observations.targets.is_empty()
        }
    }
}

struct Options {
    target: Option<String>,
    budget: Duration,
    json: bool,
}

fn parse(args: &[String]) -> anyhow::Result<Options> {
    let mut opts = Options {
        target: None,
        budget: Duration::from_secs(30),
        json: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                opts.target = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--target requires a configured name"))?
                        .clone(),
                )
            }
            "--budget" => {
                let raw = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--budget requires a duration, e.g. 30s"))?;
                opts.budget = parse_budget(raw)?;
            }
            "--format" => {
                let fmt = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--format requires json or text"))?;
                match fmt.as_str() {
                    "json" => opts.json = true,
                    "text" => opts.json = false,
                    other => anyhow::bail!("unknown format: {other} (json or text)"),
                }
            }
            "--json" => opts.json = true,
            other => anyhow::bail!("unknown run option: {other}"),
        }
    }
    Ok(opts)
}

/// `30s`, `2m`, or a bare number of seconds. Bounded at both ends: a run
/// shorter than a probe interval cannot gather evidence, and one longer than
/// ten minutes is a session, not a one-shot.
pub fn parse_budget(raw: &str) -> anyhow::Result<Duration> {
    let (value, scale) = match raw.strip_suffix('s') {
        Some(v) => (v, 1),
        None => match raw.strip_suffix('m') {
            Some(v) => (v, 60),
            None => (raw, 1),
        },
    };
    let secs: u64 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("budget must be a duration like 30s or 2m"))?;
    let secs = secs * scale;
    anyhow::ensure!(
        (5..=600).contains(&secs),
        "budget must be between 5s and 10m"
    );
    Ok(Duration::from_secs(secs))
}

/// Print to stderr what the engine will log about invalid
/// `[diagnose_thresholds]`. It replaces them with defaults and logs each one,
/// but the `diagnose` subcommands run before the log file opens, so the log
/// line goes nowhere and stderr is where their caller looks.
pub(crate) fn print_threshold_warnings(thresholds: &crate::diagnose::detectors::Thresholds) {
    for warning in thresholds.validated().1 {
        eprintln!("warning: {warning}");
    }
}

pub fn command(args: &[String]) -> anyhow::Result<()> {
    // Exit codes are the interface here, so the error path owns its own
    // status rather than inheriting whatever main does with an `Err`.
    let outcome = match parse(args).and_then(run) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("error: {e}");
            Outcome::Error
        }
    };
    std::process::exit(outcome as i32);
}

/// The user's configuration as a run uses it. A run never traces on a
/// timer: only the TUI's controller does. Each sample records the interval
/// it ran with, so the run's copy has none.
fn run_config(loaded: crate::config::NetwatchConfig) -> crate::config::NetwatchConfig {
    let mut config = crate::config::NetwatchConfig {
        insights_enabled: false,
        diagnose_record_episodes: false,
        ..loaded
    };
    config.diagnose_probes.trace_refresh_secs = None;
    config
}

fn run(opts: Options) -> anyhow::Result<Outcome> {
    use crate::{app::App, config::NetwatchConfig, diagnose::live::LiveSampler};

    let config = run_config(NetwatchConfig::load());
    print_threshold_warnings(&config.diagnose_thresholds);
    if let Some(name) = &opts.target {
        anyhow::ensure!(
            config.diagnose_targets.iter().any(|t| &t.name == name),
            "no configured target named {name}"
        );
    }
    let mode = crate::sandbox::Mode::from_config(&config.sandbox);
    let mut app = App::prepare_with_config(config);
    crate::runtime::bootstrap::start(
        &mut app,
        crate::runtime::bootstrap::SessionKind::Daemon,
        mode,
    )?;
    crate::runtime::bootstrap::prime_collectors(&mut app);

    let started_at = chrono::Local::now();
    let started = Instant::now();
    let mut sampler = LiveSampler::new();
    let mut samples = 0usize;
    let mut saw_evidence = false;

    loop {
        app.traffic.update();
        app.connection_collector.update();
        app.tcp_info.update();
        let network = &app.config_collector.config;
        app.health_prober
            .probe(network.gateway.as_deref(), network.primary_dns().as_deref());
        app.diagnose.target_prober.probe_due(
            &app.user_config.diagnose_targets,
            super::targets::ProbeEnv {
                resolvers: network
                    .dns_servers
                    .iter()
                    .filter_map(|d| d.parse().ok())
                    .collect(),
                vpn_ifaces: app
                    .interface_info
                    .iter()
                    .filter(|i| i.is_up && super::targets::is_vpn_iface(&i.name))
                    .map(|i| i.name.clone())
                    .collect(),
            },
        );
        let fingerprint = LiveSampler::fingerprint(&app);
        app.diagnose.baselines.set_network(fingerprint);
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        saw_evidence |= evidence(&observations, opts.target.as_deref());
        app.diagnose.engine.observe_live_at(
            &observations,
            &app.diagnose.baselines,
            &sampler.completed,
            Instant::now(),
        );
        samples += 1;
        if started.elapsed() >= opts.budget {
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.packet_collector.stop_capture();

    let all = app.diagnose.engine.primary();
    let findings: Vec<&Issue> = match &opts.target {
        Some(name) => all
            .into_iter()
            .filter(|i| i.subject.label() == *name)
            .collect(),
        None => all,
    };
    let outcome = outcome(&findings, saw_evidence);
    let sampling = Sampling {
        target: opts.target,
        started_at: started_at.to_rfc3339(),
        seconds: started.elapsed().as_secs_f64(),
        samples,
        evidence: saw_evidence,
    };

    if opts.json {
        let report = json_report(
            outcome,
            &sampling,
            app.diagnose.engine.coverage(),
            &findings,
        );
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", text_report(outcome, &sampling, &findings));
    }
    Ok(outcome)
}

/// What a run sampled, apart from what it found.
struct Sampling {
    target: Option<String>,
    started_at: String,
    seconds: f64,
    samples: usize,
    evidence: bool,
}

/// One finding as schema 2 writes it: the issue, with its kind beside it.
#[derive(Serialize)]
struct Finding<'a> {
    kind: Kind,
    #[serde(flatten)]
    issue: &'a Issue,
}

/// The JSON report, schema 2. Issues and Observations are separate arrays,
/// each entry says which it is, and checks carry `state` without `passed`.
/// Schema 1 listed both kinds under `issues`.
fn json_report(
    outcome: Outcome,
    sampling: &Sampling,
    coverage: &Coverage,
    findings: &[&Issue],
) -> serde_json::Value {
    let of = |kind: Kind| -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| f.kind() == kind)
            .map(|&issue| Finding { kind, issue })
            .collect()
    };
    serde_json::json!({
        "schema": 2,
        "version": env!("CARGO_PKG_VERSION"),
        "ruleset": super::rules::CATALOGUE.len(),
        "outcome": outcome.label(),
        "exit": outcome as i32,
        "target": sampling.target,
        "started_at": sampling.started_at,
        "window_seconds": sampling.seconds,
        "samples": sampling.samples,
        "evidence": sampling.evidence,
        "completeness": if sampling.evidence {
            "the rules that could be evaluated were; an empty list is not a health claim"
        } else {
            "no usable observation arrived inside the budget; nothing was concluded"
        },
        "coverage": coverage,
        "issues": of(Kind::Issue),
        "observations": of(Kind::Observation),
    })
}

/// The text report: the outcome, the Issues under it, then the Observations
/// under their own heading, since they do not set the exit status.
fn text_report(outcome: Outcome, sampling: &Sampling, findings: &[&Issue]) -> String {
    let mut out = format!(
        "{} · {} samples in {:.0}s\n",
        outcome.label(),
        sampling.samples,
        sampling.seconds
    );
    let (issues, observations): (Vec<&Issue>, Vec<&Issue>) =
        findings.iter().partition(|f| f.kind() == Kind::Issue);
    for issue in issues {
        out.push_str(&finding_lines(issue));
    }
    if outcome == Outcome::Incomplete {
        out.push_str("  no usable observation arrived inside the budget\n");
    }
    if !observations.is_empty() {
        out.push_str("observations · not counted in the exit status\n");
        for observation in observations {
            out.push_str(&finding_lines(observation));
        }
    }
    out
}

/// A finding's summary line, then its top cause and the check that cause is
/// still missing.
fn finding_lines(finding: &Issue) -> String {
    let mut out = format!("  {}\n", finding.summary_line());
    if let Some(cause) = finding.top_cause() {
        out.push_str(&format!(
            "    {} ({}, {})\n",
            cause.label,
            cause.confidence().label(),
            cause.checks_label()
        ));
        if let Some(missing) = cause.missing_discriminator() {
            out.push_str(&format!("    {}\n", missing_line(missing)));
        }
    }
    out
}

/// The check a qualified cause is still missing, led by why it did not run
/// in the words the Diagnose tab uses, so the text agrees with the JSON's
/// `why_not`.
fn missing_line(missing: &CheckResult) -> String {
    let why = missing
        .why_not
        .as_ref()
        .map_or("not measured", Availability::label);
    format!("{why}: {} — {}", missing.name, missing.detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_parse_and_are_bounded() {
        assert_eq!(parse_budget("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_budget("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_budget("45").unwrap(), Duration::from_secs(45));
        assert!(parse_budget("1s").is_err(), "shorter than a probe interval");
        assert!(parse_budget("30m").is_err(), "that is a session, not a run");
        assert!(parse_budget("soon").is_err());
    }

    /// D33-B04 review: a run never traces on a timer, so its samples must
    /// not record periodic tracing as on. B30 and the expiry guard read that
    /// field.
    #[test]
    fn a_run_records_periodic_tracing_as_off() {
        let loaded: crate::config::NetwatchConfig = toml::from_str(
            r#"
            [diagnose_probes]
            trace_target = "9.9.9.9"
            trace_refresh_secs = 120
            "#,
        )
        .unwrap();
        assert_eq!(loaded.diagnose_probes.periodic_trace_secs(), Some(120));
        let app = crate::app::App::prepare_with_config(run_config(loaded));
        let observed = crate::diagnose::live::LiveSampler::new()
            .sample(&app, &app.diagnose.engine.settings().thresholds)
            .config
            .expect("a live sample records its configuration");
        assert_eq!(observed.trace_refresh_secs, None);
        assert_eq!(
            observed.trace_target, "9.9.9.9",
            "the target is still known"
        );
    }

    #[test]
    fn an_empty_list_without_evidence_is_incomplete_not_healthy() {
        // The distinction the exit statuses exist for. A run that gathered
        // nothing has not established that anything is well.
        assert_eq!(outcome(&[], false), Outcome::Incomplete);
        assert_eq!(outcome(&[], true), Outcome::NoFinding);
        assert_eq!(Outcome::Incomplete as i32, 2);
        assert_eq!(Outcome::NoFinding as i32, 0);
    }

    const GATEWAY: &str = "192.0.2.1";

    /// The prober's status after `cycles` gateway probes, each an (rtt, loss)
    /// pair recorded the way the probe thread records it: every cycle stamps
    /// `completed.gateway`, and only a measured one joins the history.
    fn after_gateway_cycles(
        cycles: &[(Option<f64>, crate::collectors::health::Loss)],
    ) -> crate::collectors::health::HealthStatus {
        let mut status = (*crate::collectors::health::HealthProber::new().status()).clone();
        for &(rtt, loss) in cycles {
            let completed = Instant::now();
            status.gateway_rtt_ms = rtt;
            status.gateway_loss = loss;
            if loss.is_measured() {
                status.completed.gateway_history.push_back(completed);
                status.gateway_rtt_history.push_back(rtt);
            }
            status.completed.gateway = Some(completed);
            status.completed.gateway_target = Some(GATEWAY.into());
        }
        status
    }

    /// One live sample on a host whose gateway is [`GATEWAY`] and which lists
    /// no resolver, with `status` as the prober's latest.
    fn sample_with(
        status: crate::collectors::health::HealthStatus,
    ) -> (crate::diagnose::live::LiveSampler, Observations) {
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.config_collector.config.gateway = Some(GATEWAY.into());
        app.config_collector.config.dns_servers.clear();
        app.health_prober.publish_for_test(status);
        let mut sampler = crate::diagnose::live::LiveSampler::new();
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        (sampler, observations)
    }

    /// REVIEW §2.1: count gateway evidence only when loss is measured. A
    /// gateway cycle that could send nothing ("icmp is blocked here and the
    /// gateway answers no tcp port") still stamps the prober's completion
    /// time, which the run used to count; it yields no gateway observation,
    /// and with no resolver either the run has nothing to conclude from.
    #[test]
    fn an_unmeasured_gateway_is_not_evidence() {
        use crate::collectors::health::Loss;
        let unmeasured = (
            None,
            Loss::Unmeasured("icmp is blocked here and the gateway answers no tcp port"),
        );
        let measured = |rtt| (Some(rtt), Loss::Measured(0.0));
        for (case, cycles) in [
            ("never measured", vec![unmeasured]),
            (
                "measured before, not now",
                vec![measured(0.9), measured(1.1), unmeasured],
            ),
        ] {
            let (sampler, observations) = sample_with(after_gateway_cycles(&cycles));
            assert!(
                sampler.completed.health.gateway.is_some(),
                "{case}: the old check would have counted this cycle"
            );
            assert_eq!(
                sampler.completed.health.gateway_target.as_deref(),
                Some(GATEWAY),
                "{case}"
            );
            assert!(observations.gateway.is_none(), "{case}");
            assert!(observations.dns.is_none(), "{case}");
            assert!(!evidence(&observations, None), "{case}");
            assert_eq!(
                outcome(&[], evidence(&observations, None)),
                Outcome::Incomplete,
                "{case}"
            );
        }
    }

    #[test]
    fn a_measured_gateway_is_evidence() {
        use crate::collectors::health::Loss;
        use crate::diagnose::detectors::{DnsObs, GatewayObs};
        // Through the sampler, on the same seam the unmeasured test uses: a
        // measured cycle, including one that lost everything, is observed.
        for (rtt, loss) in [
            (Some(0.9), Loss::Measured(0.0)),
            (None, Loss::Measured(100.0)),
        ] {
            let (_, observations) = sample_with(after_gateway_cycles(&[(rtt, loss)]));
            let observed = observations.gateway.as_ref().expect("a measured gateway");
            assert_eq!(observed.addr.as_deref(), Some(GATEWAY));
            assert_eq!(Some(observed.loss_pct), loss.pct());
            assert!(evidence(&observations, None));
        }

        let gateway = Observations {
            gateway: Some(GatewayObs {
                addr: Some("192.0.2.2".into()),
                rtt_ms: Some(0.9),
                loss_pct: 0.0,
                arp_ok: None,
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            ..Default::default()
        };
        assert!(evidence(&gateway, None));
        assert_eq!(outcome(&[], evidence(&gateway, None)), Outcome::NoFinding);
        // Total loss is measured too: that is gateway.unreachable's input.
        let dead = Observations {
            gateway: gateway.gateway.clone().map(|g| GatewayObs {
                rtt_ms: None,
                loss_pct: 100.0,
                icmp_ok: false,
                ..g
            }),
            ..Default::default()
        };
        assert!(evidence(&dead, None));
        // A measured resolver alone is evidence as well.
        let resolver = Observations {
            dns: Some(DnsObs {
                resolver: "192.0.2.2".into(),
                rtt_p50_ms: Some(2.0),
                rtt_p95_ms: Some(3.0),
                failure_rate_pct: 0.0,
                truncation_rate_pct: 0.0,
                queries: 6,
                failed: 0,
                truncated: 0,
                alt_resolver: None,
                alt_rtt_ms: None,
                icmp_rtt_ms: None,
                cached_rtt_ms: None,
                window_secs: 30,
                cross: None,
            }),
            ..Default::default()
        };
        assert!(evidence(&resolver, None));
        // Asked about one target, the gateway says nothing about it.
        assert!(!evidence(&gateway, Some("api")));
    }

    #[test]
    fn a_finding_outranks_the_evidence_question() {
        let issue = crate::diagnose::fixture::report().issues.remove(0);
        assert_eq!(outcome(&[&issue], true), Outcome::Finding);
        assert_eq!(outcome(&[&issue], false), Outcome::Finding);
        assert_eq!(Outcome::Finding as i32, 1);
    }

    /// An engine that opens an issue on its first sample, after one sample
    /// of `obs`.
    fn engine_after(obs: &Observations) -> crate::diagnose::engine::Engine {
        use crate::diagnose::engine::{Engine, FixedClock};
        let engine = Engine::new(Box::new(FixedClock::at("2026-09-15 10:00:00")));
        let mut settings = *engine.settings();
        settings.thresholds.consecutive_n = 1;
        let mut engine = engine.with_settings(settings);
        engine.observe(obs, &crate::diagnose::fixture::baselines());
        engine
    }

    /// A host whose only finding is a symmetric NAT: an Observation.
    fn symmetric_nat() -> Issue {
        use crate::diagnose::detectors::NatObs;
        let engine = engine_after(&Observations {
            nat: Some(NatObs {
                mappings: vec![
                    ("stun1".into(), "198.51.100.7:40001".into()),
                    ("stun2".into(), "198.51.100.7:40517".into()),
                ],
                symmetric: true,
            }),
            ..Default::default()
        });
        let found = engine.primary();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule, "nat.symmetric");
        assert_eq!(found[0].kind(), Kind::Observation);
        found[0].clone()
    }

    fn sampling(evidence: bool) -> Sampling {
        Sampling {
            target: None,
            started_at: "2026-09-15T10:00:00+00:00".into(),
            seconds: 30.0,
            samples: 30,
            evidence,
        }
    }

    /// D33-B06: the exit code counts Issues only. Schema 1 exited 1 on any
    /// finding, Info included.
    #[test]
    fn observations_alone_exit_zero() {
        let nat = symmetric_nat();
        let outcome = outcome(&[&nat], true);
        assert_eq!(outcome, Outcome::NoFinding);
        assert_eq!(outcome as i32, 0);
        // An Observation is no evidence either way: with nothing measured
        // the run is still incomplete, not healthy.
        assert_eq!(super::outcome(&[&nat], false), Outcome::Incomplete);

        let json = json_report(outcome, &sampling(true), &Coverage::default(), &[&nat]);
        assert_eq!(json["exit"], 0);
        assert_eq!(json["issues"], serde_json::json!([]));
        assert_eq!(json["observations"][0]["rule"], "nat.symmetric");
        let text = text_report(outcome, &sampling(true), &[&nat]);
        let (above, below) = text
            .split_once("observations · not counted in the exit status\n")
            .expect("observations have their own heading");
        assert!(!above.contains("symmetric"), "{text}");
        assert!(below.contains(&nat.summary_line()), "{text}");
    }

    #[test]
    fn one_issue_exits_one() {
        let nat = symmetric_nat();
        let (engine, _) = crate::diagnose::fixture::run();
        let issue = engine.primary_issues()[0];
        assert_eq!(outcome(&[&nat, issue], true), Outcome::Finding);
        assert_eq!(outcome(&[issue, &nat], false), Outcome::Finding);

        let text = text_report(Outcome::Finding, &sampling(true), &[&nat, issue]);
        let (above, below) = text
            .split_once("observations · not counted in the exit status\n")
            .expect("observations have their own heading");
        assert!(above.starts_with("finding · 30 samples in 30s\n"), "{text}");
        assert!(above.contains(&issue.summary_line()), "{text}");
        assert!(below.contains(&nat.summary_line()), "{text}");
    }

    #[test]
    fn json_separates_issues_from_observations() {
        let nat = symmetric_nat();
        let (engine, _) = crate::diagnose::fixture::run();
        let mut findings = engine.primary();
        let issues = findings.len();
        findings.push(&nat);
        let json = json_report(
            outcome(&findings, true),
            &sampling(true),
            engine.coverage(),
            &findings,
        );
        assert_eq!(json["schema"], 2);
        assert_eq!(json["outcome"], "finding");
        assert_eq!(json["exit"], 1);
        let listed = |key: &str| json[key].as_array().unwrap().clone();
        assert_eq!(listed("issues").len(), issues);
        for entry in listed("issues") {
            assert_eq!(entry["kind"], "issue", "{entry}");
            assert_ne!(entry["severity"], "info", "{entry}");
        }
        let observations = listed("observations");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["kind"], "observation");
        assert_eq!(observations[0]["rule"], "nat.symmetric");
        // The finding's own `kind` sits beside the subject's, not over it.
        assert_eq!(observations[0]["subject"]["kind"], "host");
    }

    #[test]
    fn schema_2_checks_have_state_not_passed() {
        let (engine, _) = crate::diagnose::fixture::run();
        let findings = engine.primary();
        let json = json_report(
            outcome(&findings, true),
            &sampling(true),
            engine.coverage(),
            &findings,
        );
        let mut states = std::collections::BTreeSet::new();
        for entry in json["issues"].as_array().unwrap() {
            for cause in entry["causes"].as_array().unwrap() {
                for check in cause["checks"].as_array().unwrap() {
                    assert!(check.get("passed").is_none(), "{check}");
                    let state = check["state"].as_str().expect("every check has a state");
                    assert_eq!(
                        state == "not_run",
                        check.get("why_not").is_some(),
                        "{check}"
                    );
                    states.insert(state.to_string());
                }
            }
        }
        // The fixture exercises all three, so none is vacuous.
        assert_eq!(
            states.into_iter().collect::<Vec<_>>(),
            ["failed", "not_run", "passed"]
        );
    }

    #[test]
    fn the_missing_check_line_gives_the_reason_the_json_gives() {
        let awaiting = CheckResult::not_run(
            "link_level_bufferbloat_test_passed",
            "link-level bufferbloat test passed",
            Availability::AwaitingTest,
            "no loaded-rtt test has run",
        );
        assert_eq!(
            missing_line(&awaiting),
            "awaiting test: link-level bufferbloat test passed — no loaded-rtt test has run"
        );
        let never_built = CheckResult::not_run(
            "icmp_rtt_raised",
            "icmp rtt raised",
            Availability::NotImplemented,
            "no icmp probe",
        );
        assert_eq!(
            missing_line(&never_built),
            "not implemented: icmp rtt raised — no icmp probe"
        );
    }

    #[test]
    fn unknown_options_are_refused_rather_than_ignored() {
        assert!(parse(&["--target".into(), "api".into()]).is_ok());
        assert!(parse(&["--nope".into()]).is_err());
        assert!(parse(&["--target".into()]).is_err());
        assert!(parse(&["--format".into(), "yaml".into()]).is_err());
    }
}

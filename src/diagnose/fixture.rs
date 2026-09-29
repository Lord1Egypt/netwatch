//! The demo scenario, and the fixture every test and screenshot is built on.
//!
//! Nothing here is a hand-written report. The observations below are fed to
//! the real [`Engine`] on a [`FixedClock`], and the issues, the verdict line,
//! the screen and the report all fall out of that one run. That is the point:
//! a fixture assembled by hand can contain a number the engine could never
//! produce — which is exactly how the design bundle this implements ended up
//! describing 40ms against a 1.2ms baseline as "100×" in one panel and
//! stating the underlying numbers in another. Generate the demo from the
//! engine and the contradiction is unrepresentable.
//!
//! The scenario, at 06:51:19 on 2026-09-03:
//!
//! * the DHCP-supplied resolver 169.254.1.1 answers in 40ms against a 1.2ms
//!   learned baseline, since 06:48:10 — 33× baseline, so a `high`;
//! * the upstream path to 1.1.1.1 changed at hop 3 inside as7545 at 06:44:02,
//!   adding 40ms — an `info` that escalates to `medium` on the added latency,
//!   and the thing the DNS cause analysis correlates against;
//! * one LAN socket (`ncat` → 10.88.0.3:9000) shows receiver-side bufferbloat
//!   at 184ms with 12 retransmits, since 06:49:31;
//! * gateway, loss and throughput are nominal, and stay that way.

use super::baseline::{BaselineStore, NetworkFingerprint};
use super::detectors::{DnsObs, GatewayObs, HopObs, IfaceObs, Observations, PathObs, SocketObs};
use super::engine::{Clock, Engine, FixedClock};
use super::report::{Environment, Report, TimelineEvent};

/// When the demo window ends. Every timestamp in the fixture is relative to
/// this, so the whole scenario is reproducible to the second.
pub const NOW: &str = "2026-09-03 06:51:19";
pub const WINDOW_START: &str = "2026-09-03 06:44:00";
/// Length of the scenario, 06:44:00 → 06:51:19.
pub const SCENARIO_SECS: u64 = 439;

pub const RESOLVER: &str = "169.254.1.1";
pub const ALT_RESOLVER: &str = "192.168.8.1";
pub const GATEWAY: &str = "192.168.8.1";
pub const IFACE: &str = "eth0";

/// Learned baselines for the demo network, already past the learning window.
pub fn baselines() -> BaselineStore {
    let mut b = BaselineStore::new(NetworkFingerprint::new(
        IFACE,
        Some(GATEWAY.to_string()),
        vec![RESOLVER.to_string()],
        Some("192.168.8.0/24".to_string()),
    ));
    // 1.2ms mean, σ0.4 — the numbers the whole scenario hangs on.
    b.seed(RESOLVER, "dns.rtt_p50", 1.2, 0.4, 2_400);
    b.seed(GATEWAY, "gateway.rtt", 0.9, 0.2, 2_400);
    b.seed("1.1.1.1", "path.rtt", 12.0, 1.8, 2_400);
    b
}

fn hop(n: u8, ip: &str, asn: &str, rtt: f64) -> HopObs {
    HopObs {
        number: n,
        ip: Some(ip.to_string()),
        asn: Some(asn.to_string()),
        rtt_p50_ms: Some(rtt),
        rtt_p95_ms: Some(rtt * 1.4),
        loss_pct: 0.0,
        silent: false,
    }
}

/// The path as it was before 06:44:02.
pub fn path_before() -> Vec<HopObs> {
    vec![
        hop(1, GATEWAY, "-", 0.9),
        hop(2, "100.64.0.1", "as7545", 8.1),
        hop(3, "203.0.113.9", "as7545", 12.0),
        hop(4, "1.1.1.1", "as13335", 13.4),
    ]
}

/// The path after the reroute: hop 3 moved inside the same ASN and added 40ms.
pub fn path_after() -> Vec<HopObs> {
    vec![
        hop(1, GATEWAY, "-", 0.9),
        hop(2, "100.64.0.1", "as7545", 8.1),
        hop(3, "203.0.113.44", "as7545", 52.0),
        hop(4, "1.1.1.1", "as13335", 53.6),
    ]
}

/// The bufferbloated LAN socket.
pub fn bloated_socket(age_secs: u64) -> SocketObs {
    SocketObs {
        local: "10.88.0.2:52344".into(),
        remote: "10.88.0.3:9000".into(),
        process: Some("ncat".into()),
        rtt_ms: Some(184.0),
        rttvar_ms: Some(41.0),
        retrans: Some(12),
        cwnd: Some(64),
        ssthresh: Some(u32::MAX),
        rwnd: Some(262_144),
        mss: Some(1448),
        tx_bps: 2.4e6,
        rx_bps: 1.1e4,
        verdict_age_secs: age_secs,
    }
}

fn healthy_iface() -> IfaceObs {
    IfaceObs {
        counter_window_secs: None,
        name: IFACE.into(),
        carrier: Some(true),
        rx_errors: 0,
        tx_errors: 0,
        rx_dropped: 0,
        tx_dropped: 0,
        errors_per_min: 0,
        drops_per_min: Some(0),
        link_rate_bps: Some(1e9),
        wireless: Some(false),
        signal_dbm: None,
        tx_retry_pct: None,
        rx_bps: 3.1e6,
        tx_bps: 2.6e6,
    }
}

fn healthy_gateway() -> GatewayObs {
    GatewayObs {
        addr: Some(GATEWAY.into()),
        rtt_ms: Some(0.9),
        loss_pct: 0.0,
        arp_ok: Some(true),
        icmp_ok: true,
        internet_reachable: Some(true),
    }
}

fn slow_dns() -> DnsObs {
    DnsObs {
        resolver: RESOLVER.into(),
        rtt_p50_ms: Some(40.0),
        rtt_p95_ms: Some(48.0),
        failure_rate_pct: 0.0,
        truncation_rate_pct: 5.3,
        queries: 38,
        failed: 0,
        truncated: 2,
        alt_resolver: Some(ALT_RESOLVER.into()),
        alt_rtt_ms: Some(1.4),
        icmp_rtt_ms: Some(0.1),
        cached_rtt_ms: Some(0.9),
        window_secs: 189,
        cross: None,
    }
}

fn healthy_dns() -> DnsObs {
    DnsObs {
        rtt_p50_ms: Some(1.2),
        rtt_p95_ms: Some(1.9),
        truncation_rate_pct: 0.0,
        truncated: 0,
        ..slow_dns()
    }
}

/// The resolver after the session has been switched to the alternate: the
/// 1.4ms the discriminating check measured during diagnosis is what it
/// actually delivers, which is the point of having measured it.
fn fixed_dns() -> DnsObs {
    DnsObs {
        resolver: ALT_RESOLVER.into(),
        rtt_p50_ms: Some(1.4),
        rtt_p95_ms: Some(2.1),
        truncation_rate_pct: 0.0,
        truncated: 0,
        alt_resolver: Some(RESOLVER.into()),
        alt_rtt_ms: Some(40.0),
        ..slow_dns()
    }
}

/// One observation frame. `secs_from_start` counts from [`WINDOW_START`], so
/// the scenario's onsets land where the story says they do.
pub fn observations_at(secs_from_start: u64) -> Observations {
    observations_with(secs_from_start, false)
}

/// As [`observations_at`], but with the resolver remediation already applied.
///
/// This is what closes the loop in the interactive demo: switching the session
/// resolver is supposed to fix the DNS issue, so the scenario has to be able to
/// show it doing that. The engine is not told anything — it simply sees the
/// resolver answering in 1.2ms again, and its own verify condition
/// (`dns.rtt_p50 < 5ms for 60s`) closes the issue on schedule.
pub fn observations_with(secs_from_start: u64, resolver_fixed: bool) -> Observations {
    // 06:44:00 + n. Onsets: path 06:44:02 (2s), dns 06:48:10 (250s),
    // socket 06:49:31 (331s).
    let path_changed = secs_from_start >= 2;
    let dns_slow = secs_from_start >= 250 && !resolver_fixed;
    let socket_bad = secs_from_start >= 331;

    Observations {
        coverage_hints: Default::default(),
        egress: None,
        kernel: None,
        active: Default::default(),
        now: String::new(),
        iface: Some(healthy_iface()),
        gateway: Some(healthy_gateway()),
        dns: Some(match (dns_slow, resolver_fixed) {
            (true, _) => slow_dns(),
            (false, true) => fixed_dns(),
            (false, false) => healthy_dns(),
        }),
        paths: vec![PathObs {
            destination_reached: Some(true),
            target: "1.1.1.1".into(),
            hops: if path_changed {
                path_after()
            } else {
                path_before()
            },
            previous: path_changed.then(path_before),
            traced_at: "2026-09-03 06:44:02".into(),
        }],
        sockets: if socket_bad {
            // The verdict has to have held for 30s before it can open an
            // issue, so the socket's age tracks how long it has been bad.
            vec![bloated_socket(secs_from_start - 331 + 60)]
        } else {
            vec![]
        },
        // The uplink itself is fine — which is what makes the socket's
        // bufferbloat the *receiver's* problem, and the check that proves it.
        idle_rtt_ms: Some(12.0),
        loaded_rtt_ms: Some(18.0),
        captive_portal_url: None,
        nat: None,
        targets: vec![],
    }
}

struct ClockRef(std::sync::Arc<FixedClock>);

impl Clock for ClockRef {
    fn now(&self) -> chrono::DateTime<chrono::Local> {
        self.0.now()
    }
}

/// Run the real engine across the whole demo window and hand back the result.
/// Every issue, timestamp and confidence in the demo comes out of this loop.
pub fn run() -> (Engine, BaselineStore) {
    let clock = std::sync::Arc::new(FixedClock::at(WINDOW_START));
    let mut engine = Engine::new(Box::new(ClockRef(clock.clone())));
    let base = baselines();

    // 06:44:00 → 06:51:19 at one observation per second.
    for t in 0..=SCENARIO_SECS {
        engine.observe(&observations_at(t), &base);
        clock.advance_secs(1);
    }
    (engine, base)
}

pub fn environment(base: &BaselineStore) -> Environment {
    Environment {
        host: "nw-demo".into(),
        iface: IFACE.into(),
        driver: Some("e1000e".into()),
        kernel: Some("6.19.10".into()),
        qdisc: Some("fq_codel".into()),
        resolvers: vec![RESOLVER.into(), ALT_RESOLVER.into()],
        gateway: Some(GATEWAY.into()),
        netwatch_version: env!("CARGO_PKG_VERSION").into(),
        ruleset_version: "v1".into(),
        baseline_state: format!(
            "{} on {}",
            base.overall_readiness().label(),
            base.fingerprint().label()
        ),
    }
}

/// The demo report, generated from the demo run.
pub fn report() -> Report {
    let (engine, base) = run();
    let issues = engine.issues().to_vec();

    let mut timeline: Vec<TimelineEvent> = issues
        .iter()
        .map(|i| TimelineEvent {
            at: i.since.clone(),
            kind: "issue".into(),
            text: format!("{} · {}", i.title, i.subject.label()),
        })
        .collect();
    timeline.push(TimelineEvent {
        at: "2026-09-03 06:44:02".into(),
        kind: "path".into(),
        text: "hop 3 to 1.1.1.1 changed inside as7545, adding 40ms".into(),
    });
    timeline.sort_by(|a, b| a.at.cmp(&b.at));

    Report {
        coverage: engine.coverage().clone(),
        generated_at: NOW.into(),
        window_start: WINDOW_START.into(),
        window_end: NOW.into(),
        environment: environment(&base),
        issues,
        timeline,
        artifacts: vec![
            "diagnose.json".into(),
            "baselines.json".into(),
            "trace-1.1.1.1.json".into(),
            "capture.pcap".into(),
            "timeline.json".into(),
        ],
    }
}

/// A deterministic recorded episode of the scenario above.
///
/// The corpus DG08 pins replays this: same frames, same decisions, every
/// time. Its id is fixed rather than a fresh uuid, so two runs produce
/// byte-identical files and a diff means a decision changed.
pub fn episode() -> crate::diagnose::episode::Episode {
    use crate::diagnose::engine::{Clock, Engine, FixedClock, ObservationTimes};
    use crate::diagnose::episode;
    let clock = std::sync::Arc::new(FixedClock::at("2026-09-03 06:44:00"));
    let mut engine = Engine::new(Box::new(clock.clone()));
    let mut base = baselines();
    let mut rec = episode::Recorder::new(episode::EnvProfile::detect("root", 1000), 1.789e9);
    rec.schedule_quiet_sample(f64::MAX);
    let start = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
    for t in 0..=SCENARIO_SECS {
        let mut obs = observations_at(t);
        for s in &mut obs.sockets {
            s.process = Some("firefox".into());
        }
        let now = start + std::time::Duration::from_secs(t);
        let mut times = ObservationTimes {
            interface: Some(now),
            sockets: Some(now),
            path: Some(now),
            ..Default::default()
        };
        // Without health times the live engine drops the DNS and gateway
        // observations as stale, so the corpus could not see a regression in
        // either. The prober completes on its own 5s grid, not every tick;
        // stamping every frame would count each second as a new sample.
        let probed = start + std::time::Duration::from_secs(t - t % 5);
        times.health.dns = Some(probed);
        times.health.gateway = Some(probed);
        times.health.internet = Some(probed);
        times.health.dns_target = obs.dns.as_ref().map(|d| d.resolver.clone());
        times.health.gateway_target = obs.gateway.as_ref().and_then(|g| g.addr.clone());
        engine.observe_live_at(&obs, &base, &times, now);
        let _ = rec.record(episode::Tick {
            at: 1.789e9 + t as f64,
            ts: crate::diagnose::engine::format_ts(clock.now()),
            now,
            obs: &obs,
            times: &times,
            readings: &[],
            engine: &engine,
            baselines: &base,
            events: vec![],
        });
        base.set_gate_sigma(engine.settings().thresholds.sigma_k);
        clock.advance_secs(1);
    }
    let mut ep = rec
        .flush(&engine, &crate::diagnose::engine::format_ts(clock.now()))
        .expect("the scenario opens issues, so an episode exists");
    ep.id = "fixture-scenario".into();
    ep
}

/// The synthetic corpus episode `id`, rebuilt. `None` for an id no scenario
/// here builds; `diagnose corpus` refuses a manifest row naming one.
pub fn synthetic(id: &str) -> Option<crate::diagnose::episode::Episode> {
    (id == "fixture-scenario").then(episode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::Severity;

    #[test]
    fn the_demo_run_produces_the_scenario_it_describes() {
        let (engine, _) = run();
        let primary = engine.primary();
        let rules: Vec<&str> = primary.iter().map(|i| i.rule.as_str()).collect();

        assert!(rules.contains(&"dns.slow_resolver"), "{rules:?}");
        assert!(rules.contains(&"tcp.bufferbloat_remote"), "{rules:?}");
        assert!(rules.contains(&"path.changed"), "{rules:?}");
        assert_eq!(primary.len(), 3, "{rules:?}");
    }

    /// The reroute costs 40ms, which the path.rtt_spike rule also detects.
    /// Both are true; only one is a finding. The other is reported under it.
    #[test]
    fn the_latency_the_reroute_cost_is_filed_under_the_reroute() {
        let (engine, _) = run();
        let changed = engine
            .issues()
            .iter()
            .find(|i| i.rule == "path.changed")
            .expect("the path change should be a finding");
        let spike = engine
            .issues()
            .iter()
            .find(|i| i.rule == "path.rtt_spike")
            .expect("the added latency should still be detected");

        assert_eq!(spike.suppressed_by.as_deref(), Some(changed.id.as_str()));
        assert!(changed.consequences.contains(&spike.id));
        // And its evidence survives — suppression hides a finding from the
        // list, it does not throw the measurement away.
        assert!(spike.evidence.iter().any(|e| e.metric == "path.rtt"));
    }

    #[test]
    fn onsets_land_where_the_story_says() {
        let (engine, _) = run();
        let dns = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(dns.since, "2026-09-03 06:48:10");

        let sock = engine
            .issues()
            .iter()
            .find(|i| i.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_eq!(sock.since, "2026-09-03 06:49:31");
    }

    #[test]
    fn the_dns_issue_is_high_because_of_its_multiple_not_its_absolute_value() {
        let (engine, _) = run();
        let dns = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(dns.severity, Severity::High);
        assert_eq!(dns.evidence[0].multiple_label().unwrap(), "33× baseline");
    }

    #[test]
    fn the_uplink_being_healthy_is_what_makes_the_socket_the_receivers_fault() {
        let (engine, _) = run();
        let sock = engine
            .issues()
            .iter()
            .find(|i| i.rule == "tcp.bufferbloat_remote")
            .unwrap();
        let top = sock.top_cause().unwrap();
        assert!(top.label.contains("receiver"), "{}", top.label);
        assert!(top
            .checks
            .iter()
            .any(|c| c.name.contains("link-level") && c.passed == Some(true)));
    }

    /// The gateway and link are healthy throughout, so no finding may be
    /// filed as a consequence of one. (The reroute does suppress its own
    /// latency spike — see the test above; that edge is the point.)
    #[test]
    fn a_healthy_gateway_explains_nothing() {
        let (engine, _) = run();
        for issue in engine.issues() {
            let Some(root_id) = &issue.suppressed_by else {
                continue;
            };
            let root = engine.get(root_id).expect("suppressing issue exists");
            assert!(
                !root.rule.starts_with("gateway.") && !root.rule.starts_with("link."),
                "{} was blamed on {} while the gateway was healthy",
                issue.rule,
                root.rule
            );
        }
    }

    #[test]
    fn applying_the_fix_lets_the_issue_close_itself() {
        use super::super::engine::{Engine, FixedClock};
        let clock = std::sync::Arc::new(FixedClock::at(WINDOW_START));
        let mut engine = Engine::new(Box::new(ClockRef(clock.clone())));
        let base = baselines();

        // Run into the incident.
        for t in 0..=300 {
            engine.observe(&observations_with(t, false), &base);
            clock.advance_secs(1);
        }
        assert!(engine
            .primary()
            .iter()
            .any(|i| i.rule == "dns.slow_resolver"));

        let id = engine
            .primary()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap()
            .id
            .clone();
        engine.record_applied(
            &id,
            '1',
            crate::diagnose::issue::Applied::Yes {
                at: NOW.into(),
                before: RESOLVER.into(),
                after: ALT_RESOLVER.into(),
            },
        );

        // The operator switches resolver. dns.slow_resolver verifies on
        // p50 < 5ms held for 60s, so it must survive a while and then close.
        for t in 301..=340 {
            engine.observe(&observations_with(t, true), &base);
            clock.advance_secs(1);
        }
        assert!(
            engine
                .primary()
                .iter()
                .any(|i| i.rule == "dns.slow_resolver"),
            "40s of quiet is not the 60s the rule asks for"
        );

        for t in 341..=380 {
            engine.observe(&observations_with(t, true), &base);
            clock.advance_secs(1);
        }
        assert!(
            !engine
                .primary()
                .iter()
                .any(|i| i.rule == "dns.slow_resolver"),
            "once verify has held for its window the issue closes itself"
        );
        let closed = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert!(matches!(
            closed.state,
            crate::diagnose::issue::IssueState::AutoClosed { .. }
        ));
    }

    /// The pinned corpus replays this episode through `observe_live_at`,
    /// which drops DNS and gateway observations with no completion time.
    /// Without health ages the corpus could not see either regress.
    #[test]
    fn fixture_episode_carries_health_ages() {
        let ep = episode();
        assert_eq!(ep.frames.len() as u64, SCENARIO_SECS + 1);
        for (t, f) in ep.frames.iter().enumerate() {
            for (probe, age) in [
                ("dns", f.ages.dns),
                ("gateway", f.ages.gateway),
                ("internet", f.ages.internet),
            ] {
                let age = age.unwrap_or_else(|| panic!("{}: no {probe} age", f.ts));
                assert_eq!(
                    age,
                    (t % 5) as f64,
                    "{}: {probe} age {age}s is off the prober's 5s grid",
                    f.ts
                );
            }
            assert_eq!(f.ages.dns_target.as_deref(), Some(RESOLVER), "{}", f.ts);
            assert_eq!(f.ages.gateway_target.as_deref(), Some(GATEWAY), "{}", f.ts);
        }
    }

    #[test]
    fn the_run_is_deterministic() {
        let a = report();
        let b = report();
        assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    }

    #[test]
    fn the_verdict_line_leads_with_the_worst_issue() {
        let (engine, base) = run();
        let line = engine.verdict(&base).line();
        assert!(line.starts_with("3 issues"), "{line}");
        assert!(line.contains("slow dns resolver"), "{line}");
        assert!(line.contains("33× baseline"), "{line}");
    }
}

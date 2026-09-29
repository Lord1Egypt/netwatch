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
//!
//! The same machinery builds the replay corpus's synthetic episodes: a
//! [`Scenario`] is a frame function and a collector [`Cadence`], and
//! [`record`] runs it through the engine and the episode recorder. The demo
//! incident is [`Scenario::incident`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::baseline::{BaselineStore, NetworkFingerprint};
use super::detectors::{
    DnsObs, GatewayObs, HopObs, IfaceObs, Observations, PathObs, SocketObs, Thresholds,
};
use super::engine::{format_ts, Clock, Engine, FixedClock, ObservationTimes, Settings};
use super::episode::{EnvProfile, Episode, Recorder, Tick};
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
        // Unknown, as in every recording made before the snapshot existed.
        config: None,
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

// ------------------------------------------------------------------ scenarios

/// Unix seconds of every scenario's first frame. Only differences between
/// frame times are ever read, and a fixed origin keeps a recording
/// independent of the timezone its `start` is read in.
const SCENARIO_UNIX_START: f64 = 1.789e9;

/// How often each collector completes, in seconds. Each frame is stamped
/// with the last completion on that grid, as the live tick is: stamping
/// every frame would count each second as a new sample. A collector left
/// `None` never completes, and the engine drops its input as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    pub interface: Option<u64>,
    pub sockets: Option<u64>,
    /// The DNS, gateway and internet probes, which complete together.
    pub health: Option<u64>,
    pub path: Option<u64>,
}

impl Cadence {
    /// The app's: interface and sockets every tick, the health prober every
    /// 5 s, a trace every 30 s.
    pub fn live() -> Self {
        Self {
            interface: Some(1),
            sockets: Some(1),
            health: Some(5),
            path: Some(30),
        }
    }

    /// The last completion on a `period`-second grid, `t` seconds in.
    fn stamp(period: Option<u64>, start: Instant, t: u64) -> Option<Instant> {
        let period = period?.max(1);
        Some(start + Duration::from_secs(t - t % period))
    }
}

/// The stretches of a scenario's story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Healthy,
    Fault,
    Clear,
}

/// The phase `t` falls in: the last one starting at or before it, so
/// `phase(t, &[(0, Healthy), (120, Fault), (300, Clear)])` is a fault from
/// 120 s to 299 s.
pub fn phase(t: u64, phases: &[(u64, Phase)]) -> Phase {
    phases
        .iter()
        .rev()
        .find(|(from, _)| *from <= t)
        .or(phases.first())
        .map(|(_, p)| *p)
        .expect("a scenario has at least one phase")
}

/// A synthetic episode: observations as a function of time, run through the
/// real engine and the real recorder by [`record`]. Every `synthetic` row of
/// the corpus manifest is one of [`scenarios`].
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// The corpus id, which names its files.
    pub id: &'static str,
    /// Local time of the first frame, `YYYY-MM-DD HH:MM:SS`.
    pub start: &'static str,
    /// Seconds from the first frame to the last; one frame a second.
    pub secs: u64,
    pub baselines: fn() -> BaselineStore,
    /// The observations `t` seconds after `start`.
    pub obs: fn(u64) -> Observations,
    pub cadence: Cadence,
    pub thresholds: Thresholds,
}

impl Scenario {
    /// The demo incident at the top of this file.
    pub fn incident() -> Self {
        Self {
            id: "fixture-scenario",
            start: WINDOW_START,
            secs: SCENARIO_SECS,
            baselines,
            obs: incident_frame,
            // The demo re-traces every second: that is what opens
            // path.changed at 06:44:04, on the third trace after the reroute.
            cadence: Cadence {
                path: Some(1),
                ..Cadence::live()
            },
            thresholds: Thresholds::default(),
        }
    }
}

fn incident_frame(t: u64) -> Observations {
    let mut obs = observations_at(t);
    for s in &mut obs.sockets {
        s.process = Some("firefox".into());
    }
    obs
}

/// Every scenario the corpus can pin, by id.
pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario::incident()]
}

/// The profile every synthetic episode carries. Detected, it held this
/// host's kernel and netwatch's version, so the same scenario recorded on
/// another machine, or after a release, made a different file.
fn synthetic_env() -> EnvProfile {
    EnvProfile {
        os: "linux".into(),
        arch: "x86_64".into(),
        kernel: None,
        netwatch_version: "synthetic".into(),
        capability: "root".into(),
        refresh_rate_ms: 1000,
    }
}

/// Run `scenario` through the real engine and recorder, one frame a second,
/// and return the episode. Two runs give byte-identical files.
///
/// The recorder starts a quiet sample on the first frame, so a scenario that
/// opens nothing still yields its frames, and one that does keeps up to 10
/// minutes of them as pre-roll, as live. Panics if the recorder ends the
/// episode before `secs`: a quiet sample lasts 15 minutes, and an incident
/// ends 10 minutes after its last issue closes.
pub fn record(scenario: &Scenario) -> Episode {
    let clock = Arc::new(FixedClock::at(scenario.start));
    let mut engine = Engine::new(Box::new(clock.clone())).with_settings(Settings {
        thresholds: scenario.thresholds,
        ..Settings::default()
    });
    let mut base = (scenario.baselines)();
    let mut rec = Recorder::new(synthetic_env(), SCENARIO_UNIX_START);
    rec.schedule_quiet_sample(SCENARIO_UNIX_START);
    let start = Instant::now() + Duration::from_secs(86_400);
    let cadence = scenario.cadence;
    for t in 0..=scenario.secs {
        let obs = (scenario.obs)(t);
        let now = start + Duration::from_secs(t);
        let mut times = ObservationTimes {
            interface: Cadence::stamp(cadence.interface, start, t),
            sockets: Cadence::stamp(cadence.sockets, start, t),
            path: Cadence::stamp(cadence.path, start, t),
            ..Default::default()
        };
        // Without health times the live engine drops the DNS and gateway
        // observations as stale, so the corpus could not see a regression in
        // either.
        let probed = Cadence::stamp(cadence.health, start, t);
        times.health.dns = probed;
        times.health.gateway = probed;
        times.health.internet = probed;
        times.health.dns_target = obs.dns.as_ref().map(|d| d.resolver.clone());
        times.health.gateway_target = obs.gateway.as_ref().and_then(|g| g.addr.clone());
        engine.observe_live_at(&obs, &base, &times, now);
        let ended = rec.record(Tick {
            at: SCENARIO_UNIX_START + t as f64,
            ts: format_ts(clock.now()),
            now,
            obs: &obs,
            times: &times,
            readings: &[],
            engine: &engine,
            baselines: &base,
            events: vec![],
        });
        assert!(
            ended.is_none(),
            "{}: the recorder ended the episode {t}s in, before the scenario's {}s",
            scenario.id,
            scenario.secs
        );
        base.set_gate_sigma(engine.settings().thresholds.sigma_k);
        clock.advance_secs(1);
    }
    let mut ep = rec
        .flush(&engine, &format_ts(clock.now()))
        .expect("a quiet sample starts on the first frame");
    ep.id = scenario.id.into();
    ep
}

/// A deterministic recorded episode of the demo incident. The corpus pins
/// it as `fixture-scenario`: same frames, same decisions, every time.
pub fn episode() -> Episode {
    record(&Scenario::incident())
}

/// The synthetic corpus episode `id`, rebuilt. `None` for an id no scenario
/// here builds; `diagnose corpus` refuses a manifest row naming one.
pub fn synthetic(id: &str) -> Option<Episode> {
    scenarios()
        .into_iter()
        .find(|s| s.id == id)
        .map(|s| record(&s))
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

    fn gzip(episode: &Episode) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        serde_json::to_writer(&mut gz, episode).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn record_is_deterministic() {
        let scenario = Scenario::incident();
        assert!(
            gzip(&record(&scenario)) == gzip(&record(&scenario)),
            "two recordings of one scenario differ"
        );
    }

    /// `Err` unless the pinned corpus episode `id` is what `rebuilt` holds:
    /// the frames the corpus replays, the settings and the profile. Issue
    /// snapshots are left out; they are the engine's output, which the
    /// pinned decisions already cover.
    fn is_pinned(id: &str, rebuilt: &Episode) -> Result<(), String> {
        use crate::diagnose::episode::{load, CORPUS_DIR};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(CORPUS_DIR)
            .join(format!("{id}.json.gz"));
        let mut pinned = load(&path).map_err(|e| format!("{id}: {}: {e}", path.display()))?;
        // Through JSON, as the pinned copy went, so floats parse alike.
        let mut rebuilt: Episode =
            serde_json::from_str(&serde_json::to_string(rebuilt).unwrap()).unwrap();
        pinned.issues.clear();
        rebuilt.issues.clear();
        if rebuilt == pinned {
            return Ok(());
        }
        Err(format!(
            "{id}: its scenario no longer records the pinned episode; if that is intended, \
             run `cargo run -- diagnose corpus --only {id}` and review the diff"
        ))
    }

    /// The pinned `fixture-scenario` is what [`Scenario::incident`] records.
    #[test]
    fn the_incident_episode_is_unchanged_by_the_refactor() {
        is_pinned("fixture-scenario", &episode()).unwrap();
    }

    /// The replay test holds a pinned episode only to itself, so a scenario
    /// renamed, removed or edited without regenerating still passed it, and
    /// the next `diagnose corpus` failed on that row or quietly rewrote it.
    #[test]
    fn every_synthetic_corpus_entry_is_what_its_scenario_records() {
        use crate::diagnose::episode::{CorpusKind, Manifest, CORPUS_DIR};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR);
        let manifest = Manifest::load(&dir).expect("corpus manifest");
        let failures: Vec<String> = manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == CorpusKind::Synthetic)
            .filter_map(|entry| match synthetic(&entry.id) {
                Some(rebuilt) => is_pinned(&entry.id, &rebuilt).err(),
                None => Some(format!("{}: no scenario in fixture.rs builds it", entry.id)),
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// What a new corpus scenario costs: a frame function and a `Scenario`.
    /// The gateway and everything past it stop answering for three minutes.
    fn gateway_outage(t: u64) -> Observations {
        use Phase::*;
        let mut obs = observations_at(0);
        if phase(t, &[(0, Healthy), (120, Fault), (300, Clear)]) == Fault {
            obs.gateway = Some(GatewayObs {
                rtt_ms: None,
                loss_pct: 100.0,
                arp_ok: Some(false),
                icmp_ok: false,
                internet_reachable: Some(false),
                ..healthy_gateway()
            });
        }
        obs
    }

    #[test]
    fn a_new_scenario_records_an_open_and_a_close() {
        let ep = record(&Scenario {
            id: "gateway-outage",
            start: WINDOW_START,
            secs: 600,
            baselines,
            obs: gateway_outage,
            cadence: Cadence::live(),
            thresholds: Thresholds::default(),
        });
        // A quiet sample from the first frame, so the pre-roll is all there.
        assert_eq!(ep.frames.len(), 601);
        let (decisions, report) = crate::diagnose::episode::CanonicalDecisions::of(&ep);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        let spans: Vec<_> = decisions
            .issues
            .iter()
            .map(|s| (s.key.as_str(), s.close_reason.as_deref()))
            .collect();
        assert_eq!(
            spans,
            vec![("gateway.unreachable|host", Some("auto-closed"))],
            "{:#?}",
            decisions.issues
        );
    }

    #[test]
    fn a_scenario_that_opens_nothing_still_records_its_frames() {
        let ep = record(&Scenario {
            id: "quiet",
            // Before the reroute, and with the resolver still fast.
            obs: |_| observations_at(0),
            secs: 60,
            cadence: Cadence::live(),
            ..Scenario::incident()
        });
        assert_eq!(ep.frames.len(), 61);
        assert!(ep.issue_keys().is_empty(), "{:?}", ep.issue_keys());
    }

    #[test]
    fn a_phase_runs_from_its_start_to_the_next() {
        use Phase::*;
        let story = [(0, Healthy), (120, Fault), (300, Clear)];
        assert_eq!(phase(0, &story), Healthy);
        assert_eq!(phase(119, &story), Healthy);
        assert_eq!(phase(120, &story), Fault);
        assert_eq!(phase(299, &story), Fault);
        assert_eq!(phase(300, &story), Clear);
        assert_eq!(phase(10_000, &story), Clear);
    }

    #[test]
    fn live_cadence_stamps_each_collector_on_its_own_grid() {
        let start = Instant::now();
        let c = Cadence::live();
        let at =
            |period, t| Cadence::stamp(period, start, t).map(|i: Instant| (i - start).as_secs());
        assert_eq!(at(c.interface, 37), Some(37));
        assert_eq!(at(c.sockets, 37), Some(37));
        assert_eq!(at(c.health, 37), Some(35));
        assert_eq!(at(c.path, 37), Some(30));
        assert_eq!(at(None, 37), None);
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

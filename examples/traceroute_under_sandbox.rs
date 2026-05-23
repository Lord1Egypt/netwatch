//! Verify native UDP+TTL traceroute survives the sandbox.
//!
//! The v0.17.x+ sandbox sets NO_NEW_PRIVS via Landlock, which makes
//! the kernel ignore the setcap on /usr/bin/traceroute — so the
//! subprocess fallback returned EPERM under sandbox. The native path
//! in `src/collectors/traceroute.rs` opens a plain UDP socket, enables
//! IP_RECVERR, and reads ICMP Time Exceeded / Port Unreachable from
//! the error queue — no capabilities required.
//!
//! Linux-only: IP_RECVERR + MSG_ERRQUEUE are Linux extensions.

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("traceroute_under_sandbox is Linux-only; no-op on this platform.");
}

#[cfg(target_os = "linux")]
fn main() {
    use netwatch::collectors::traceroute::{TracerouteRunner, TracerouteStatus};
    use netwatch::config::NetwatchConfig;
    use netwatch::sandbox::{self, Mode, SandboxPaths};

    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "192.168.0.54".to_string());

    println!("target = {target}");

    let cfg = NetwatchConfig::default();
    let paths = SandboxPaths::from_config(&cfg);
    let report = sandbox::apply(Mode::BestEffort, &paths);
    println!("sandbox summary = {}", report.summary());

    let runner = TracerouteRunner::new();
    runner.run(&target);

    // run() spawns a thread; wait up to 60 s for Done/Error.
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let r = runner.result.lock().unwrap();
        match &r.status {
            TracerouteStatus::Done => {
                println!("\nhops:");
                for hop in &r.hops {
                    let rtt_summary: Vec<String> = hop
                        .rtt_ms
                        .iter()
                        .map(|r| {
                            r.map(|v| format!("{v:.2} ms"))
                                .unwrap_or_else(|| "*".into())
                        })
                        .collect();
                    println!(
                        "  {:>2}  {:<16}  {}",
                        hop.hop_number,
                        hop.ip.as_deref().unwrap_or("*"),
                        rtt_summary.join("  "),
                    );
                }
                if r.hops.is_empty() {
                    eprintln!("FAIL no hops returned");
                    std::process::exit(1);
                }
                if r.hops.iter().all(|h| h.ip.is_none()) {
                    eprintln!("FAIL every hop timed out — native path returned no addresses");
                    std::process::exit(1);
                }
                println!("\ntraceroute_under_sandbox: ok");
                return;
            }
            TracerouteStatus::Error(e) => {
                eprintln!("FAIL traceroute error: {e}");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    eprintln!("FAIL traceroute didn't complete within 60 s");
    std::process::exit(1);
}

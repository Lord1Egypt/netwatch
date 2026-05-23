use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub rtt_ms: Vec<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerouteStatus {
    Idle,
    Running,
    Done,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub target: String,
    pub status: TracerouteStatus,
    pub hops: Vec<TracerouteHop>,
}

pub struct TracerouteRunner {
    pub result: Arc<Mutex<TracerouteResult>>,
}

impl Default for TracerouteRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl TracerouteRunner {
    pub fn new() -> Self {
        Self {
            result: Arc::new(Mutex::new(TracerouteResult {
                target: String::new(),
                status: TracerouteStatus::Idle,
                hops: Vec::new(),
            })),
        }
    }

    pub fn run(&self, target: &str) {
        {
            let mut r = self.result.lock().unwrap();
            // Don't start if already running
            if r.status == TracerouteStatus::Running {
                return;
            }
            r.target = target.to_string();
            r.status = TracerouteStatus::Running;
            r.hops.clear();
        }

        let result = Arc::clone(&self.result);
        let target = target.to_string();
        thread::spawn(move || match run_traceroute(&target) {
            Ok(hops) => {
                let mut r = result.lock().unwrap();
                r.hops = hops;
                r.status = TracerouteStatus::Done;
            }
            Err(e) => {
                let mut r = result.lock().unwrap();
                r.status = TracerouteStatus::Error(e);
            }
        });
    }

    pub fn clear(&self) {
        let mut r = self.result.lock().unwrap();
        r.target.clear();
        r.status = TracerouteStatus::Idle;
        r.hops.clear();
    }
}

fn run_traceroute(target: &str) -> Result<Vec<TracerouteHop>, String> {
    // Prefer native UDP+TTL traceroute on Linux — works under the
    // sandbox because Landlock sets NO_NEW_PRIVS, which makes the
    // kernel ignore the setcap on /usr/bin/traceroute. The native
    // path uses IP_RECVERR (Linux-only) to receive ICMP Time Exceeded
    // / Port Unreachable from intermediate hops and the destination
    // respectively, with no capability requirement.
    //
    // macOS lacks IP_RECVERR / MSG_ERRQUEUE in its BSD sockets API,
    // so the subprocess path is preserved there (and macOS has no
    // sandbox today, so the setcap issue doesn't bite).
    #[cfg(target_os = "linux")]
    if let Some(hops) = run_traceroute_native(target) {
        return Ok(hops);
    }

    run_traceroute_subprocess(target)
}

#[cfg(target_os = "linux")]
fn run_traceroute_native(target: &str) -> Option<Vec<TracerouteHop>> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        recvmsg, sendto, setsockopt, socket,
        sockopt::{Ipv4RecvErr, Ipv4Ttl},
        AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
    };
    use std::io::IoSliceMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::Instant;

    let dst_v4: Ipv4Addr = match target.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => v,
        // IPv6 path needs Ipv6RecvErr + a separate sockopt for hoplimit;
        // not implemented here. Falls back to the subprocess.
        IpAddr::V6(_) => return None,
    };

    // SOCK_DGRAM UDP needs no capabilities. We never bind — the kernel
    // assigns an ephemeral source port automatically.
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .ok()?;

    // Kernel queues ICMP errors (Time Exceeded, Dest Unreach) with
    // the originating router's address in a SOCK_EXTENDED_ERR cmsg.
    // Critical: SO_RCVTIMEO does NOT apply to MSG_ERRQUEUE reads —
    // recvmsg returns EAGAIN immediately if the queue is empty. We
    // use poll(POLLERR) below to wait for the queue to become readable.
    setsockopt(&sock, Ipv4RecvErr, &true).ok()?;

    let fd = sock.as_raw_fd();

    const PROBES: usize = 3;
    const MAX_HOPS: u8 = 30;
    // Classic Van Jacobson traceroute base port: 33434. We bump by
    // hop_number * PROBES + probe so each datagram has a unique
    // destination port, matching the wire-level behaviour of `traceroute`.
    const BASE_PORT: u16 = 33434;

    let mut hops: Vec<TracerouteHop> = Vec::new();
    let mut target_reached = false;

    for ttl in 1..=MAX_HOPS {
        setsockopt(&sock, Ipv4Ttl, &(ttl as i32)).ok()?;

        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(PROBES);
        let mut hop_ip: Option<String> = None;

        for probe in 0..PROBES {
            let port = BASE_PORT
                .wrapping_add((ttl as u16).wrapping_mul(PROBES as u16))
                .wrapping_add(probe as u16);
            let dst: SockaddrIn = SocketAddrV4::new(dst_v4, port).into();
            let payload = [0u8; 32];

            let send_t = Instant::now();
            if sendto(fd, &payload, &dst, MsgFlags::empty()).is_err() {
                rtts.push(None);
                continue;
            }

            // Wait up to 1 s for the kernel to queue an ICMP error
            // on this socket. `MSG_ERRQUEUE` reads are not affected
            // by SO_RCVTIMEO and would return EAGAIN immediately if
            // we called recvmsg directly, so we gate the read on
            // poll(POLLERR) instead.
            let pfd = PollFd::new(sock.as_fd(), PollFlags::POLLERR);
            let mut fds = [pfd];
            let ready = match poll(
                &mut fds,
                PollTimeout::try_from(1000i32).unwrap_or(PollTimeout::NONE),
            ) {
                Ok(n) => n > 0,
                Err(_) => false,
            };
            if !ready {
                rtts.push(None);
                continue;
            }

            // Read the error queue. The cmsg carries
            // (sock_extended_err, sockaddr_in) where sockaddr_in is the
            // address of the router that sent the ICMP error.
            let mut cmsg_buf =
                nix::cmsg_space!(nix::libc::sock_extended_err, nix::libc::sockaddr_in);
            let mut data = [0u8; 128];
            let mut iov = [IoSliceMut::new(&mut data)];

            match recvmsg::<SockaddrIn>(
                fd,
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(msg) => {
                    let rtt_ms = send_t.elapsed().as_secs_f64() * 1000.0;
                    let mut got_useful = false;
                    for cmsg in msg.cmsgs().ok()? {
                        if let ControlMessageOwned::Ipv4RecvErr(err, src) = cmsg {
                            // Only count ICMP-origin errors. SO_EE_ORIGIN_ICMP = 2.
                            if err.ee_origin != 2 {
                                continue;
                            }
                            if let Some(addr) = src {
                                let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                                hop_ip.get_or_insert_with(|| ip.to_string());
                            }
                            // ee_type 11 = ICMP_TIME_EXCEEDED (intermediate hop).
                            // ee_type 3  = ICMP_DEST_UNREACH; code 3 = port unreachable
                            //   (we reached the target — its UDP port is closed).
                            if err.ee_type == 11 || (err.ee_type == 3 && err.ee_code == 3) {
                                got_useful = true;
                            }
                            if err.ee_type == 3 && err.ee_code == 3 {
                                target_reached = true;
                            }
                        }
                    }
                    rtts.push(if got_useful { Some(rtt_ms) } else { None });
                }
                Err(_) => {
                    // EAGAIN / EWOULDBLOCK: hop timed out → `*`.
                    rtts.push(None);
                }
            }
        }

        hops.push(TracerouteHop {
            hop_number: ttl,
            host: None,
            ip: hop_ip,
            rtt_ms: rtts,
        });

        if target_reached {
            break;
        }
    }

    Some(hops)
}

/// Subprocess fallback for Windows and for IPv6 targets (the native
/// path is IPv4-only today). Under the v0.17.x+ Linux sandbox this
/// path is broken because Landlock sets NO_NEW_PRIVS and the setcap
/// on /usr/bin/traceroute is ignored on exec — the native path above
/// is what makes traceroute work under sandbox.
fn run_traceroute_subprocess(target: &str) -> Result<Vec<TracerouteHop>, String> {
    #[cfg(target_os = "windows")]
    let output = Command::new("tracert")
        .args(["-d", "-w", "1000", "-h", "30", target])
        .output()
        .map_err(|e| spawn_error("tracert", e))?;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("traceroute")
        .args(["-n", "-q", "3", "-w", "1", "-m", "30", target])
        .output()
        .map_err(|e| spawn_error("traceroute", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            return Err(stderr.trim().to_string());
        }
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_traceroute_output(&text))
}

/// Format a `Command::output()` failure with an install hint when the
/// binary isn't on PATH. The generic `std::io::Error` Display for
/// `NotFound` is `"No such file or directory"` which doesn't help users
/// figure out what to install — substitute the package name explicitly.
fn spawn_error(binary: &str, err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        let hint = match binary {
            "traceroute" => "install with `sudo apt install traceroute` (Debian/Ubuntu), `sudo dnf install traceroute` (Fedora), or `brew install traceroute` (macOS)",
            "tracert" => "tracert ships with Windows; PATH or %SystemRoot%\\System32 may be misconfigured",
            _ => "binary not found on PATH",
        };
        format!("`{binary}` not installed — {hint}")
    } else {
        format!("Failed to run {binary}: {err}")
    }
}

fn parse_traceroute_output(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip header lines (e.g., "traceroute to 8.8.8.8 ...")
        let first_token = trimmed.split_whitespace().next().unwrap_or("");
        let hop_number: u8 = match first_token.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let rest = &trimmed[first_token.len()..];
        let tokens: Vec<&str> = rest.split_whitespace().collect();

        if tokens.is_empty() {
            continue;
        }

        // All stars = no response
        if tokens.iter().all(|t| *t == "*") {
            hops.push(TracerouteHop {
                hop_number,
                host: None,
                ip: None,
                rtt_ms: vec![None; 3],
            });
            continue;
        }

        // With -n flag, output is: hop_number  IP  rtt1 ms  rtt2 ms  rtt3 ms
        // or:  hop_number  IP  rtt1 ms  *  rtt3 ms
        let mut ip: Option<String> = None;
        let mut host: Option<String> = None;
        let mut rtts: Vec<Option<f64>> = Vec::new();

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i];

            if tok == "*" {
                rtts.push(None);
                i += 1;
            } else if tok == "ms" {
                // skip, already consumed the number before it
                i += 1;
            } else if let Ok(val) = tok.parse::<f64>() {
                rtts.push(Some(val));
                // Skip trailing "ms" if present
                if i + 1 < tokens.len() && tokens[i + 1] == "ms" {
                    i += 2;
                } else {
                    i += 1;
                }
            } else if ip.is_none() {
                // Could be IP or hostname
                // Check if it looks like an IP (contains dots or colons for IPv6)
                if tok.contains('.') || tok.contains(':') {
                    // Might be "IP" or "(IP)"
                    let cleaned = tok.trim_start_matches('(').trim_end_matches(')');
                    ip = Some(cleaned.to_string());
                } else {
                    host = Some(tok.to_string());
                }
                i += 1;
            } else if tok.starts_with('(') && tok.ends_with(')') {
                // Hostname resolution case: hostname (IP)
                let cleaned = tok.trim_start_matches('(').trim_end_matches(')');
                ip = Some(cleaned.to_string());
                i += 1;
            } else {
                i += 1;
            }
        }

        hops.push(TracerouteHop {
            hop_number,
            host,
            ip,
            rtt_ms: rtts,
        });
    }

    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceroute_basic() {
        let output = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms
 2  10.0.0.1  5.123 ms  5.456 ms  5.789 ms
 3  * * *
 4  8.8.8.8  12.345 ms  12.456 ms  12.789 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0].hop_number, 1);
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[2].ip, None);
        assert!(hops[2].rtt_ms.iter().all(|r| r.is_none()));
        assert_eq!(hops[3].ip.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn test_parse_traceroute_partial_stars() {
        let output = "\
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max
 1  192.168.1.1  1.0 ms  *  1.5 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].rtt_ms.len(), 3);
        assert!(hops[0].rtt_ms[0].is_some());
        assert!(hops[0].rtt_ms[1].is_none());
        assert!(hops[0].rtt_ms[2].is_some());
    }
}

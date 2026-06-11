//! Live end-to-end verification of TLS 1.2 Application-Data decryption.
//!
//! Sibling of `tls_decrypt_live.rs` (the 1.3 harness). Drives the *real*
//! capture path — `PacketCollector` + keylog watcher +
//! `StreamTracker::try_decrypt_tls_record` — against actual wire traffic,
//! then proves we recover plaintext from a TLS **1.2** flow.
//!
//! Flow:
//!   1. Start the keylog watcher on a fresh temp SSLKEYLOGFILE.
//!   2. Start live pcap capture on the default interface (BPF: tcp port 443).
//!   3. Spawn an OpenSSL-backed Python client pinned to TLS 1.2 with an AEAD
//!      cipher (so it negotiates one of our supported GCM/ChaCha suites and
//!      writes a CLIENT_RANDOM master-secret line to the keylog), which then
//!      sends recognizable `GET / HTTP/1.1` requests over a keep-alive.
//!   4. Scan captured packets for `decrypted_plaintext` containing that GET.
//!
//! Requires pcap access (member of `access_bpf` group, or run as root) and
//! a Python 3.8+ linked against OpenSSL (honors the `SSLKEYLOGFILE` env var).
//!
//! Run:  cargo run --example tls12_decrypt_live -- [host] [interface]

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use netwatch::collectors::packets::PacketCollector;

fn main() {
    // Emit the decryptor's own trace logs when RUST_LOG is set, e.g.
    //   RUST_LOG=netwatch::dpi::tls_decrypt=trace
    // so you can see the literal "decrypted record (1.2)" branch fire and
    // distinguish it from the TLS 1.3 path.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".into());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "en0".into());

    let keylog: PathBuf =
        std::env::temp_dir().join(format!("netwatch-keylog12-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&keylog);
    std::fs::File::create(&keylog).expect("create keylog file");

    println!("keylog:    {}", keylog.display());
    println!("interface: {iface}");
    println!("host:      {host}\n");

    let mut collector = PacketCollector::new();
    collector.configure_tls_keylog(Some(keylog.clone()));
    collector.start_capture(&iface, Some("tcp port 443"));

    thread::sleep(Duration::from_millis(800));
    if let Some(err) = collector.error.lock().unwrap().clone() {
        eprintln!("capture failed to start: {err}");
        std::process::exit(2);
    }
    println!("capture running, launching TLS 1.2 client...\n");

    // Cooperating client pinned to TLS 1.2 + AEAD ciphers. OpenSSL-backed
    // Python writes the NSS keylog (a CLIENT_RANDOM line for 1.2) from the
    // SSLKEYLOGFILE env var.
    let py = r#"
import ssl, socket, time, sys, os
host = sys.argv[1]
ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
# Restrict to AEAD suites so we never negotiate a CBC suite (out of scope).
# Overridable via SSLCIPHERS to probe specific AEAD paths (AES256-GCM=SHA384
# PRF, CHACHA20=no explicit nonce).
ctx.set_ciphers(os.environ.get("SSLCIPHERS", "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM"))
raw = socket.create_connection((host, 443), timeout=10)
s = ctx.wrap_socket(raw, server_hostname=host)
print("  [py] handshake ok:", s.version(), s.cipher()[0], flush=True)
assert s.version() == "TLSv1.2", "expected TLS 1.2, got %s" % s.version()
s.settimeout(3.0)
# No post-handshake sleep: the first request races the keylog watcher and
# will likely be missed. Keep-alive and keep sending — sequence-resync must
# lock onto the later requests once the watcher ingests the master secret.
n = int(os.environ.get("REQUESTS", "6"))
sent = 0
for i in range(n):
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: netwatch-tls12-verify\r\n\r\n" % host).encode()
    try:
        s.sendall(req); sent += 1
        s.recv(16384)
    except Exception:
        break
    time.sleep(0.2)
print("  [py] sent", sent, "keep-alive requests over ~%.1fs" % (sent*0.2), flush=True)
try: s.close()
except Exception: pass
"#;

    let status = Command::new("python3")
        .arg("-c")
        .arg(py)
        .arg(&host)
        .env("SSLKEYLOGFILE", &keylog)
        .status()
        .expect("spawn python3");
    if !status.success() {
        eprintln!("python client failed");
        std::process::exit(2);
    }

    thread::sleep(Duration::from_millis(800));

    let keylog_lines = std::fs::read_to_string(&keylog)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    println!("\nkeylog lines ingested by client: {keylog_lines}");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut decrypted_count;
    let mut found_get = false;
    let mut samples: Vec<String> = Vec::new();
    loop {
        {
            let pkts = collector.get_packets();
            decrypted_count = 0;
            samples.clear();
            for p in pkts.iter() {
                if let Some(pt) = &p.decrypted_plaintext {
                    decrypted_count += 1;
                    let preview: String = pt
                        .iter()
                        .take(64)
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    if samples.len() < 6 {
                        samples.push(format!(
                            "  {}:{} -> {}:{}  [{} B] {:?}",
                            p.src_ip,
                            p.src_port.unwrap_or(0),
                            p.dst_ip,
                            p.dst_port.unwrap_or(0),
                            pt.len(),
                            preview
                        ));
                    }
                    const NEEDLE: &[u8] = b"GET / HTTP/1.1";
                    if pt.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
                        found_get = true;
                    }
                }
            }
        }
        if found_get || Instant::now() > deadline {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    collector.stop_capture();
    let _ = std::io::stdout().flush();
    let _ = std::fs::remove_file(&keylog);

    println!("\n=== RESULT ===");
    println!("decrypted application-data records captured: {decrypted_count}");
    for s in &samples {
        println!("{s}");
    }
    if found_get {
        println!(
            "\n✅ VERIFIED: recovered our plaintext \"GET / HTTP/1.1\" from a live TLS 1.2 flow."
        );
    } else if decrypted_count > 0 {
        println!("\n⚠️  Decrypted {decrypted_count} record(s) but did not match the exact GET line (may be a coalesced/segmented record). Decryption pipeline is working.");
    } else {
        println!("\n❌ No records decrypted. Check: keylog written (CLIENT_RANDOM line)? client used OpenSSL? TLS 1.2 + AEAD negotiated? capture on the right interface? watcher race?");
        std::process::exit(1);
    }
}

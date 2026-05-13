//! File-only structured logging.
//!
//! The TUI owns stdout/stderr in alternate-screen mode, so the subscriber
//! installed here MUST write only to a file — anything that lands on the
//! terminal corrupts the alternate screen. Logs go to a daily-rotated file
//! under the user's cache dir:
//!
//! - Linux:   `~/.cache/netwatch/netwatch.log.YYYY-MM-DD`
//! - macOS:   `~/Library/Caches/netwatch/netwatch.log.YYYY-MM-DD`
//! - Windows: `%LOCALAPPDATA%\netwatch\netwatch.log.YYYY-MM-DD`
//!
//! Level defaults to WARN (quiet — captures real failures, not chatter).
//! Override via `RUST_LOG`, e.g. `RUST_LOG=netwatch=debug` when reproducing
//! a stuck resolver, a pcap startup failure, or a remote-stream issue.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Install the global subscriber. The returned `WorkerGuard` must be held for
/// the lifetime of the program — when it drops, the non-blocking writer's
/// background thread flushes and exits, so logs queued near shutdown can be
/// lost otherwise.
///
/// Returns `None` (silently) if we can't determine a cache dir or create the
/// log directory. The macros become no-ops in that case; the app keeps
/// running. Logging is best-effort diagnostic plumbing, never load-bearing.
pub fn init() -> Option<WorkerGuard> {
    let log_dir = log_dir()?;
    if std::fs::create_dir_all(&log_dir).is_err() {
        return None;
    }
    let file_appender = rolling::daily(&log_dir, "netwatch.log");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,netwatch=warn"));

    let layer = fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    // `try_init` so tests and embedded uses that install their own subscriber
    // don't panic; the first installer wins.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();

    Some(guard)
}

pub fn log_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|c| c.join("netwatch"))
}

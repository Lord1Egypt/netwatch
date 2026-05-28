//! Cross-platform clipboard write via platform tools — `pbcopy` on
//! macOS, `wl-copy` / `xclip` / `xsel` on Linux, `clip` on Windows.
//!
//! Avoids a heavyweight clipboard crate dependency at the cost of
//! requiring the platform tool to be installed (always on macOS and
//! Windows; usually needs `apt install xclip` or equivalent on Linux).
//! Errors are reported back to the caller so the UI can surface a
//! useful message rather than failing silently.

use std::io::{self, Write};
use std::process::{Command, Stdio};

/// Write `text` to the system clipboard. Returns `Ok(tool_name)` on
/// success so the UI can confirm which underlying tool was used (e.g.
/// "Copied to clipboard via pbcopy"); returns a descriptive error
/// when no platform tool is available or invocation failed.
pub fn copy(text: &str) -> io::Result<&'static str> {
    #[cfg(target_os = "macos")]
    {
        run("pbcopy", &[], text)?;
        return Ok("pbcopy");
    }

    #[cfg(target_os = "linux")]
    {
        // Wayland first, then X11 fallbacks. Stops at the first tool
        // that exists on the system — doesn't try every tool if one
        // is missing.
        let candidates: &[(&str, &[&str])] = &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ];
        for (cmd, args) in candidates {
            if which(cmd) {
                run(cmd, args, text)?;
                // Return a static str — match on cmd to pick the right
                // one (we can't return the &str borrowed from the loop
                // because the iteration ends).
                return Ok(match *cmd {
                    "wl-copy" => "wl-copy",
                    "xclip" => "xclip",
                    "xsel" => "xsel",
                    _ => "clipboard",
                });
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no clipboard tool found (install wl-clipboard, xclip, or xsel)",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        run("clip", &[], text)?;
        return Ok("clip");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = text;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "clipboard not supported on this platform",
        ))
    }
}

fn run(cmd: &str, args: &[&str], text: &str) -> io::Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to spawn {cmd}: {e} (is it installed?)"),
            )
        })?;
    // `take()` then drop the handle after write so the child sees EOF
    // and exits — otherwise wait() would block forever on tools that
    // read to EOF (which is all of them).
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other(format!("{cmd}: stdin not captured")))?;
        stdin.write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("{cmd} exited with {status}")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn which(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

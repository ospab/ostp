//! `ostp start | stop | restart | status | log`: the installed service.
//!
//! On Linux the service is the systemd unit `ostp` written by `ostp setup`; it
//! runs whatever mode the config is in. Windows and macOS have no service: the
//! tunnel runs from the app or from `ostp` in a terminal, so there only `status`
//! and `log` mean something.

use anyhow::{bail, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::manage_cmd::{journal_tail, service_active, systemctl, UNIT};

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

/// How long a started service has to stay up before it counts as running:
/// a bad config makes it exit within a second, then systemd restarts it after 5.
const SETTLE: Duration = Duration::from_secs(3);

fn has_systemd_unit() -> bool {
    cfg!(target_os = "linux")
        && (Path::new(UNIT).exists() || Path::new("/lib/systemd/system/ostp.service").exists())
}

fn require_unit() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!(
            "there is no OSTP service on this system. Start the tunnel from the OSTP app, \
             or run `ostp` in a terminal and stop it with Ctrl+C"
        );
    }
    if !has_systemd_unit() {
        bail!("the ostp service is not registered. Run `sudo ostp setup` to register it");
    }
    Ok(())
}

pub fn run(action: Action) -> Result<()> {
    require_unit()?;
    let verb = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    if matches!(action, Action::Start) && service_active() {
        println!("ostp is already running. Use `ostp restart` to restart it.");
        return Ok(());
    }
    if matches!(action, Action::Stop) && !service_active() {
        println!("ostp is not running.");
        return Ok(());
    }

    // Inherit stdio so systemctl can ask for a password through polkit and show its own errors.
    let ok = Command::new("systemctl").args([verb, "ostp"]).status().is_ok_and(|s| s.success());
    if !ok {
        bail!("systemctl {verb} ostp failed (run it with sudo?)");
    }
    if matches!(action, Action::Stop) {
        println!("ostp stopped.");
        return Ok(());
    }

    let deadline = Instant::now() + SETTLE;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if !service_active() {
            break;
        }
    }
    if service_active() {
        println!("ostp is running. Log: `ostp log -f`");
        Ok(())
    } else {
        for line in journal_tail(15) {
            eprintln!("  {line}");
        }
        bail!("ostp did not stay up; the log above says why")
    }
}

pub fn status(config: &Path) -> Result<()> {
    println!("Config:  {}", config.display());
    if has_systemd_unit() {
        let props = Command::new("systemctl")
            .args(["show", "ostp", "--property=ActiveState,SubState,ActiveEnterTimestamp,MainPID,UnitFileState,NRestarts"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let get = |key: &str| {
            props
                .lines()
                .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
                .unwrap_or("")
                .to_string()
        };
        let state = get("ActiveState");
        let line = match state.as_str() {
            "active" => format!("running since {} (pid {})", get("ActiveEnterTimestamp"), get("MainPID")),
            "activating" => "starting".to_string(),
            "failed" => "failed".to_string(),
            "" => "unknown (systemctl gave no answer)".to_string(),
            other => format!("{other} ({})", get("SubState")),
        };
        println!("Service: {line}");
        let autostart = if systemctl(&["is-enabled", "--quiet", "ostp"]) { "on" } else { "off" };
        println!("Starts at boot: {autostart}");
        let restarts = get("NRestarts");
        if !restarts.is_empty() && restarts != "0" {
            println!("Restarts after a crash: {restarts}");
        }
        let tail = journal_tail(5);
        if !tail.is_empty() {
            println!("\nLast log lines:");
            for line in tail {
                println!("  {line}");
            }
        }
    } else {
        if cfg!(target_os = "linux") {
            println!("Service: not registered (`sudo ostp setup` registers it)");
        } else {
            println!("Service: none on this system; the tunnel runs from the OSTP app or a terminal");
        }
        let path = ostp_client::logging::log_file_path();
        let tail = last_lines(&path, 5);
        if !tail.is_empty() {
            println!("\nLast lines of {}:", path.display());
            for line in tail {
                println!("  {line}");
            }
        }
    }
    Ok(())
}

pub fn log(lines: usize, follow: bool) -> Result<()> {
    if has_systemd_unit() {
        let mut cmd = Command::new("journalctl");
        cmd.args(["-u", "ostp", "-n", &lines.to_string(), "--no-pager", "-o", "short-iso"]);
        if follow {
            cmd.arg("-f");
        }
        let ok = cmd.status().is_ok_and(|s| s.success());
        if !ok {
            bail!("journalctl failed; try `sudo ostp log`");
        }
        return Ok(());
    }

    let path = ostp_client::logging::log_file_path();
    if !path.exists() {
        bail!("no log yet: {} does not exist", path.display());
    }
    for line in last_lines(&path, lines) {
        println!("{line}");
    }
    if follow {
        follow_file(&path)?;
    }
    Ok(())
}

/// The last `n` lines of a text file; reads at most the final 4 MB so a huge
/// log does not have to fit in memory.
fn last_lines(path: &Path, n: usize) -> Vec<String> {
    const MAX_READ: u64 = 4 * 1024 * 1024;
    let Ok(mut file) = std::fs::File::open(path) else { return Vec::new() };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(MAX_READ);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // cut mid-line
    }
    let from = lines.len().saturating_sub(n);
    lines[from..].iter().map(|s| s.to_string()).collect()
}

/// Prints what is appended to the file until Ctrl+C. The client trims the
/// log in place when a connection starts, so a shrinking file means start over.
fn follow_file(path: &Path) -> Result<()> {
    let mut pos = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut stdout = std::io::stdout();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let len = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if len < pos {
            pos = 0;
        }
        if len == pos {
            continue;
        }
        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = Vec::new();
        file.take(len - pos).read_to_end(&mut buf)?;
        pos += buf.len() as u64;
        stdout.write_all(&buf)?;
        stdout.flush()?;
    }
}

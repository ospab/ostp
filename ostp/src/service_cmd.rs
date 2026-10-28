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

// The one place that knows the unit: its path and text, systemctl, the journal.

/// Where `ostp setup` writes the unit.
pub(crate) const UNIT: &str = "/etc/systemd/system/ostp.service";
/// Where a distribution package would put it.
const PACKAGED_UNIT: &str = "/lib/systemd/system/ostp.service";

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

/// How long a started service has to stay up before it counts as running:
/// a bad config makes it exit within a second, then systemd restarts it after 5.
const SETTLE: Duration = Duration::from_secs(3);

/// Whether a unit file exists, on any OS.
pub(crate) fn unit_registered() -> bool {
    Path::new(UNIT).exists() || Path::new(PACKAGED_UNIT).exists()
}

fn has_systemd_unit() -> bool {
    cfg!(target_os = "linux") && unit_registered()
}

pub(crate) fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl").args(args).output().is_ok_and(|o| o.status.success())
}

/// Like `systemctl`, but with the terminal attached, so polkit can ask for a
/// password and systemctl's own messages show.
pub(crate) fn systemctl_visible(args: &[&str]) -> bool {
    Command::new("systemctl").args(args).status().is_ok_and(|s| s.success())
}

pub(crate) fn service_active() -> bool {
    systemctl(&["is-active", "--quiet", "ostp"])
}

/// `systemctl is-active` text of any unit ("active", "inactive", ...).
pub(crate) fn unit_state(unit: &str) -> Option<String> {
    let out = Command::new("systemctl").args(["is-active", unit]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

pub(crate) fn journal_tail(lines: usize) -> Vec<String> {
    Command::new("journalctl")
        .args(["-u", "ostp", "-n", &lines.to_string(), "--no-pager", "-o", "short-iso"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// The unit that runs this binary on `config_path`.
fn unit_text(config_path: &Path) -> String {
    let binary = std::env::current_exe().unwrap_or_else(|_| "/opt/ostp/ostp".into());
    let dir = binary.parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/opt/ostp".into());
    format!(
        "[Unit]\nDescription=OSTP Stealth Transport Protocol\nAfter=network.target\nWants=network-online.target\n\n\
         [Service]\nType=simple\nUser=root\nWorkingDirectory={dir}\nExecStart={} --config {}\n\
         Restart=always\nRestartSec=5\nLimitNOFILE=65535\nEnvironment=RUST_LOG=info\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        binary.display(),
        config_path.display()
    )
}

/// Writes the unit file; reloading and enabling are the caller's call.
pub(crate) fn write_unit(config_path: &Path) -> std::io::Result<()> {
    std::fs::write(UNIT, unit_text(config_path))
}

/// Stops and disables the service and removes the unit (`ostp uninstall`).
#[cfg(unix)]
pub(crate) fn remove_unit() -> Result<()> {
    for action in ["stop", "disable"] {
        let _ = Command::new("systemctl").args([action, "ostp"]).status();
    }
    let unit_path = Path::new(UNIT);
    if unit_path.exists() {
        std::fs::remove_file(unit_path)?;
        println!("[ostp] Removed {}", unit_path.display());
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Restarted {
    /// systemctl refused (no rights, no such unit).
    Failed,
    /// Restarted but not active two seconds later.
    Down,
    Up,
}

/// Restarts the service and checks it stayed up. `visible` attaches the
/// terminal to systemctl; `ostp manage` keeps stdout clean instead.
pub(crate) fn restart_and_check(visible: bool) -> Restarted {
    let ok = if visible { systemctl_visible(&["restart", "ostp"]) } else { systemctl(&["restart", "ostp"]) };
    if !ok {
        return Restarted::Failed;
    }
    std::thread::sleep(Duration::from_secs(2));
    if service_active() { Restarted::Up } else { Restarted::Down }
}

/// Applies a config change to the running service: restarts it if it is
/// running (a stopped service stays stopped), then checks it came back.
pub(crate) fn restart_service(skip: bool) {
    use colored::Colorize;
    if skip || !unit_registered() {
        println!("\n  Restart OSTP to apply this: {}", "sudo systemctl restart ostp".bold());
        return;
    }
    if !service_active() {
        println!("\n  The ostp service is not running; the change applies when it starts.");
        return;
    }
    match restart_and_check(true) {
        Restarted::Up => crate::wizard_ok("ostp restarted with the new settings"),
        Restarted::Down => {
            crate::wizard_warn("ostp did not stay up after the restart; last log lines:");
            let _ = Command::new("journalctl").args(["-u", "ostp", "-n", "15", "--no-pager"]).status();
        }
        Restarted::Failed => crate::wizard_warn("could not restart ostp; run: sudo systemctl restart ostp"),
    }
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
    if !systemctl_visible(&[verb, "ostp"]) {
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

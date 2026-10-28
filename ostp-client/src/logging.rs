use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// The one log file shared by every process (CLI, GUI, TUN helper) and subsystem.
pub const LOG_FILE_NAME: &str = "ostp.log";

/// Absolute path to the shared log file, next to the running executable.
pub fn log_file_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(LOG_FILE_NAME)))
        .unwrap_or_else(|| PathBuf::from(LOG_FILE_NAME))
}

/// True for a long-running invocation (`ostp`, `ostp connect <url>`), false for a
/// one-shot subcommand. Only the daemon trims the log at startup.
pub fn invocation_is_daemon<I: IntoIterator<Item = String>>(args: I) -> bool {
    const ONE_SHOT: &[&str] = &[
        "gk", "generate-key", "check", "init", "setup", "links", "import",
        "update", "migrate", "proxy-env", "proxy-env-clear", "uninstall",
        "cert", "sub", "panel", "dns", "overnet", "manage", "changelog", "cl", "hash-password", "hp",
        "start", "stop", "restart", "status", "log",
        "-V", "--version", "-h", "--help", "help",
    ];
    !args
        .into_iter()
        .skip(1) // program name
        .any(|a| ONE_SHOT.contains(&a.as_str()))
}

/// Appends one timestamped line to the shared log file.
pub fn append_line(msg: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file_path()) {
        let _ = writeln!(
            file,
            "[{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            msg
        );
    }
}

/// The line that opens each connection's part of `ostp.log`.
pub const CONNECTION_MARK: &str = "===== connection";

/// Call when a connection starts: drops everything before the previous
/// connection's mark and writes a new mark, so `ostp.log` holds the previous
/// connection and the current one instead of all history.
///
/// The file is cut in place rather than replaced: the processes still
/// writing to it (the GUI, a helper finishing its stop) have it open for
/// appending, and their next lines land at the new end.
pub fn begin_connection() {
    let path = log_file_path();
    if let Ok(text) = std::fs::read(&path) {
        if let Some(from) = last_mark(&text) {
            if from > 0 {
                if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
                    let _ = file.set_len(0).and_then(|_| file.write_all(&text[from..]));
                }
            }
        }
    }
    append_line(&format!("{CONNECTION_MARK} started ====="));
}

/// `ostp.log` is cut down once it passes this size...
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
/// ...to roughly this much of its end.
const KEPT_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Keeps the end of an oversized `ostp.log` and drops the rest. `begin_connection`
/// only trims when a connection starts, which a long-running server or client
/// never does again.
///
/// Cut in place for the same reason as in [`begin_connection`]: other processes
/// hold the file open for appending.
pub fn cap_log_size() {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_file_path();
    let len = match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_LOG_BYTES => m.len(),
        _ => return,
    };
    let Ok(mut file) = OpenOptions::new().read(true).write(true).open(&path) else {
        return;
    };
    // One byte before the kept part, to tell whether it starts on a line boundary.
    let mut tail = Vec::new();
    if file.seek(SeekFrom::Start(len - KEPT_LOG_BYTES - 1)).is_err()
        || file.read_to_end(&mut tail).is_err()
    {
        return;
    }
    let kept = from_line_boundary(&tail);
    let _ = file
        .set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(kept));
}

/// `buf` without its leading partial line.
fn from_line_boundary(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == b'\n') {
        Some(i) => &buf[i + 1..],
        None => &[],
    }
}

/// Offset of the line holding the last connection mark.
fn last_mark(text: &[u8]) -> Option<usize> {
    let mark = CONNECTION_MARK.as_bytes();
    let mut found = None;
    let mut line_start = 0;
    for line in text.split(|&b| b == b'\n') {
        // The mark comes after append_line's "[timestamp] ".
        if line.windows(mark.len()).any(|w| w == mark) {
            found = Some(line_start);
        }
        line_start += line.len() + 1;
    }
    found
}

pub fn setup_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            *s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.as_str()
        } else {
            "Box<dyn Any>"
        };

        let location = info.location().unwrap_or_else(|| std::panic::Location::caller());
        let backtrace = std::backtrace::Backtrace::force_capture();

        let crash_msg = format!(
            "[{}] PANIC at {}:{}\nMessage: {}\nBacktrace:\n{:?}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            location.file(),
            location.line(),
            msg,
            backtrace
        );

        eprintln!("{}", crash_msg);
        tracing::error!("{}", crash_msg);

        // Written directly: the tracing worker may already be gone.
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file_path()) {
            let _ = file.write_all(crash_msg.as_bytes());
            let _ = file.write_all(b"\n");
        }
    }));
}

/// Sets up tracing into the shared `ostp.log`. `level` is error, warn, info, debug or
/// trace; `RUST_LOG` overrides it.
///
/// `new_connection` keeps only the previous connection's log (see [`begin_connection`]).
/// It applies on Windows only; Linux servers keep their history (under systemd the
/// output also goes to the journal), but the file is capped at [`MAX_LOG_BYTES`] everywhere.
/// Only the daemon passes `true`; the GUI calls `begin_connection` itself.
pub fn init_tracing(
    level: &str,
    app_name: &str,
    version: &str,
    new_connection: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if level == "debug" || level == "trace" {
                // Dependencies stay at warn.
                EnvFilter::new(format!(
                    "warn,ostp_client={level},ostp_core={level},ostp_jni={level},ostp_gui_lib={level}"
                ))
            } else {
                EnvFilter::new(level)
            }
        });

    let path = log_file_path();

    if new_connection && cfg!(windows) {
        begin_connection();
    }
    cap_log_size();
    // Always append: several processes write this file, and a handle that
    // writes at its own offset would overwrite what the others wrote.
    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);

    if let Ok(mut file) = open_opts.open(&path) {
        // Written to the file only, so one-shot commands do not print it to the terminal.
        let _ = writeln!(
            file,
            "{} v{} | OS: {} | Arch: {} | log_level: {} | log_file: {}",
            app_name,
            version,
            std::env::consts::OS,
            std::env::consts::ARCH,
            level,
            path.display(),
        );

        let (file_writer, guard) = tracing_appender::non_blocking(file);

        // A server or client that runs for weeks keeps writing to the same file.
        let _ = std::thread::Builder::new().name("log-cap".into()).spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            cap_log_size();
        });

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_ansi(false)
            .with_writer(file_writer);

        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_writer(std::io::stderr);

        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(stderr_layer)
            .try_init();

        Some(guard)
    } else {
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_writer(std::io::stderr);
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::new(level))
            .with(stderr_layer)
            .try_init();
        eprintln!("[warn] cannot open {}; logging to stderr only", path.display());
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{from_line_boundary, last_mark};

    #[test]
    fn cap_starts_on_a_whole_line() {
        assert_eq!(from_line_boundary(b"rt of a line\nnext\nlast\n"), b"next\nlast\n");
        assert_eq!(from_line_boundary(b"\nnext\n"), b"next\n");
        assert_eq!(from_line_boundary(b"no newline"), b"");
    }

    #[test]
    fn finds_the_last_connection() {
        let log = b"old
[t] ===== connection started =====
first
[t] ===== connection started =====
second
";
        let from = last_mark(log).unwrap();
        assert!(log[from..].starts_with(b"[t] ===== connection started =====
second"));
        assert_eq!(last_mark(b"no marks
"), None);
    }
}

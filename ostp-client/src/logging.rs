use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// The single canonical log file for the whole core. Every process (CLI daemon,
/// GUI, TUN helper) and every subsystem (tracing, the core event logger, the
/// helper IPC, panics) writes here — no more per-binary / per-subsystem sprawl
/// (`ostp-cli.log` + `ostp-core.log` + `ostp-helper.log` + `ostp-crash.log`).
pub const LOG_FILE_NAME: &str = "ostp.log";

/// Absolute path to the shared log file, next to the running executable.
pub fn log_file_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(LOG_FILE_NAME)))
        .unwrap_or_else(|| PathBuf::from(LOG_FILE_NAME))
}

/// True if this invocation is the long-running daemon (a client/server run),
/// as opposed to a one-shot subcommand (`gk`, `check`, `init`, `-V`, ...).
///
/// Used to gate log trimming: only the daemon trims the log at startup, so a
/// one-shot command run while a daemon is live can never cut the daemon's log.
/// A daemon invocation is simply one that carries none of the one-shot tokens
/// (`ostp`, `ostp run`, `ostp connect <url>` → daemon; everything else → one-shot).
pub fn invocation_is_daemon<I: IntoIterator<Item = String>>(args: I) -> bool {
    const ONE_SHOT: &[&str] = &[
        "gk", "generate-key", "check", "init", "setup", "links", "import",
        "update", "migrate", "prober", "proxy-env", "proxy-env-clear",
        "uninstall", "-V", "--version", "-h", "--help", "help",
    ];
    !args
        .into_iter()
        .skip(1) // program name
        .any(|a| ONE_SHOT.contains(&a.as_str()))
}

/// Append a single timestamped line to the shared log file. Used by the manual
/// writers (core event logger, TUN helper IPC) so their output lands in the same
/// `ostp.log` as the tracing subscriber instead of a separate file.
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

        // Crashes land in the same shared log file (append — a crash must never
        // trim it, and the tracing worker may already be dead so we write direct).
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file_path()) {
            let _ = file.write_all(crash_msg.as_bytes());
            let _ = file.write_all(b"\n===================================================\n");
        }
    }));
}

/// Initialises tracing and writes to the shared `ostp.log` next to the executable.
///
/// The `level` parameter controls the minimum log level:
/// - `"error"` — only errors
/// - `"warn"`  — warnings and errors
/// - `"info"`  — informational messages (default)
/// - `"debug"` — detailed debug messages (use when `debug: true` in config)
/// - `"trace"` — all messages including very verbose internal state
///
/// The environment variable `RUST_LOG` overrides this value if set.
///
/// `new_connection`: this process starts a connection, so the log keeps only
/// the previous one before it (see [`begin_connection`]). Honoured **only on
/// Windows** — Linux servers keep their history (OS-rotated). Pass `true`
/// only from the daemon's own entrypoint; one-shot commands and child
/// processes (the TUN helper) pass `false`. The GUI passes `false` and calls
/// `begin_connection` on each connect instead.
pub fn init_tracing(
    level: &str,
    app_name: &str,
    version: &str,
    new_connection: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    // RUST_LOG overrides the config-derived level
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // When debug or trace is requested, enable for all ostp crates
            if level == "debug" || level == "trace" {
                // Enable the requested level for ostp crates, but keep noisy deps at warn
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
    // Always append: several processes write this file, and a handle that
    // writes at its own offset would overwrite what the others wrote.
    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);

    if let Ok(mut file) = open_opts.open(&path) {
        // Write the startup banner directly to the log file, bypassing the
        // tracing subscriber entirely. Emitting it via tracing::info!() hits
        // BOTH layers below (file AND stderr), so every one-shot CLI command
        // (`ostp -V`, `ostp gk`, `ostp check`, ...) printed this banner to the
        // terminal on every single invocation — pure noise for anything that
        // isn't the long-running daemon. It's still genuinely useful for
        // whoever's reading the log file later, so keep it there, just not on
        // screen for commands that aren't the daemon.
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
        // Fallback: stderr only
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_writer(std::io::stderr);
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::new(level))
            .with(stderr_layer)
            .try_init();
        eprintln!("[WARN] Could not open log file at {}. Logging to stderr only.", path.display());
        None
    }
}

#[cfg(test)]
mod tests {
    use super::last_mark;

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

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

        let path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("ostp-crash.log")))
            .unwrap_or_else(|| PathBuf::from("ostp-crash.log"));

        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(crash_msg.as_bytes());
            let _ = file.write_all(b"\n===================================================\n");
        }
    }));
}

/// Initialises tracing and writes to `<app_name>.log` next to the executable.
///
/// The `level` parameter controls the minimum log level:
/// - `"error"` — only errors
/// - `"warn"`  — warnings and errors
/// - `"info"`  — informational messages (default)
/// - `"debug"` — detailed debug messages (use when `debug: true` in config)
/// - `"trace"` — all messages including very verbose internal state
///
/// The environment variable `RUST_LOG` overrides this value if set.
pub fn init_tracing(level: &str, app_name: &str, version: &str) -> Option<tracing_appender::non_blocking::WorkerGuard> {
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

    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(format!("{}.log", app_name))))
        .unwrap_or_else(|| PathBuf::from(format!("{}.log", app_name)));

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
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
            
        tracing::info!(
            "{} v{} | OS: {} | Arch: {} | log_level: {} | log_file: {}",
            app_name,
            version,
            std::env::consts::OS,
            std::env::consts::ARCH,
            level,
            path.display(),
        );
        
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

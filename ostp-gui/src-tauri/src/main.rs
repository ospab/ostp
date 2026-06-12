// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ostp_client::logging::setup_panic_hook();

    // Read config BEFORE init_tracing so we can use the correct log level from config.
    // If config is missing or debug=false we default to "info".
    let log_level = detect_log_level_from_config();
    let _log_guard = ostp_client::logging::init_tracing(&log_level, "ostp-gui", env!("CARGO_PKG_VERSION"));

    tracing::info!("ostp-gui starting (log_level={})", log_level);

    if let Err(e) = std::panic::catch_unwind(|| {
        ostp_gui_lib::run();
    }) {
        let msg = if let Some(s) = e.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        tracing::error!("ostp-gui fatal panic: {}", msg);
        // Show a dialog so the user knows what happened instead of silent exit
        #[cfg(target_os = "windows")]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            let msg_w: Vec<u16> = OsStr::new(&format!("OSTP GUI crashed:\n\n{}\n\nSee ostp-gui.log for details.", msg))
                .encode_wide().chain(Some(0)).collect();
            let title_w: Vec<u16> = OsStr::new("OSTP GUI — Fatal Error").encode_wide().chain(Some(0)).collect();
            #[link(name = "user32")] extern "system" {
                fn MessageBoxW(hWnd: *mut std::ffi::c_void, lpText: *const u16, lpCaption: *const u16, uType: u32) -> i32;
            }
            unsafe { MessageBoxW(std::ptr::null_mut(), msg_w.as_ptr(), title_w.as_ptr(), 0x10); }
        }
        std::process::exit(1);
    }
}

/// Reads config.json from the exe directory (or cwd) and returns "debug" if debug=true,
/// or the value of log_level field, otherwise returns "info".
fn detect_log_level_from_config() -> String {
    let config_path = {
        let mut p = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("config.json")))
            .unwrap_or_else(|| std::path::PathBuf::from("config.json"));
        if !p.exists() {
            p = std::path::PathBuf::from("config.json");
        }
        p
    };

    if let Ok(content) = std::fs::read_to_string(&config_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            // debug: true overrides everything
            if val.get("debug").and_then(|v| v.as_bool()).unwrap_or(false) {
                return "debug".to_string();
            }
            // explicit log_level field
            if let Some(level) = val.get("log_level").and_then(|v| v.as_str()) {
                return level.to_string();
            }
        }
    }
    "info".to_string()
}

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ostp_client::logging::setup_panic_hook();
    let _log_guard = ostp_client::logging::init_tracing("info", "ostp-gui", env!("CARGO_PKG_VERSION"));
    ostp_gui_lib::run()
}

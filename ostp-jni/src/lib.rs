use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;

use std::collections::VecDeque;
use std::sync::{atomic::Ordering, Arc, RwLock};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use ostp_client::bridge::{Bridge, BridgeMetrics};
use ostp_client::config::ClientConfig;
use ostp_client::tunnel;
use ostp_client::app::{BridgeCommand, UiEvent};
use std::io::Write;

static LOG_TX: std::sync::OnceLock<std::sync::mpsc::Sender<String>> = std::sync::OnceLock::new();

struct JniLogWriter;

impl Write for JniLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf).trim().to_string();
        if !s.is_empty() {
            if let Some(tx) = LOG_TX.get() {
                let _ = tx.send(s);
            } else {
                add_log(s);
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for JniLogWriter {
    type Writer = JniLogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        JniLogWriter
    }
}

static TRACING_INIT: std::sync::Once = std::sync::Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        LOG_TX.set(tx).ok();
        std::thread::spawn(move || {
            while let Ok(text) = rx.recv() {
                add_log(text);
            }
        });

        let subscriber = tracing_subscriber::fmt()
            .with_writer(JniLogWriter)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

struct SdkState {
    runtime: Option<Runtime>,
    shutdown_tx: Option<watch::Sender<bool>>,
    metrics: Option<Arc<BridgeMetrics>>,
    cmd_tx: Option<mpsc::Sender<BridgeCommand>>,
}

impl SdkState {
    const fn new() -> Self {
        Self {
            runtime: None,
            shutdown_tx: None,
            metrics: None,
            cmd_tx: None,
        }
    }
}

static STATE: RwLock<SdkState> = RwLock::new(SdkState::new());
static LOGS: RwLock<VecDeque<String>> = RwLock::new(VecDeque::new());
static JVM: RwLock<Option<jni::JavaVM>> = RwLock::new(None);
static CLASS_REF: RwLock<Option<jni::objects::GlobalRef>> = RwLock::new(None);

fn add_log(text: String) {
    if let Ok(mut guard) = LOGS.write() {
        if guard.len() >= 1000 {
            guard.pop_front();
        }
        guard.push_back(text);
    }
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_nativeStartClient(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
    fd: jni::sys::jint,
    // tun2socks ("system" TUN stack) removed in 0.4.0 — native OSTP TUN is the only path.
    // These two args are retained to keep the JNI signature ABI-stable with Kotlin; unused.
    _t2s_bin_path: JString,
    _local_proxy: JString,
) -> jboolean {
    let mut state = match STATE.write() {
        Ok(s) => s,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    if state.runtime.is_some() {
        add_log("Client is already running!".to_string());
        return jni::sys::JNI_TRUE;
    }

    init_tracing();

    if let Ok(jvm) = env.get_java_vm() {
        if let Ok(mut guard) = JVM.write() {
            *guard = Some(jvm);
        }
    }

    if let Ok(cls) = env.find_class("net/ostp/client/OstpClientSdk") {
        if let Ok(global_cls) = env.new_global_ref(cls) {
            if let Ok(mut guard) = CLASS_REF.write() {
                *guard = Some(global_cls);
            }
        }
    }

    ostp_client::bridge::set_socket_protector(|fd| {
        let jvm_guard = match JVM.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let class_guard = match CLASS_REF.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let (Some(ref jvm), Some(ref class_ref)) = (&*jvm_guard, &*class_guard) {
            if let Ok(mut env) = jvm.attach_current_thread() {
                let class_obj = unsafe { jni::objects::JClass::from_raw(class_ref.as_obj().as_raw()) };
                let val = env.call_static_method(
                    &class_obj,
                    "protectSocket",
                    "(I)Z",
                    &[jni::objects::JValue::from(fd)],
                );
                if let Ok(jval) = val {
                    return jval.z().unwrap_or(false);
                }
            }
        }
        false
    });

    let config_str: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(_) => return jni::sys::JNI_FALSE,
    };

    // Parse config from JSON
    let config: ClientConfig = match serde_json::from_str(&config_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            add_log(format!("Failed to parse config JSON: {e}"));
            return jni::sys::JNI_FALSE;
        }
    };

    let debug = config.debug;

    // Create tokio runtime
    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            add_log(format!("Failed to create Tokio runtime: {e}"));
            return jni::sys::JNI_FALSE;
        }
    };

    let (proxy_events_tx, proxy_events_rx) = mpsc::channel(512);
    let (client_msgs_tx, client_msgs_rx) = mpsc::unbounded_channel();

    let metrics = Arc::new(BridgeMetrics {
        bytes_sent: portable_atomic::AtomicU64::new(0),
        bytes_recv: portable_atomic::AtomicU64::new(0),
        connection_state: portable_atomic::AtomicU8::new(0),
        rtt_ms: portable_atomic::AtomicU32::new(0),
    });

    let bridge = match Bridge::new(&config, Arc::clone(&metrics)) {
        Ok(b) => b,
        Err(e) => {
            add_log(format!("Failed to initialize Bridge: {e}"));
            return jni::sys::JNI_FALSE;
        }
    };

    let (ui_tx, mut ui_rx) = mpsc::channel(512);
    let (cmd_tx, cmd_rx) = mpsc::channel(128);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_shutdown_rx = shutdown_tx.subscribe();
    
    // Create exclusions channel
    let (exclusions_tx, exclusions_rx) = watch::channel(config.exclusions.clone());
    let _exclusions_rx_tun = exclusions_tx.subscribe();

    let metrics_clone = Arc::clone(&metrics);

    // Spawn async tasks inside runtime
    rt.spawn(async move {
        bridge.run(ui_tx, cmd_rx, shutdown_rx, proxy_events_rx, client_msgs_tx).await
    });

    let config_proxy = config.clone();
    rt.spawn(async move {
        tunnel::run_local_proxy(
            config_proxy.local_proxy,
            config_proxy.ostp,
            exclusions_rx,
            config_proxy.debug,
            proxy_shutdown_rx,
            proxy_events_tx,
            client_msgs_rx,
        )
        .await
    });

    // Start logs receiver task
    rt.spawn(async move {
        while let Some(msg) = ui_rx.recv().await {
            match msg {
                UiEvent::Log(text) => add_log(text),
                UiEvent::ProfileChanged(p) => add_log(format!("Profile changed: {p:?}")),
                UiEvent::TunnelStopped => add_log("Tunnel stopped".to_string()),
                _ => {}
            }
        }
    });

    // Toggle tunnel to initiate handshake
    let cmd_tx_clone = cmd_tx.clone();
    rt.spawn(async move {
        let _ = cmd_tx_clone.send(BridgeCommand::ToggleTunnel).await;
    });

    // Native OSTP TUN stack is the only path (tun2socks "system" stack removed in 0.4.0).
    if debug {
        add_log("Using OSTP native TUN stack.".to_string());
    }
    {
        let shutdown_rx_clone = shutdown_tx.subscribe();
        let config_clone = config.clone();
        let (exclusions_tx, exclusions_rx) = tokio::sync::watch::channel(config.exclusions.clone());
        rt.spawn(async move {
            let _tx = exclusions_tx; // keep tx alive
            if let Err(e) = tunnel::native_handler::run_native_tunnel_from_fd(config_clone, shutdown_rx_clone, exclusions_rx, fd).await {
                add_log(format!("Native TUN exited with error: {}", e));
            }
        });
    }

    state.runtime = Some(rt);
    state.shutdown_tx = Some(shutdown_tx);
    state.metrics = Some(metrics_clone);
    state.cmd_tx = Some(cmd_tx);

    add_log("OSTP SDK: Client successfully started".to_string());
    jni::sys::JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_startClient(
    env: JNIEnv,
    class: JClass,
    config_json: JString,
    fd: jni::sys::jint,
    t2s_bin_path: JString,
    local_proxy: JString,
) -> jboolean {
    Java_net_ostp_client_OstpClientSdk_nativeStartClient(env, class, config_json, fd, t2s_bin_path, local_proxy)
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_nativeStopClient(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let (shutdown_tx, runtime) = {
        let mut state = match STATE.write() {
            Ok(s) => s,
            Err(_) => return jni::sys::JNI_FALSE,
        };
        let s = state.shutdown_tx.take();
        let r = state.runtime.take();
        state.cmd_tx = None;
        state.metrics = None;
        (s, r)
    };

    if let Some(s) = shutdown_tx {
        let _ = s.send(true);
    }

    if let Some(rt) = runtime {
        rt.shutdown_background();
    }

    add_log("OSTP SDK: Client successfully stopped".to_string());
    jni::sys::JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_stopClient(
    env: JNIEnv,
    class: JClass,
) -> jboolean {
    Java_net_ostp_client_OstpClientSdk_nativeStopClient(env, class)
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_nativeGetMetrics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let state = match STATE.read() {
        Ok(s) => s,
        Err(_) => return match env.new_string("{}") {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
    };

    if let Some(m) = &state.metrics {
        let sent = m.bytes_sent.load(Ordering::Relaxed);
        let recv = m.bytes_recv.load(Ordering::Relaxed);
        let conn_state = m.connection_state.load(Ordering::Relaxed);
        let rtt = m.rtt_ms.load(Ordering::Relaxed);
        let json = format!(
            r#"{{"bytes_sent": {}, "bytes_recv": {}, "connection_state": {}, "rtt_ms": {}}}"#,
            sent, recv, conn_state, rtt
        );
        match env.new_string(json.replace('\0', "")) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    } else {
        match env.new_string(r#"{"bytes_sent": 0, "bytes_recv": 0, "connection_state": 0, "rtt_ms": 0}"#) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_getMetrics(
    env: JNIEnv,
    class: JClass,
) -> jstring {
    Java_net_ostp_client_OstpClientSdk_nativeGetMetrics(env, class)
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_nativeGetLogs(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let logs_vec: Vec<String> = match LOGS.write() {
        Ok(mut guard) => guard.drain(..).collect(),
        Err(_) => Vec::new(),
    };

    let json = match serde_json::to_string(&logs_vec) {
        Ok(s) => s,
        Err(_) => "[]".to_string(),
    };

    match env.new_string(json.replace('\0', "")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_getLogs(
    env: JNIEnv,
    class: JClass,
) -> jstring {
    Java_net_ostp_client_OstpClientSdk_nativeGetLogs(env, class)
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_addLog(
    mut env: JNIEnv,
    _class: JClass,
    log_msg: JString,
) {
    if let Ok(s) = env.get_string(&log_msg) {
        let text: String = s.into();
        add_log(text);
    }
}

#[derive(serde::Deserialize)]
struct ProberMatrixRequest {
    server_addr: String,
    access_key: String,
    /// Set for a TLS profile: probe UoT inside TLS instead.
    #[serde(default)]
    tls: Option<ostp_client::prober::ProbeTls>,
    #[serde(default = "default_matrix_timeout_ms")]
    timeout_ms: u64,
}
fn default_matrix_timeout_ms() -> u64 { 2500 }

/// Runs a real, authenticated handshake against every resolved
/// address × transport combination for `server_addr` and reports which ones
/// actually complete. Uses its own short-lived tokio runtime, independent of
/// any active VPN session in `STATE` — this can run while a tunnel is
/// connected without disturbing it. Blocks the calling thread until the
/// sweep finishes (callers must invoke this off the UI thread).
#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_runProberMatrix(
    mut env: JNIEnv,
    _class: JClass,
    request_json: JString,
) -> jstring {
    let req_str: String = match env.get_string(&request_json) {
        Ok(s) => s.into(),
        Err(_) => return null_jstring(&mut env),
    };

    let req: ProberMatrixRequest = match serde_json::from_str(&req_str) {
        Ok(r) => r,
        Err(e) => return error_jstring(&mut env, &format!("invalid request json: {e}")),
    };

    let result = match Runtime::new() {
        Ok(rt) => rt.block_on(ostp_client::prober::run_matrix(
            &req.server_addr,
            req.access_key.as_bytes(),
            std::time::Duration::from_millis(req.timeout_ms),
            req.tls,
        )),
        Err(e) => Err(anyhow::anyhow!("failed to create tokio runtime: {e}")),
    };

    match result {
        Ok(entries) => json_jstring(&mut env, &entries),
        Err(e) => error_jstring(&mut env, &e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct ProberTtlRequest {
    address: String,
    port: u16,
    transport: String,
    access_key: String,
    #[serde(default)]
    tls: Option<ostp_client::prober::ProbeTls>,
    #[serde(default = "default_max_ttl")]
    max_ttl: u32,
    #[serde(default = "default_ttl_timeout_ms")]
    timeout_ms: u64,
}
fn default_max_ttl() -> u32 { 20 }
fn default_ttl_timeout_ms() -> u64 { 900 }

/// Repeats a handshake attempt at increasing IP_TTL against one
/// already-known address × transport combination (normally one the matrix
/// scan above found working, or failing in an interesting way), to estimate
/// the hop distance at which a middlebox starts answering in place of the
/// real server. Same threading model as the matrix scan.
#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_runProberTtlScan(
    mut env: JNIEnv,
    _class: JClass,
    request_json: JString,
) -> jstring {
    let req_str: String = match env.get_string(&request_json) {
        Ok(s) => s.into(),
        Err(_) => return null_jstring(&mut env),
    };

    let req: ProberTtlRequest = match serde_json::from_str(&req_str) {
        Ok(r) => r,
        Err(e) => return error_jstring(&mut env, &format!("invalid request json: {e}")),
    };

    let target_ip: std::net::IpAddr = match req.address.parse() {
        Ok(ip) => ip,
        Err(e) => return error_jstring(&mut env, &format!("invalid address: {e}")),
    };
    let Some(transport) = ostp_client::prober::TransportKind::parse(&req.transport) else {
        return error_jstring(&mut env, &format!("unknown transport: {}", req.transport));
    };

    let report = match Runtime::new() {
        Ok(rt) => rt.block_on(ostp_client::prober::run_ttl_scan(
            target_ip,
            req.port,
            transport,
            req.access_key.as_bytes(),
            req.max_ttl,
            std::time::Duration::from_millis(req.timeout_ms),
            req.tls,
        )),
        Err(e) => return error_jstring(&mut env, &format!("failed to create tokio runtime: {e}")),
    };

    json_jstring(&mut env, &report)
}

/// Runs the generic (non-ostp) DPI/TSPU fingerprinting battery against fixed
/// public targets — the same differential SNI/DNS/CONNECT tests the
/// standalone `ostp-prober` desktop tool uses — to characterize what the
/// current network filters, independent of whether the user's own server
/// works. Same threading model as the matrix/TTL scans: its own short-lived
/// runtime, safe to run while a tunnel is connected (every probe socket is
/// protected against the VPN), blocks the calling thread (~10s).
#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_runProberDpiBattery(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = match Runtime::new() {
        Ok(rt) => rt.block_on(ostp_client::dpi_probes::run_dpi_battery()),
        Err(e) => return error_jstring(&mut env, &format!("failed to create tokio runtime: {e}")),
    };

    json_jstring(&mut env, &report)
}

fn null_jstring(env: &mut JNIEnv) -> jstring {
    match env.new_string("{}") {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn error_jstring(env: &mut JNIEnv, msg: &str) -> jstring {
    let body = serde_json::json!({ "error": msg }).to_string();
    match env.new_string(body.replace('\0', "")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn json_jstring<T: serde::Serialize>(env: &mut JNIEnv, value: &T) -> jstring {
    let body = serde_json::to_string(value).unwrap_or_else(|e| {
        serde_json::json!({ "error": format!("failed to serialize report: {e}") }).to_string()
    });
    match env.new_string(body.replace('\0', "")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Called by Android NetworkCallback when the active network changes (WiFi→LTE, etc.).
/// Sends BridgeCommand::NetworkChanged to trigger an immediate reconnect in the Rust bridge.
#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_notifyNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
) {
    let state = match STATE.read() {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Some(ref cmd_tx) = state.cmd_tx {
        // Use try_send since we're likely on a background thread from Android's ConnectivityManager
        let _ = cmd_tx.try_send(ostp_client::app::BridgeCommand::NetworkChanged);
        add_log("notifyNetworkChanged: BridgeCommand::NetworkChanged sent".to_string());
    }
}


#[cfg(test)]
mod tests {
    /// Every `external fun` the Android app declares must have a matching
    /// export here, or the call fails only at runtime ("No implementation
    /// found for ..."), which no build step catches.
    #[test]
    fn every_kotlin_external_has_a_jni_export() {
        const KOTLIN: &str =
            include_str!("../../ostp-flutter/android/app/src/main/kotlin/net/ostp/client/OstpClientSdk.kt");
        const RUST: &str = include_str!("lib.rs");
        let mut checked = 0;
        for line in KOTLIN.lines() {
            let Some(rest) = line.trim().strip_prefix("external fun ") else { continue };
            let name = rest.split('(').next().unwrap().trim();
            let export = format!("fn Java_net_ostp_client_OstpClientSdk_{name}(");
            assert!(RUST.contains(&export), "Kotlin declares `{name}` but ostp-jni has no `{export}`");
            checked += 1;
        }
        assert!(checked >= 5, "found only {checked} external declarations; did the Kotlin file move?");
    }
}

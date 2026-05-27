use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use lazy_static::lazy_static;
use std::collections::VecDeque;
use std::sync::{atomic::Ordering, Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use ostp_client::bridge::{Bridge, BridgeMetrics};
use ostp_client::config::ClientConfig;
use ostp_client::tunnel;
use ostp_client::app::{BridgeCommand, UiEvent};
use std::io::Write;

struct JniLogWriter;

impl Write for JniLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf).trim().to_string();
        if !s.is_empty() {
            add_log(s);
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
    tun_child: Option<std::process::Child>,
    cmd_tx: Option<mpsc::Sender<BridgeCommand>>,
}

lazy_static! {
    static ref STATE: Mutex<SdkState> = Mutex::new(SdkState {
        runtime: None,
        shutdown_tx: None,
        metrics: None,
        tun_child: None,
        cmd_tx: None,
    });
    static ref LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
    static ref JVM: Mutex<Option<jni::JavaVM>> = Mutex::new(None);
    static ref CLASS_REF: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);
}

fn add_log(text: String) {
    if let Ok(mut guard) = LOGS.lock() {
        if guard.len() >= 1000 {
            guard.pop_front();
        }
        guard.push_back(text);
    }
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_startClient(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
    fd: jni::sys::jint,
    t2s_bin_path: JString,
    local_proxy: JString,
) -> jboolean {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    if state.runtime.is_some() {
        add_log("Client is already running!".to_string());
        return jni::sys::JNI_TRUE;
    }

    init_tracing();

    if let Ok(jvm) = env.get_java_vm() {
        if let Ok(mut guard) = JVM.lock() {
            *guard = Some(jvm);
        }
    }

    if let Ok(cls) = env.find_class("net/ostp/client/OstpClientSdk") {
        if let Ok(global_cls) = env.new_global_ref(cls) {
            if let Ok(mut guard) = CLASS_REF.lock() {
                *guard = Some(global_cls);
            }
        }
    }

    ostp_client::bridge::set_socket_protector(|fd| {
        let jvm_guard = match JVM.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let class_guard = match CLASS_REF.lock() {
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

    let t2s_path: String = match env.get_string(&t2s_bin_path) {
        Ok(s) => s.into(),
        Err(_) => return jni::sys::JNI_FALSE,
    };

    let proxy_addr: String = match env.get_string(&local_proxy) {
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
            config_proxy.exclusions,
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

    if config.tun_stack == "system" {
        // Spawn tun2socks
        let fd_str = format!("fd://{}", fd);
        let proxy_str = format!("socks5://{}", proxy_addr);

        if debug {
            add_log(format!("Spawning tun2socks: {} -device {} -proxy {}", t2s_path, fd_str, proxy_str));
        }

        let mut cmd = std::process::Command::new(&t2s_path);
    cmd.arg("-device")
       .arg(&fd_str)
       .arg("-proxy")
       .arg(&proxy_str);
    
    if config.ostp.mtu > 0 {
        cmd.arg("-mtu").arg(config.ostp.mtu.to_string());
    }
    
    cmd.stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            add_log(format!("Failed to spawn tun2socks from Rust: {e}"));
            return jni::sys::JNI_FALSE;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            add_log("Failed to capture tun2socks stdout".to_string());
            return jni::sys::JNI_FALSE;
        }
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => {
            add_log("Failed to capture tun2socks stderr".to_string());
            return jni::sys::JNI_FALSE;
        }
    };

    // Read stdout
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                if debug {
                    add_log(format!("tun2socks: {}", l));
                }
            }
        }
    });

        // Read stderr & wait
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(l) = line {
                    if debug {
                        add_log(format!("tun2socks ERROR: {}", l));
                    }
                }
            }
        });
        state.tun_child = Some(child);
    } else {
        if debug {
            add_log("Using OSTP native TUN stack. Bypassing tun2socks.".to_string());
        }
        let shutdown_rx_clone = shutdown_tx.subscribe();
        let config_clone = config.clone();
        rt.spawn(async move {
            if let Err(e) = tunnel::native_handler::run_native_tunnel_from_fd(config_clone, shutdown_rx_clone, fd).await {
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
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_stopClient(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let (tun_child, shutdown_tx, runtime) = {
        let mut state = match STATE.lock() {
            Ok(s) => s,
            Err(_) => return jni::sys::JNI_FALSE,
        };
        let c = state.tun_child.take();
        let s = state.shutdown_tx.take();
        let r = state.runtime.take();
        state.cmd_tx = None;
        state.metrics = None;
        (c, s, r)
    };

    if let Some(mut child) = tun_child {
        let _ = child.kill();
        add_log("Killed tun2socks process".to_string());
    }

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
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_getMetrics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let state = match STATE.lock() {
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
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_getLogs(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let logs_vec: Vec<String> = match LOGS.lock() {
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

/// Called by Android NetworkCallback when the active network changes (WiFi→LTE, etc.).
/// Sends BridgeCommand::NetworkChanged to trigger an immediate reconnect in the Rust bridge.
#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_notifyNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
) {
    let state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Some(ref cmd_tx) = state.cmd_tx {
        // Use try_send since we're likely on a background thread from Android's ConnectivityManager
        let _ = cmd_tx.try_send(ostp_client::app::BridgeCommand::NetworkChanged);
        add_log("notifyNetworkChanged: BridgeCommand::NetworkChanged sent".to_string());
    }
}


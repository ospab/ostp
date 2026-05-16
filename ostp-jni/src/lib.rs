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

struct SdkState {
    runtime: Option<Runtime>,
    shutdown_tx: Option<watch::Sender<bool>>,
    metrics: Option<Arc<BridgeMetrics>>,
}

lazy_static! {
    static ref STATE: Mutex<SdkState> = Mutex::new(SdkState {
        runtime: None,
        shutdown_tx: None,
        metrics: None,
    });
    static ref LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
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
) -> jboolean {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    if state.runtime.is_some() {
        add_log("Client is already running!".to_string());
        return jni::sys::JNI_TRUE;
    }

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

    state.runtime = Some(rt);
    state.shutdown_tx = Some(shutdown_tx);
    state.metrics = Some(metrics_clone);

    add_log("OSTP SDK: Client successfully started".to_string());
    jni::sys::JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_net_ostp_client_OstpClientSdk_stopClient(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    if let Some(shutdown_tx) = state.shutdown_tx.take() {
        let _ = shutdown_tx.send(true);
    }

    if let Some(rt) = state.runtime.take() {
        rt.shutdown_background();
    }

    state.metrics = None;
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
        Err(_) => return env.new_string("{}").unwrap().into_raw(),
    };

    if let Some(m) = &state.metrics {
        let sent = m.bytes_sent.load(Ordering::Relaxed);
        let recv = m.bytes_recv.load(Ordering::Relaxed);
        let json = format!(r#"{{"bytes_sent": {}, "bytes_recv": {}}}"#, sent, recv);
        env.new_string(json).unwrap().into_raw()
    } else {
        env.new_string(r#"{"bytes_sent": 0, "bytes_recv": 0}"#).unwrap().into_raw()
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

    env.new_string(json).unwrap().into_raw()
}

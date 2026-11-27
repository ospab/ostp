use std::collections::VecDeque;

use ostp_core::TrafficProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Stopped,
    Handshaking,
    Established,
}

impl ConnectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Handshaking => "Handshaking",
            Self::Established => "Established",
        }
    }
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    Metrics {
        status: ConnectionStatus,
        /// The path's round trip (see `crate::rtt`).
        rtt_ms: f64,
        /// How much longer the in-tunnel ping takes than the path.
        queue_ms: f64,
        throughput_bps: u64,
    },
    Traffic {
        incoming_bps: u64,
        outgoing_bps: u64,
    },
    Log(String),
    ProfileChanged(TrafficProfile),
    TunnelStopped,
    /// The server ended the session with an authenticated `Close` (v6): the
    /// text is what to tell the user (see `server_close_message`). The tunnel
    /// is stopped and will not start again by itself. Sent just before
    /// `TunnelStopped`.
    ServerClosed(String),
}

/// What to tell the user when the server closed the session. Plain words,
/// including what to do about it. `note` is the optional text of the `Close`
/// frame; it comes from the server and is shown as it is, minus anything that
/// is not printable.
pub fn server_close_message(reason: ostp_core::CloseReason, note: &str) -> String {
    use ostp_core::CloseReason::*;
    let what = match reason {
        Normal => "The server closed the connection.",
        ServerRestarting => "The server is restarting: reconnecting on its own.",
        KeyRevoked => "The server closed the connection: your key was revoked or removed. Ask the server owner for a new key.",
        TrafficLimit => "The server closed the connection: the traffic limit of your key is used up. Ask the server owner to raise it.",
        TooManySessions => "The server closed the connection: too many sessions are open with this key, and this was the oldest. Close it on your other devices, then connect again.",
        ServerShutdown => "The server closed the connection: it is shutting down. Connect again later.",
        KeyExpired => "The server closed the connection: the access key has expired. Ask the server owner to extend it.",
    };
    let note: String = note.chars().filter(|c| !c.is_control()).collect();
    let note = note.trim();
    if note.is_empty() {
        what.to_string()
    } else {
        format!("{what} Message from the server: {note}")
    }
}

static STOP_NOTICE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Records why the tunnel stopped on its own (the server's `Close`), before the
/// connection state turns to "stopped", so an app that polls that state finds
/// the reason with it. One tunnel runs per process.
pub fn set_stop_notice(message: Option<String>) {
    *STOP_NOTICE.lock().unwrap_or_else(|e| e.into_inner()) = message;
}

/// The reason the tunnel last stopped on its own, until the next start.
pub fn stop_notice() -> Option<String> {
    STOP_NOTICE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

static SERVER_INFO: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static SERVER_INFO_SUPPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SERVER_INFO_WANTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The latest info the connected server sent about itself inside the tunnel,
/// as the JSON it sent:
/// `{ "operator": {name, location, contact, about}, "server": {version,
/// carriers, log_privacy, ipv6, dns_filtering}, "key": {used_bytes,
/// limit_bytes, expires_at, max_devices} }` (`operator` and its keys only
/// when set). `None` before the server sent it, with a server that does not
/// support it, and after a new connection starts. It stays after the tunnel
/// stops, so an app can show it next to the stop reason (an expired key).
pub fn server_info() -> Option<String> {
    SERVER_INFO.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub(crate) fn set_server_info(json: Option<String>) {
    *SERVER_INFO.lock().unwrap_or_else(|e| e.into_inner()) = json;
}

pub(crate) fn set_server_info_supported(yes: bool) {
    SERVER_INFO_SUPPORTED.store(yes, std::sync::atomic::Ordering::Relaxed);
}

/// Asks the connected server for its info again; the answer replaces what
/// `server_info` returns (the bridge sends the request within half a second).
/// False, and nothing is sent, while no connected server supports it. The
/// server answers a session at most once per 10 seconds.
pub fn request_server_info() -> bool {
    let supported = SERVER_INFO_SUPPORTED.load(std::sync::atomic::Ordering::Relaxed);
    if supported {
        SERVER_INFO_WANTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    supported
}

/// Whether an app asked for the server's info since the last call.
pub(crate) fn take_server_info_request() -> bool {
    SERVER_INFO_WANTED.swap(false, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostp_core::CloseReason;

    #[test]
    fn every_reason_has_a_message_and_the_actionable_ones_say_what_to_do() {
        for byte in 0..=6u8 {
            let reason = CloseReason::from_wire(byte).unwrap();
            let m = server_close_message(reason, "");
            assert!(m.starts_with("The server closed the connection"), "{m}");
        }
        assert!(server_close_message(CloseReason::KeyRevoked, "").contains("Ask the server owner"));
        assert!(server_close_message(CloseReason::TrafficLimit, "").contains("Ask the server owner"));
        assert!(server_close_message(CloseReason::KeyExpired, "").contains("has expired"));
        assert!(server_close_message(CloseReason::ServerRestarting, "").contains("reconnecting"));
    }

    #[test]
    fn server_info_is_asked_for_only_when_supported() {
        set_server_info_supported(false);
        let _ = take_server_info_request();
        assert!(!request_server_info());
        assert!(!take_server_info_request());
        set_server_info_supported(true);
        assert!(request_server_info());
        assert!(take_server_info_request());
        assert!(!take_server_info_request(), "taken once");
        set_server_info(Some("{}".into()));
        assert_eq!(server_info().as_deref(), Some("{}"));
        set_server_info(None);
        set_server_info_supported(false);
    }

    #[test]
    fn the_servers_note_is_shown_without_control_characters() {
        let m = server_close_message(CloseReason::KeyRevoked, "  expired\n\x1b[31m today ");
        assert!(m.ends_with("Message from the server: expired[31m today"), "{m:?}");
        assert!(!m.contains('\x1b') && !m.contains('\n'));
    }
}

#[derive(Debug, Clone)]
pub enum BridgeCommand {
    ToggleTunnel,
    NextProfile,
    ReloadConfig,
    /// The default network changed (Wi-Fi to cellular, SIM switch). Starts the
    /// recovery at once: move the session to a new socket, else reconnect.
    NetworkChanged,
    /// Ask the connected server for its info again (`server_info`). Nothing
    /// is sent to a server that does not support it.
    RequestServerInfo,
    Shutdown,
}

pub struct AppState {
    pub status: ConnectionStatus,
    pub active_profile: TrafficProfile,
    pub rtt_ms: f64,
    pub queue_ms: f64,
    pub throughput_bps: u64,
    pub incoming_history: Vec<u64>,
    pub outgoing_history: Vec<u64>,
    pub logs: VecDeque<String>,
    pub log_scroll: u16,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            status: ConnectionStatus::Stopped,
            active_profile: TrafficProfile::JsonRpc,
            rtt_ms: 0.0,
            queue_ms: 0.0,
            throughput_bps: 0,
            incoming_history: vec![0; 64],
            outgoing_history: vec![0; 64],
            logs: VecDeque::with_capacity(512),
            log_scroll: 0,
        }
    }

    pub fn apply_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Metrics {
                status,
                rtt_ms,
                queue_ms,
                throughput_bps,
            } => {
                self.status = status;
                self.rtt_ms = rtt_ms;
                self.queue_ms = queue_ms;
                self.throughput_bps = throughput_bps;
            }
            UiEvent::Traffic {
                incoming_bps,
                outgoing_bps,
            } => {
                push_sample(&mut self.incoming_history, incoming_bps);
                push_sample(&mut self.outgoing_history, outgoing_bps);
            }
            UiEvent::Log(line) => {
                if self.logs.len() >= 500 {
                    self.logs.pop_front();
                }
                self.logs.push_back(line);
            }
            UiEvent::ProfileChanged(profile) => {
                self.active_profile = profile;
            }
            UiEvent::TunnelStopped => {
                self.status = ConnectionStatus::Stopped;
            }
            UiEvent::ServerClosed(message) => {
                if self.logs.len() >= 500 {
                    self.logs.pop_front();
                }
                self.logs.push_back(message);
            }
        }
    }
}

fn push_sample(history: &mut Vec<u64>, value: u64) {
    if !history.is_empty() {
        history.remove(0);
    }
    history.push(value);
}

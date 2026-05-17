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
        rtt_ms: f64,
        throughput_bps: u64,
    },
    Traffic {
        incoming_bps: u64,
        outgoing_bps: u64,
    },
    Log(String),
    ProfileChanged(TrafficProfile),
    TunnelStopped,
}

#[derive(Debug, Clone)]
pub enum BridgeCommand {
    ToggleTunnel,
    NextProfile,
    ReloadConfig,
    Shutdown,
}

pub struct AppState {
    pub status: ConnectionStatus,
    pub active_profile: TrafficProfile,
    pub rtt_ms: f64,
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
                throughput_bps,
            } => {
                self.status = status;
                self.rtt_ms = rtt_ms;
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
        }
    }
}

fn push_sample(history: &mut Vec<u64>, value: u64) {
    if !history.is_empty() {
        history.remove(0);
    }
    history.push(value);
}

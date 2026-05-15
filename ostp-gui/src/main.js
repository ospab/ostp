const { invoke } = window.__TAURI__.core;

// State management
let appState = 'disconnected'; // 'disconnected', 'connecting', 'connected'
let pollInterval = null;
let elapsedSeconds = 0;
let elapsedTimer = null;

// DOM Elements
const btnConnect = document.getElementById('btn-connect');
const powerContainer = document.querySelector('.power-button-container');
const statusText = document.getElementById('status-text');
const uptimeText = document.getElementById('uptime-text');
const metricDown = document.getElementById('metric-down');
const metricUp = document.getElementById('metric-up');

const homeScreen = document.getElementById('home-screen');
const settingsScreen = document.getElementById('settings-screen');
const btnGoSettings = document.getElementById('btn-go-settings');
const btnBack = document.getElementById('btn-back');
const btnSaveConfig = document.getElementById('btn-save-config');
const configEditor = document.getElementById('config-editor');
const configToast = document.getElementById('config-toast');

// Utils
function formatBytes(bytes) {
  if (bytes === 0) return '0.0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatTime(seconds) {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return [
    hrs > 0 ? String(hrs).padStart(2, '0') : null,
    String(mins).padStart(2, '0'),
    String(secs).padStart(2, '0')
  ].filter(x => x !== null).join(':');
}

// State Updates
function setUIState(state) {
  appState = state;
  
  // Clean up classes
  btnConnect.className = 'power-btn';
  powerContainer.className = 'power-button-container';
  statusText.className = '';

  if (state === 'disconnected') {
    statusText.textContent = 'Disconnected';
    statusText.classList.add('status-disconnected');
    uptimeText.textContent = 'Tap to protect your traffic';
    
    clearInterval(pollInterval);
    clearInterval(elapsedTimer);
    pollInterval = null;
    elapsedTimer = null;
    elapsedSeconds = 0;

  } else if (state === 'connecting') {
    btnConnect.classList.add('connecting');
    powerContainer.classList.add('connecting');
    statusText.textContent = 'Connecting...';
    statusText.classList.add('status-connecting');
    uptimeText.textContent = 'Establishing secure tunnel';

  } else if (state === 'connected') {
    btnConnect.classList.add('connected');
    powerContainer.classList.add('connected');
    statusText.textContent = 'Protected';
    statusText.classList.add('status-connected');
    
    // Start poll timer
    if (!pollInterval) {
      pollInterval = setInterval(fetchMetrics, 1000);
    }
    // Start uptime timer
    if (!elapsedTimer) {
      elapsedSeconds = 0;
      elapsedTimer = setInterval(() => {
        elapsedSeconds++;
        uptimeText.textContent = `Uptime: ${formatTime(elapsedSeconds)}`;
      }, 1000);
    }
  }
}

// UI Event Handlers
async function handleToggleConnect() {
  if (appState === 'disconnected') {
    setUIState('connecting');
    try {
      const success = await invoke('start_tunnel');
      if (success) {
        // The start_tunnel call waits briefly or returns if spawn worked
        // Backend will periodically check status. Let's monitor it.
        monitorTunnelState();
      } else {
        alert('Failed to start tunnel process. Check config.json');
        setUIState('disconnected');
      }
    } catch (err) {
      alert('Error launching tunnel: ' + err);
      setUIState('disconnected');
    }
  } else {
    try {
      await invoke('stop_tunnel');
    } catch (err) {
      console.error(err);
    }
    setUIState('disconnected');
  }
}

async function monitorTunnelState() {
  // Check status for up to 5 seconds to confirm it connects
  let attempts = 0;
  const check = async () => {
    try {
      const isAlive = await invoke('get_tunnel_status');
      if (isAlive) {
        setUIState('connected');
        return true;
      }
    } catch (e) {}
    
    attempts++;
    if (attempts < 5 && appState === 'connecting') {
      setTimeout(check, 1000);
    } else if (appState === 'connecting') {
      alert('Tunnel failed to stay alive. Make sure you run with Admin privileges if using TUN mode.');
      setUIState('disconnected');
    }
  };
  setTimeout(check, 1500); // Delay initial check to give it time to boot
}

async function fetchMetrics() {
  try {
    const stats = await invoke('get_metrics'); // Expected format: { bytes_sent: u64, bytes_recv: u64 }
    if (stats) {
      metricDown.textContent = formatBytes(stats.bytes_recv);
      metricUp.textContent = formatBytes(stats.bytes_sent);
    }
  } catch (e) {
    console.error('Failed to fetch metrics', e);
  }
  
  // Also verify process is still alive
  try {
    const isAlive = await invoke('get_tunnel_status');
    if (!isAlive && appState === 'connected') {
      setUIState('disconnected');
    }
  } catch (e) {}
}

function switchScreen(target) {
  if (target === 'settings') {
    loadConfigText();
    homeScreen.classList.remove('active');
    settingsScreen.classList.add('active');
  } else {
    settingsScreen.classList.remove('active');
    homeScreen.classList.add('active');
  }
}

async function loadConfigText() {
  configEditor.value = 'Loading configuration...';
  try {
    const rawConfig = await invoke('get_config');
    configEditor.value = rawConfig;
  } catch (err) {
    configEditor.value = '// Error loading configuration: ' + err;
  }
}

async function handleSaveConfig() {
  try {
    const val = configEditor.value;
    JSON.parse(val); // Validate JSON format first
    const success = await invoke('save_config', { jsonContent: val });
    if (success) {
      showToast();
      setTimeout(() => switchScreen('home'), 800);
    }
  } catch (err) {
    alert('Invalid JSON or saving failed: ' + err.message);
  }
}

function showToast() {
  configToast.classList.add('show');
  setTimeout(() => configToast.classList.remove('show'), 2000);
}

// Initialization
window.addEventListener('DOMContentLoaded', async () => {
  btnConnect.addEventListener('click', handleToggleConnect);
  btnGoSettings.addEventListener('click', () => switchScreen('settings'));
  btnBack.addEventListener('click', () => switchScreen('home'));
  btnSaveConfig.addEventListener('click', handleSaveConfig);

  // Check current status on startup (reconnect UI if process already active)
  try {
    const isAlive = await invoke('get_tunnel_status');
    if (isAlive) {
      setUIState('connected');
    } else {
      setUIState('disconnected');
    }
  } catch (err) {
    setUIState('disconnected');
  }
});

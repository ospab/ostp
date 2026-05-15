const { invoke } = window.__TAURI__.core;

// State management
let appState = 'disconnected'; 
let pollInterval = null;
let elapsedSeconds = 0;
let elapsedTimer = null;
let rawConfigObj = null; // Cache original config object to preserve extra keys

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
const configToast = document.getElementById('config-toast');

// Input Form Elements
const inImportUrl = document.getElementById('in-import-url');
const btnImportUrl = document.getElementById('btn-import-url');
const inServer = document.getElementById('in-server');
const inKey = document.getElementById('in-key');
const inSocks = document.getElementById('in-socks');
const inDns = document.getElementById('in-dns');
const inTunMode = document.getElementById('in-tun-mode');
const inDebug = document.getElementById('in-debug');

// Exclusions Textareas
const inExDomains = document.getElementById('in-ex-domains');
const inExIps = document.getElementById('in-ex-ips');
const inExProcesses = document.getElementById('in-ex-processes');

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
  if (appState === state) return;
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

    clearInterval(elapsedTimer);
    elapsedTimer = null;
    elapsedSeconds = 0;

  } else if (state === 'connected') {
    btnConnect.classList.add('connected');
    powerContainer.classList.add('connected');
    statusText.textContent = 'Protected';
    statusText.classList.add('status-connected');
    
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
        startGlobalPolling();
      } else {
        alert('Failed to start tunnel process.');
        setUIState('disconnected');
      }
    } catch (err) {
      alert('Error starting tunnel: ' + err);
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

function startGlobalPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(uiSyncTick, 1000);
  uiSyncTick(); 
}

async function uiSyncTick() {
  try {
    const statusCode = await invoke('get_tunnel_status');
    
    if (statusCode === 0) {
      setUIState('disconnected');
      return;
    } else if (statusCode === 1) {
      setUIState('connecting');
    } else if (statusCode === 2) {
      setUIState('connected');
    }
    
    const stats = await invoke('get_metrics'); 
    if (stats) {
      metricDown.textContent = formatBytes(stats.bytes_recv);
      metricUp.textContent = formatBytes(stats.bytes_sent);
    }
  } catch (e) {
    console.error('Sync error', e);
    setUIState('disconnected');
  }
}

function switchScreen(target) {
  if (target === 'settings') {
    loadConfigIntoFields();
    homeScreen.classList.remove('active');
    settingsScreen.classList.add('active');
  } else {
    settingsScreen.classList.remove('active');
    homeScreen.classList.add('active');
  }
}

// Config Management
async function loadConfigIntoFields() {
  try {
    const rawStr = await invoke('get_config');
    rawConfigObj = JSON.parse(rawStr);
    
    const isClient = rawConfigObj.mode === 'client';
    const clientConf = isClient ? rawConfigObj : null;

    if (clientConf) {
      inServer.value = clientConf.server || '';
      inKey.value = clientConf.access_key || '';
      inSocks.value = clientConf.socks5_bind || '127.0.0.1:1088';
      
      const tunEnabled = clientConf.tun && clientConf.tun.enable;
      inTunMode.checked = !!tunEnabled;
      
      inDns.value = (clientConf.tun && clientConf.tun.dns) || '';
      inDebug.checked = !!clientConf.debug;

      // Load exclusions (arrays to multiline string)
      const exc = clientConf.exclude || {};
      inExDomains.value = (exc.domains || []).join('\n');
      inExIps.value = (exc.ips || []).join('\n');
      inExProcesses.value = (exc.processes || []).join('\n');
    } else {
      alert('Loaded configuration is for OSTP Server. Please adjust manually.');
    }
  } catch (err) {
    console.error('Error loading config', err);
  }
}

function parseTextAreaToArray(val) {
  return val.split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0);
}

async function handleSaveConfig() {
  if (!rawConfigObj) rawConfigObj = { mode: 'client', log_level: 'info' };
  
  rawConfigObj.mode = 'client';
  rawConfigObj.server = inServer.value.trim();
  rawConfigObj.access_key = inKey.value.trim();
  rawConfigObj.socks5_bind = inSocks.value.trim() || null;
  
  if (!rawConfigObj.tun) {
    rawConfigObj.tun = {
      wintun_path: "./wintun.dll",
      ipv4_address: "10.1.0.2/24"
    };
  }
  rawConfigObj.tun.enable = inTunMode.checked;
  
  const dnsVal = inDns.value.trim();
  rawConfigObj.tun.dns = dnsVal ? dnsVal : null;

  rawConfigObj.debug = inDebug.checked;

  // Save Exclusions
  rawConfigObj.exclude = {
    domains: parseTextAreaToArray(inExDomains.value),
    ips: parseTextAreaToArray(inExIps.value),
    processes: parseTextAreaToArray(inExProcesses.value)
  };

  // Validation
  if (!rawConfigObj.server) {
    alert('Server Address is required!');
    return;
  }
  if (!rawConfigObj.access_key) {
    alert('Access Key is required!');
    return;
  }

  try {
    const finalJson = JSON.stringify(rawConfigObj, null, 2);
    const success = await invoke('save_config', { jsonContent: finalJson });
    if (success) {
      showToast();
      setTimeout(() => switchScreen('home'), 800);
    }
  } catch (err) {
    alert('Saving failed: ' + err);
  }
}

// OSTP URI Sharing Parser (Simplified: only extract HOST & KEY)
function handleImportUrl() {
  const urlStr = inImportUrl.value.trim();
  if (!urlStr) return;

  try {
    if (!urlStr.startsWith('ostp://')) {
      throw new Error('Link must start with ostp://');
    }
    const url = new URL(urlStr);
    
    const accessKey = decodeURIComponent(url.username);
    const serverHost = url.host; 

    if (!accessKey || !serverHost) {
      throw new Error('Incomplete parameters: missing key or server address.');
    }

    // Update primary connection fields
    inServer.value = serverHost;
    inKey.value = accessKey;

    inImportUrl.value = ''; 
    
    inImportUrl.placeholder = 'Import successful!';
    setTimeout(() => { inImportUrl.placeholder = 'Paste ostp:// share link here...'; }, 2000);

  } catch (err) {
    alert('Failed to parse ostp:// share link: ' + err.message);
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
  
  btnImportUrl.addEventListener('click', handleImportUrl);
  inImportUrl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleImportUrl();
  });

  try {
    const statusCode = await invoke('get_tunnel_status');
    if (statusCode > 0) {
      startGlobalPolling();
    } else {
      setUIState('disconnected');
    }
  } catch (err) {
    setUIState('disconnected');
  }
});

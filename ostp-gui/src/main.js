import { t, toggleLang, applyTranslations } from './i18n.js';

// ── Tauri invoke shim ────────────────────────────────────────────────────────
let invoke = () => Promise.resolve(null);
if (window.__TAURI__?.core) {
  invoke = window.__TAURI__.core.invoke;
}

// ── State ────────────────────────────────────────────────────────────────────
let appState    = 'disconnected'; // 'disconnected' | 'connecting' | 'connected'
let pollTimer   = null;
let uptimeTimer = null;
let uptimeSecs  = 0;
let rawConfig   = null;           // parsed config.json object
let serverAddr  = '';             // current server address (for badge)

// ── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const homeScreen     = $('home-screen');
const settingsScreen = $('settings-screen');
const btnConnect     = $('btn-connect');
const orbitWrap      = $('orbit-wrap');
const brandDot       = $('brand-dot');
const statusLabel    = $('status-text');
const statusSub      = $('uptime-text');
const connInfo       = $('connection-info');
const serverBadgeTxt = $('server-badge-text');
const metricDown     = $('metric-down');
const metricUp       = $('metric-up');
const pingValueTxt   = $('ping-text-value');
const btnTestPing    = $('btn-test-ping');
const toast          = $('toast');

const btnGoSettings  = $('btn-go-settings');
const btnAutoConnect = $('btn-auto-connect');
const btnBack        = $('btn-back');
const btnImport      = $('btn-import-url');
const btnPeekKey     = $('btn-peek-key');
const importInput    = $('in-import-url');
const inServer       = $('in-server');
const inKey          = $('in-key');
const inSocks        = $('in-socks');
const inDns          = $('in-dns');
const inOwndns       = $('in-owndns');
const groupCustomDns = $('group-custom-dns');
const inTransport    = $('in-transport');
const inSni          = $('in-stealth-sni');
const inWss          = $('in-wss');
const inPbk          = $('in-pbk');
const inSid          = $('in-sid');
const inMtu          = $('in-mtu');
const inTun          = $('in-tun-mode');
const inKillSwitch   = $('in-kill-switch');
const inMux          = $('in-mux-mode');
const inMuxSessions  = $('in-mux-sessions');
const inDebug        = $('in-debug');
const inDomains      = $('in-ex-domains');
const inIps          = $('in-ex-ips');
const inProcesses    = $('in-ex-processes');

const wintunModal       = $('wintun-modal');
const btnWintunCancel   = $('btn-wintun-cancel');
const btnWintunDownload = $('btn-wintun-download');

// ── Utilities ────────────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (!b || b === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log2(b) / 10), 4);
  return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtTime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = n => String(n).padStart(2, '0');
  return h > 0
    ? `${h}:${pad(m)}:${pad(sec)}`
    : `${pad(m)}:${pad(sec)}`;
}

function splitLines(val) {
  return val.split('\n').map(l => l.trim()).filter(Boolean);
}

// ── Theme ────────────────────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('ostp-theme', theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  applyTheme(current === 'light' ? 'dark' : 'light');
}

// Apply saved theme immediately (before any paint)
(function() {
  const saved = localStorage.getItem('ostp-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
})();
// ── Toast ────────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, variant = '') {
  toast.textContent = msg;
  toast.className = 'toast show' + (variant ? ' is-' + variant : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
  }, 2400);
}

// ── DNS & Kill Switch visibility ──────────────────────────────────────────────
function updateDnsVisibility() {
  if (!groupCustomDns || !inOwndns) return;
  groupCustomDns.style.display = inOwndns.checked ? 'none' : 'block';
}

function updateKillSwitchVisibility() {
  const group = $('group-kill-switch');
  if (!group || !inTun) return;
  group.style.display = inTun.checked ? 'flex' : 'none';
}


// ── State machine ────────────────────────────────────────────────────────────
function setState(next) {
  if (appState === next) return;
  appState = next;

  // Reset all dynamic classes
  btnConnect.className = 'power-btn';
  orbitWrap.className  = 'orbit-wrap';
  brandDot.className   = 'brand-dot';
  statusLabel.className = 'status-label';

  if (next === 'disconnected') {
    statusLabel.textContent = t('status_disconnected');
    statusSub.textContent   = t('hint_tap');
    statusLabel.classList.add('');
    connInfo.classList.add('hidden');
    metricDown.textContent  = '0 B';
    metricUp.textContent    = '0 B';
    pingValueTxt.textContent = 'Target Ping: -- ms';
    pingValueTxt.className = 'ping-test-value';
    clearInterval(pollTimer);
    clearInterval(uptimeTimer);
    pollTimer = uptimeTimer = null;
    uptimeSecs = 0;

  } else if (next === 'connecting') {
    btnConnect.classList.add('connecting');
    orbitWrap.classList.add('connecting');
    brandDot.classList.add('connecting');
    statusLabel.classList.add('is-connecting');
    statusLabel.textContent = t('status_connecting');
    statusSub.textContent   = t('hint_connecting');
    connInfo.classList.add('hidden');
    clearInterval(uptimeTimer);
    uptimeTimer = null;
    uptimeSecs = 0;

  } else if (next === 'connected') {
    btnConnect.classList.add('connected');
    orbitWrap.classList.add('connected');
    brandDot.classList.add('connected');
    statusLabel.classList.add('is-connected');
    statusLabel.textContent = t('status_connected');

    // Show connection info
    if (serverAddr) {
      serverBadgeTxt.textContent = serverAddr;
      connInfo.classList.remove('hidden');
    }

    // Start uptime counter
    if (!uptimeTimer) {
      uptimeSecs = 0;
      statusSub.textContent = fmtTime(uptimeSecs);
      uptimeTimer = setInterval(() => {
        uptimeSecs++;
        statusSub.textContent = fmtTime(uptimeSecs);
      }, 1000);
    }
  }
}

// ── Polling ──────────────────────────────────────────────────────────────────
async function poll() {
  if (!pollTimer) return;
  try {
    const code = await invoke('get_tunnel_status');
    if (!pollTimer) return; // Prevent race condition if disconnected during await
    
    if      (code === 0) { setState('disconnected'); return; }
    else if (code === 1)   setState('connecting');
    else if (code === 2)   setState('connected');

    const metrics = await invoke('get_metrics');
    if (metrics && pollTimer) {
      metricDown.textContent = fmtBytes(metrics.bytes_recv);
      metricUp.textContent   = fmtBytes(metrics.bytes_sent);
    }
  } catch {
    if (pollTimer) setState('disconnected');
  }
}

function startPolling() {
  clearInterval(pollTimer);
  poll();
  pollTimer = setInterval(poll, 1000);
}

// ── Connect / Disconnect ─────────────────────────────────────────────────────
async function handleToggle() {
  if (appState === 'disconnected') {
    try {
      const raw = await invoke('get_config');
      const cfg = JSON.parse(raw);
      serverAddr = cfg.server || '';
    } catch { serverAddr = ''; }

    setState('connecting');

    try {
      const ok = await invoke('start_tunnel');
      if (ok) {
        startPolling();
      } else {
        setState('disconnected');
        showToast(t('toast_error') || 'Failed to connect', 'error');
        alert(t('toast_error') || 'Failed to connect');
      }
    } catch (err) {
      setState('disconnected');
      if (err === "WINTUN_MISSING") {
        wintunModal.classList.remove('hidden');
      } else {
        showToast(String(err), 'error');
        alert(String(err));
      }
    }
  } else {
    try { await invoke('stop_tunnel'); } catch { /* ignore */ }
    setState('disconnected');
    showToast(t('toast_disconnected') || 'Disconnected');
  }
}

// ── Screen navigation ────────────────────────────────────────────────────────
function showScreen(name) {
  if (name === 'settings') {
    loadConfigIntoForm();
    homeScreen.classList.remove('active');
    settingsScreen.classList.add('active');
  } else {
    settingsScreen.classList.remove('active');
    homeScreen.classList.add('active');
  }
}

// ── Config — load ─────────────────────────────────────────────────────────────
async function loadConfigIntoForm() {
  try {
    const raw = await invoke('get_config');
    rawConfig = JSON.parse(raw);
    const c = rawConfig.mode === 'client' ? rawConfig : null;
    if (!c) return;

    inServer.value  = c.server        || '';
    inKey.value     = c.access_key    || '';
    inSocks.value   = c.socks5_bind   || '127.0.0.1:1088';
    inTransport.value = c.transport?.mode || 'udp';
    inSni.value     = c.transport?.stealth_sni || '';
    inWss.checked   = !!c.transport?.wss;
    inPbk.value     = c.reality?.pbk           || '';
    inSid.value     = c.reality?.sid           || '';
    inMtu.value     = c.mtu           || '';
    inTun.checked   = !!c.tun?.enable;
    if (inKillSwitch) inKillSwitch.checked = !!c.tun?.kill_switch;
    inMux.checked   = !!c.mux?.enabled;
    inMuxSessions.value = c.mux?.sessions || '';
    
    // owndns: detect if saved dns is 10.1.0.1
    const savedDns = c.tun?.dns || '';
    const isOwndns = savedDns === '10.1.0.1';
    inOwndns.checked = isOwndns;
    inDns.value = isOwndns ? '' : savedDns;
    updateDnsVisibility();
    updateKillSwitchVisibility();

    inDebug.checked = !!c.debug;

    const ex = c.exclude || {};
    inDomains.value   = (ex.domains   || []).join('\n');
    inIps.value       = (ex.ips       || []).join('\n');
    inProcesses.value = (ex.processes || []).join('\n');
  } catch (err) {
    showToast(String(err), 'error');
  }
}

// ── Config — save ─────────────────────────────────────────────────────────────
let autoSaveTimer = null;
function scheduleAutoSave() {
  clearTimeout(autoSaveTimer);
  autoSaveTimer = setTimeout(() => handleSave(true), 600);
}

async function handleSave(silent = false) {
  if (!rawConfig) rawConfig = { mode: 'client', log_level: 'info' };

  const server = inServer.value.trim();
  const key    = inKey.value.trim();

  if (!server) { if (!silent) showToast(t('err_server_req') || 'Server address required', 'error'); return; }
  if (!key)    { if (!silent) showToast(t('err_key_req')    || 'Access key required',     'error'); return; }

  rawConfig.mode       = 'client';
  rawConfig.server     = server;
  rawConfig.access_key = key;
  rawConfig.socks5_bind = inSocks.value.trim() || null;
  rawConfig.debug      = inDebug.checked;

  rawConfig.transport = rawConfig.transport || {};
  rawConfig.transport.mode = inTransport.value;
  rawConfig.transport.stealth_sni = inSni.value.trim() || undefined;
  rawConfig.transport.wss = inWss.checked;

  const pbk = inPbk.value.trim();
  if (pbk) {
    rawConfig.reality = {
      enabled: true,
      dest: '',
      private_key: '',
      pbk: pbk,
      sid: inSid.value.trim(),
      sni_list: []
    };
  } else {
    delete rawConfig.reality;
  }

  const mtuStr = inMtu.value.trim();
  if (mtuStr) rawConfig.mtu = parseInt(mtuStr, 10);
  else delete rawConfig.mtu;

  if (inMux.checked) {
    const s = parseInt(inMuxSessions.value.trim(), 10);
    rawConfig.mux = { enabled: true, sessions: isNaN(s) ? 1 : s };
  } else {
    delete rawConfig.mux;
  }

  rawConfig.tun = rawConfig.tun || {};
  rawConfig.tun.enable = inTun.checked;
  rawConfig.tun.kill_switch = inKillSwitch ? inKillSwitch.checked : false;
  rawConfig.tun.wintun_path = rawConfig.tun.wintun_path || './wintun.dll';
  rawConfig.tun.ipv4_address = rawConfig.tun.ipv4_address || '10.1.0.2/24';
  rawConfig.tun.stack = 'ostp';
  // owndns: if toggle is on, always write 10.1.0.1; otherwise use the custom field
  rawConfig.tun.dns    = inOwndns.checked ? '10.1.0.1' : (inDns.value.trim() || null);

  rawConfig.exclude = {
    domains:   splitLines(inDomains.value),
    ips:       splitLines(inIps.value),
    processes: splitLines(inProcesses.value),
  };

  try {
    const ok = await invoke('save_config', { jsonContent: JSON.stringify(rawConfig, null, 2) });
    if (!ok && !silent) {
      showToast(t('toast_error'), 'error');
    }
  } catch (err) {
    if (!silent) showToast(String(err), 'error');
  }
}

// ── Import share link ─────────────────────────────────────────────────────────
function handleImport() {
  const raw = importInput.value.trim();
  if (!raw) return;
  try {
    if (!raw.startsWith('ostp://')) throw new Error('Link must start with ostp://');
    const url = new URL(raw);
    const key  = decodeURIComponent(url.username);
    const host = url.host;
    if (!key || !host) throw new Error('Incomplete link parameters');
    inServer.value = host;
    inKey.value    = key;
    inSni.value    = url.searchParams.get('sni') || '';
    inPbk.value    = url.searchParams.get('pbk') || '';
    inSid.value    = url.searchParams.get('sid') || '';
    
    const type = url.searchParams.get('type');
    if (type === 'tcp' || type === 'http') inTransport.value = 'uot';
    else inTransport.value = 'udp';
    
    importInput.value = '';
    showToast(t('toast_imported'), 'ok');
    handleSave(false);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── Peek key ──────────────────────────────────────────────────────────────────
let peeking = false;
function togglePeek() {
  peeking = !peeking;
  inKey.type = peeking ? 'text' : 'password';
  btnPeekKey.style.color = peeking
    ? 'var(--c-accent)'
    : 'var(--c-txt-3)';
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  applyTranslations();
  setState('disconnected');
  updateDnsVisibility(); // initialise field visibility from current checkbox state
  updateKillSwitchVisibility();

  // Event wiring
  if (window.__TAURI__ && window.__TAURI__.event) {
    window.__TAURI__.event.listen('tunnel-error', (evt) => {
      setState('disconnected');
      showToast(String(evt.payload), 'error');
      alert(String(evt.payload));
    });
  }

  btnConnect.addEventListener('click',       handleToggle);
  
  if (btnAutoConnect) {
    btnAutoConnect.addEventListener('click', async () => {
      if (appState !== 'disconnected') {
        showToast('Disconnect first to run Auto mode', 'error');
        return;
      }
      
      try {
        const raw = await invoke('get_config');
        rawConfig = JSON.parse(raw);
      } catch {
        showToast('Please save your config first', 'error');
        return;
      }

      showToast('Starting Auto search...', 'ok');
      try {
        const mtus = [1500, 1350, 1280];
        const modes = [
          { t: 'udp', w: false, r: false },
          { t: 'uot', w: false, r: false },
          { t: 'uot', w: true, r: false },
          { t: 'uot', w: false, r: true }
        ];

        for (let mode of modes) {
          for (let mtu of mtus) {
            showToast(`Testing: ${mode.t} | WSS: ${mode.w} | XTLS: ${mode.r} | MTU: ${mtu}`);
            
            rawConfig.ostp = rawConfig.ostp || {};
            rawConfig.ostp.mtu = mtu;
            rawConfig.transport = rawConfig.transport || {};
            rawConfig.transport.mode = mode.t;
            rawConfig.transport.wss = mode.w;
            
            if (mode.r) {
              rawConfig.reality = rawConfig.reality || {};
              rawConfig.reality.enabled = true;
            } else if (rawConfig.reality) {
              rawConfig.reality.enabled = false;
            }

            await invoke('save_config', { jsonContent: JSON.stringify(rawConfig, null, 2) });
            
            setState('connecting');
            const ok = await invoke('start_tunnel');
            if (ok) {
              startPolling();
              // Wait a bit to see if it stays connected and ping works
              await new Promise(r => setTimeout(r, 3000));
              try {
                const metrics = await invoke('get_metrics');
                if (metrics && metrics.rtt_ms > 0) {
                  showToast(`Success! Found working config: ${mode.t} (MTU ${mtu})`, 'ok');
                  return; // Stop on first working
                }
              } catch {}
              
              // If we are here, ping failed, so stop and try next
              await invoke('stop_tunnel');
              setState('disconnected');
            }
          }
        }
        showToast('Auto search finished. No working config found.', 'error');
      } catch (err) {
        showToast('Error during auto-connect: ' + String(err), 'error');
      }
    });
  }

  btnGoSettings.addEventListener('click',    () => showScreen('settings'));
  btnBack.addEventListener('click',          () => showScreen('home'));
  btnImport.addEventListener('click',        handleImport);
  btnPeekKey.addEventListener('click',       togglePeek);

  // Theme toggle
  const btnThemeToggle = $('btn-theme-toggle');
  if (btnThemeToggle) {
    btnThemeToggle.addEventListener('click', toggleTheme);
  }
  inOwndns.addEventListener('change', () => {
    updateDnsVisibility();
    scheduleAutoSave();
  });
  inTun.addEventListener('change', () => {
    updateKillSwitchVisibility();
    scheduleAutoSave();
  });
  importInput.addEventListener('keydown', e => { if (e.key === 'Enter') handleImport(); });

  // Auto-save wiring
  const formInputs = document.querySelectorAll('#settings-screen input:not(#in-import-url), #settings-screen textarea, #settings-screen select');
  formInputs.forEach(el => {
    el.addEventListener('input', () => {
      scheduleAutoSave();
      if (appState === 'connected') {
        if (window.__TAURI__ && window.__TAURI__.invoke) {
          window.__TAURI__.invoke('reload_tunnel');
        }
      }
    });
    el.addEventListener('change', scheduleAutoSave);
  });

  btnTestPing.addEventListener('click', runPingTest);

  btnWintunCancel.addEventListener('click', () => {
    wintunModal.classList.add('hidden');
  });

  btnWintunDownload.addEventListener('click', async () => {
    try {
      btnWintunDownload.disabled = true;
      btnWintunDownload.textContent = "Downloading...";
      await invoke('download_wintun');
      wintunModal.classList.add('hidden');
      showToast("Wintun driver downloaded successfully!", "ok");
      handleToggle();
    } catch (err) {
      showToast("Failed to download: " + err, "error");
      alert("Download failed: " + err);
    } finally {
      btnWintunDownload.disabled = false;
      btnWintunDownload.textContent = "Download";
    }
  });

  async function runPingTest() {
    pingValueTxt.textContent = 'Testing...';
    pingValueTxt.className = 'ping-test-value';
    try {
      const metrics = await invoke('get_metrics');
      if (metrics && metrics.rtt_ms > 0) {
        const rtt = metrics.rtt_ms;
        pingValueTxt.textContent = `Target Ping: ${rtt} ms`;
        if (rtt < 80) pingValueTxt.classList.add('good');
        else if (rtt < 200) pingValueTxt.classList.add('warn');
        else pingValueTxt.classList.add('bad');
      } else {
        pingValueTxt.textContent = 'Target Ping: -- ms';
      }
    } catch {
      pingValueTxt.textContent = 'Target Ping: Error';
    }
  }

  // Restore status on app open
  try {
    const code = await invoke('get_tunnel_status');
    if (code > 0) startPolling();
  } catch { /* not in Tauri context */ }

  if (window.__TAURI__?.event) {
    const { listen } = window.__TAURI__.event;
    listen('tray_connect', () => {
      if (appState === 'disconnected') handleToggle();
    });
    listen('tray_disconnect', () => {
      if (appState !== 'disconnected') handleToggle();
    });
  }
});

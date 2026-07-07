import { t, toggleLang, applyTranslations } from './i18n.js';

// ── Tauri invoke shim ────────────────────────────────────────────────────────
let invoke = () => Promise.resolve(null);
if (window.__TAURI__?.core) {
  invoke = window.__TAURI__.core.invoke;
}

// ── JSONC parsing ─────────────────────────────────────────────────────────────
// config.json is JSONC: save_config prepends a `// OSTP Configuration` header
// and the default template carries comments. Strip // line and /* */ block
// comments before JSON.parse, while preserving them inside string literals
// (config values contain URLs like https:// and paths like ./wintun.dll).
function parseJsonc(raw) {
  let out = '';
  let inStr = false, inLine = false, inBlock = false, escaped = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i], n = raw[i + 1];
    if (inLine) { if (c === '\n') { inLine = false; out += c; } continue; }
    if (inBlock) { if (c === '*' && n === '/') { inBlock = false; i++; } continue; }
    if (inStr) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && n === '/') { inLine = true; i++; continue; }
    if (c === '/' && n === '*') { inBlock = true; i++; continue; }
    out += c;
  }
  return JSON.parse(out);
}

// ── State ────────────────────────────────────────────────────────────────────
let appState    = 'disconnected'; // 'disconnected' | 'connecting' | 'connected'
let pollTimer   = null;
let uptimeTimer = null;
let uptimeSecs  = 0;
let rawConfig   = null;
let profiles = [];           // parsed config.json object
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

const btnAddProfile = $('btn-add-profile');
const profilesList  = $('profiles-list');
const profilesEmpty = $('profiles-empty');
const profileModal  = $('profile-modal');
const inProfName    = $('in-prof-name');
const inProfServer  = $('in-prof-server');
const inProfKey     = $('in-prof-key');
const inProfTransport = $('in-prof-transport');
const btnProfDelete = $('btn-prof-delete');
const btnProfCancel = $('btn-prof-cancel');
const btnProfSave   = $('btn-prof-save');

let editingProfileId = null;
const btnBack        = $('btn-back');
const btnImport      = $('btn-import-url');
const btnPeekKey     = $('btn-peek-key');
const importInput    = $('in-import-url');
const inServer       = $('in-server');
const inKey          = $('in-key');
const inSocks        = $('in-socks');
const inDns          = $('in-dns');

const groupCustomDns = $('group-custom-dns');
const inTransport    = $('in-transport');
const groupDnsProxy  = $('group-dns-proxy');
const inDnsDomain    = $('in-dns-domain');
const inDnsRegion    = $('in-dns-region');
const inMtu          = $('in-mtu');
const inTun          = $('in-tun-mode');
const inKillSwitch   = $('in-kill-switch');
const inMux          = $('in-mux-mode');
const inMuxSessions  = $('in-mux-sessions');
const inDebug          = $('in-debug');
const inAutoconnect    = $('in-autoconnect');
const inLaunchStartup  = $('in-launch-startup');

function bindSettingsInputs() {
  const ids = [
    'in-socks', 'in-dns',
    'in-dns-domain', 'in-dns-region',
    'in-mtu', 'in-mux-sessions',
    'in-tun-mode', 'in-kill-switch', 'in-mux-mode',
    'in-debug', 'in-autoconnect', 'in-launch-startup'
  ];
  ids.forEach(id => {
    const el = $(id);
    if (el) el.addEventListener('change', scheduleAutoSave);
    if (el && el.type === 'text') el.addEventListener('input', scheduleAutoSave);
    if (el && el.type === 'password') el.addEventListener('input', scheduleAutoSave);
  });

  if (inTransport) {
    inTransport.addEventListener('change', () => {
      if (inTransport.value === 'dns') {
        groupDnsProxy.style.display = 'flex';
      } else {
        groupDnsProxy.style.display = 'none';
      }
    });
  }
}

const wintunModal        = $('wintun-modal');
const btnWintunCancel    = $('btn-wintun-cancel');
const btnWintunOpen      = $('btn-wintun-open');
const wintunInstallPath  = $('wintun-install-path');

const dnsProberModal     = $('dns-prober-modal');
const proberStatus       = $('prober-status');
const proberList         = $('prober-list');
const btnProberClose     = $('btn-prober-close');
const btnDnsProber       = $('btn-dns-prober');

// ── DNS Prober ───────────────────────────────────────────────────────────────
async function openDnsProber() {
  dnsProberModal.classList.remove('hidden');
  proberList.innerHTML = '';
  proberStatus.textContent = 'Running probes...';

  const domain = inDnsDomain?.value?.trim() || 'example.com';

  let results;
  try {
    results = await invoke('run_dns_prober', { domain });
  } catch (err) {
    proberStatus.textContent = 'Error: ' + err;
    return;
  }

  proberList.innerHTML = '';

  if (!results || results.length === 0) {
    proberStatus.textContent = 'No results.';
    return;
  }

  let bestIp = null;

  results.forEach((r, i) => {
    const isBest = i === 0 && r.latency_ms != null;
    if (isBest && !bestIp) bestIp = r.ip;

    const row = document.createElement('div');
    row.style.cssText = `
      display: flex; align-items: center; justify-content: space-between;
      padding: 6px 10px; border-radius: 6px; cursor: pointer;
      background: ${isBest ? 'rgba(99,179,237,0.12)' : 'rgba(255,255,255,0.04)'};
      border: 1px solid ${isBest ? 'rgba(99,179,237,0.35)' : 'transparent'};
      transition: background 0.15s;
    `;

    const latText = r.latency_ms != null ? `${r.latency_ms} ms` : 'TIMEOUT';
    const latColor = r.latency_ms == null ? '#f56565'
      : r.latency_ms < 50 ? '#68d391'
      : r.latency_ms < 150 ? '#f6e05e'
      : '#fc8181';

    row.innerHTML = `
      <span style="font-size:0.78rem; color: var(--c-txt-1);">${isBest ? '⭐ ' : ''}${r.name}</span>
      <span style="font-size:0.78rem; color: var(--c-txt-2);">${r.ip}</span>
      <span style="font-size:0.78rem; font-weight:600; color:${latColor};">${latText}</span>
    `;

    if (r.latency_ms != null) {
      row.addEventListener('click', () => {
        inDnsRegion.value = r.ip;
        scheduleAutoSave();
        dnsProberModal.classList.add('hidden');
        showToast('DNS server set to ' + r.ip, 'ok');
      });
      row.addEventListener('mouseenter', () => { row.style.background = 'rgba(99,179,237,0.18)'; });
      row.addEventListener('mouseleave', () => { row.style.background = isBest ? 'rgba(99,179,237,0.12)' : 'rgba(255,255,255,0.04)'; });
    }

    proberList.appendChild(row);
  });

  if (bestIp) {
    proberStatus.textContent = `✓ Best: ${bestIp} — click any row to select`;
    // Auto-fill best
    inDnsRegion.value = bestIp;
    scheduleAutoSave();
  } else {
    proberStatus.textContent = 'All servers timed out.';
  }
}

// ── Tag-input state ───────────────────────────────────────────────────────────
// Map of tagId -> Set<string>
const tagState = {
  domains:   new Set(),
  ips:       new Set(),
  processes: new Set(),
};

function renderTagList(key) {
  const list = $('tag-list-' + key);
  if (!list) return;
  list.innerHTML = '';
  for (const val of tagState[key]) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.innerHTML = `${val}<button class="tag-chip-remove" title="Remove" tabindex="-1"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg></button>`;
    chip.querySelector('.tag-chip-remove').addEventListener('click', () => {
      tagState[key].delete(val);
      renderTagList(key);
      scheduleAutoSave();
    });
    list.appendChild(chip);
  }
}

function addTag(key, raw) {
  const vals = raw.split(/[\s,;]+/).map(v => v.trim()).filter(Boolean);
  let added = false;
  for (const v of vals) {
    if (!tagState[key].has(v)) { tagState[key].add(v); added = true; }
  }
  if (added) { renderTagList(key); scheduleAutoSave(); }
}

function wireTagInput(key) {
  const input = $('tag-input-' + key);
  const wrap  = $('tag-wrap-' + key);
  if (!input) return;
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const v = input.value.trim();
      if (v) { addTag(key, v); input.value = ''; }
    } else if (e.key === 'Backspace' && !input.value) {
      const arr = [...tagState[key]];
      if (arr.length) { tagState[key].delete(arr[arr.length - 1]); renderTagList(key); scheduleAutoSave(); }
    }
  });
  input.addEventListener('paste', e => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text');
    addTag(key, text);
    input.value = '';
  });
  // click on wrap focuses input
  if (wrap) wrap.addEventListener('click', () => input.focus());
}

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
    connInfo.classList.remove('hidden');

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
    console.log('[OSTP] poll status code:', code);
    
    if      (code === 0) { setState('disconnected'); return; }
    else if (code === 1)   setState('connecting');
    else if (code === 2)   setState('connected');

    const metrics = await invoke('get_metrics');
    if (metrics && pollTimer) {
      metricDown.textContent = fmtBytes(metrics.bytes_recv);
      metricUp.textContent   = fmtBytes(metrics.bytes_sent);
      if (metrics.rtt_ms > 0 && pingValueTxt.textContent !== 'Testing...') {
        const rtt = metrics.rtt_ms;
        pingValueTxt.textContent = `Target Ping: ${rtt} ms`;
        pingValueTxt.className = 'ping-test-value ' + (rtt < 80 ? 'good' : rtt < 200 ? 'warn' : 'bad');
      }
    }
  } catch (err) {
    console.error('[OSTP] poll threw:', err);
    if (pollTimer) {
      setState('disconnected');
      showToast(String(err), 'error');
      alert('[OSTP POLL ERROR] ' + String(err));
    }
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
      const cfg = parseJsonc(raw);
      serverAddr = cfg.server || '';
    } catch { serverAddr = ''; }

    const activeProfiles = profiles.filter(p => p.active);
    if (activeProfiles.length === 0) {
      showToast('Select at least one profile in Settings', 'error');
      return;
    }

    setState('connecting');
    // Rebuild config.json from the current active profiles so a freshly added,
    // edited or toggled profile actually takes effect on connect.
    await handleSave(true);

    try {
      console.log('[OSTP] invoking start_tunnel...');
      const ok = await invoke('start_tunnel');
      console.log('[OSTP] start_tunnel returned:', ok);
      if (ok) {
        startPolling();
      } else {
        setState('disconnected');
        showToast(t('toast_error') || 'Failed to connect', 'error');
        alert('[OSTP] start_tunnel returned false');
      }
    } catch (err) {
      console.error('[OSTP] start_tunnel threw:', err);
      setState('disconnected');
      if (String(err).includes("WINTUN_MISSING")) {
        if (wintunModal) wintunModal.classList.remove('hidden');
      } else {
        showToast(String(err), 'error');
        alert('[OSTP ERROR] ' + String(err));
      }
    }
  } else {
    setState('disconnected');
    try { await invoke('stop_tunnel'); } catch { /* ignore */ }
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
    rawConfig = parseJsonc(raw);
    const c = rawConfig.mode === 'client' ? rawConfig : null;
    if (!c) return;

    // Restore the profile list from persisted GUI state.
    profiles = rawConfig.gui?.profiles || [];
    renderProfiles();

    const tunIn = (c.inbounds || []).find(i => i.type === 'tun');
    if (tunIn) {
      inTun.checked = true;
      inMtu.value = tunIn.mtu || '';
    } else {
      inTun.checked = false;
    }
    
    const socksIn = (c.inbounds || []).find(i => i.type === 'local_proxy');
    if (socksIn) {
      inSocks.value = `${socksIn.listen || '127.0.0.1'}:${socksIn.port || 1088}`;
    }

    if (inKillSwitch) inKillSwitch.checked = !!c.gui?.kill_switch;
    inDebug.checked = c.log?.level === 'debug';
    
    const ex = c.routing?.rules || [];
    const doms = new Set();
    const ips = new Set();
    const procs = new Set();
    ex.forEach(r => {
       if (r.outbound === 'direct') {
           if (r.domain_suffix) r.domain_suffix.forEach(d => doms.add(d));
           if (r.ip_cidr) r.ip_cidr.forEach(ip => ips.add(ip));
           if (r.process_name) r.process_name.forEach(p => procs.add(p));
       }
    });
    tagState.domains = doms;
    tagState.ips = ips;
    tagState.processes = procs;

    if (inAutoconnect) inAutoconnect.checked = !!c.gui?.autoconnect;
    if (inLaunchStartup) inLaunchStartup.checked = !!c.gui?.launch_startup;

    updateKillSwitchVisibility();
    renderTagList('domains');
    renderTagList('ips');
    renderTagList('processes');
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

  if (inLaunchStartup) {
    try { await invoke('set_autostart', { enable: inLaunchStartup.checked }); } catch (err) { console.error('autostart error', err); }
  }

  const activeProfiles = profiles.filter(p => p.active);
  if (activeProfiles.length === 0) {
    if (!silent) showToast('Please select at least one profile in Settings', 'error');
    return;
  }

  const socksStr = inSocks.value.trim() || '127.0.0.1:1088';
  const socksHost = socksStr.includes(':') ? socksStr.substring(0, socksStr.lastIndexOf(':')) : '127.0.0.1';
  const socksPort = socksStr.includes(':') ? parseInt(socksStr.substring(socksStr.lastIndexOf(':') + 1), 10) : 1088;

  const inbounds = [];
  inbounds.push({
    type: "local_proxy",
    tag: "socks-in",
    protocol: "socks",
    listen: socksHost,
    port: socksPort
  });

  if (inTun.checked) {
    inbounds.push({
      type: "tun",
      tag: "tun-in",
      auto_route: !(inKillSwitch && inKillSwitch.checked), 
      mtu: parseInt(inMtu.value, 10) || 1140
    });
  }

  const outbounds = [];
  const ostpTags = [];

  activeProfiles.forEach((p, i) => {
    const tag = activeProfiles.length > 1 ? `proxy-${i}` : 'proxy';
    ostpTags.push(tag);
    
    const parts = p.serverAddr.split(':');
    const host = parts[0] || '127.0.0.1';
    const port = parseInt(parts[1]) || 50000;
    
    outbounds.push({
      type: "ostp",
      tag: tag,
      server: host,
      port: port,
      access_key: p.accessKey,
      transport: { type: p.transportMode },
      multiplex: inMux.checked ? {
        enabled: true,
        sessions: parseInt(inMuxSessions.value, 10) || 1
      } : { enabled: false, sessions: 1 }
    });
  });

  if (activeProfiles.length > 1) {
    outbounds.push({
      type: "urltest",
      tag: "proxy",
      outbounds: ostpTags,
      url: "http://cp.cloudflare.com",
      interval: "3m"
    });
  }

  outbounds.push({ type: "direct", tag: "direct" }, { type: "block", tag: "block" });

  const rules = [];
  if (tagState.domains.size > 0) rules.push({ domain_suffix: Array.from(tagState.domains), outbound: "direct" });
  if (tagState.ips.size > 0) rules.push({ ip_cidr: Array.from(tagState.ips), outbound: "direct" });
  if (tagState.processes.size > 0) rules.push({ process_name: Array.from(tagState.processes), outbound: "direct" });

  if (inKillSwitch && inKillSwitch.checked && inTun.checked) {
      rules.push({ ip_cidr: ["0.0.0.0/0", "::/0"], outbound: "proxy" });
  }

  rawConfig = {
    mode: 'client',
    version: '0.3.1',
    log: { level: inDebug.checked ? 'debug' : 'info' },
    inbounds,
    outbounds,
    routing: { rules, default_outbound: "proxy" },
    gui: rawConfig.gui || {},
    api: rawConfig.api || undefined
  };

  if (inAutoconnect) rawConfig.gui.autoconnect = inAutoconnect.checked;
  if (inLaunchStartup) rawConfig.gui.launch_startup = inLaunchStartup.checked;
  if (inKillSwitch) rawConfig.gui.kill_switch = inKillSwitch.checked;
  // Persist the full profile list (including inactive ones) so it survives restarts.
  rawConfig.gui.profiles = profiles;

  try {
    const ok = await invoke('save_config', { jsonContent: JSON.stringify(rawConfig, null, 2) });
    if (!ok && !silent) {
      showToast(t('toast_error'), 'error');
    } else if (ok && appState === 'connected') {
      try { await invoke('reload_tunnel'); } catch { }
    }
  } catch (err) {
    if (!silent) showToast(String(err), 'error');
  }
}

// Called by profile add/edit/toggle/delete. saveSettings() was referenced but
// never defined — every profile mutation threw ReferenceError, so nothing
// persisted and the list never re-rendered. It rebuilds config.json (outbounds
// from active profiles) and persists the profile list via handleSave.
function saveSettings() { handleSave(true); }


// ── Import share link ─────────────────────────────────────────────────────────
function handleImport() {
  const raw = importInput.value.trim();
  if (!raw) return;
  try {
    createProfileFromLink(raw);
    importInput.value = '';
    showToast(t('toast_imported') || 'Profile added', 'ok');
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
  updateKillSwitchVisibility();
  bindSettingsInputs();

  // Event wiring
  if (window.__TAURI__ && window.__TAURI__.event) {
    window.__TAURI__.event.listen('tunnel-error', (evt) => {
      setState('disconnected');
      const errStr = String(evt.payload);
      showToast(errStr, 'error');
      alert(errStr);
    });
  }

  // Load wintun install path for modal instruction
  if (wintunInstallPath) {
    try {
      const p = await invoke('get_wintun_install_path');
      if (p) wintunInstallPath.textContent = p;
    } catch { /* ignore */ }
  }

  // Load persisted config (form fields + profiles) so connect has the right
  // inbounds/outbounds even if the user never opens Settings, then auto-connect.
  try {
    await loadConfigIntoForm();
    if (rawConfig?.gui?.autoconnect) {
      setTimeout(() => {
        if (appState === 'disconnected') handleToggle();
      }, 800);
    }
  } catch (err) {
    console.error('Failed to load config on startup', err);
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
        rawConfig = parseJsonc(raw);
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
            
            const ostpOut = (rawConfig.outbounds || []).find(o => o.type === 'ostp');
            if (ostpOut) {
              ostpOut.transport = ostpOut.transport || { type: 'udp' };
              ostpOut.transport.type = mode.t;
              ostpOut.transport.wss = mode.w ? true : undefined;
            } else {
              rawConfig.transport = { mode: mode.t, wss: mode.w };
            }
            
            const tunIn = (rawConfig.inbounds || []).find(i => i.type === 'tun');
            if (tunIn) {
               tunIn.mtu = mtu;
            } else {
               rawConfig.mtu = mtu;
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
  if (btnImport) btnImport.addEventListener('click', handleImport);
  // btn-peek-key / in-key etc. were removed with the old single-server UI.
  // Guard so a missing element can't throw and abort the rest of init wiring.
  if (btnPeekKey) btnPeekKey.addEventListener('click', togglePeek);

  // Theme toggle
  const btnThemeToggle = $('btn-theme-toggle');
  if (btnThemeToggle) {
    btnThemeToggle.addEventListener('click', toggleTheme);
  }
  scheduleAutoSave();
  inTun.addEventListener('change', () => {
    updateKillSwitchVisibility();
    scheduleAutoSave();
  });
  importInput.addEventListener('keydown', e => { if (e.key === 'Enter') handleImport(); });

  // Auto-save wiring for standard form elements (excluding tag-inputs which wire themselves)
  const formInputs = document.querySelectorAll('#settings-screen input:not(#in-import-url):not(.tag-input-field), #settings-screen select');
  formInputs.forEach(el => {
    el.addEventListener('input', scheduleAutoSave);
    el.addEventListener('change', scheduleAutoSave);
  });

  // Wire tag inputs
  wireTagInput('domains');
  wireTagInput('ips');
  wireTagInput('processes');

  btnTestPing.addEventListener('click', runPingTest);

  btnWintunCancel.addEventListener('click', () => {
    wintunModal.classList.add('hidden');
  });

  // DNS Prober modal
  if (btnDnsProber) {
    btnDnsProber.addEventListener('click', openDnsProber);
  }
  if (btnProberClose) {
    btnProberClose.addEventListener('click', () => {
      dnsProberModal.classList.add('hidden');
    });
  }
  // Close prober on backdrop click
  if (dnsProberModal) {
    dnsProberModal.addEventListener('click', (e) => {
      if (e.target === dnsProberModal) dnsProberModal.classList.add('hidden');
    });
  }

  // Open wintun.net link — handled natively by <a target="_blank">, but also wire as fallback
  if (btnWintunOpen && window.__TAURI__) {
    btnWintunOpen.addEventListener('click', (e) => {
      e.preventDefault();
      const opener = window.__TAURI__?.opener || window.__TAURI__?.shell;
      if (opener && opener.open) {
        opener.open('https://www.wintun.net');
      } else {
        window.open('https://www.wintun.net', '_blank');
      }
    });
  }

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


function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderProfiles() {
  const hasProfiles = profiles.length > 0;
  const rowsHtml = profiles.map(p => `
      <div class="profile-item">
        <input type="checkbox" ${p.active ? 'checked' : ''} onchange="toggleProfile('${p.id}')">
        <div class="profile-info">
          <div class="profile-name">${escapeHtml(p.name)}</div>
          <div class="profile-addr">${escapeHtml(p.serverAddr)}</div>
        </div>
        <button class="icon-btn" onclick="shareProfile('${p.id}')" title="Share" style="width:26px;height:26px;">⤴</button>
        <button class="icon-btn" onclick="editProfile('${p.id}')" title="Edit" style="width:26px;height:26px;">✎</button>
      </div>`).join('');

  // Profiles live on the Settings page.
  if (profilesList) profilesList.innerHTML = rowsHtml;
  if (profilesEmpty) profilesEmpty.style.display = hasProfiles ? 'none' : 'block';
  // Settings page shows only "Create a new profile" + "+" until a profile exists.
  const csb = $('client-settings-block');
  if (csb) csb.style.display = hasProfiles ? '' : 'none';
}

window.toggleProfile = function(id) {
  const p = profiles.find(x => x.id === id);
  if (p) { p.active = !p.active; saveSettings(); renderProfiles(); }
};

window.editProfile = function(id) {
  editingProfileId = id;
  const p = profiles.find(x => x.id === id);
  $('profile-modal-title').innerText = 'Edit Profile';
  inProfName.value = p.name;
  inProfServer.value = p.serverAddr;
  inProfKey.value = p.accessKey;
  inProfTransport.value = p.transportMode || 'udp';
  btnProfDelete.style.display = 'block';
  profileModal.classList.remove('hidden');
};

function openProfileModalNew() {
  editingProfileId = null;
  $('profile-modal-title').innerText = 'New Profile';
  inProfName.value = '';
  inProfServer.value = '';
  inProfKey.value = '';
  inProfTransport.value = 'udp';
  if (btnProfDelete) btnProfDelete.style.display = 'none';
  profileModal.classList.remove('hidden');
}
if (btnAddProfile) btnAddProfile.addEventListener('click', () => { const m = $('add-menu'); if (m) m.classList.remove('hidden'); });

// Build / parse the ostp:// share link (key in userinfo, host:port authority,
// transport in ?type, name in #fragment).
function buildShareLink(p) {
  const type = p.transportMode === 'uot' ? 'tcp' : 'udp';
  return `ostp://${encodeURIComponent(p.accessKey)}@${p.serverAddr}?type=${type}#${encodeURIComponent(p.name || '')}`;
}
function createProfileFromLink(raw) {
  if (!raw.startsWith('ostp://')) throw new Error('Link must start with ostp://');
  const url = new URL(raw);
  const key = decodeURIComponent(url.username || '');
  const host = url.host;
  if (!key || !host) throw new Error('Incomplete link');
  const type = url.searchParams.get('type');
  const transportMode = (type === 'tcp' || type === 'http') ? 'uot' : 'udp';
  let name = url.searchParams.get('name');
  if (!name && url.hash) { try { name = decodeURIComponent(url.hash.slice(1)); } catch {} }
  profiles.push({
    id: Date.now().toString(),
    name: name || host,
    serverAddr: host,
    accessKey: key,
    transportMode,
    active: profiles.length === 0,
  });
  saveSettings();
  renderProfiles();
}

// Share a profile: show its link + a scannable QR (QR rendered by the Rust
// `generate_qr` command so the access key never leaves the device).
window.shareProfile = async function(id) {
  const p = profiles.find(x => x.id === id);
  if (!p) return;
  const link = buildShareLink(p);
  const linkInput = $('share-link');
  if (linkInput) linkInput.value = link;
  const qrBox = $('share-qr');
  if (qrBox) {
    qrBox.innerHTML = '<div style="color:var(--c-txt-3);font-size:0.8rem;">Generating…</div>';
    try {
      qrBox.innerHTML = await invoke('generate_qr', { text: link });
    } catch {
      qrBox.innerHTML = '<div style="color:var(--c-red);font-size:0.8rem;">QR unavailable — rebuild app</div>';
    }
  }
  const m = $('share-modal');
  if (m) m.classList.remove('hidden');
};

// ── Add-profile menu + link/share modal wiring ────────────────────
(function wireProfileMenus() {
  const addMenu = $('add-menu');
  const closeAddMenu = () => { if (addMenu) addMenu.classList.add('hidden'); };
  // Clicking the overlay (outside the card) closes the menu.
  if (addMenu) addMenu.addEventListener('click', (e) => { if (e.target === addMenu) closeAddMenu(); });
  if ($('btn-add-cancel')) $('btn-add-cancel').addEventListener('click', closeAddMenu);

  const linkModal = $('link-modal');
  if ($('btn-add-from-link')) $('btn-add-from-link').addEventListener('click', () => {
    closeAddMenu();
    if ($('in-link')) $('in-link').value = '';
    if (linkModal) linkModal.classList.remove('hidden');
  });
  if ($('btn-add-manual')) $('btn-add-manual').addEventListener('click', () => {
    closeAddMenu();
    openProfileModalNew();
  });
  if ($('btn-link-cancel')) $('btn-link-cancel').addEventListener('click', () => { if (linkModal) linkModal.classList.add('hidden'); });
  if ($('btn-link-import')) $('btn-link-import').addEventListener('click', () => {
    const raw = ($('in-link')?.value || '').trim();
    if (!raw) return;
    try { createProfileFromLink(raw); if (linkModal) linkModal.classList.add('hidden'); showToast(t('toast_imported') || 'Profile added', 'ok'); }
    catch (err) { showToast(err.message, 'error'); }
  });
  // Share modal
  if ($('btn-share-close')) $('btn-share-close').addEventListener('click', () => { const m = $('share-modal'); if (m) m.classList.add('hidden'); });
  if ($('btn-share-copy')) $('btn-share-copy').addEventListener('click', () => {
    const v = $('share-link')?.value || '';
    if (v) { navigator.clipboard?.writeText(v); showToast('Copied', 'ok'); }
  });
})();

if (btnProfCancel) btnProfCancel.addEventListener('click', () => profileModal.classList.add('hidden'));

if (btnProfDelete) {
  btnProfDelete.addEventListener('click', () => {
    profiles = profiles.filter(x => x.id !== editingProfileId);
    profileModal.classList.add('hidden');
    saveSettings();
    renderProfiles();
  });
}

if (btnProfSave) {
  btnProfSave.addEventListener('click', () => {
    if (editingProfileId) {
      const p = profiles.find(x => x.id === editingProfileId);
      if (p) {
        p.name = inProfName.value.trim();
        p.serverAddr = inProfServer.value.trim();
        p.accessKey = inProfKey.value;
        p.transportMode = inProfTransport.value;
      }
    } else {
      profiles.push({
        id: Date.now().toString(),
        name: inProfName.value.trim() || 'New Profile',
        serverAddr: inProfServer.value.trim(),
        accessKey: inProfKey.value,
        transportMode: inProfTransport.value,
        active: true
      });
    }
    profileModal.classList.add('hidden');
    saveSettings();
    renderProfiles();
  });
}

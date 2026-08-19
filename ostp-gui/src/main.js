// ── Tauri invoke shim ─────────────────────────────────────────────────
let invoke = () => Promise.resolve(null);
if (window.__TAURI__?.core) {
  invoke = window.__TAURI__.core.invoke;
}

// ── Theme: apply saved theme ASAP (before first paint) to avoid a flash ─
if (localStorage.getItem('ostp_theme') === 'light') {
  document.documentElement.classList.add('light');
}

// ── PROFILE STORE ─────────────────────────────────────────────────────
// Profiles are stored in localStorage only — the core never knows about them.
// Only the active profile is compiled into a config and passed to Tauri.
//
// Profile shape:
// { id: string, name: string, server: string, key: string, transport: 'udp'|'uot' }

const PROFILES_KEY  = 'ostp_profiles_v1';
const ACTIVE_KEY    = 'ostp_active_profile';
const SETTINGS_KEY  = 'ostp_client_settings';

function loadProfiles() {
  try { return JSON.parse(localStorage.getItem(PROFILES_KEY) || '[]'); }
  catch { return []; }
}

function saveProfiles(profiles) {
  localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles));
}

function loadActiveId() {
  return localStorage.getItem(ACTIVE_KEY) || null;
}

function saveActiveId(id) {
  localStorage.setItem(ACTIVE_KEY, id || '');
}

function loadClientSettings() {
  try { return JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}'); }
  catch { return {}; }
}

function saveClientSettings(s) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

// ── APP STATE ─────────────────────────────────────────────────────────
let appState   = 'disconnected'; // 'disconnected'|'connecting'|'connected'
let pollTimer  = null;
let uptimeSecs = 0;
let uptimeTimer = null;

// for throughput calc
let prevBytesRecv = 0, prevBytesSent = 0;

// profiles
let profiles  = loadProfiles();
let activeId  = loadActiveId();

// editor state
let editingProfileId = null; // null = new profile

// ── DOM ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const homeScreen     = $('home-screen');
const settingsScreen = $('settings-screen');
const brandDot       = $('brand-dot');
const orbitWrap      = $('orbit-wrap');
const btnConnect     = $('btn-connect');
const statusText     = $('status-text');
const uptimeText     = $('uptime-text');
const errorBanner    = $('error-banner');
const connInfo       = $('connection-info');
const serverBadge    = $('server-badge-text');
const liveRtt        = $('live-rtt');
const liveDown       = $('live-down-speed');
const liveUp         = $('live-up-speed');
const metricDown     = $('metric-down');
const metricUp       = $('metric-up');
const toast          = $('toast');

const btnGoSettings  = $('btn-go-settings');
const btnAutoConnect = $('btn-auto-connect');
const btnBack        = $('btn-back');

const btnAddProfile  = $('btn-add-profile');
const addMenu        = $('add-menu');
const profileList    = $('profile-list');
const profileEmpty   = $('profile-empty');

// add menu
const addFromLink      = $('add-from-link');
const addFromClipboard = $('add-from-clipboard');
const addManually      = $('add-manually');

// link modal
const linkModal    = $('link-modal');
const linkInput    = $('link-input');
const btnLinkCancel = $('btn-link-cancel');
const btnLinkImport = $('btn-link-import');

// profile editor modal
const profileModal    = $('profile-modal');
const profileModalTitle = $('profile-modal-title');
const pmName    = $('pm-name');
const pmServer  = $('pm-server');
const pmKey     = $('pm-key');
const pmTransport = $('pm-transport');
const btnProfileCancel = $('btn-profile-cancel');
const btnProfileSave   = $('btn-profile-save');
const btnProfileDelete = $('btn-profile-delete');
const btnPeekPm = $('btn-peek-pm');

// share modal
const shareModal   = $('share-modal');
const shareQr      = $('share-qr');
const shareLink    = $('share-link');
const btnShareClose = $('btn-share-close');
const btnShareCopy  = $('btn-share-copy');

// wintun modal
const wintunModal   = $('wintun-modal');
const wintunPath    = $('wintun-install-path');
const btnWintunCancel = $('btn-wintun-cancel');
const btnWintunOpen   = $('btn-wintun-open');

// client settings
const inTun         = $('in-tun-mode');
const inKillSwitch  = $('in-kill-switch');
const inMux         = $('in-mux-mode');
const inMuxSessions = $('in-mux-sessions');
const inMtu         = $('in-mtu');
const inDns         = $('in-dns');
const inSocks       = $('in-socks');
const inExDomains   = $('in-ex-domains');
const inExIps       = $('in-ex-ips');
const inExProcs     = $('in-ex-procs');
const inAutoconnect = $('in-autoconnect');
const inLaunchStartup = $('in-launch-startup');
const inDebug       = $('in-debug');
const inShowRtt     = $('in-show-rtt');
const inShowSpeed   = $('in-show-speed');
const groupKillSwitch  = $('group-kill-switch');
const groupMuxSessions = $('group-mux-sessions');

const inJunkEnabled   = $('cs-junk-enabled');
const btnJunkSettings = $('btn-junk-settings');
const junkModal       = $('junk-modal');
const inJunkPcMin     = $('cs-junk-pc-min');
const inJunkPcMax     = $('cs-junk-pc-max');
const inJunkPsMin     = $('cs-junk-ps-min');
const inJunkPsMax     = $('cs-junk-ps-max');
const btnJunkDone     = $('btn-junk-done');

const inTcpFrag       = $('cs-tcp-frag');
const btnFragSettings = $('btn-frag-settings');
const inTtlDesync     = $('cs-ttl-desync');
const fragModal       = $('frag-modal');
const inFragChunk     = $('cs-frag-chunk');
const inFragSleep     = $('cs-frag-sleep');
const btnFragDone     = $('btn-frag-done');

// ── UTILITIES ─────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (!b || b === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log2(b) / 10), 3);
  return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtTime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const p = n => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${p(m)}:${p(sec)}` : `${p(m)}:${p(sec)}`;
}

let toastTimer = null;
function showToast(msg, variant = '') {
  toast.textContent = msg;
  toast.className = 'toast show' + (variant ? ' is-' + variant : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2600);
}

function showError(msg) {
  errorBanner.textContent = msg;
  errorBanner.classList.remove('hidden');
  btnConnect.classList.add('error');
  setTimeout(() => {
    errorBanner.classList.add('hidden');
    btnConnect.classList.remove('error');
  }, 5000);
}

// ── STATE MACHINE ─────────────────────────────────────────────────────
function setState(next) {
  if (appState === next) return;
  appState = next;

  btnConnect.className = 'power-btn';
  orbitWrap.className  = 'orbit-wrap';
  brandDot.className   = 'brand-dot';
  statusText.className = 'status-label';

  if (next === 'disconnected') {
    statusText.textContent = 'Disconnected';
    uptimeText.textContent  = 'Tap to protect your traffic';
    connInfo.classList.add('hidden');
    metricDown.textContent = liveDown.textContent = '0 B';
    metricUp.textContent   = liveUp.textContent   = '0 B';
    liveRtt.textContent    = '--';
    liveRtt.className      = 'live-stat-value';
    prevBytesRecv = prevBytesSent = 0;
    clearInterval(pollTimer);  pollTimer  = null;
    clearInterval(uptimeTimer); uptimeTimer = null;
    uptimeSecs = 0;

  } else if (next === 'connecting') {
    btnConnect.classList.add('connecting');
    orbitWrap.classList.add('connecting');
    brandDot.classList.add('connecting');
    statusText.classList.add('is-connecting');
    statusText.textContent = 'Connecting…';
    uptimeText.textContent  = 'Establishing secure tunnel';
    connInfo.classList.add('hidden');
    clearInterval(uptimeTimer); uptimeTimer = null;
    uptimeSecs = 0;

  } else if (next === 'connected') {
    btnConnect.classList.add('connected');
    orbitWrap.classList.add('connected');
    brandDot.classList.add('connected');
    statusText.classList.add('is-connected');
    statusText.textContent = 'Connected';

    const active = profiles.find(p => p.id === activeId);
    if (active) {
      serverBadge.textContent = active.server;
      connInfo.classList.remove('hidden');
    }

    uptimeSecs = 0;
    statusText.textContent = 'Connected';
    uptimeTimer = setInterval(() => {
      uptimeSecs++;
      uptimeText.textContent = fmtTime(uptimeSecs);
    }, 1000);
  }
}

// ── POLLING ───────────────────────────────────────────────────────────
async function poll() {
  if (!pollTimer) return;
  try {
    const code = await invoke('get_tunnel_status');
    if (!pollTimer) return;

    if      (code === 0) { setState('disconnected'); return; }
    else if (code === 1) setState('connecting');
    else if (code === 2) setState('connected');

    const metrics = await invoke('get_metrics');
    if (metrics && pollTimer) {
      const recv = metrics.bytes_recv || 0;
      const sent = metrics.bytes_sent || 0;
      const rtt  = metrics.rtt_ms    || 0;

      // Total bytes
      metricDown.textContent = fmtBytes(recv);
      metricUp.textContent   = fmtBytes(sent);

      // Throughput (delta per second)
      const dRecv = Math.max(0, recv - prevBytesRecv);
      const dSent = Math.max(0, sent - prevBytesSent);
      prevBytesRecv = recv; prevBytesSent = sent;
      liveDown.textContent = fmtBytes(dRecv) + '/s';
      liveUp.textContent   = fmtBytes(dSent) + '/s';

      // RTT coloring
      if (rtt > 0) {
        liveRtt.textContent = rtt + ' ms';
        liveRtt.className = 'live-stat-value ' + (rtt < 100 ? 'rtt-good' : rtt < 250 ? 'rtt-warn' : 'rtt-bad');
      }
    }
  } catch (err) {
    console.error('[OSTP] poll error:', err);
    if (pollTimer) setState('disconnected');
  }
}

function startPolling() {
  clearInterval(pollTimer);
  poll();
  pollTimer = setInterval(poll, 1000);
}

// ── BUILD CONFIG from active profile + client settings ────────────────
function buildConfig() {
  const active = profiles.find(p => p.id === activeId);
  if (!active) return null;

  const s = loadClientSettings();
  const cfg = {
    mode: 'client',
    server: active.server,
    access_key: active.key,
    socks5_bind: s.socks || null,
    debug: !!s.debug,
    transport: {
      mode: active.transport || 'udp',
      tcp_fragmentation: s.tcpFrag || !!active.tcp_fragmentation,
      frag_chunk: s.tcpFrag ? (s.fragChunk || 2) : (active.frag_chunk || 2),
      frag_sleep: s.tcpFrag ? (!isNaN(parseInt(s.fragSleep)) ? s.fragSleep : 2) : (active.frag_sleep !== undefined ? active.frag_sleep : 2),
      junk_pc: s.junkEnabled ? [s.junkPcMin || 2, s.junkPcMax || 5] : (active.junk_pc || [2, 5]),
      junk_ps: s.junkEnabled ? [s.junkPsMin || 100, s.junkPsMax || 1000] : (active.junk_ps || [100, 1000]),
      ttl_desync: !!s.ttlDesync,
      ttl_desync_auto: true
    },
    tun: {
      enable: !!s.tun,
      wintun_path: './wintun.dll',
      ipv4_address: '10.1.0.2/24',
      stack: 'ostp',
      dns: s.dns || null,
      kill_switch: !!s.killSwitch,
    },
    exclude: {
      domains: s.exDomains ? s.exDomains.split(/[\n,]+/).map(x => x.trim()).filter(Boolean) : [],
      ips: s.exIps ? s.exIps.split(/[\n,]+/).map(x => x.trim()).filter(Boolean) : [],
      processes: s.exProcs ? s.exProcs.split(/[\n,]+/).map(x => x.trim()).filter(Boolean) : [],
    },
    mux: s.mux ? { enabled: true, sessions: parseInt(s.muxSessions, 10) || 2 } : undefined,
    gui: {
      autoconnect: !!s.autoconnect,
      launch_startup: !!s.launchStartup,
    },
  };
  if (s.mtu) cfg.mtu = parseInt(s.mtu, 10);
  return cfg;
}

// ── CONNECT / DISCONNECT ──────────────────────────────────────────────
async function handleToggle() {
  if (appState !== 'disconnected') {
    setState('disconnected');
    try { await invoke('stop_tunnel'); } catch { /* ignore */ }
    showToast('Disconnected');
    return;
  }

  if (!activeId || !profiles.find(p => p.id === activeId)) {
    showToast('Select a profile first', 'error');
    return;
  }

  const cfg = buildConfig();
  if (!cfg) { showToast('Active profile invalid', 'error'); return; }

  setState('connecting');
  errorBanner.classList.add('hidden');

  try {
    await invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) });
    const ok = await invoke('start_tunnel');
    if (ok) {
      startPolling();
    } else {
      setState('disconnected');
      showError('Failed to start tunnel. Check the log file.');
    }
  } catch (err) {
    setState('disconnected');
    const msg = String(err);
    if (msg.includes('WINTUN_MISSING')) {
      wintunModal.classList.remove('hidden');
    } else {
      showError(msg);
      showToast(msg, 'error');
    }
  }
}

// ── AUTO-CONNECT ──────────────────────────────────────────────────────
async function handleAutoConnect() {
  if (appState !== 'disconnected') {
    showToast('Disconnect first', 'error'); return;
  }
  if (!activeId || !profiles.find(p => p.id === activeId)) {
    showToast('Select a profile first', 'error'); return;
  }

  const modes = ['udp', 'uot'];
  const mtus  = [1500, 1350, 1280];

  showToast('Auto-connect: scanning…');

  for (const transport of modes) {
    for (const mtu of mtus) {
      showToast(`Testing ${transport.toUpperCase()} · MTU ${mtu}`);
      const active = profiles.find(p => p.id === activeId);
      const tmpCfg = buildConfig();
      if (!tmpCfg) return;
      tmpCfg.transport.mode = transport;
      tmpCfg.mtu = mtu;

      try {
        await invoke('save_config', { jsonContent: JSON.stringify(tmpCfg, null, 2) });
        setState('connecting');
        const ok = await invoke('start_tunnel');
        if (ok) {
          await new Promise(r => setTimeout(r, 3000));
          const metrics = await invoke('get_metrics');
          if (metrics?.rtt_ms > 0) {
            startPolling();
            showToast(`✓ ${transport.toUpperCase()} · MTU ${mtu}`, 'ok');
            return;
          }
          await invoke('stop_tunnel');
          setState('disconnected');
        }
      } catch { setState('disconnected'); }
    }
  }
  showToast('No working config found', 'error');
}

// ── SCREEN NAVIGATION ─────────────────────────────────────────────────
function showScreen(name) {
  if (name === 'settings') {
    loadSettingsIntoForm();
    homeScreen.classList.remove('active');
    settingsScreen.classList.add('active');
  } else {
    settingsScreen.classList.remove('active');
    homeScreen.classList.add('active');
  }
}

// ── PROFILE RENDERING ─────────────────────────────────────────────────
function renderProfiles() {
  // Remove all cards but keep empty-state node
  Array.from(profileList.querySelectorAll('.profile-card')).forEach(n => n.remove());

  if (profiles.length === 0) {
    profileEmpty.style.display = '';
    return;
  }
  profileEmpty.style.display = 'none';

  profiles.forEach(p => {
    const card = document.createElement('div');
    card.className = 'profile-card' + (p.id === activeId ? ' active' : '');
    card.dataset.id = p.id;
    card.innerHTML = `
      <div class="profile-radio">
        <div class="profile-radio-dot"></div>
      </div>
      <div class="profile-info">
        <div class="profile-name">${escHtml(p.name || p.server)}</div>
        <div class="profile-server">${escHtml(p.server)}</div>
      </div>
      <span class="profile-transport-badge">${escHtml(p.transport || 'udp')}</span>
      <div class="profile-actions">
        <button class="profile-action-btn btn-share-profile" title="Share" data-id="${p.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </button>
        <button class="profile-action-btn btn-edit-profile" title="Edit" data-id="${p.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
      </div>
    `;

    // Select profile on card click (not on action buttons)
    card.addEventListener('click', e => {
      if (e.target.closest('.profile-action-btn')) return;
      activeId = p.id;
      saveActiveId(activeId);
      renderProfiles();
      // Auto-save into config
      const cfg = buildConfig();
      if (cfg) invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) }).catch(() => {});
    });

    card.querySelector('.btn-edit-profile').addEventListener('click', e => {
      e.stopPropagation();
      openProfileEditor(p.id);
    });
    card.querySelector('.btn-share-profile').addEventListener('click', e => {
      e.stopPropagation();
      openShare(p.id);
    });

    profileList.appendChild(card);
  });
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── PROFILE EDITOR ────────────────────────────────────────────────────
function openProfileEditor(id) {
  editingProfileId = id || null;
  if (id) {
    const p = profiles.find(p => p.id === id);
    if (!p) return;
    profileModalTitle.textContent = 'Edit Profile';
    pmName.value = p.name || '';
    pmServer.value = p.server || '';
    pmKey.value = p.key || '';
    pmTransport.value = p.transport || 'udp';
    btnProfileDelete.style.display = '';
  } else {
    profileModalTitle.textContent = 'New Profile';
    pmName.value = pmServer.value = pmKey.value = '';
    pmTransport.value = 'udp';
    btnProfileDelete.style.display = 'none';
  }
  pmKey.type = 'password';
  profileModal.classList.remove('hidden');
  setTimeout(() => pmName.focus(), 80);
}

function saveProfileFromEditor() {
  const server = pmServer.value.trim();
  const key    = pmKey.value.trim();
  if (!server) { showToast('Server address required', 'error'); return; }
  if (!key)    { showToast('Access key required', 'error'); return; }

  if (editingProfileId) {
    const idx = profiles.findIndex(p => p.id === editingProfileId);
    if (idx >= 0) {
      profiles[idx] = { ...profiles[idx],
        name: pmName.value.trim() || server,
        server,
        key,
        transport: pmTransport.value,
      };
    }
  } else {
    const p = {
      id: genId(),
      name: pmName.value.trim() || server,
      server,
      key,
      transport: pmTransport.value,
    };
    profiles.push(p);
    if (!activeId) { activeId = p.id; saveActiveId(activeId); }
  }

  saveProfiles(profiles);
  profileModal.classList.add('hidden');
  renderProfiles();
  showToast('Profile saved', 'ok');

  // Persist config if this is the active profile
  const cfg = buildConfig();
  if (cfg) invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) }).catch(() => {});
}

function deleteEditingProfile() {
  if (!editingProfileId) return;
  profiles = profiles.filter(p => p.id !== editingProfileId);
  if (activeId === editingProfileId) {
    activeId = profiles[0]?.id || null;
    saveActiveId(activeId);
  }
  saveProfiles(profiles);
  profileModal.classList.add('hidden');
  renderProfiles();
  showToast('Profile deleted');
}

// ── PARSE ostp:// link ─────────────────────────────────────────────────
function parseOstpLink(raw) {
  raw = raw.trim();
  if (!raw.startsWith('ostp://')) throw new Error('Must start with ostp://');
  const url = new URL(raw);
  const key  = decodeURIComponent(url.username);
  // host includes port
  const server = url.host;
  if (!key || !server) throw new Error('Incomplete link');
  const type = url.searchParams.get('type') || 'udp';
  const transport = (type === 'tcp' || type === 'http' || type === 'uot') ? 'uot' : 'udp';
  const name = url.searchParams.get('name') || server;
  return { name, server, key, transport };
}

function importFromLink(raw) {
  try {
    const parsed = parseOstpLink(raw);
    // Pre-fill editor
    editingProfileId = null;
    profileModalTitle.textContent = 'New Profile';
    pmName.value = parsed.name;
    pmServer.value = parsed.server;
    pmKey.value = parsed.key;
    pmTransport.value = parsed.transport;
    btnProfileDelete.style.display = 'none';
    profileModal.classList.remove('hidden');
    showToast('Link imported — tap Save', 'ok');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── SHARE ─────────────────────────────────────────────────────────────
function buildShareLink(p) {
  const params = [];
  if (p.transport && p.transport !== 'udp') params.push(`type=${p.transport}`);
  if (p.name) params.push(`name=${encodeURIComponent(p.name)}`);
  const qs = params.length ? '?' + params.join('&') : '';
  return `ostp://${encodeURIComponent(p.key)}@${p.server}${qs}`;
}

async function openShare(id) {
  const p = profiles.find(p => p.id === id);
  if (!p) return;
  const link = buildShareLink(p);
  shareLink.value = link;
  shareQr.innerHTML = '';
  try {
    const svg = await invoke('generate_qr', { text: link });
    if (svg) shareQr.innerHTML = svg;
  } catch { /* QR optional */ }
  shareModal.classList.remove('hidden');
}

// ── CLIENT SETTINGS ───────────────────────────────────────────────────
function loadSettingsIntoForm() {
  const s = loadClientSettings();
  inTun.checked         = !!s.tun;
  inKillSwitch.checked  = !!s.killSwitch;
  inMux.checked         = !!s.mux;
  inMuxSessions.value   = s.muxSessions || '2';
  inMtu.value           = s.mtu || '';
  inDns.value           = s.dns || '';
  inSocks.value         = s.socks || '';
  inExDomains.value     = s.exDomains || '';
  inExIps.value         = s.exIps || '';
  inExProcs.value       = s.exProcs || '';
  inAutoconnect.checked = !!s.autoconnect;
  inLaunchStartup.checked = !!s.launchStartup;
  inDebug.checked       = !!s.debug;
  inShowRtt.checked     = s.showRtt !== false;
  inShowSpeed.checked   = s.showSpeed !== false;
  inJunkEnabled.checked = !!s.junkEnabled;
  inJunkPcMin.value     = s.junkPcMin || 2;
  inJunkPcMax.value     = s.junkPcMax || 5;
  inJunkPsMin.value     = s.junkPsMin || 100;
  inJunkPsMax.value     = s.junkPsMax || 1000;
  inTcpFrag.checked     = !!s.tcpFrag;
  inFragChunk.value     = s.fragChunk || 2;
  inFragSleep.value     = !isNaN(parseInt(s.fragSleep)) ? s.fragSleep : 2;
  if (inTtlDesync) inTtlDesync.checked = !!s.ttlDesync;
  updateClientVisibility();
}

// Last values actually pushed to the OS / backend, so repeated saves that did
// not change them stay free. Undefined until the first save, which is correct:
// the first one should apply.
let lastAppliedAutostart;
let lastAppliedTunnelConfig;
let hotReloadTimer;

function collectAndSaveSettings() {
  const s = {
    tun:          inTun.checked,
    killSwitch:   inKillSwitch.checked,
    mux:          inMux.checked,
    muxSessions:  inMuxSessions.value.trim(),
    mtu:          inMtu.value.trim(),
    dns:          inDns.value.trim(),
    socks:        inSocks.value.trim(),
    exDomains:    inExDomains.value.trim(),
    exIps:        inExIps.value.trim(),
    exProcs:      inExProcs.value.trim(),
    autoconnect:  inAutoconnect.checked,
    launchStartup: inLaunchStartup.checked,
    debug:        inDebug.checked,
    showRtt:      inShowRtt.checked,
    showSpeed:    inShowSpeed.checked,
    junkEnabled:  inJunkEnabled.checked,
    junkPcMin:    parseInt(inJunkPcMin.value) || 2,
    junkPcMax:    parseInt(inJunkPcMax.value) || 5,
    junkPsMin:    parseInt(inJunkPsMin.value) || 100,
    junkPsMax:    parseInt(inJunkPsMax.value) || 1000,
    tcpFrag:      inTcpFrag.checked,
    fragChunk:    parseInt(inFragChunk.value) || 2,
    fragSleep:    !isNaN(parseInt(inFragSleep.value)) ? parseInt(inFragSleep.value) : 2,
    ttlDesync:    inTtlDesync ? inTtlDesync.checked : false,
  };
  // Cheap and local: safe to run on every debounced keystroke.
  saveClientSettings(s);
  updateClientVisibility();

  // Everything below talks to the OS or restarts the tunnel. Running it per
  // keystroke is what made typing in the exclusion fields lag by seconds: the
  // 400ms debounce fires during natural pauses in typing, and each firing hit
  // the Windows registry and then tore down and rebuilt the tunnel.

  // Only touch autostart when it actually changed — this is a registry write.
  if (s.launchStartup !== lastAppliedAutostart) {
    lastAppliedAutostart = s.launchStartup;
    invoke('set_autostart', { enable: s.launchStartup }).catch(() => {});
  }

  // Hot-reload the tunnel only when something it actually reads has changed,
  // and on a much longer debounce: a reload is disruptive, so it should land
  // once the user has stopped editing rather than between keystrokes.
  if (appState === 'connected') {
    const tunnelRelevant = JSON.stringify([
      s.tun, s.killSwitch, s.mux, s.muxSessions, s.mtu, s.dns, s.socks,
      s.exDomains, s.exIps, s.exProcs, s.junkEnabled, s.junkPcMin, s.junkPcMax,
      s.junkPsMin, s.junkPsMax, s.tcpFrag, s.fragChunk, s.fragSleep, s.ttlDesync,
    ]);
    if (tunnelRelevant !== lastAppliedTunnelConfig) {
      clearTimeout(hotReloadTimer);
      hotReloadTimer = setTimeout(() => {
        lastAppliedTunnelConfig = tunnelRelevant;
        const cfg = buildConfig();
        if (cfg) {
          invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) })
            .then(() => invoke('reload_tunnel'))
            .catch(() => {});
        }
      }, 1500);
    }
  }
}

function updateClientVisibility() {
  groupKillSwitch.style.display  = inTun.checked  ? 'flex' : 'none';
  groupMuxSessions.style.display = inMux.checked  ? 'flex' : 'none';

  const showRtt = inShowRtt.checked;
  const showSpeed = inShowSpeed.checked;
  const rttBox = $('stat-rtt-box');
  const downBox = $('stat-down-box');
  const upBox = $('stat-up-box');
  const sep1 = $('stat-sep-1');
  const sep2 = $('stat-sep-2');
  const container = $('live-stats-container');

  if (rttBox) rttBox.style.display = showRtt ? 'flex' : 'none';
  if (downBox) downBox.style.display = showSpeed ? 'flex' : 'none';
  if (upBox) upBox.style.display = showSpeed ? 'flex' : 'none';
  
  if (sep1) sep1.style.display = (showRtt && showSpeed) ? 'block' : 'none';
  if (sep2) sep2.style.display = showSpeed ? 'block' : 'none';
  if (container) container.style.display = (showRtt || showSpeed) ? 'flex' : 'none';
}

// ── INIT ──────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {

  // Render profiles
  renderProfiles();

  // Restore tunnel state if already running
  try {
    const code = await invoke('get_tunnel_status');
    if (code > 0) {
      setState(code === 1 ? 'connecting' : 'connected');
      startPolling();
    }
  } catch { /* not in Tauri */ }

  // Wintun path
  try {
    const p = await invoke('get_wintun_install_path');
    if (p && wintunPath) wintunPath.textContent = p;
  } catch { /* ignore */ }

  // Tauri events
  if (window.__TAURI__?.event) {
    const { listen } = window.__TAURI__.event;
    listen('tunnel-error', evt => {
      setState('disconnected');
      showError(String(evt.payload));
    });
    listen('tray_connect', () => { if (appState === 'disconnected') handleToggle(); });
    listen('tray_disconnect', () => { if (appState !== 'disconnected') handleToggle(); });
  }

  // Auto-connect on startup
  try {
    const s = loadClientSettings();
    if (s.autoconnect && appState === 'disconnected') {
      setTimeout(() => { if (appState === 'disconnected') handleToggle(); }, 800);
    }
  } catch { /* ignore */ }

  // ── Event wiring ──────────────────────────────────────────────────

  btnConnect.addEventListener('click', handleToggle);
  btnAutoConnect.addEventListener('click', handleAutoConnect);
  btnGoSettings.addEventListener('click', () => showScreen('settings'));
  btnBack.addEventListener('click', () => showScreen('home'));

  // Theme toggle (dark ⇄ light), persisted in localStorage
  const btnTheme = $('btn-theme');
  if (btnTheme) btnTheme.addEventListener('click', () => {
    const isLight = document.documentElement.classList.toggle('light');
    localStorage.setItem('ostp_theme', isLight ? 'light' : 'dark');
  });

  // GUI version shown at the bottom of Settings
  const appVersionEl = $('app-version');
  if (appVersionEl) {
    const setV = v => { appVersionEl.textContent = 'OSTP GUI v' + v; };
    if (window.__TAURI__?.app?.getVersion) {
      window.__TAURI__.app.getVersion().then(setV).catch(() => setV('0.4.1'));
    } else {
      setV('0.4.1');
    }
  }

  // Add-profile button → dropdown
  btnAddProfile.addEventListener('click', e => {
    e.stopPropagation();
    addMenu.classList.toggle('hidden');
  });
  document.addEventListener('click', e => {
    if (!addMenu.classList.contains('hidden') && !addMenu.contains(e.target) && e.target !== btnAddProfile) {
      addMenu.classList.add('hidden');
    }
  });

  addFromLink.addEventListener('click', () => {
    addMenu.classList.add('hidden');
    linkModal.classList.remove('hidden');
    setTimeout(() => linkInput.focus(), 80);
    linkInput.value = '';
  });

  addFromClipboard.addEventListener('click', async () => {
    addMenu.classList.add('hidden');
    try {
      const text = await navigator.clipboard.readText();
      if (text.startsWith('ostp://')) {
        importFromLink(text);
      } else {
        showToast('No ostp:// link in clipboard', 'error');
      }
    } catch {
      showToast('Cannot read clipboard', 'error');
    }
  });

  addManually.addEventListener('click', () => {
    addMenu.classList.add('hidden');
    openProfileEditor(null);
  });

  // Link modal
  btnLinkCancel.addEventListener('click', () => linkModal.classList.add('hidden'));
  btnLinkImport.addEventListener('click', () => {
    importFromLink(linkInput.value);
    linkModal.classList.add('hidden');
  });
  linkInput.addEventListener('keydown', e => { if (e.key === 'Enter') btnLinkImport.click(); });
  linkModal.addEventListener('click', e => { if (e.target === linkModal) linkModal.classList.add('hidden'); });

  // Profile editor modal
  btnProfileCancel.addEventListener('click', () => profileModal.classList.add('hidden'));
  btnProfileSave.addEventListener('click', saveProfileFromEditor);
  btnProfileDelete.addEventListener('click', deleteEditingProfile);
  btnPeekPm.addEventListener('click', () => {
    pmKey.type = pmKey.type === 'password' ? 'text' : 'password';
  });
  profileModal.addEventListener('click', e => { if (e.target === profileModal) profileModal.classList.add('hidden'); });

  // Share modal
  btnShareClose.addEventListener('click', () => shareModal.classList.add('hidden'));
  btnShareCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(shareLink.value);
      showToast('Link copied', 'ok');
    } catch {
      shareLink.select();
      document.execCommand('copy');
      showToast('Link copied', 'ok');
    }
  });
  shareModal.addEventListener('click', e => { if (e.target === shareModal) shareModal.classList.add('hidden'); });

  // Wintun modal
  btnWintunCancel.addEventListener('click', () => wintunModal.classList.add('hidden'));
  if (btnWintunOpen && window.__TAURI__) {
    btnWintunOpen.addEventListener('click', e => {
      e.preventDefault();
      const opener = window.__TAURI__?.opener || window.__TAURI__?.shell;
      if (opener?.open) opener.open('https://www.wintun.net');
      else window.open('https://www.wintun.net', '_blank');
    });
  }
  wintunModal.addEventListener('click', e => { if (e.target === wintunModal) wintunModal.classList.add('hidden'); });

  // Client settings — wire all inputs
  [inTun, inKillSwitch, inMux, inAutoconnect, inLaunchStartup, inDebug, inShowRtt, inShowSpeed, inJunkEnabled, inTcpFrag, inTtlDesync]
    .filter(Boolean)
    .forEach(el => el.addEventListener('change', collectAndSaveSettings));
  [inMuxSessions, inMtu, inDns, inSocks, inExDomains, inExIps, inExProcs, inJunkPcMin, inJunkPcMax, inJunkPsMin, inJunkPsMax, inFragChunk, inFragSleep]
    .forEach(el => {
      el.addEventListener('input', () => {
        clearTimeout(el._saveTimer);
        el._saveTimer = setTimeout(collectAndSaveSettings, 400);
      });
    });

  // Junk and Frag modals
  btnJunkSettings.addEventListener('click', () => junkModal.classList.remove('hidden'));
  btnJunkDone.addEventListener('click', () => {
    collectAndSaveSettings();
    junkModal.classList.add('hidden');
  });
  junkModal.addEventListener('click', e => { if (e.target === junkModal) junkModal.classList.add('hidden'); });

  btnFragSettings.addEventListener('click', () => fragModal.classList.remove('hidden'));
  btnFragDone.addEventListener('click', () => {
    collectAndSaveSettings();
    fragModal.classList.add('hidden');
  });
  fragModal.addEventListener('click', e => { if (e.target === fragModal) fragModal.classList.add('hidden'); });

  // ── Global Keyboard Shortcuts (TUI emulation) ─────────────────────
  window.addEventListener('keydown', async e => {
    // Ignore if typing in an input or textarea
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

    if (e.code === 'Space') {
      e.preventDefault();
      handleToggle();
    } else if (e.code === 'Tab') {
      e.preventDefault();
      if (profiles.length > 0) {
        let idx = profiles.findIndex(p => p.id === activeId);
        idx = (idx + 1) % profiles.length;
        activeId = profiles[idx].id;
        saveActiveId(activeId);
        renderProfiles();
        const cfg = buildConfig();
        if (cfg) invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) }).catch(() => {});
        showToast('Profile: ' + profiles[idx].name);
      }
    } else if (e.key === 'b' || e.key === 'B') {
      // Hide to tray (background)
      try { invoke('hide_window'); } catch { window.close(); }
    } else if (e.key === 'q' || e.key === 'Q' || e.key === 'Escape') {
      // Quit
      if (e.key === 'Escape') {
        // if modals are open, don't quit
        if (!linkModal.classList.contains('hidden') || 
            !profileModal.classList.contains('hidden') || 
            !shareModal.classList.contains('hidden') || 
            !wintunModal.classList.contains('hidden') ||
            !junkModal.classList.contains('hidden') ||
            !fragModal.classList.contains('hidden') ||
            !addMenu.classList.contains('hidden')) {
          return;
        }
      }
      try { invoke('close_window'); } catch { window.close(); }
    }
  });
});


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
// { id: string, name: string, server: string, key: string, transport: 'udp'|'uot',
//   tls?: bool, tls_sni?: string, tls_insecure?: bool, ws_path?: string,
//   sub_id?: string }   // set on profiles owned by a subscription

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
const pmTlsGroup  = $('pm-tls-group');
const pmTlsFields = $('pm-tls-fields');
const pmTls       = $('pm-tls');
const pmSni       = $('pm-sni');
const pmWsPath    = $('pm-ws-path');
const pmTlsInsecure = $('pm-tls-insecure');

// With SNI empty the client uses the host from the Server field: show it.
function updateSniHint() {
  const s = pmServer.value.trim();
  const host = s.startsWith('[') ? s.slice(1, s.indexOf(']')) : (s.lastIndexOf(':') > 0 ? s.slice(0, s.lastIndexOf(':')) : s);
  pmSni.placeholder = host ? `${host} (from Server)` : 'the host from Server';
}
pmServer.addEventListener('input', updateSniHint);

// TLS only exists on UoT; its details only while it is on.
function updateTlsVisibility() {
  pmTlsGroup.style.display = pmTransport.value === 'uot' ? '' : 'none';
  pmTlsFields.style.display = pmTls.checked ? '' : 'none';
}
pmTransport.addEventListener('change', updateTlsVisibility);
pmTls.addEventListener('change', updateTlsVisibility);

function setTlsFields(p) {
  pmTls.checked = !!p.tls;
  pmSni.value = p.tls_sni || '';
  pmWsPath.value = p.ws_path || '';
  pmTlsInsecure.checked = !!p.tls_insecure;
  updateTlsVisibility();
  updateSniHint();
}

function tlsFieldsFromEditor() {
  const uot = pmTransport.value === 'uot';
  return {
    tls: uot && pmTls.checked,
    tls_sni: pmSni.value.trim(),
    tls_insecure: pmTlsInsecure.checked,
    ws_path: pmWsPath.value.trim(),
  };
}
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
    config_version: 2,
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
      ttl_desync_auto: true,
      tls: (active.transport === 'uot') && !!active.tls,
      tls_sni: active.tls_sni || null,
      tls_insecure: !!active.tls_insecure,
      ws_path: active.ws_path || null
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
  const prober = $('prober-screen');
  [homeScreen, settingsScreen, prober].forEach(s => s.classList.remove('active'));
  if (name === 'settings') {
    loadSettingsIntoForm();
    renderSubs();
    settingsScreen.classList.add('active');
  } else if (name === 'prober') {
    fillProberProfiles();
    prober.classList.add('active');
  } else {
    homeScreen.classList.add('active');
  }
}

// ── PROFILE RENDERING ─────────────────────────────────────────────────
// Profiles added by hand are listed here; a subscription's profiles are
// listed inside its card (renderSubs), since every refresh rewrites them.
function renderProfiles() {
  // Remove all cards but keep empty-state node
  Array.from(profileList.querySelectorAll('.profile-card')).forEach(n => n.remove());
  const manual = profiles.filter(p => !p.sub_id);
  const hasSubs = loadSubs().length > 0;
  profileEmpty.style.display = manual.length || hasSubs ? 'none' : '';
  manual.forEach(p => profileList.appendChild(profileCard(p)));
  renderSubs();
}

function profileCard(p) {
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
      <span class="profile-transport-badge">${escHtml(p.transport === 'uot' && p.tls ? 'tls' : (p.transport || 'udp'))}</span>
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

    return card;
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
    setTlsFields(p);
    btnProfileDelete.style.display = '';
  } else {
    profileModalTitle.textContent = 'New Profile';
    pmName.value = pmServer.value = pmKey.value = '';
    pmTransport.value = 'udp';
    setTlsFields({});
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
        ...tlsFieldsFromEditor(),
      };
    }
  } else {
    const p = {
      id: genId(),
      name: pmName.value.trim() || server,
      server,
      key,
      transport: pmTransport.value,
      ...tlsFieldsFromEditor(),
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
// Port of ostp-core/src/share_link.rs (and the Flutter copy): keep in step.
const truthy = v => ['1', 'true', 'yes'].includes(String(v).toLowerCase());
const linkDecode = s => decodeURIComponent(s.replace(/\+/g, ' '));
// RFC 3986 unreserved stay; encodeURIComponent also leaves !'()* alone.
const linkEncode = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

function splitHostPort(hostPort) {
  let host, port;
  if (hostPort.startsWith('[')) {
    const end = hostPort.indexOf(']');
    if (end < 0) throw new Error('Unterminated IPv6 address');
    host = hostPort.slice(1, end);
    if (hostPort[end + 1] !== ':') throw new Error('Link has no port');
    port = hostPort.slice(end + 2);
  } else {
    const c = hostPort.lastIndexOf(':');
    if (c < 0) throw new Error('Link has no port');
    host = hostPort.slice(0, c);
    port = hostPort.slice(c + 1);
  }
  const n = Number(port);
  if (!host || !/^\d+$/.test(port) || n > 65535) throw new Error('Invalid host or port');
  return { host, port: n };
}

function parseOstpLink(raw) {
  raw = raw.trim();
  if (!raw.toLowerCase().startsWith('ostp://')) throw new Error('Must start with ostp://');
  let rest = raw.slice(7).split('#')[0];
  const q = rest.indexOf('?');
  const authority = (q >= 0 ? rest.slice(0, q) : rest).replace(/\/+$/, '');
  const query = q >= 0 ? rest.slice(q + 1) : '';
  const at = authority.lastIndexOf('@');
  if (at < 0) throw new Error('Link has no access key');
  const key = linkDecode(authority.slice(0, at));
  if (!key) throw new Error('Link has an empty access key');
  const { host, port } = splitHostPort(authority.slice(at + 1));
  const server = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;

  const out = { name: host, server, key, transport: 'udp', tls: false, tls_sni: '', tls_insecure: false, ws_path: '' };
  for (const pair of query.split('&').filter(Boolean)) {
    const eq = pair.indexOf('=');
    const k = eq >= 0 ? pair.slice(0, eq) : pair;
    const v = linkDecode(eq >= 0 ? pair.slice(eq + 1) : '');
    if (k === 'type') out.transport = ['uot', 'tcp', 'http'].includes(v.toLowerCase()) ? 'uot' : 'udp';
    else if (k === 'tls') out.tls = truthy(v);
    else if (k === 'sni') out.tls_sni = v;
    else if (k === 'insecure') out.tls_insecure = truthy(v);
    else if (k === 'path') out.ws_path = v;
    else if (k === 'name' && v) out.name = v;
  }
  if (out.tls || out.ws_path) out.transport = 'uot';
  return out;
}

function importFromLink(raw) {
  if (isSubscriptionUrl(raw)) { addSubscription(raw.trim()); return; }
  try {
    const parsed = parseOstpLink(raw);
    // Pre-fill editor
    editingProfileId = null;
    profileModalTitle.textContent = 'New Profile';
    pmName.value = parsed.name;
    pmServer.value = parsed.server;
    pmKey.value = parsed.key;
    pmTransport.value = parsed.transport;
    setTlsFields(parsed);
    btnProfileDelete.style.display = 'none';
    profileModal.classList.remove('hidden');
    showToast('Link imported — tap Save', 'ok');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── SHARE ─────────────────────────────────────────────────────────────
function buildShareLink(p) {
  const uot = p.transport === 'uot';
  const tls = uot && !!p.tls;
  const params = [`type=${uot ? 'uot' : 'udp'}`];
  if (tls) params.push('tls=1');
  if (tls && p.tls_sni) params.push(`sni=${linkEncode(p.tls_sni)}`);
  if (tls && p.tls_insecure) params.push('insecure=1');
  if (uot && p.ws_path) params.push(`path=${linkEncode(p.ws_path)}`);
  if (p.name) params.push(`name=${linkEncode(p.name)}`);
  return `ostp://${linkEncode(p.key)}@${p.server}?${params.join('&')}`;
}

async function openShare(id) {
  const p = profiles.find(p => p.id === id);
  if (!p) return;
  showShare('Share Profile', buildShareLink(p));
}

async function showShare(title, text) {
  $('share-title').textContent = title;
  shareLink.value = text;
  shareQr.innerHTML = '';
  const err = $('share-qr-error');
  err.style.display = 'none';
  shareModal.classList.remove('hidden');
  try {
    const svg = await invoke('generate_qr', { text });
    if (svg) shareQr.innerHTML = svg;
    else throw new Error('QR codes need the desktop app');
  } catch (e) {
    err.textContent = 'QR code unavailable: ' + (e?.message || e);
    err.style.display = '';
  }
}

// ── SUBSCRIPTIONS ─────────────────────────────────────────────────────
// A subscription URL (https://<domain>/sub/<token>) returns the user's
// current links. Its profiles carry sub_id and are rewritten on every
// refresh, so server-side changes reach the app without a new link.
const SUBS_KEY = 'ostp_subscriptions_v1';

function loadSubs() {
  try { return JSON.parse(localStorage.getItem(SUBS_KEY) || '[]'); }
  catch { return []; }
}
function saveSubs(subs) { localStorage.setItem(SUBS_KEY, JSON.stringify(subs)); }

const isSubscriptionUrl = s => /^https:\/\//i.test(String(s).trim());
const subIsDue = s => Date.now() - (s.updatedAt || 0) >= (s.intervalHours || 12) * 3600 * 1000;
const refreshing = new Set();

function timeAgo(ms) {
  if (!ms) return 'never';
  const m = Math.floor((Date.now() - ms) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.floor(m / 60)} h ago`;
  return `${Math.floor(m / 1440)} d ago`;
}

function carrierOf(p) { return p.transport === 'uot' && p.tls ? 'tls' : (p.transport || 'udp'); }

// Rewrites the subscription's profiles from a fetched document, keeping the
// active carrier and per-profile tweaks.
function applySubscription(sub, doc) {
  const links = [];
  for (const l of doc.links || []) {
    try { links.push(parseOstpLink(l)); } catch { /* skip malformed */ }
  }
  if (!links.length) throw new Error('the subscription has no usable links');

  sub.name = (doc.name || '').trim() || (() => { try { return new URL(sub.url).host; } catch { return sub.url; } })();
  sub.intervalHours = Math.min(720, Math.max(1, doc.update_interval_hours || 12));
  sub.usedBytes = doc.usage ? doc.usage.used_bytes : null;
  sub.limitBytes = doc.usage ? doc.usage.limit_bytes : null;
  sub.updatedAt = Date.now();
  sub.lastError = null;

  const old = profiles.filter(p => p.sub_id === sub.id);
  const activeOld = old.find(p => p.id === activeId);
  const fresh = links.map((l, i) => {
    const prev = old.find(p => carrierOf(p) === carrierOf(l));
    return { ...(prev || {}), ...l, id: prev ? prev.id : genId(), sub_id: sub.id,
             name: l.name || `${sub.name} · ${carrierOf(l).toUpperCase()}` };
  });
  const at = profiles.findIndex(p => p.sub_id === sub.id);
  profiles = profiles.filter(p => p.sub_id !== sub.id);
  profiles.splice(at >= 0 ? at : profiles.length, 0, ...fresh);

  if (activeOld) {
    const same = fresh.find(p => carrierOf(p) === carrierOf(activeOld)) || fresh[0];
    activeId = same.id;
  } else if (!activeId || !profiles.some(p => p.id === activeId)) {
    activeId = fresh[0].id;
  }
  saveActiveId(activeId);
  saveProfiles(profiles);
  return fresh.length;
}

async function refreshSubscription(id, { quiet = false } = {}) {
  const subs = loadSubs();
  const sub = subs.find(s => s.id === id);
  if (!sub || refreshing.has(id)) return;
  refreshing.add(id);
  renderSubs();
  try {
    const doc = await invoke('fetch_subscription', { url: sub.url });
    if (!doc) throw new Error('subscriptions need the desktop app');
    const n = applySubscription(sub, doc);
    if (!quiet) showToast(`Updated: ${n} profile(s)`, 'ok');
  } catch (e) {
    sub.lastError = String(e?.message || e);
    if (!quiet) showToast('Update failed: ' + sub.lastError, 'error');
  } finally {
    refreshing.delete(id);
    saveSubs(subs);
    renderSubs();
    renderProfiles();
    const cfg = buildConfig();
    if (cfg) invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) }).catch(() => {});
  }
}

async function addSubscription(url) {
  const subs = loadSubs();
  let sub = subs.find(s => s.url === url);
  if (!sub) {
    sub = { id: 'sub' + genId(), url, name: '', updatedAt: 0, intervalHours: 12 };
    subs.push(sub);
    saveSubs(subs);
  }
  showToast('Fetching subscription…');
  await refreshSubscription(sub.id);
  const saved = loadSubs().find(s => s.id === sub.id);
  // A URL that never worked is not worth keeping.
  if (saved && !saved.updatedAt) {
    saveSubs(loadSubs().filter(s => s.id !== sub.id));
    renderSubs();
  }
}

function removeSubscription(id) {
  const sub = loadSubs().find(s => s.id === id);
  if (!sub || !confirm(`Remove "${sub.name || sub.url}" and its profiles?`)) return;
  saveSubs(loadSubs().filter(s => s.id !== id));
  profiles = profiles.filter(p => p.sub_id !== id);
  if (!profiles.some(p => p.id === activeId)) { activeId = profiles[0]?.id || null; saveActiveId(activeId); }
  saveProfiles(profiles);
  renderSubs();
  renderProfiles();
}

async function refreshDueSubscriptions() {
  for (const s of loadSubs().filter(subIsDue)) await refreshSubscription(s.id, { quiet: true });
}

function renderSubs() {
  const subs = loadSubs();
  $('sub-section').style.display = subs.length ? '' : 'none';
  const list = $('sub-list');
  list.innerHTML = '';
  for (const s of subs) {
    const used = s.usedBytes, limit = s.limitBytes;
    const ratio = used != null && limit ? Math.min(1, used / limit) : null;
    const usage = used == null ? '' : (limit ? `${fmtBytes(used)} of ${fmtBytes(limit)}` : `${fmtBytes(used)} used`);
    const meta = [usage, `updated ${timeAgo(s.updatedAt)}`, `every ${s.intervalHours || 12} h`].filter(Boolean).join(' · ');
    const card = document.createElement('div');
    card.className = 'sub-card';
    card.innerHTML = `
      <div class="sub-head">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
        <div class="sub-name">${escHtml(s.name || s.url)}</div>
        <button class="profile-action-btn sub-refresh${refreshing.has(s.id) ? ' spinning' : ''}" title="Update now">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        </button>
        <button class="profile-action-btn sub-share" title="Share subscription (QR)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM18 18h3v3h-3z"/></svg>
        </button>
        <button class="profile-action-btn sub-remove" title="Remove">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        </button>
      </div>
      ${ratio != null ? `<div class="sub-bar${ratio >= 1 ? ' full' : ratio >= 0.8 ? ' warn' : ''}"><div style="width:${(ratio * 100).toFixed(1)}%"></div></div>` : ''}
      <div class="sub-meta">${escHtml(meta)}</div>
      ${s.lastError ? `<div class="sub-error">${escHtml(s.lastError)}</div>` : ''}
      <div class="sub-profiles"></div>
    `;
    const own = card.querySelector('.sub-profiles');
    profiles.filter(p => p.sub_id === s.id).forEach(p => own.appendChild(profileCard(p)));
    card.querySelector('.sub-refresh').addEventListener('click', () => refreshSubscription(s.id));
    card.querySelector('.sub-share').addEventListener('click', () => showShare('Share Subscription', s.url));
    card.querySelector('.sub-remove').addEventListener('click', () => removeSubscription(s.id));
    list.appendChild(card);
  }
}

// ── PROBER ────────────────────────────────────────────────────────────
let lastMatrix = null;
const CARRIER_NAMES = { udp: 'UDP', uot: 'TCP', uot_frag: 'TCP + frag', uot_tls: 'TLS' };
const carrierName = t => CARRIER_NAMES[t] || String(t).toUpperCase();

function proberTls(p) {
  if (p.transport !== 'uot' || !p.tls) return null;
  return { sni: p.tls_sni || '', insecure: !!p.tls_insecure, ws_path: p.ws_path || null };
}

function fillProberProfiles() {
  const sel = $('pr-profile');
  sel.innerHTML = profiles.map(p =>
    `<option value="${escHtml(p.id)}"${p.id === activeId ? ' selected' : ''}>${escHtml(p.name || p.server)}${
      (p.name || '').toUpperCase().includes(carrierOf(p).toUpperCase()) ? '' : ' — ' + escHtml(carrierOf(p).toUpperCase())}</option>`).join('');
}

function prStatus(msg, busy = false) {
  const el = $('pr-status');
  el.textContent = msg;
  el.className = 'prober-status' + (busy ? ' busy' : '');
}

function prCard(title, html) {
  const card = document.createElement('div');
  card.className = 'pr-card';
  card.innerHTML = `<h4>${escHtml(title)}</h4>${html}`;
  $('pr-results').prepend(card);
}

function setProberBusy(busy) {
  ['btn-pr-matrix', 'btn-pr-dpi'].forEach(id => { $(id).disabled = busy; });
  $('btn-pr-ttl').disabled = busy || !lastMatrix;
}

async function runMatrix() {
  const p = profiles.find(x => x.id === $('pr-profile').value);
  if (!p) { showToast('Add a profile first', 'error'); return; }
  setProberBusy(true);
  prStatus(`Handshaking with ${p.server} over every address and carrier…`, true);
  try {
    const rows = await invoke('run_prober_matrix', { request: { server: p.server, key: p.key, tls: proberTls(p) } });
    if (!rows) throw new Error('the prober needs the desktop app');
    lastMatrix = { profile: p, rows };
    const ok = rows.filter(r => r.outcome.success);
    const foreign = rows.filter(r => r.outcome.foreign_bytes);
    const verdict = ok.length === rows.length
      ? `<div class="pr-verdict ok">All ${rows.length} combinations work.</div>`
      : ok.length
        ? `<div class="pr-verdict warn">${ok.length} of ${rows.length} work. Use: ${escHtml(ok.map(r => carrierName(r.transport) + ' over ' + r.address_kind).join(', '))}.</div>`
        : `<div class="pr-verdict bad">Nothing got through.${foreign.length ? ' Something other than the server answered — likely DPI; try the path scan.' : ''}</div>`;
    const table = `<table class="pr-table"><tr><th>Address</th><th>Carrier</th><th>Result</th></tr>${rows.map(r => `
      <tr><td class="mono">${escHtml(r.address)}<span class="pr-dim"> ${escHtml(r.address_kind)}</span></td>
      <td>${escHtml(carrierName(r.transport))}</td>
      <td>${r.outcome.success
        ? `<span class="pr-ok">✓ ${r.outcome.rtt_ms != null ? Math.round(r.outcome.rtt_ms) + ' ms' : 'ok'}</span>`
        : `<span class="${r.outcome.foreign_bytes ? 'pr-warn' : 'pr-bad'}">✕ ${escHtml(r.outcome.error || 'failed')}</span>`}</td></tr>`).join('')}</table>`;
    prCard(`Server check — ${p.name || p.server}`, verdict + table);
    prStatus('Done.');
  } catch (e) {
    prStatus('Check failed: ' + (e?.message || e));
  } finally {
    setProberBusy(false);
  }
}

async function runTtl() {
  if (!lastMatrix) return;
  const { profile: p, rows } = lastMatrix;
  // Scan the combination that failed with a foreign answer, else the first that worked.
  const target = rows.find(r => r.outcome.foreign_bytes) || rows.find(r => r.outcome.success) || rows[0];
  setProberBusy(true);
  prStatus(`Scanning ${target.address} hop by hop (${carrierName(target.transport)}); up to 20 steps…`, true);
  try {
    const rep = await invoke('run_prober_ttl', { request: {
      address: target.address, port: target.port, transport: target.transport, key: p.key, tls: proberTls(p), max_ttl: 20 } });
    const cells = rep.steps.map(s => `<span class="pr-ttl ${s.outcome}" title="${escHtml(s.preview || s.outcome)}">${s.ttl}</span>`).join('');
    let verdict;
    if (rep.first_foreign_ttl != null && (rep.first_genuine_ttl == null || rep.first_foreign_ttl < rep.first_genuine_ttl)) {
      verdict = `<div class="pr-verdict bad">Something answers at hop ${rep.first_foreign_ttl}${rep.first_genuine_ttl != null ? `, before the server at hop ${rep.first_genuine_ttl}` : ''}: an in-path filter (estimate).</div>`;
    } else if (rep.first_genuine_ttl != null) {
      verdict = `<div class="pr-verdict ok">The server answers at hop ${rep.first_genuine_ttl}; nothing answered in its place.</div>`;
    } else {
      verdict = '<div class="pr-verdict warn">No answer at any hop count.</div>';
    }
    prCard(`Path scan — ${target.address}`, verdict + `<div class="pr-ttl-row">${cells}</div>
      <p class="field-hint">Green: the server. Red: someone else answered. Grey: no answer. Routing noise can blur this; read it as an estimate.</p>`);
    prStatus('Done.');
  } catch (e) {
    prStatus('Path scan failed: ' + (e?.message || e));
  } finally {
    setProberBusy(false);
  }
}

async function runDpi() {
  setProberBusy(true);
  prStatus('Testing what this network filters (about 10 s)…', true);
  try {
    const r = await invoke('run_dpi_battery');
    if (!r) throw new Error('the prober needs the desktop app');
    const line = (bad, text, okText) => `<tr><td>${bad ? '<span class="pr-bad">✕</span>' : '<span class="pr-ok">✓</span>'}</td><td>${escHtml(bad ? text : okText)}</td></tr>`;
    const score = Math.round((r.dpi_score || 0) * 100) / 100;
    const verdict = score >= 0.5
      ? `<div class="pr-verdict bad">Heavy filtering (score ${score}).</div>`
      : score > 0
        ? `<div class="pr-verdict warn">Some filtering (score ${score}).</div>`
        : '<div class="pr-verdict ok">No filtering detected.</div>';
    const rows = [
      line(r.sni_blocked, 'TLS by server name (SNI) is blocked', 'TLS server names are not filtered'),
      line(r.http_host_blocked, 'HTTP by Host header is blocked', 'HTTP Host headers are not filtered'),
      line(r.rst_injection_detected, 'Forged TCP resets are injected', 'No forged TCP resets'),
      line(r.random_payload_blocked, 'Unknown protocols are blocked', 'Unknown protocols pass'),
      line(r.udp_throttled, 'UDP is throttled', 'UDP is not throttled'),
      line(r.dns_hijacked, `DNS is hijacked${r.dns_hijacker_ip ? ' by ' + r.dns_hijacker_ip : ''}`, 'DNS answers are not hijacked'),
      line(r.dns_injected, `DNS answers are injected${r.dns_injection_msg ? ': ' + r.dns_injection_msg : ''}`, 'No injected DNS answers'),
      line(r.transparent_proxy_detected, 'A transparent proxy sits on the path', 'No transparent proxy'),
      line(r.connect_hijacked, 'Connections are hijacked', 'Connections reach their targets'),
    ].join('');
    const tip = r.vulnerable_to_fragmentation
      ? '<p class="field-hint">The filter misses fragmented handshakes: TCP fragmentation (UoT) helps here.</p>' : '';
    prCard('Network DPI test', verdict + `<table class="pr-table">${rows}</table>` + tip);
    prStatus('Done.');
  } catch (e) {
    prStatus('DPI test failed: ' + (e?.message || e));
  } finally {
    setProberBusy(false);
  }
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
  renderSubs();
  // Subscriptions past their interval refresh in the background, now and hourly.
  refreshDueSubscriptions();
  setInterval(refreshDueSubscriptions, 3600 * 1000);

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
  $('btn-go-prober').addEventListener('click', () => showScreen('prober'));
  $('btn-prober-back').addEventListener('click', () => showScreen('home'));
  $('btn-pr-matrix').addEventListener('click', runMatrix);
  $('btn-pr-ttl').addEventListener('click', runTtl);
  $('btn-pr-dpi').addEventListener('click', runDpi);
  $('pr-profile').addEventListener('change', () => { lastMatrix = null; setProberBusy(false); });

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
      if (text.trim().startsWith('ostp://') || isSubscriptionUrl(text)) {
        importFromLink(text.trim());
      } else {
        showToast('No ostp:// link or subscription URL in clipboard', 'error');
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


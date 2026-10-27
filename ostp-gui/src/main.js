import { initServers, renderServers, mountSshForm, confirmBox, fmtBytes } from './servers.js';

// ── Tauri invoke shim ─────────────────────────────────────────────────
let rawInvoke = () => Promise.resolve(null);
if (window.__TAURI__?.core) {
  rawInvoke = window.__TAURI__.core.invoke;
}

// A backend call that never returns would freeze whatever waits on it. Every
// call gets a limit; the work itself may still finish on the Rust side.
const TIMEOUT_MS = {
  get_tunnel_status: 5000, get_metrics: 5000, save_config: 10000, reload_tunnel: 10000,
  stop_tunnel: 15000, start_tunnel: 150000, generate_qr: 10000, decode_qr: 30000,
  fetch_subscription: 45000, check_updates: 45000, set_autostart: 15000, get_wintun_install_path: 5000,
  app_build_tag: 5000, run_prober_matrix: 75000, run_prober_ttl: 75000, run_dpi_battery: 135000,
  servers_list: 15000, server_rename: 15000, server_remove: 15000, server_add: 120000, server_probe: 120000,
  server_open_panel: 60000, server_install: 20 * 60000, server_action: 20 * 60000,
};
const DEFAULT_TIMEOUT_MS = 60000;
const TIMEOUT_MSG = 'The app core did not answer in time';

function invoke(cmd, args) {
  let ms = TIMEOUT_MS[cmd] ?? DEFAULT_TIMEOUT_MS;
  // Reading a server's state is quick; changing it can take minutes.
  if (cmd === 'server_manage') ms = ['status', 'users', 'logs'].includes(args?.args?.[0]) ? 90000 : 5 * 60000;
  let timer;
  const limit = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(TIMEOUT_MSG)), ms);
  });
  return Promise.race([rawInvoke(cmd, args), limit]).finally(() => clearTimeout(timer));
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

// localStorage can hold anything: another version, a hand edit, a half-written
// value. Each loader returns only what the rest of the code can use.
const MAX_PROFILES = 200;
const MAX_SUBS = 20;
const LIMITS = { name: 100, server: 255, key: 512, sni: 255, path: 255, link: 4096, url: 2048 };

function readJson(key, fallback) {
  try {
    const v = JSON.parse(localStorage.getItem(key) || 'null');
    return v == null ? fallback : v;
  } catch { return fallback; }
}

let storageWarned = false;
function writeJson(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); }
  catch {
    if (!storageWarned) {
      storageWarned = true;
      showToast('Could not save to the app storage. Changes will be lost when the app closes.', 'error');
    }
  }
}

const isObj = v => v && typeof v === 'object' && !Array.isArray(v);

function loadProfiles() {
  const raw = readJson(PROFILES_KEY, []);
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  return raw.filter(p => isObj(p) && typeof p.id === 'string' && typeof p.server === 'string'
    && typeof p.key === 'string' && !seen.has(p.id) && seen.add(p.id)).slice(0, MAX_PROFILES);
}

function saveProfiles(profiles) {
  writeJson(PROFILES_KEY, profiles);
}

function loadActiveId() {
  try { return localStorage.getItem(ACTIVE_KEY) || null; } catch { return null; }
}

function saveActiveId(id) {
  try { localStorage.setItem(ACTIVE_KEY, id || ''); } catch { /* reported by writeJson */ }
}

function loadClientSettings() {
  const v = readJson(SETTINGS_KEY, {});
  return isObj(v) ? v : {};
}

function saveClientSettings(s) {
  writeJson(SETTINGS_KEY, s);
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
  // An error needs time to be read; a confirmation does not.
  toastTimer = setTimeout(() => toast.classList.remove('show'), variant === 'error' ? 7000 : 2600);
}

// The banner stays until the next connection attempt: a failure that
// disappears after a few seconds is easy to miss and impossible to copy.
function showError(msg) {
  errorBanner.textContent = msg;
  errorBanner.classList.remove('hidden');
  btnConnect.classList.add('error');
}

function clearError() {
  errorBanner.classList.add('hidden');
  btnConnect.classList.remove('error');
}

// The core reads its settings from the config file, so every change to the
// active profile or the settings is written there. Resolves to false when the
// write failed (the user has been told).
// Writes go one after another so the last change is the one left in the file,
// whatever order the backend finishes them in.
let persistChain = Promise.resolve();
function persistConfig() {
  const run = () => {
    const cfg = buildConfig();
    if (!cfg) return Promise.resolve(false);
    return invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) })
      .then(() => true)
      .catch(err => { showToast('Could not save the configuration: ' + (err?.message || err), 'error'); return false; });
  };
  const result = persistChain.then(run);
  persistChain = result.catch(() => {});
  return result;
}

// The tunnel stopped on its own: say so, with the reason.
function onTunnelError(msg) {
  setState('disconnected');
  showError('The connection stopped: ' + msg);
}

// ── STATE MACHINE ─────────────────────────────────────────────────────
function setState(next) {
  if (appState === next) return;
  appState = next;

  btnConnect.className = 'power-btn';
  brandDot.className   = 'brand-dot';
  statusText.className = 'status-label';
  btnConnect.setAttribute('aria-label',
    next === 'disconnected' ? 'Connect' : next === 'connecting' ? 'Cancel connecting' : 'Disconnect');

  if (next === 'disconnected') {
    statusText.textContent = 'Disconnected';
    uptimeText.textContent  = 'Press the button to connect';
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
    clearError();
    btnConnect.classList.add('connecting');
    brandDot.classList.add('connecting');
    statusText.classList.add('is-connecting');
    statusText.textContent = 'Connecting…';
    uptimeText.textContent  = 'Press the button to cancel';
    connInfo.classList.add('hidden');
    clearInterval(uptimeTimer); uptimeTimer = null;
    uptimeSecs = 0;

  } else if (next === 'connected') {
    clearError();
    btnConnect.classList.add('connected');
    brandDot.classList.add('connected');
    statusText.classList.add('is-connected');
    statusText.textContent = 'Connected';

    const active = profiles.find(p => p.id === activeId);
    if (active) {
      serverBadge.textContent = active.server;
      connInfo.classList.remove('hidden');
    }

    // Counted from the clock, not by ticks: timers stall while the computer
    // sleeps. A clock set backwards shows 0 rather than a negative time.
    const since = Date.now();
    uptimeSecs = 0;
    uptimeText.textContent = 'Connected for ' + fmtTime(0);
    clearInterval(uptimeTimer);
    uptimeTimer = setInterval(() => {
      uptimeSecs = Math.max(0, Math.floor((Date.now() - since) / 1000));
      uptimeText.textContent = 'Connected for ' + fmtTime(uptimeSecs);
    }, 1000);
  }
}

// ── POLLING ───────────────────────────────────────────────────────────
// A tick is skipped while the previous one is still waiting, so a core that
// answers slowly never piles up requests.
let pollBusy = false;
let lastPollAt = 0;
let pollStalls = 0;

async function poll() {
  if (!pollTimer || pollBusy) return;
  pollBusy = true;
  try {
    await pollOnce();
  } finally {
    pollBusy = false;
  }
}

async function pollOnce() {
  try {
    const code = await invoke('get_tunnel_status');
    if (!pollTimer) return;
    pollStalls = 0;

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

      // Throughput: bytes since the last answer over the time that really
      // passed (ticks stretch after sleep or a slow core).
      const now = Date.now();
      const secs = Math.max(1, (now - lastPollAt) / 1000);
      lastPollAt = now;
      const dRecv = Math.max(0, recv - prevBytesRecv) / secs;
      const dSent = Math.max(0, sent - prevBytesSent) / secs;
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
    if (!pollTimer) return;
    // No answer is not the same as a stopped tunnel: say so, change nothing.
    if (err instanceof Error && err.message === TIMEOUT_MSG) {
      if (++pollStalls === 3) showToast('The app core is not answering. The state shown may be out of date.', 'error');
      return;
    }
    // get_tunnel_status reports the reason the tunnel ended as an error.
    onTunnelError(String(err?.message || err));
  }
}

function startPolling() {
  clearInterval(pollTimer);
  lastPollAt = Date.now();
  pollStalls = 0;
  pollTimer = setInterval(poll, 1000);
  poll();
}

// ── BUILD CONFIG from active profile + client settings ────────────────
// Numbers go to the core as typed unless kept in range here: an inverted or
// absurd range would fail (or stall) deep inside the core.
function clampInt(v, lo, hi, dflt) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}

function rangePair(a, b, lo, hi, d) {
  const x = clampInt(a, lo, hi, d[0]), y = clampInt(b, lo, hi, d[1]);
  return x <= y ? [x, y] : [y, x];
}

const MAX_LIST_ITEMS = 500;
function listOf(text) {
  return String(text || '').split(/[\n,]+/).map(x => x.trim().slice(0, 253)).filter(Boolean).slice(0, MAX_LIST_ITEMS);
}

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
      frag_chunk: clampInt(s.tcpFrag ? s.fragChunk : active.frag_chunk, 1, 1400, 2),
      frag_sleep: clampInt(s.tcpFrag ? s.fragSleep : active.frag_sleep, 0, 1000, 2),
      junk_pc: s.junkEnabled ? rangePair(s.junkPcMin, s.junkPcMax, 0, 100, [2, 5]) : (active.junk_pc || [2, 5]),
      junk_ps: s.junkEnabled ? rangePair(s.junkPsMin, s.junkPsMax, 1, 1400, [100, 1000]) : (active.junk_ps || [100, 1000]),
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
      domains: listOf(s.exDomains),
      ips: listOf(s.exIps),
      processes: listOf(s.exProcs),
    },
    mux: s.mux ? { enabled: true, sessions: clampInt(s.muxSessions, 1, 8, 2) } : undefined,
    gui: {
      autoconnect: !!s.autoconnect,
      launch_startup: !!s.launchStartup,
    },
  };
  if (s.mtu) cfg.mtu = clampInt(s.mtu, 576, 1500, 1350);
  return cfg;
}

// ── CONNECT / DISCONNECT ──────────────────────────────────────────────
// The button is disabled while start_tunnel / stop_tunnel are running (a TUN
// start can wait for the administrator prompt), so a click is never ignored
// without a sign that it is.
let toggleBusy = false;

async function handleToggle() {
  if (toggleBusy) return;
  toggleBusy = true;
  btnConnect.disabled = true;
  try {
    if (appState !== 'disconnected') {
      // Show "disconnected" only once the core has really stopped.
      try {
        await invoke('stop_tunnel');
        setState('disconnected');
        showToast('Disconnected');
      } catch (err) {
        showError('Could not stop the connection: ' + (err?.message || err));
      }
      return;
    }

    clearError();
    if (!profiles.some(p => p.id === activeId)) {
      showError('No profile is selected. Open Settings and add or choose one.');
      return;
    }
    const cfg = buildConfig();
    if (!cfg) { showError('The selected profile is not valid. Open Settings and check it.'); return; }
    const socksBad = socksProblem(cfg.socks5_bind || '');
    if (socksBad) { showError(socksBad + '. Change it in More settings.'); return; }

    setState('connecting');
    try {
      await invoke('save_config', { jsonContent: JSON.stringify(cfg, null, 2) });
      const ok = await invoke('start_tunnel');
      if (ok) {
        startPolling();
      } else {
        setState('disconnected');
        showError('The connection did not start. The file ostp.log next to the app has details.');
      }
    } catch (err) {
      setState('disconnected');
      const msg = String(err?.message || err);
      if (msg.includes('WINTUN_MISSING')) wintunModal.classList.remove('hidden');
      else showError('Could not connect: ' + msg);
    }
  } finally {
    toggleBusy = false;
    btnConnect.disabled = false;
  }
}

// ── SCREEN NAVIGATION ─────────────────────────────────────────────────
function showScreen(name) {
  const screens = {
    home: homeScreen, settings: settingsScreen, more: $('more-screen'), prober: $('prober-screen'),
    welcome: $('welcome-screen'), servers: $('servers-screen'), server: $('server-screen'),
  };
  Object.values(screens).forEach(s => s.classList.remove('active'));
  if (name === 'settings') {
    loadSettingsIntoForm();
    renderSubs();
  } else if (name === 'more') {
    loadSettingsIntoForm();
  } else if (name === 'prober') {
    fillProberProfiles();
  } else if (name === 'servers') {
    renderServers();
  }
  const target = screens[name] || homeScreen;
  target.classList.add('active');
  // The screen the focus was on is gone; start from this one.
  (target === homeScreen ? btnConnect : target.querySelector('button'))?.focus({ preventScroll: true });
}

// ── FIRST RUN ─────────────────────────────────────────────────────────
// Shown until the app has a profile or a subscription, or is skipped.
const WELCOMED_KEY = 'ostp_welcomed';

function finishWelcome() {
  localStorage.setItem(WELCOMED_KEY, '1');
  showScreen('home');
}

// Step 1 picks how the user gets a connection; step 2 is that page alone.
function welcomeStep(step) {
  document.querySelectorAll('#welcome-screen [data-welcome]').forEach(el => {
    el.style.display = el.dataset.welcome === step ? '' : 'none';
  });
  $('btn-welcome-back').style.visibility = step === 'choose' ? 'hidden' : 'visible';
  if (step === 'link') $('welcome-link').focus();
  if (step === 'qr') $('welcome-qr-status').textContent = 'Drop a picture here';
}

const REPO_URL = 'https://github.com/ospab/ostp';

// A link or a subscription URL, typed, pasted or read from a QR code.
async function welcomeAdd(raw) {
  raw = String(raw || '').trim();
  if (!raw) return false;
  if (raw.length > LIMITS.link) { showToast('The text is too long to be a link', 'error'); return false; }
  if (isSubscriptionUrl(raw)) {
    await addSubscription(raw);
    if (loadSubs().some(s => s.url === raw)) { finishWelcome(); return true; }
    return false;
  }
  try {
    parseOstpLink(raw);
    if (!importLinks([raw], {})) { showToast('This profile is already in the app', 'error'); return false; }
    showToast('Profile added', 'ok');
    finishWelcome();
    return true;
  } catch (e) {
    showToast(e.message, 'error');
    return false;
  }
}

const MAX_QR_BYTES = 10 * 1024 * 1024;
let qrBusy = false;

// Reads the QR code in a picture (a File or Blob) on the Rust side.
async function welcomeQrFrom(blob) {
  const status = $('welcome-qr-status');
  if (!blob || !/^image\//.test(blob.type || '')) { status.textContent = 'That file is not a picture'; return; }
  if (blob.size > MAX_QR_BYTES) { status.textContent = 'The picture is too large (the limit is 10 MB)'; return; }
  if (qrBusy) return;
  qrBusy = true;
  status.textContent = 'Reading the code…';
  try {
    const b64 = await new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result).split(',')[1] || '');
      r.onerror = () => reject(r.error);
      r.readAsDataURL(blob);
    });
    const text = await invoke('decode_qr', { imageBase64: b64 });
    if (!text) throw new Error('QR codes can be read only in the desktop app');
    status.textContent = 'Found a code';
    if (!await welcomeAdd(text)) status.textContent = 'The code was read, but it is not an ostp:// link or a subscription URL';
  } catch (e) {
    status.textContent = String(e?.message || e);
  } finally {
    qrBusy = false;
  }
}

function setupWelcome() {
  $('btn-welcome-skip').addEventListener('click', finishWelcome);
  $('btn-welcome-back').addEventListener('click', () => welcomeStep('choose'));
  document.querySelectorAll('#welcome-screen [data-go]').forEach(b =>
    b.addEventListener('click', () => welcomeStep(b.dataset.go)));
  $('btn-welcome-paste').addEventListener('click', async () => {
    try { $('welcome-link').value = (await navigator.clipboard.readText()).trim(); }
    catch { showToast('The clipboard cannot be read here. Click the field and press Ctrl+V.', 'error'); }
  });
  $('btn-welcome-link').addEventListener('click', async () => {
    if (!$('welcome-link').value.trim()) { $('welcome-link').focus(); return; }
    // A subscription is downloaded here: one request at a time.
    const btn = $('btn-welcome-link');
    if (btn.disabled) return;
    btn.disabled = true;
    try { await welcomeAdd($('welcome-link').value); }
    finally { btn.disabled = false; }
  });
  $('btn-welcome-repo').addEventListener('click', () => openUrl(REPO_URL));

  // QR code: a chosen file, a dropped file, or a screenshot pasted with Ctrl+V.
  const qrOpen = () => $('welcome-screen').classList.contains('active')
    && document.querySelector('#welcome-screen [data-welcome="qr"]').style.display !== 'none';
  $('btn-welcome-qr-file').addEventListener('click', () => $('welcome-qr-file').click());
  $('welcome-qr-file').addEventListener('change', () => {
    const f = $('welcome-qr-file').files[0];
    $('welcome-qr-file').value = '';
    if (f) welcomeQrFrom(f);
  });
  const drop = $('welcome-qr-drop');
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.classList.remove('over');
    welcomeQrFrom(e.dataTransfer?.files?.[0]);
  });
  document.addEventListener('paste', e => {
    if (!qrOpen()) return;
    const item = [...(e.clipboardData?.items || [])].find(i => i.type.startsWith('image/'));
    if (item) { e.preventDefault(); welcomeQrFrom(item.getAsFile()); }
  });
  mountSshForm($('welcome-ssh-form'), { onInstalled: finishWelcome });
  const firstRun = !localStorage.getItem(WELCOMED_KEY) && !profiles.length && !loadSubs().length;
  if (firstRun) showScreen('welcome');
}

// Adds profiles from ostp:// links, skipping ones already in the app.
// Returns how many were added. The first one becomes active when nothing is.
function importLinks(links, { baseName = '', serverId = null } = {}) {
  let added = 0;
  for (const raw of links) {
    let l;
    try { l = parseOstpLink(raw); } catch { continue; }
    const dup = profiles.some(p => p.key === l.key && p.server === l.server && carrierOf(p) === carrierOf(l));
    if (dup) continue;
    if (profiles.length >= MAX_PROFILES) { showToast(`The app keeps up to ${MAX_PROFILES} profiles. Delete some first.`, 'error'); break; }
    const name = baseName ? cleanName(`${baseName} · ${carrierOf(l).toUpperCase()}`) : (l.name || l.server);
    const p = { ...l, id: genId(), name };
    if (serverId) p.server_id = serverId;
    profiles.push(p);
    if (!activeId || !profiles.some(x => x.id === activeId)) activeId = p.id;
    added++;
  }
  if (added) {
    saveProfiles(profiles);
    saveActiveId(activeId);
    renderProfiles();
    persistConfig();
  }
  return added;
}

// Whether the tunnel is up through this host (a server being managed).
function connectedThrough(host) {
  if (appState === 'disconnected') return false;
  const p = profiles.find(x => x.id === activeId);
  if (!p) return false;
  const h = String(p.server).replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return h === host;
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
    card.tabIndex = 0;
    card.setAttribute('role', 'radio');
    card.setAttribute('aria-checked', String(p.id === activeId));
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
        <button class="profile-action-btn btn-share-profile" title="Share profile" data-id="${p.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </button>
        <button class="profile-action-btn btn-edit-profile" title="Edit profile" data-id="${p.id}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
      </div>
    `;

    // Select the profile on a click or Enter/Space (not on the action buttons)
    const select = () => {
      activeId = p.id;
      saveActiveId(activeId);
      renderProfiles();
      persistConfig();
      if (appState !== 'disconnected') showToast('The connection keeps using the previous profile until you reconnect');
    };
    card.addEventListener('click', e => {
      if (e.target.closest('.profile-action-btn')) return;
      select();
    });
    card.addEventListener('keydown', e => {
      if (e.target !== card || (e.key !== 'Enter' && e.key !== ' ')) return;
      e.preventDefault();
      select();
      document.querySelector(`.profile-card[data-id="${p.id}"]`)?.focus();
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
    profileModalTitle.textContent = 'Edit profile';
    pmName.value = p.name || '';
    pmServer.value = p.server || '';
    pmKey.value = p.key || '';
    pmTransport.value = p.transport || 'udp';
    setTlsFields(p);
    btnProfileDelete.style.display = '';
  } else {
    profileModalTitle.textContent = 'New profile';
    pmName.value = pmServer.value = pmKey.value = '';
    pmTransport.value = 'udp';
    setTlsFields({});
    btnProfileDelete.style.display = 'none';
  }
  pmKey.type = 'password';
  profileModal.classList.remove('hidden');
}

function saveProfileFromEditor() {
  const server = pmServer.value.trim();
  const key    = pmKey.value.trim();
  if (!server) { showToast('Enter the server address', 'error'); pmServer.focus(); return; }
  try { splitHostPort(server); }
  catch { showToast('The server must be written as host:port, for example 203.0.113.10:50000', 'error'); pmServer.focus(); return; }
  if (!key)    { showToast('Enter the access key', 'error'); pmKey.focus(); return; }
  if (server.length > LIMITS.server) { showToast('The server address is too long', 'error'); pmServer.focus(); return; }
  if (key.length > LIMITS.key) { showToast('The access key is too long', 'error'); pmKey.focus(); return; }
  if (/\s/.test(server)) { showToast('The server address cannot contain spaces', 'error'); pmServer.focus(); return; }
  if (pmName.value.trim().length > LIMITS.name) { showToast(`The name is longer than ${LIMITS.name} characters`, 'error'); pmName.focus(); return; }
  if (pmSni.value.trim().length > LIMITS.sni || pmWsPath.value.trim().length > LIMITS.path) {
    showToast('The TLS name or the path is too long', 'error'); return;
  }
  const candidate = { server, key, transport: pmTransport.value, ...tlsFieldsFromEditor() };
  const twin = profiles.find(p => p.id !== editingProfileId && p.key === key && p.server === server && carrierOf(p) === carrierOf(candidate));
  if (twin) { showToast(`This profile already exists as "${twin.name || twin.server}"`, 'error'); return; }
  if (!editingProfileId && profiles.length >= MAX_PROFILES) {
    showToast(`The app keeps up to ${MAX_PROFILES} profiles. Delete some first.`, 'error'); return;
  }

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

  persistConfig();
}

async function deleteEditingProfile() {
  const doomed = profiles.find(p => p.id === editingProfileId);
  if (!doomed) return;
  const inUse = doomed.id === activeId && appState !== 'disconnected';
  if (!await confirmBox(`Delete "${doomed.name || doomed.server}"?`,
    'The profile and its access key are removed from this app.'
      + (doomed.sub_id ? ' Its subscription brings it back on the next update.' : '')
      + (inUse ? ' The connection stays up until you disconnect.' : ''), 'Delete profile')) return;
  profiles = profiles.filter(p => p.id !== editingProfileId);
  if (activeId === editingProfileId) {
    activeId = profiles[0]?.id || null;
    saveActiveId(activeId);
  }
  saveProfiles(profiles);
  profileModal.classList.add('hidden');
  renderProfiles();
  persistConfig();
  showToast('Profile deleted');
}

// ── PARSE ostp:// link ─────────────────────────────────────────────────
// Port of ostp-core/src/share_link.rs (and the Flutter copy): keep in step.
const truthy = v => ['1', 'true', 'yes'].includes(String(v).toLowerCase());
const linkDecode = s => {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); }
  catch { throw new Error('The link has broken % escapes'); }
};
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
  if (!host || !/^\d+$/.test(port) || n < 1 || n > 65535 || /\s/.test(host)) throw new Error('Invalid host or port');
  return { host, port: n };
}

// Printable text only, one line, of a sane length: names come from outside.
const cleanName = s => String(s).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').trim().slice(0, LIMITS.name);

function parseOstpLink(raw) {
  raw = String(raw).trim();
  if (raw.length > LIMITS.link) throw new Error('The link is too long');
  if (!raw.toLowerCase().startsWith('ostp://')) throw new Error('Must start with ostp://');
  let rest = raw.slice(7).split('#')[0];
  const q = rest.indexOf('?');
  const authority = (q >= 0 ? rest.slice(0, q) : rest).replace(/\/+$/, '');
  const query = q >= 0 ? rest.slice(q + 1) : '';
  const at = authority.lastIndexOf('@');
  if (at < 0) throw new Error('Link has no access key');
  const key = linkDecode(authority.slice(0, at));
  if (!key) throw new Error('Link has an empty access key');
  if (key.length > LIMITS.key) throw new Error('The access key in the link is too long');
  const { host, port } = splitHostPort(authority.slice(at + 1));
  const server = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
  if (server.length > LIMITS.server) throw new Error('The server address in the link is too long');

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
    else if (k === 'name' && cleanName(v)) out.name = cleanName(v);
  }
  out.tls_sni = out.tls_sni.trim().slice(0, LIMITS.sni);
  out.ws_path = out.ws_path.trim().slice(0, LIMITS.path);
  out.name = cleanName(out.name) || host;
  if (out.tls || out.ws_path) out.transport = 'uot';
  return out;
}

// Returns false when the text is not a usable link (the user has been told).
function importFromLink(raw) {
  if (raw.length > LIMITS.link) { showToast('The text is too long to be a link', 'error'); return false; }
  if (isSubscriptionUrl(raw)) { addSubscription(raw.trim()); return true; }
  try {
    const parsed = parseOstpLink(raw);
    // Pre-fill editor
    editingProfileId = null;
    profileModalTitle.textContent = 'New profile';
    pmName.value = parsed.name;
    pmServer.value = parsed.server;
    pmKey.value = parsed.key;
    pmTransport.value = parsed.transport;
    setTlsFields(parsed);
    btnProfileDelete.style.display = 'none';
    profileModal.classList.remove('hidden');
    showToast('Check the details, then press Save', 'ok');
    return true;
  } catch (err) {
    showToast(err.message, 'error');
    return false;
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
  showShare('Share profile', buildShareLink(p));
}

let shareSeq = 0;
async function showShare(title, text) {
  $('share-title').textContent = title;
  shareLink.value = text;
  shareQr.innerHTML = '';
  const err = $('share-qr-error');
  err.style.display = 'none';
  shareModal.classList.remove('hidden');
  const mine = ++shareSeq;
  try {
    const svg = await invoke('generate_qr', { text });
    if (mine !== shareSeq) return; // another link was opened meanwhile
    if (svg) shareQr.innerHTML = svg;
    else throw new Error('QR codes need the desktop app');
  } catch (e) {
    if (mine !== shareSeq) return;
    err.textContent = 'The QR code could not be made: ' + (e?.message || e) + '. The link below still works.';
    err.style.display = '';
  }
}

// ── SUBSCRIPTIONS ─────────────────────────────────────────────────────
// A subscription URL (https://<domain>/sub/<token>) returns the user's
// current links. Its profiles carry sub_id and are rewritten on every
// refresh, so server-side changes reach the app without a new link.
const SUBS_KEY = 'ostp_subscriptions_v1';

function loadSubs() {
  const raw = readJson(SUBS_KEY, []);
  if (!Array.isArray(raw)) return [];
  return raw.filter(s => isObj(s) && typeof s.id === 'string' && typeof s.url === 'string').slice(0, MAX_SUBS);
}
function saveSubs(subs) { writeJson(SUBS_KEY, subs); }

// Why a subscription URL cannot be used, or '' when it can.
function subscriptionUrlProblem(url) {
  if (url.length > LIMITS.url) return 'The subscription URL is too long';
  let u;
  try { u = new URL(url); } catch { return 'This is not a valid URL'; }
  if (u.protocol !== 'https:' || !u.hostname) return 'A subscription URL must start with https://';
  return '';
}

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
const MAX_SUB_LINKS = 50;
const finiteOrNull = v => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);

function applySubscription(sub, doc) {
  if (!isObj(doc)) throw new Error('the answer is not a subscription');
  const links = [];
  const rawLinks = Array.isArray(doc.links) ? doc.links.slice(0, MAX_SUB_LINKS) : [];
  for (const l of rawLinks) {
    if (typeof l !== 'string') continue;
    try { links.push(parseOstpLink(l)); } catch { /* skip malformed */ }
  }
  if (!links.length) throw new Error('the subscription has no usable links');
  const others = profiles.filter(p => p.sub_id !== sub.id).length;
  if (others + links.length > MAX_PROFILES) throw new Error(`the app keeps up to ${MAX_PROFILES} profiles`);

  sub.name = cleanName(doc.name || '') || (() => { try { return new URL(sub.url).host; } catch { return sub.url.slice(0, LIMITS.name); } })();
  sub.intervalHours = clampInt(doc.update_interval_hours, 1, 720, 12);
  sub.usedBytes = isObj(doc.usage) ? finiteOrNull(doc.usage.used_bytes) : null;
  sub.limitBytes = isObj(doc.usage) ? finiteOrNull(doc.usage.limit_bytes) : null;
  sub.updatedAt = Date.now();
  sub.lastError = null;

  const old = profiles.filter(p => p.sub_id === sub.id);
  const activeOld = old.find(p => p.id === activeId);
  const fresh = links.map((l, i) => {
    const prev = old.find(p => carrierOf(p) === carrierOf(l));
    return { ...(prev || {}), ...l, id: prev ? prev.id : genId(), sub_id: sub.id,
             name: l.name || `${sub.name} · ${carrierOf(l).toUpperCase()}` };
  });
  // Profiles added by hand for the same key and carrier are what this
  // subscription now provides: keep one copy, the subscription's.
  const covered = p => !p.sub_id && fresh.some(f => f.key === p.key && f.server === p.server && carrierOf(f) === carrierOf(p));
  const replaced = profiles.find(p => p.id === activeId && covered(p));
  profiles = profiles.filter(p => !covered(p));
  const at = profiles.findIndex(p => p.sub_id === sub.id);
  profiles = profiles.filter(p => p.sub_id !== sub.id);
  profiles.splice(at >= 0 ? at : profiles.length, 0, ...fresh);

  if (activeOld || replaced) {
    const was = activeOld || replaced;
    const same = fresh.find(p => carrierOf(p) === carrierOf(was)) || fresh[0];
    activeId = same.id;
  } else if (!activeId || !profiles.some(p => p.id === activeId)) {
    activeId = fresh[0].id;
  }
  saveActiveId(activeId);
  saveProfiles(profiles);
  return fresh.length;
}

async function refreshSubscription(id, { quiet = false } = {}) {
  const url = loadSubs().find(s => s.id === id)?.url;
  if (!url || refreshing.has(id)) return;
  refreshing.add(id);
  renderSubs();
  let outcome = null;
  try {
    const doc = await invoke('fetch_subscription', { url });
    if (!doc) throw new Error('subscriptions need the desktop app');
    outcome = { doc };
  } catch (e) {
    outcome = { error: String(e?.message || e) };
  }
  refreshing.delete(id);
  // The list is read again: the subscription may have been removed, or the
  // list changed, while the download ran.
  const subs = loadSubs();
  const sub = subs.find(s => s.id === id);
  if (sub) {
    try {
      if (outcome.error) throw new Error(outcome.error);
      const n = applySubscription(sub, outcome.doc);
      if (!quiet) showToast(`Subscription updated: ${n} ${n === 1 ? 'profile' : 'profiles'}`, 'ok');
    } catch (e) {
      sub.lastError = String(e?.message || e).slice(0, 300);
      if (!quiet) showToast('Could not update the subscription: ' + sub.lastError, 'error');
    }
    saveSubs(subs);
  }
  renderSubs();
  renderProfiles();
  persistConfig();
}

async function addSubscription(url) {
  url = String(url).trim();
  const problem = subscriptionUrlProblem(url);
  if (problem) { showToast(problem, 'error'); return; }
  const subs = loadSubs();
  let sub = subs.find(s => s.url === url);
  if (sub && refreshing.has(sub.id)) { showToast('This subscription is already being fetched'); return; }
  if (!sub && subs.length >= MAX_SUBS) {
    showToast(`The app keeps up to ${MAX_SUBS} subscriptions. Remove one first.`, 'error'); return;
  }
  if (!sub) {
    sub = { id: 'sub' + genId(), url, name: '', updatedAt: 0, intervalHours: 12 };
    subs.push(sub);
    saveSubs(subs);
  }
  showToast('Fetching the subscription…');
  await refreshSubscription(sub.id);
  const saved = loadSubs().find(s => s.id === sub.id);
  // A URL that never worked is not worth keeping.
  if (saved && !saved.updatedAt) {
    saveSubs(loadSubs().filter(s => s.id !== sub.id));
    renderSubs();
  }
}

async function removeSubscription(id) {
  const sub = loadSubs().find(s => s.id === id);
  if (!sub || !await confirmBox(`Remove "${sub.name || sub.url}"?`, 'The subscription and its profiles are removed from this app.', 'Remove subscription')) return;
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
        <button class="profile-action-btn sub-refresh${refreshing.has(s.id) ? ' spinning' : ''}" title="Update subscription now">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        </button>
        <button class="profile-action-btn sub-share" title="Share subscription (QR)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM18 18h3v3h-3z"/></svg>
        </button>
        <button class="profile-action-btn sub-remove" title="Remove subscription">
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
    card.querySelector('.sub-share').addEventListener('click', () => showShare('Share subscription', s.url));
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

function prStatus(msg, state = '') {
  const el = $('pr-status');
  el.textContent = msg;
  el.className = 'prober-status' + (state ? ' ' + state : '');
}

function prCard(title, html) {
  const card = document.createElement('div');
  card.className = 'pr-card';
  card.innerHTML = `<h4>${escHtml(title)}</h4>${html}`;
  const box = $('pr-results');
  box.prepend(card);
  // Old results scroll away; the page does not grow without end.
  while (box.children.length > 8) box.lastElementChild.remove();
}

function setProberBusy(busy) {
  ['btn-pr-matrix', 'btn-pr-dpi'].forEach(id => { $(id).disabled = busy; });
  $('btn-pr-ttl').disabled = busy || !lastMatrix;
  $('btn-pr-ttl').title = lastMatrix ? '' : 'Run “Check server” first';
}

async function runMatrix() {
  const p = profiles.find(x => x.id === $('pr-profile').value);
  if (!p) { showToast('Add a profile first', 'error'); return; }
  setProberBusy(true);
  prStatus(`Trying a handshake with ${p.server} on every address and carrier…`, 'busy');
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
    prCard(`Server check: ${p.name || p.server}`, verdict + table);
    prStatus('Done.');
  } catch (e) {
    prStatus('Could not run the check: ' + (e?.message || e), 'is-error');
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
  prStatus(`Scanning the path to ${target.address} (${carrierName(target.transport)}), up to 20 hops…`, 'busy');
  try {
    const rep = await invoke('run_prober_ttl', { request: {
      address: target.address, port: target.port, transport: target.transport, key: p.key, tls: proberTls(p), max_ttl: 20 } });
    if (!rep) throw new Error('the prober needs the desktop app');
    const cells = rep.steps.map(s => `<span class="pr-ttl ${s.outcome}" title="${escHtml(s.preview || s.outcome)}">${s.ttl}</span>`).join('');
    let verdict;
    if (rep.first_foreign_ttl != null && (rep.first_genuine_ttl == null || rep.first_foreign_ttl < rep.first_genuine_ttl)) {
      verdict = `<div class="pr-verdict bad">Something answers at hop ${rep.first_foreign_ttl}${rep.first_genuine_ttl != null ? `, before the server at hop ${rep.first_genuine_ttl}` : ''}: an in-path filter (estimate).</div>`;
    } else if (rep.first_genuine_ttl != null) {
      verdict = `<div class="pr-verdict ok">The server answers at hop ${rep.first_genuine_ttl}; nothing answered in its place.</div>`;
    } else {
      verdict = '<div class="pr-verdict warn">No answer at any hop count.</div>';
    }
    prCard(`Path scan: ${target.address}`, verdict + `<div class="pr-ttl-row">${cells}</div>
      <p class="field-hint">Green: the server. Red: someone else answered. Grey: no answer. Routing noise can blur this; read it as an estimate.</p>`);
    prStatus('Done.');
  } catch (e) {
    prStatus('Could not run the path scan: ' + (e?.message || e), 'is-error');
  } finally {
    setProberBusy(false);
  }
}

async function runDpi() {
  setProberBusy(true);
  prStatus('Testing what this network filters, outside the VPN tunnel. This takes 10 to 30 seconds…', 'busy');
  try {
    const r = await invoke('run_dpi_battery');
    if (!r) throw new Error('the prober needs the desktop app');
    const unmeasured = r.unmeasured || [];
    const line = (bad, text, okText, id) => unmeasured.includes(id)
      ? `<tr><td><span class="pr-dim">–</span></td><td>${escHtml(okText)} <span class="pr-dim">(not measured: nothing to compare against)</span></td></tr>`
      : `<tr><td>${bad ? '<span class="pr-bad">✕</span>' : '<span class="pr-ok">✓</span>'}</td><td>${escHtml(bad ? text : okText)}</td></tr>`;
    // The verdict and advice come from the prober: the level of the worst
    // finding, and what to do about it with OSTP.
    const score = r.dpi_score || 0;
    const level = score >= 0.6 ? 'bad' : score > 0 ? 'warn' : 'ok';
    const advice = (r.advice || []).map(a => `<li>${escHtml(a)}</li>`).join('');
    const verdict = `<div class="pr-verdict ${level}">${escHtml(r.verdict || 'No filtering found')}.</div>`
      + (advice ? `<ul class="field-hint" style="margin:6px 0 10px 18px">${advice}</ul>` : '');
    const rows = [
      line(r.sni_blocked, 'TLS by server name (SNI) is blocked', 'TLS server names are not filtered', 'sni'),
      line(r.http_host_blocked, 'HTTP by Host header is blocked', 'HTTP Host headers are not filtered', 'http_host'),
      line(r.rst_injection_detected, 'Forged TCP resets are injected', 'No forged TCP resets seen', 'rst'),
      line(r.dns_hijacked, `DNS is hijacked${r.dns_hijacker_ip ? ' by ' + r.dns_hijacker_ip : ''}`, 'DNS answers come from the server asked', 'dns_hijack'),
      line(r.dns_injected, `DNS answers are injected${r.dns_injection_msg ? ': ' + r.dns_injection_msg : ''}`, 'No injected DNS answers'),
      line(r.transparent_proxy_detected, 'A transparent proxy sits on the path', 'No transparent proxy', 'proxy'),
      line(r.connect_hijacked, 'Block pages are injected', 'No injected block pages', 'connect'),
    ].join('');
    const tip = r.vulnerable_to_fragmentation
      ? '<p class="field-hint">The filter misses fragmented handshakes: TCP fragmentation (UoT) helps here.</p>' : '';
    // Checks with a verdict and, when the censor answers, its hop.
    const checks = (r.checks || []).map(c => {
      const mark = c.ok === true ? '<span class="pr-ok">✓</span>' : c.ok === false ? '<span class="pr-bad">✕</span>' : '<span class="pr-dim">–</span>';
      const hop = c.locate && c.locate.verdict === 'on_path'
        ? `<div class="pr-where">Censor at hop ${c.locate.reaction_hop}${c.locate.reaction_hop_address ? ' (' + escHtml(c.locate.reaction_hop_address) + ')' : ''}, server at hop ${c.locate.server_hop ?? '?'}</div>` : '';
      return `<tr><td>${mark}</td><td><b>${escHtml(c.title)}</b><div class="pr-dim">${escHtml(c.detail)}</div>${hop}</td></tr>`;
    }).join('');
    // The path toward a foreign host: where a silent drop can be.
    const path = (r.path || []).map(h => `<tr><td class="mono">${h.ttl}</td><td class="mono">${escHtml(h.address || '*')}</td><td>${escHtml(h.asn ? 'AS' + h.asn + ' ' + (h.as_name || '') : (h.address ? 'local network' : 'no answer'))}${h.is_target ? ' <span class="pr-ok">destination</span>' : ''}</td></tr>`).join('');
    const pathBlock = path
      ? `<h4 style="margin-top:14px">Path to ${escHtml(r.path_target || '')}</h4>
         ${r.path_summary ? `<p class="field-hint">${escHtml(r.path_summary.charAt(0).toUpperCase() + r.path_summary.slice(1))}.</p>` : ''}
         <table class="pr-table"><tr><th>Hop</th><th>Router</th><th>Network</th></tr>${path}</table>
         <p class="field-hint">A censor that resets or answers is placed by TTL; one that drops silently can only be narrowed to the hops before the destination network.</p>` : '';
    prCard('Network test', verdict + `<table class="pr-table">${checks}${rows}</table>` + tip + pathBlock);
    prStatus('Done.');
  } catch (e) {
    prStatus('Could not run the network test: ' + (e?.message || e), 'is-error');
  } finally {
    setProberBusy(false);
  }
}

// ── UPDATES ───────────────────────────────────────────────────────────
// Checked once when the app opens (not when the window is shown again from
// the tray), and on demand. Stable and beta releases; a beta comes with a
// warning. "Skip this version" silences that one tag.
const SKIP_UPDATE_KEY = 'ostp_skip_update_tag';
let pendingUpdate = null;

function openUrl(url) {
  const opener = window.__TAURI__?.opener || window.__TAURI__?.shell;
  if (opener?.openUrl) opener.openUrl(url);
  else if (opener?.open) opener.open(url);
  else window.open(url, '_blank');
}

async function checkUpdates({ manual }) {
  const btn = $('btn-check-updates');
  if (manual) { btn.disabled = true; btn.textContent = 'Checking…'; }
  try {
    const r = await invoke('check_updates');
    if (!r) throw new Error('update checks need the desktop app');
    // Offer the beta only when it is newer than the newest stable.
    const offer = r.beta || r.stable;
    let skipped = null;
    try { skipped = localStorage.getItem(SKIP_UPDATE_KEY); } catch {}
    if (!offer) {
      if (manual) showToast(`You have the latest version (${r.current})`, 'ok');
      return;
    }
    if (!manual && skipped === offer.tag) return;
    pendingUpdate = offer;
    const isBeta = offer.channel === 'beta';
    $('update-title').textContent = isBeta ? 'Beta version available' : 'Update available';
    $('update-text').textContent = `Version ${offer.tag} is available. You have ${r.current}.` +
      (isBeta && r.stable ? ` The newest stable release is ${r.stable.tag}.` : '');
    $('update-warning').classList.toggle('hidden', !isBeta);
    $('update-modal').classList.remove('hidden');
  } catch (e) {
    if (manual) showToast('Could not check for updates: ' + (e?.message || e), 'error');
  } finally {
    if (manual) { btn.disabled = false; btn.textContent = 'Check for updates now'; }
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
  $('in-update-check').checked = s.updateCheck !== false;
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
let autostartChain = Promise.resolve();

// Number fields accept anything typed. When the user leaves a field, a value
// out of range is replaced by the nearest allowed one and a reversed pair is
// put in order, so what the form shows is what the core gets.
const NUMBER_FIELDS = [
  [() => inMuxSessions, 1, 8], [() => inMtu, 576, 1500],
  [() => inJunkPcMin, 0, 100], [() => inJunkPcMax, 0, 100],
  [() => inJunkPsMin, 1, 1400], [() => inJunkPsMax, 1, 1400],
  [() => inFragChunk, 1, 1400], [() => inFragSleep, 0, 1000],
];

function normalizeNumberFields() {
  for (const [get, lo, hi] of NUMBER_FIELDS) {
    const el = get();
    if (el.value.trim() === '') continue;
    el.value = String(clampInt(el.value, lo, hi, lo));
  }
  for (const [a, b] of [[inJunkPcMin, inJunkPcMax], [inJunkPsMin, inJunkPsMax]]) {
    if (a.value !== '' && b.value !== '' && +a.value > +b.value) [a.value, b.value] = [b.value, a.value];
  }
}

function socksProblem(v) {
  if (!v) return '';
  try { splitHostPort(v); return ''; }
  catch { return 'The local proxy address must be host:port, for example 127.0.0.1:1088'; }
}

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
    updateCheck:  $('in-update-check').checked,
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
    // One registry write at a time, in the order the user flipped the switch.
    autostartChain = autostartChain.then(() => invoke('set_autostart', { enable: s.launchStartup })).catch(err => {
      // Put the switch back: it must not claim something the system refused.
      lastAppliedAutostart = !s.launchStartup;
      inLaunchStartup.checked = !s.launchStartup;
      saveClientSettings({ ...loadClientSettings(), launchStartup: !s.launchStartup });
      showToast('Could not change start with the system: ' + (err?.message || err), 'error');
    });
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
      hotReloadTimer = setTimeout(async () => {
        lastAppliedTunnelConfig = tunnelRelevant;
        if (!await persistConfig()) return;
        try {
          const applied = await invoke('reload_tunnel');
          showToast(applied ? 'Settings applied. TUN mode changes need a reconnect.' : 'Settings saved. Reconnect to apply them.', applied ? 'ok' : '');
        } catch (err) {
          showToast('Could not apply the settings to the running connection: ' + err, 'error');
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
    listen('tunnel-error', evt => onTunnelError(String(evt.payload)));
    listen('tray_connect', () => { if (appState === 'disconnected') handleToggle(); });
    listen('tray_disconnect', () => { if (appState !== 'disconnected') handleToggle(); });
    // Quit from the tray was refused because a server job is running.
    listen('exit-blocked', () => showToast('A server job is still running. Wait for it to finish, then quit again.', 'error'));
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
  btnGoSettings.addEventListener('click', () => showScreen('settings'));
  $('btn-go-servers').addEventListener('click', () => showScreen('servers'));
  $('btn-go-more').addEventListener('click', () => showScreen('more'));
  $('btn-more-back').addEventListener('click', () => showScreen('settings'));
  initServers({
    invoke, showToast, showScreen, escHtml, importLinks, connectedThrough, showShare,
    // Resolves to the subscription's profile count, 0 when it did not work.
    addSubscription: async url => {
      await addSubscription(url);
      const sub = loadSubs().find(s => s.url === url);
      return sub ? profiles.filter(p => p.sub_id === sub.id).length : 0;
    },
  });
  setupWelcome();
  btnBack.addEventListener('click', () => showScreen('home'));
  $('btn-go-prober').addEventListener('click', () => showScreen('prober'));
  $('btn-prober-back').addEventListener('click', () => showScreen('home'));
  $('btn-pr-matrix').addEventListener('click', runMatrix);
  $('btn-pr-ttl').addEventListener('click', runTtl);
  $('btn-pr-dpi').addEventListener('click', runDpi);
  $('pr-profile').addEventListener('change', () => { lastMatrix = null; setProberBusy(false); });

  // GUI version shown at the bottom of More settings
  const appVersionEl = $('app-version');
  if (appVersionEl) {
    const setV = v => { appVersionEl.textContent = 'OSTP GUI ' + v; };
    invoke('app_build_tag').then(tag => {
      if (tag) setV(tag);
      else if (window.__TAURI__?.app?.getVersion) window.__TAURI__.app.getVersion().then(v => setV('v' + v)).catch(() => {});
    }).catch(() => {});
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
    linkInput.value = '';
    linkModal.classList.remove('hidden');
  });

  addFromClipboard.addEventListener('click', async () => {
    addMenu.classList.add('hidden');
    try {
      const text = await navigator.clipboard.readText();
      if (text.length > LIMITS.link) {
        showToast('The clipboard text is too long to be a link', 'error');
      } else if (text.trim().startsWith('ostp://') || isSubscriptionUrl(text)) {
        importFromLink(text.trim());
      } else {
        showToast('The clipboard has no ostp:// link or subscription URL', 'error');
      }
    } catch {
      showToast('The clipboard cannot be read here. Use "Add a link" and press Ctrl+V.', 'error');
    }
  });

  addManually.addEventListener('click', () => {
    addMenu.classList.add('hidden');
    openProfileEditor(null);
  });

  // Link modal
  btnLinkCancel.addEventListener('click', () => linkModal.classList.add('hidden'));
  btnLinkImport.addEventListener('click', () => {
    const raw = linkInput.value.trim();
    if (!raw) { linkInput.focus(); return; }
    if (importFromLink(raw)) linkModal.classList.add('hidden');
  });
  linkInput.addEventListener('keydown', e => { if (e.key === 'Enter') btnLinkImport.click(); });
  linkModal.addEventListener('click', e => { if (e.target === linkModal) linkModal.classList.add('hidden'); });

  // Profile editor modal
  btnProfileCancel.addEventListener('click', () => profileModal.classList.add('hidden'));
  btnProfileSave.addEventListener('click', saveProfileFromEditor);
  profileModal.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type !== 'checkbox') btnProfileSave.click();
  });
  btnProfileDelete.addEventListener('click', deleteEditingProfile);
  btnPeekPm.addEventListener('click', () => {
    const show = pmKey.type === 'password';
    pmKey.type = show ? 'text' : 'password';
    btnPeekPm.setAttribute('aria-label', show ? 'Hide key' : 'Show key');
    btnPeekPm.title = show ? 'Hide key' : 'Show key';
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

  // Updates: once per app start, and the manual button.
  $('btn-check-updates').addEventListener('click', () => checkUpdates({ manual: true }));
  $('btn-update-later').addEventListener('click', () => $('update-modal').classList.add('hidden'));
  $('btn-update-skip').addEventListener('click', () => {
    try { if (pendingUpdate) localStorage.setItem(SKIP_UPDATE_KEY, pendingUpdate.tag); } catch {}
    $('update-modal').classList.add('hidden');
  });
  $('btn-update-download').addEventListener('click', () => {
    if (pendingUpdate) openUrl(pendingUpdate.url);
    $('update-modal').classList.add('hidden');
  });
  if (loadClientSettings().updateCheck !== false) setTimeout(() => checkUpdates({ manual: false }), 1500);

  // Wintun modal
  btnWintunCancel.addEventListener('click', () => wintunModal.classList.add('hidden'));
  btnWintunOpen.addEventListener('click', e => {
    e.preventDefault();
    openUrl('https://www.wintun.net');
  });
  wintunModal.addEventListener('click', e => { if (e.target === wintunModal) wintunModal.classList.add('hidden'); });

  // Client settings — wire all inputs
  [inTun, inKillSwitch, inMux, inAutoconnect, inLaunchStartup, inDebug, inShowRtt, inShowSpeed, inJunkEnabled, inTcpFrag, inTtlDesync, $('in-update-check')]
    .filter(Boolean)
    .forEach(el => el.addEventListener('change', collectAndSaveSettings));
  [inMuxSessions, inMtu, inDns, inSocks, inExDomains, inExIps, inExProcs, inJunkPcMin, inJunkPcMax, inJunkPsMin, inJunkPsMax, inFragChunk, inFragSleep]
    .forEach(el => {
      el.addEventListener('input', () => {
        clearTimeout(el._saveTimer);
        el._saveTimer = setTimeout(collectAndSaveSettings, 400);
      });
      el.addEventListener('change', () => {
        clearTimeout(el._saveTimer);
        normalizeNumberFields();
        collectAndSaveSettings();
      });
    });
  inSocks.addEventListener('change', () => {
    const problem = socksProblem(inSocks.value.trim());
    if (problem) showToast(problem, 'error');
  });

  // Junk and Frag modals
  btnJunkSettings.addEventListener('click', () => junkModal.classList.remove('hidden'));
  btnJunkDone.addEventListener('click', () => {
    normalizeNumberFields();
    collectAndSaveSettings();
    junkModal.classList.add('hidden');
  });
  junkModal.addEventListener('click', e => { if (e.target === junkModal) junkModal.classList.add('hidden'); });

  btnFragSettings.addEventListener('click', () => fragModal.classList.remove('hidden'));
  btnFragDone.addEventListener('click', () => {
    normalizeNumberFields();
    collectAndSaveSettings();
    fragModal.classList.add('hidden');
  });
  fragModal.addEventListener('click', e => { if (e.target === fragModal) fragModal.classList.add('hidden'); });

  setupInputLimits();
  setupAccessibility();
});

// A pasted multi-megabyte text would be copied into the page, saved and sent to
// the core. The limit is one more than the allowed length, so a value that is
// too long is seen as too long and refused, not silently cut.
function setupInputLimits() {
  const over = n => n + 1;
  const max = {
    'pm-name': over(LIMITS.name), 'pm-server': over(LIMITS.server), 'pm-key': over(LIMITS.key),
    'pm-sni': over(LIMITS.sni), 'pm-ws-path': over(LIMITS.path),
    'link-input': over(LIMITS.link), 'welcome-link': over(LIMITS.link),
    'in-dns': 253, 'in-socks': 300,
    'in-ex-domains': 60000, 'in-ex-ips': 60000, 'in-ex-procs': 60000,
  };
  for (const [id, n] of Object.entries(max)) $(id)?.setAttribute('maxlength', String(n));
}

// ── ACCESSIBILITY ─────────────────────────────────────────────────────
// Names for controls whose text is elsewhere, dialog semantics, and the
// keyboard rules for dialogs: Escape closes, Tab stays inside.
function setupAccessibility() {
  document.querySelectorAll('.toggle input').forEach(i => {
    const name = i.closest('.toggle-row')?.querySelector('.toggle-name');
    if (name) i.setAttribute('aria-label', name.textContent.trim());
  });

  // Buttons made later (cards, user lists) only have a title: reuse it as the name.
  const label = n => {
    if (n.nodeType !== 1) return;
    if (n.matches('button[title]:not([aria-label])')) n.setAttribute('aria-label', n.title);
    n.querySelectorAll('button[title]:not([aria-label])').forEach(b => b.setAttribute('aria-label', b.title));
  };
  label(document.body);
  new MutationObserver(ms => ms.forEach(r => r.addedNodes.forEach(label))).observe(document.body, { childList: true, subtree: true });

  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    const box = overlay.querySelector('.modal-content');
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    const title = box.querySelector('.modal-title');
    if (title) { title.id = title.id || overlay.id + '-title'; box.setAttribute('aria-labelledby', title.id); }
    let opener = null;
    new MutationObserver(() => {
      if (!overlay.classList.contains('hidden')) {
        opener = document.activeElement;
        if (!overlay.contains(document.activeElement)) {
          (overlay.querySelector('input:not([readonly]):not([type="file"]), textarea, select') || overlay.querySelector('.btn'))?.focus();
        }
      } else if (opener) {
        if (document.contains(opener)) opener.focus();
        opener = null;
      }
    }).observe(overlay, { attributes: true, attributeFilter: ['class'] });
  });

  const topDialog = () => [...document.querySelectorAll('.modal-overlay:not(.hidden)')].pop();
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (!addMenu.classList.contains('hidden')) { addMenu.classList.add('hidden'); btnAddProfile.focus(); return; }
      // The button marked data-dismiss is the dialog's way out (Cancel, Close,
      // Later). It is disabled while a server job runs, which keeps Escape
      // from hiding a job in progress.
      topDialog()?.querySelector('[data-dismiss]:not(:disabled)')?.click();
    } else if (e.key === 'Tab') {
      const dlg = topDialog();
      if (!dlg) return;
      const items = [...dlg.querySelectorAll('button, input, textarea, select, a[href], summary')]
        .filter(x => !x.disabled && x.offsetParent !== null && x.type !== 'file');
      if (!items.length) return;
      const first = items[0], last = items[items.length - 1];
      if (!dlg.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
}

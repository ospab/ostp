// ── Servers: install OSTP over SSH and manage it ─────────────────────
// The Rust side (src-tauri/src/servers.rs, crate ostp-ssh) does the SSH
// work; this file is the first-run screen's "I have a server", the list of
// servers and each server's page.

let app = null; // helpers handed over by main.js (initServers)
const $ = id => document.getElementById(id);

// Secrets typed for servers whose password or key is not remembered:
// kept for this run of the app only.
const typedAuth = new Map();
let currentId = null;
let currentTab = 'status';
let lineSink = null; // receives `server-line` events while a command runs

export function initServers(helpers) {
  app = helpers;
  window.__TAURI__?.event?.listen('server-line', e => {
    if (lineSink && e.payload?.id === lineSink.id) lineSink.fn(e.payload.line);
  });

  $('btn-servers-back').addEventListener('click', () => app.showScreen('more'));
  $('btn-servers-add').addEventListener('click', openAddModal);
  $('btn-server-back').addEventListener('click', () => { currentId = null; app.showScreen('servers'); });
  $('btn-server-refresh').addEventListener('click', () => renderTab());
  $('btn-install-close').addEventListener('click', () => $('install-modal').classList.add('hidden'));
  $('ssh-modal').addEventListener('click', e => { if (e.target.id === 'ssh-modal') $('ssh-modal').classList.add('hidden'); });
  document.querySelectorAll('#server-tabs .tab').forEach(t => t.addEventListener('click', () => {
    currentTab = t.dataset.tab;
    document.querySelectorAll('#server-tabs .tab').forEach(x => x.classList.toggle('active', x === t));
    renderTab();
  }));
}

const esc = s => app.escHtml(s == null ? '' : String(s));

// ── Small dialogs ──────────────────────────────────────────────────────
// The app's own dialog: never window.confirm, whose native box is titled
// "tauri.localhost".
export function confirmBox(title, text, okLabel = 'OK', danger = true) {
  return new Promise(resolve => {
    $('confirm-title').textContent = title;
    $('confirm-text').textContent = text;
    const ok = $('btn-confirm-ok');
    ok.textContent = okLabel;
    ok.className = 'btn ' + (danger ? 'danger' : 'primary');
    const done = v => { $('confirm-modal').classList.add('hidden'); ok.onclick = null; $('btn-confirm-cancel').onclick = null; resolve(v); };
    ok.onclick = () => done(true);
    $('btn-confirm-cancel').onclick = () => done(false);
    $('confirm-modal').classList.remove('hidden');
  });
}

// options: [{ value, title, hint }] → the chosen value, or null on cancel.
function choiceBox(title, text, options, cancelLabel = 'Cancel') {
  return new Promise(resolve => {
    $('choice-title').textContent = title;
    $('choice-text').textContent = text || '';
    $('choice-text').style.display = text ? '' : 'none';
    const box = $('choice-options');
    box.innerHTML = options.map((o, i) => `
      <button type="button" class="choice-card choice-pick" data-i="${i}">
        <div class="choice-body"><div class="choice-title">${esc(o.title)}</div>
          ${o.hint ? `<div class="choice-hint">${esc(o.hint)}</div>` : ''}</div>
      </button>`).join('');
    const done = v => { $('choice-modal').classList.add('hidden'); resolve(v); };
    box.querySelectorAll('[data-i]').forEach(b => { b.onclick = () => done(options[+b.dataset.i].value); });
    $('btn-choice-cancel').textContent = cancelLabel;
    $('btn-choice-cancel').onclick = () => done(null);
    $('choice-modal').classList.remove('hidden');
  });
}

// fields: [{ name, label, type, value, placeholder }] → { name: value } or null
function promptBox(title, text, fields) {
  return new Promise(resolve => {
    $('prompt-title').textContent = title;
    $('prompt-text').textContent = text || '';
    $('prompt-text').style.display = text ? '' : 'none';
    const box = $('prompt-fields');
    box.innerHTML = fields.map(f => `
      <div class="field-group">
        <label class="field-label">${esc(f.label)}</label>
        <input class="field-input" data-name="${esc(f.name)}" type="${f.type || 'text'}"
               value="${esc(f.value || '')}" placeholder="${esc(f.placeholder || '')}" />
      </div>`).join('');
    const done = v => { $('prompt-modal').classList.add('hidden'); resolve(v); };
    $('btn-prompt-ok').onclick = () => {
      const out = {};
      box.querySelectorAll('input').forEach(i => { out[i.dataset.name] = i.value; });
      done(out);
    };
    $('btn-prompt-cancel').onclick = () => done(null);
    $('prompt-modal').classList.remove('hidden');
    box.querySelector('input')?.focus();
  });
}

function askSecret(server) {
  return new Promise(resolve => {
    const isKey = server.auth === 'key';
    $('secret-title').textContent = `Sign in to ${server.name}`;
    $('secret-text').textContent = isKey
      ? `Private key for ${server.user}@${server.host} (not remembered on this computer).`
      : `Password for ${server.user}@${server.host} (not remembered on this computer).`;
    const input = $('secret-input');
    input.value = '';
    input.rows = isKey ? 5 : 1;
    input.style.webkitTextSecurity = isKey ? 'none' : 'disc';
    $('secret-passphrase').style.display = isKey ? '' : 'none';
    $('secret-passphrase').value = '';
    const done = v => { $('secret-modal').classList.add('hidden'); resolve(v); };
    $('btn-secret-ok').onclick = () => done(input.value ? {
      kind: isKey ? 'key' : 'password', secret: input.value, passphrase: $('secret-passphrase').value || null,
    } : null);
    $('btn-secret-cancel').onclick = () => done(null);
    $('secret-modal').classList.remove('hidden');
    input.focus();
  });
}

// ── Calls with the secret asked for when it is not remembered ─────────
let serversCache = [];

async function call(cmd, args) {
  const id = args.id;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await app.invoke(cmd, { ...args, auth: typedAuth.get(id) || null });
    } catch (e) {
      const msg = String(e?.message || e);
      const needsSecret = msg.includes('SECRET_NEEDED') || msg.includes('credential store') || msg.includes('cannot be opened');
      const rejected = /did not accept the (password|key)|cannot read the private key|passphrase/.test(msg) && typedAuth.has(id);
      if (!needsSecret && !rejected) throw new Error(msg);
      typedAuth.delete(id);
      const server = serversCache.find(s => s.id === id);
      const auth = server && await askSecret(server);
      if (!auth) throw new Error('Cancelled');
      typedAuth.set(id, auth);
    }
  }
  throw new Error('Sign-in failed');
}

async function loadServers() {
  const r = await app.invoke('servers_list');
  serversCache = r?.servers || [];
  return r || { servers: [], can_remember: false };
}

// ── The SSH form (first-run screen and "Add server") ───────────────────
// onInstalled(result) runs after OSTP is installed and profiles imported.
export async function mountSshForm(container, { onInstalled, submitLabel = 'Connect' } = {}) {
  const info = await loadServers().catch(() => ({ can_remember: false }));
  container.innerHTML = `
    <div class="ssh-form">
      <div class="ssh-row">
        <div class="field-group"><label class="field-label">Server address</label>
          <input class="field-input mono" data-f="host" placeholder="203.0.113.10" autocomplete="off" spellcheck="false" /></div>
        <div class="field-group port"><label class="field-label">SSH port</label>
          <input class="field-input mono" data-f="port" value="22" inputmode="numeric" /></div>
      </div>
      <div class="field-group"><label class="field-label">Login</label>
        <input class="field-input mono" data-f="user" value="root" autocomplete="off" spellcheck="false" /></div>
      <div class="segmented" data-f="kind">
        <button type="button" class="active" data-kind="password">Password</button>
        <button type="button" data-kind="key">Private key</button>
      </div>
      <div data-part="password" class="field-group">
        <input class="field-input" data-f="password" type="password" placeholder="SSH password" autocomplete="off" />
      </div>
      <div data-part="key" style="display:none;">
        <div class="field-group">
          <textarea class="field-input mono" data-f="key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false"></textarea>
          <div style="display:flex;justify-content:space-between;margin-top:6px;">
            <button type="button" class="link-btn" data-f="keyfile-btn">Choose a key file…</button>
            <span class="field-hint" style="margin:0;">OpenSSH, PEM or PuTTY (.ppk)</span>
          </div>
          <input type="file" data-f="keyfile" style="display:none;" />
        </div>
        <div class="field-group"><input class="field-input" data-f="passphrase" type="password" placeholder="Key passphrase (if it has one)" /></div>
      </div>
      <label class="check-row"><input type="checkbox" data-f="remember" ${info.can_remember ? 'checked' : 'disabled'} />
        ${info.can_remember ? 'Remember the password or key (encrypted, in the system credential store)'
                            : 'This system has no credential store: the password or key is asked for each time'}</label>
      <p class="field-hint is-error" data-f="error"></p>
      <div class="choice-actions"><button type="button" class="btn primary" data-f="submit">${esc(submitLabel)}</button></div>
    </div>`;
  const f = name => container.querySelector(`[data-f="${name}"]`);
  let kind = 'password';
  container.querySelectorAll('.segmented button').forEach(b => b.addEventListener('click', () => {
    kind = b.dataset.kind;
    container.querySelectorAll('.segmented button').forEach(x => x.classList.toggle('active', x === b));
    container.querySelector('[data-part="password"]').style.display = kind === 'password' ? '' : 'none';
    container.querySelector('[data-part="key"]').style.display = kind === 'key' ? '' : 'none';
  }));
  f('keyfile-btn').addEventListener('click', () => f('keyfile').click());
  f('keyfile').addEventListener('change', async () => {
    const file = f('keyfile').files[0];
    if (file) f('key').value = (await file.text()).trim();
  });

  f('submit').addEventListener('click', async () => {
    f('error').textContent = '';
    // "host:port" in the address field wins over the port field.
    let host = f('host').value.trim();
    let port = parseInt(f('port').value, 10) || 22;
    const m = host.match(/^\[?([^\]]+?)\]?:(\d+)$/);
    if (m && !host.includes('::')) { host = m[1]; port = parseInt(m[2], 10); }
    const secret = kind === 'password' ? f('password').value : f('key').value.trim();
    if (!host) { f('error').textContent = 'Enter the server address'; return; }
    if (!secret) { f('error').textContent = kind === 'password' ? 'Enter the password' : 'Paste the private key or choose its file'; return; }
    const auth = { kind, secret, passphrase: kind === 'key' ? (f('passphrase').value || null) : null };
    f('submit').disabled = true;
    try {
      const result = await addAndInstall({
        host, port, user: f('user').value.trim() || 'root', auth, remember: f('remember').checked,
      });
      if (result) onInstalled?.(result);
    } catch (e) {
      f('error').textContent = String(e?.message || e);
    } finally {
      f('submit').disabled = false;
    }
  });
}

// ── Install flow ───────────────────────────────────────────────────────
function steps(list) {
  const ol = $('install-steps');
  ol.innerHTML = list.map((s, i) => `<li data-i="${i}">${esc(s)}</li>`).join('');
  return {
    run: i => { ol.querySelector(`[data-i="${i}"]`).className = 'running'; },
    done: i => { ol.querySelector(`[data-i="${i}"]`).className = 'done'; },
    fail: i => { ol.querySelector(`[data-i="${i}"]`).className = 'failed'; },
  };
}

function openInstallModal(title) {
  $('install-title').textContent = title;
  $('install-log').textContent = '';
  $('install-error').textContent = '';
  $('btn-install-close').disabled = true;
  $('install-modal').classList.remove('hidden');
  const log = $('install-log');
  return line => { log.textContent += line + '\n'; log.scrollTop = log.scrollHeight; };
}

async function addAndInstall({ host, port, user, auth, remember }) {
  const appendLog = openInstallModal('Setting up your server');
  const st = steps(['Connecting over SSH', 'Checking the system', 'Installing OSTP', 'Adding the connection to this app']);
  let step = 0;
  let server = null;
  try {
    st.run(0);
    server = await app.invoke('server_add', { name: host, host, port, user, auth, remember });
    if (!remember || !server.remembered) typedAuth.set(server.id, auth);
    await loadServers();
    appendLog(`Connected to ${user}@${host}:${port}. Host key ${server.host_key}`);
    st.done(0); step = 1; st.run(1);

    const probe = await call('server_probe', { id: server.id });
    appendLog(`System: ${probe.os} (${probe.arch}); ${probe.installed ? 'OSTP ' + probe.version + ' is installed' : 'OSTP is not installed'}`);
    if (!probe.systemd) throw new Error('This system has no systemd; OSTP needs it to run as a service');
    st.done(1); step = 2;

    // OSTP already there: nothing on the server changes unless the user says so.
    let mode = 'install';
    if (probe.installed) {
      mode = await choiceBox(`OSTP ${probe.version} is already on this server`,
        'Nothing on the server changes unless you choose to update it.', [
          { value: 'keep', title: 'Add it as it is', hint: "OSTP is left untouched; the app takes the users' links from it" },
          { value: 'install', title: 'Update OSTP', hint: "The newest release of this app's channel; the config and users are kept, the service restarts" },
        ]);
      if (!mode) {
        appendLog('Nothing was changed on the server. It stays in Settings → Servers.');
        $('install-title').textContent = 'Server added';
        $('btn-install-close').disabled = false;
        return null;
      }
    }
    const label = $('install-steps').querySelector('[data-i="2"]');
    if (mode === 'keep') label.textContent = 'Reading the users';
    else if (probe.installed) label.textContent = 'Updating OSTP';
    st.run(2);

    let result;
    if (mode === 'keep') {
      result = await call('server_manage', { id: server.id, args: ['users'] });
    } else {
      lineSink = { id: server.id, fn: appendLog };
      result = await call('server_install', { id: server.id, port: 50000 });
      lineSink = null;
    }
    st.done(2); step = 3; st.run(3);

    const first = (result.users || [])[0];
    const imported = first ? await addUserToApp(server, first) : 0;
    st.done(3);
    appendLog(imported == null ? 'No connection was added to this app.' : `Added ${imported} connection profile(s).`);
    $('install-title').textContent = 'Your server is ready';
    $('btn-install-close').disabled = false;
    return { server, result };
  } catch (e) {
    lineSink = null;
    st.fail(step);
    const msg = String(e?.message || e);
    $('install-error').textContent = msg;
    $('btn-install-close').disabled = false;
    // A server that never connected is not kept.
    if (server && step === 0) app.invoke('server_remove', { id: server.id }).catch(() => {});
    throw new Error(step === 0 ? msg : 'Installation did not finish; see the server output');
  }
}

// Adds one user to this app: as a subscription (profiles that follow the
// server's changes) or as fixed profiles. Asks when both are possible.
// Returns the number of profiles added, or null when the user declined.
async function addUserToApp(server, u, { cancelLabel = 'Cancel' } = {}) {
  let how = 'profiles';
  if (u.subscription) {
    how = await choiceBox(`Add ${u.name || 'user ' + u.number} to this app`, '', [
      { value: 'subscription', title: 'As a subscription', hint: 'Profiles update themselves when the server changes (new domain, TLS, ports)' },
      { value: 'profiles', title: 'As profiles', hint: 'Fixed connection profiles; changes on the server need adding them again' },
    ], cancelLabel);
    if (!how) return null;
  }
  if (how === 'subscription') return app.addSubscription(u.subscription);
  return importUsers(server, [u]);
}

// Imports a user's links as profiles; `limit` users from the start.
function importUsers(server, users, limit = Infinity) {
  let n = 0;
  for (const u of users.slice(0, limit)) {
    const links = (u.links || []).map(l => l.uri);
    n += app.importLinks(links, { baseName: `${server.name}${u.name ? ' · ' + u.name : ''}`, serverId: server.id });
  }
  return n;
}

// ── Servers list ───────────────────────────────────────────────────────
function openAddModal() {
  $('ssh-modal').classList.remove('hidden');
  mountSshForm($('modal-ssh-form'), {
    onInstalled: ({ server }) => {
      $('ssh-modal').classList.add('hidden');
      renderServers();
      openServer(server.id);
    },
  });
}

export async function renderServers() {
  const list = $('servers-list');
  list.innerHTML = '<div class="loading-note">Loading…</div>';
  let r;
  try { r = await loadServers(); } catch (e) { list.innerHTML = `<div class="empty-note">${esc(e?.message || e)}</div>`; return; }
  if (!r.servers.length) {
    list.innerHTML = `<div class="profile-empty"><p>No servers yet.<br/>Tap <strong>+</strong> to install OSTP on your own VPS over SSH.</p></div>`;
    return;
  }
  list.innerHTML = '';
  for (const s of r.servers) {
    const card = document.createElement('div');
    card.className = 'profile-card server-card';
    card.innerHTML = `
      <div class="profile-info">
        <div class="profile-name">${esc(s.name)}</div>
        <div class="profile-server">${esc(s.user)}@${esc(s.host)}${s.port !== 22 ? ':' + s.port : ''}</div>
      </div>
      <span class="profile-transport-badge">${s.remembered ? esc(s.auth) : 'ask'}</span>`;
    card.addEventListener('click', () => openServer(s.id));
    list.appendChild(card);
  }
}

export function openServer(id) {
  currentId = id;
  currentTab = 'status';
  const s = serversCache.find(x => x.id === id);
  $('server-title').textContent = s ? s.name : 'Server';
  document.querySelectorAll('#server-tabs .tab').forEach(x => x.classList.toggle('active', x.dataset.tab === 'status'));
  app.showScreen('server');
  renderTab();
}

// ── One server ─────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function fmtDuration(sec) {
  if (sec == null) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}
const kv = (k, v, cls = '') => `<div class="kv-row"><span class="k">${esc(k)}</span><span class="v ${cls}">${v}</span></div>`;

async function renderTab() {
  const id = currentId;
  if (!id) return;
  const body = $('server-body');
  body.innerHTML = '<div class="loading-note">Talking to the server…</div>';
  try {
    if (currentTab === 'status') await renderStatus(body, id);
    else if (currentTab === 'users') await renderUsers(body, id);
    else if (currentTab === 'connection') await renderConnection(body, id);
    else await renderManage(body, id);
  } catch (e) {
    if (id !== currentId) return;
    body.innerHTML = `<div class="empty-note">${esc(e?.message || e)}</div>
      <div class="btn-row"><button class="btn secondary" id="btn-tab-retry">Try again</button></div>`;
    $('btn-tab-retry').onclick = () => renderTab();
  }
}

async function renderStatus(body, id) {
  const s = await call('server_manage', { id, args: ['status'] });
  if (id !== currentId) return;
  const sys = s.system || {};
  const now = Date.now() / 1000;
  const memUsed = sys.mem_total && sys.mem_available != null ? sys.mem_total - sys.mem_available : null;
  const diskUsed = sys.disk_total && sys.disk_free != null ? sys.disk_total - sys.disk_free : null;
  const meter = (used, total) => used != null && total ? `<div class="meter"><div style="width:${Math.min(100, used / total * 100).toFixed(0)}%"></div></div>` : '';
  const active = s.service?.active;
  body.innerHTML = `
    <div class="kv-card">
      ${kv('OSTP service', active ? '<span class="pill ok">running</span>' : '<span class="pill bad">stopped</span>')}
      ${kv('Version', esc(s.version))}
      ${kv('Running for', s.service?.started_at && active ? fmtDuration(now - s.service.started_at) : '—')}
      ${kv('Connected sessions', s.sessions ?? '—')}
      ${kv('Users', s.users)}
      ${kv('Listens on', esc(s.listen), 'mono')}
    </div>
    <div class="kv-card">
      ${kv('System', esc(sys.os || '—'))}
      ${kv('Uptime', fmtDuration(sys.uptime_secs))}
      ${kv('Load', sys.load?.length ? esc(sys.load.map(x => x.toFixed(2)).join(' · ')) + (sys.cpus ? ` <span style="color:var(--c-txt-2)">/ ${sys.cpus} CPU</span>` : '') : '—')}
      <div class="kv-row" style="display:block;"><div style="display:flex;justify-content:space-between;"><span class="k">Memory</span><span class="v">${fmtBytes(memUsed)} / ${fmtBytes(sys.mem_total)}</span></div>${meter(memUsed, sys.mem_total)}</div>
      <div class="kv-row" style="display:block;"><div style="display:flex;justify-content:space-between;"><span class="k">Disk</span><span class="v">${fmtBytes(diskUsed)} / ${fmtBytes(sys.disk_total)}</span></div>${meter(diskUsed, sys.disk_total)}</div>
    </div>
    <div class="btn-row">
      <button class="btn secondary" id="btn-srv-restart">Restart OSTP</button>
      <button class="btn secondary" id="btn-srv-update">Update OSTP</button>
    </div>
    <p class="card-note">Restarting or updating drops every active connection, this one too if it goes through this server.</p>`;
  $('btn-srv-restart').onclick = () => runAction(id, 'restart', 'Restart OSTP?', 'Every connected client is disconnected for a few seconds.');
  $('btn-srv-update').onclick = () => runAction(id, 'update', 'Update OSTP?', 'The newest release of this app\'s channel is installed and the service restarts. The config is kept.');
}

async function renderUsers(body, id) {
  const r = await call('server_manage', { id, args: ['users'] });
  if (id !== currentId) return;
  const users = r.users || [];
  const server = serversCache.find(s => s.id === id);
  body.innerHTML = `
    <div class="inline-add">
      <input class="field-input" id="new-user-name" placeholder="New user's name, e.g. phone" />
      <button class="btn primary" id="btn-user-add">Add</button>
    </div>
    <div id="users-list"></div>
    <p class="card-note">Traffic is kept across restarts and updates${r.stats_at ? `, as of ${new Date(r.stats_at * 1000).toLocaleTimeString()}` : ''}.</p>`;
  const list = $('users-list');
  users.forEach(u => {
    const card = document.createElement('div');
    card.className = 'user-card';
    const traffic = u.bytes_down != null ? `↓ ${fmtBytes(u.bytes_down)} · ↑ ${fmtBytes(u.bytes_up)}` : 'no traffic yet';
    card.innerHTML = `
      <div class="user-head">
        <span class="online-dot ${u.online ? 'on' : ''}" title="${u.online ? 'Online' : 'Offline'}"></span>
        <span class="user-name">${esc(u.name || 'user ' + u.number)}</span>
        <button class="profile-action-btn" data-a="import" title="Add to this app"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>
        <button class="profile-action-btn" data-a="share" title="Share (QR)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></button>
        <button class="profile-action-btn" data-a="rename" title="Rename"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
        <button class="profile-action-btn" data-a="remove" title="Revoke"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>
      </div>
      <div class="user-meta">${traffic}${u.limit_bytes ? ` · limit ${fmtBytes(u.limit_bytes)}` : ''}</div>`;
    const who = String(u.number);
    card.querySelector('[data-a="import"]').onclick = async () => {
      const n = await addUserToApp(server, u);
      if (n != null) app.showToast(n ? `Added ${n} profile(s)` : 'Already in the app', 'ok');
    };
    card.querySelector('[data-a="share"]').onclick = () => {
      const best = u.subscription || u.links?.[0]?.uri;
      if (best) app.showShare(`Share: ${u.name || 'user ' + u.number}`, best);
    };
    card.querySelector('[data-a="rename"]').onclick = async () => {
      const v = await promptBox('Rename user', '', [{ name: 'name', label: 'Name', value: u.name }]);
      if (!v || !v.name.trim()) return;
      try { await call('server_manage', { id, args: ['user-rename', who, v.name.trim()] }); renderTab(); }
      catch (e) { app.showToast(String(e.message || e), 'error'); }
    };
    card.querySelector('[data-a="remove"]').onclick = async () => {
      if (!await confirmBox(`Revoke ${u.name || 'user ' + u.number}?`, 'Their key stops working at once. Profiles made from it stop connecting.', 'Revoke')) return;
      try { await call('server_manage', { id, args: ['user-remove', u.key] }); renderTab(); }
      catch (e) { app.showToast(String(e.message || e), 'error'); }
    };
    list.appendChild(card);
  });
  $('btn-user-add').onclick = async () => {
    const name = $('new-user-name').value.trim();
    if (!name) { $('new-user-name').focus(); return; }
    $('btn-user-add').disabled = true;
    try {
      const r = await call('server_manage', { id, args: ['user-add', name] });
      app.showToast(`User ${name} added`, 'ok');
      // The new user may be for someone else: "Not now" leaves the app as is.
      if (r?.user) {
        const n = await addUserToApp(server, r.user, { cancelLabel: 'Not now' });
        if (n) app.showToast(`Added ${n} profile(s)`, 'ok');
      }
      renderTab();
    } catch (e) {
      app.showToast(String(e.message || e), 'error');
      $('btn-user-add').disabled = false;
    }
  };
}

async function renderConnection(body, id) {
  const s = await call('server_manage', { id, args: ['status'] });
  if (id !== currentId) return;
  const tls = s.tls || {};
  const days = tls.cert_days_left;
  const certPill = !tls.enabled ? '<span class="pill warn">not set up</span>'
    : tls.cert_self_signed ? '<span class="pill warn">not issued yet</span>'
    : days == null ? '<span class="pill ok">by the web server</span>'
    : days < 10 ? `<span class="pill bad">${days} days left</span>` : `<span class="pill ok">${days} days left</span>`;
  body.innerHTML = `
    <div class="kv-card">
      ${kv('UDP / TCP port', s.udp_port)}
      ${kv('TLS on 443', tls.enabled ? '<span class="pill ok">on</span>' : '<span class="pill warn">off</span>')}
      ${kv('Domain', esc(tls.domain || '—'))}
      ${kv('Certificate', certPill)}
      ${kv('Subscriptions', s.subscription ? '<span class="pill ok">on</span>' : '<span class="pill warn">off</span>')}
    </div>
    <p class="card-note">TLS makes OSTP look like an ordinary HTTPS site on port 443, which gets through where UDP is blocked.
      It needs a domain whose A record points at this server.</p>
    <div class="btn-row">
      <button class="btn ${tls.enabled ? 'secondary' : 'primary'}" id="btn-cert">${tls.enabled ? 'Change domain' : 'Set up TLS'}</button>
      <button class="btn secondary" id="btn-sub" ${tls.enabled ? '' : 'disabled title="Needs TLS first"'}>${s.subscription ? 'Turn subscriptions off' : 'Turn subscriptions on'}</button>
    </div>`;
  $('btn-cert').onclick = async () => {
    const v = await promptBox('TLS certificate', 'A free Let\'s Encrypt certificate. Port 80 must be reachable for the check.', [
      { name: 'domain', label: 'Domain', value: tls.domain || '', placeholder: 'vpn.example.com' },
      { name: 'email', label: 'Email for expiry notices (optional)', type: 'email' },
    ]);
    if (!v || !v.domain.trim()) return;
    runAction(id, 'cert-issue', null, null, { domain: v.domain.trim(), email: v.email.trim() });
  };
  $('btn-sub').onclick = () => runAction(id, s.subscription ? 'sub-disable' : 'sub-enable',
    s.subscription ? 'Turn subscriptions off?' : null, s.subscription ? 'Subscription links stop updating in the apps.' : null);
}

// overnet (github.com/ospab/overnet): .ov sites for this server's clients
// through the overnet gateway on the server. Off until the owner turns it on.
function overnetSection(ov) {
  if (!ov) return ''; // a server older than 0.4.7
  const pill = (on, yes = 'on', no = 'off') => on ? `<span class="pill ok">${yes}</span>` : `<span class="pill warn">${no}</span>`;
  const gw = !ov.installed ? '<span class="pill warn">not installed</span>'
    : ov.gateway_up ? '<span class="pill ok">answers</span>' : '<span class="pill bad">not answering</span>';
  return `
    <div class="section-divider"><span>overnet</span></div>
    <div class="kv-card">
      ${kv('.ov sites for clients', pill(ov.entry))}
      ${kv('overnet gateway', gw)}
      ${kv('Exit', pill(ov.exit))}
    </div>
    <div class="btn-row">
      ${ov.installed ? '' : '<button class="btn secondary" id="btn-ov-install">Install overnet gateway</button>'}
      ${ov.entry ? '<button class="btn secondary" id="btn-ov-off">Turn .ov off</button>'
                 : '<button class="btn primary" id="btn-ov-on">Turn .ov on</button>'}
      <button class="btn secondary" id="btn-ov-exit">${ov.exit ? 'Close the exit' : 'Open an exit'}</button>
    </div>
    <p class="card-note">With .ov on, devices connected through this server open .ov sites (try http://search.ov/) in any browser.
      The gateway is overnet's own program; nothing is installed until you press the button.
      An exit lets overnet users reach the internet from this server's IP.</p>`;
}

function bindOvernet(id, ov) {
  if (!ov) return;
  const b = x => document.getElementById(x);
  if (b('btn-ov-install')) b('btn-ov-install').onclick = () => runAction(id, 'overnet-install',
    'Install the overnet gateway?', 'Runs overnet\'s installer from github.com/ospab/overnet on the server and starts the overnet-gateway service. OSTP settings do not change.');
  if (b('btn-ov-on')) b('btn-ov-on').onclick = () => runAction(id, 'overnet-enable',
    'Turn .ov on?', ov.gateway_up ? 'The OSTP service restarts; connected clients drop for a few seconds.'
      : 'The overnet gateway is not answering yet: clients get "not found" for .ov until it runs. The OSTP service restarts.');
  if (b('btn-ov-off')) b('btn-ov-off').onclick = () => runAction(id, 'overnet-disable',
    'Turn .ov off?', 'The OSTP service restarts; connected clients drop for a few seconds.');
  b('btn-ov-exit').onclick = () => runAction(id, ov.exit ? 'overnet-exit-off' : 'overnet-exit-on',
    ov.exit ? 'Close the exit?' : 'Open an overnet exit?',
    ov.exit ? 'The OSTP service restarts.' : 'overnet users\' internet traffic will leave from this server\'s IP, and you answer for it. The OSTP service restarts.');
}

async function renderManage(body, id) {
  const s = await call('server_manage', { id, args: ['status'] });
  if (id !== currentId) return;
  const server = serversCache.find(x => x.id === id);
  const panel = s.panel || {};
  body.innerHTML = `
    <div class="section-divider"><span>Web panel</span></div>
    <div class="kv-card">
      ${kv('Panel', panel.enabled ? '<span class="pill ok">on</span>' : '<span class="pill warn">off</span>')}
      ${kv('Sign-in', panel.login ? 'set' : 'not set')}
    </div>
    <div class="btn-row">
      ${panel.enabled ? '<button class="btn primary" id="btn-panel-open">Open the panel</button><button class="btn secondary" id="btn-panel-off">Turn off</button>'
                      : '<button class="btn primary" id="btn-panel-on">Turn on the panel</button>'}
    </div>
    ${panel.enabled ? `<div class="kv-card">${kv('Through the VPN', esc(vpnPanelUrl(panel)), 'mono')}</div>` : ''}
    <p class="card-note">"Open the panel" goes through this SSH connection and needs no open port.
      The VPN address works in any browser on a device connected through this server, phones included.</p>

    ${overnetSection(s.overnet)}

    <div class="section-divider"><span>Server log</span></div>
    <div class="btn-row"><button class="btn secondary" id="btn-logs">Show the last 300 lines</button></div>
    <pre class="log-view" id="server-log" style="display:none;"></pre>

    <div class="section-divider"><span>This server</span></div>
    <div class="kv-card">
      ${kv('SSH', esc(`${server?.user}@${server?.host}:${server?.port}`), 'mono')}
      ${kv('Host key', esc(server?.host_key || ''), 'mono')}
    </div>
    <div class="btn-row">
      <button class="btn secondary" id="btn-srv-rename">Rename</button>
      <button class="btn secondary" id="btn-srv-reboot">Reboot server</button>
    </div>
    <div class="btn-row">
      <button class="btn danger" id="btn-srv-uninstall">Uninstall OSTP</button>
      <button class="btn danger" id="btn-srv-forget">Forget server</button>
    </div>`;

  if (panel.enabled) {
    $('btn-panel-open').onclick = async () => {
      try { await call('server_open_panel', { id }); }
      catch (e) { app.showToast(String(e.message || e), 'error'); }
    };
    $('btn-panel-off').onclick = () => runAction(id, 'panel-disable', 'Turn off the panel?', 'The OSTP service restarts; connected clients drop for a few seconds.');
  } else {
    $('btn-panel-on').onclick = async () => {
      const v = await promptBox('Turn on the panel', 'The OSTP service restarts; connected clients drop for a few seconds.', [
        { name: 'user', label: 'Sign-in name', value: 'admin' },
        { name: 'password', label: 'Password (8+ characters)', type: 'password' },
      ]);
      if (!v) return;
      runAction(id, 'panel-enable', null, null, { user: v.user, password: v.password });
    };
  }
  bindOvernet(id, s.overnet);
  $('btn-logs').onclick = async () => {
    const pre = $('server-log');
    pre.style.display = '';
    pre.textContent = 'Loading…';
    try {
      const r = await call('server_manage', { id, args: ['logs', '-n', '300'] });
      pre.textContent = (r.lines || []).join('\n') || '(empty)';
      pre.scrollTop = pre.scrollHeight;
    } catch (e) { pre.textContent = String(e.message || e); }
  };
  $('btn-srv-rename').onclick = async () => {
    const v = await promptBox('Rename server', '', [{ name: 'name', label: 'Name', value: server?.name }]);
    if (!v || !v.name.trim()) return;
    await app.invoke('server_rename', { id, name: v.name.trim() });
    await loadServers();
    $('server-title').textContent = v.name.trim();
    renderTab();
  };
  $('btn-srv-reboot').onclick = () => runAction(id, 'reboot', 'Reboot the server?', 'It is back in about a minute. Every connection drops until then.');
  $('btn-srv-uninstall').onclick = () => runAction(id, 'uninstall', 'Remove OSTP from the server?',
    'The service, the config and every user key are deleted. Nobody can connect to this server afterwards.');
  $('btn-srv-forget').onclick = async () => {
    if (!await confirmBox('Remove from the app?', 'Only this app forgets the server and its saved password or key. OSTP keeps running on it.', 'Remove')) return;
    await app.invoke('server_remove', { id });
    typedAuth.delete(id);
    currentId = null;
    app.showScreen('servers');
  };
}

// The panel inside the tunnel: 10.1.0.1 is the server as clients see it.
function vpnPanelUrl(panel) {
  const port = String(panel.bind || '').split(':').pop();
  // An empty webpath means /panel/ (servers older than 0.4.6 report it empty).
  const path = String(panel.webpath || '').replace(/^\/+|\/+$/g, '') || 'panel';
  return `http://10.1.0.1:${port}/${path}/`;
}

// Actions that restart or remove things are refused while this app is
// connected through the same server: the answer would never arrive.
async function runAction(id, action, confirmTitle, confirmText, params = null) {
  const server = serversCache.find(s => s.id === id);
  const disruptive = ['restart', 'update', 'reboot', 'uninstall', 'panel-enable', 'panel-disable', 'cert-issue',
    'overnet-enable', 'overnet-disable', 'overnet-exit-on', 'overnet-exit-off'].includes(action);
  if (disruptive && server && app.connectedThrough(server.host)) {
    await confirmBox('Disconnect first', 'This app is connected through this server, and this change interrupts that connection. Disconnect, then try again.', 'OK', false);
    return;
  }
  if (confirmTitle && !await confirmBox(confirmTitle, confirmText || '', 'Continue')) return;
  const appendLog = openInstallModal({
    update: 'Updating OSTP', restart: 'Restarting OSTP', reboot: 'Rebooting', uninstall: 'Removing OSTP',
    'panel-enable': 'Turning on the panel', 'panel-disable': 'Turning off the panel', 'cert-issue': 'Getting a certificate',
    'sub-enable': 'Turning on subscriptions', 'sub-disable': 'Turning off subscriptions',
  }[action] || action);
  const st = steps(['Running on the server']);
  st.run(0);
  lineSink = { id, fn: appendLog };
  try {
    await call('server_action', { id, action, params });
    st.done(0);
    $('install-title').textContent += ': done';
  } catch (e) {
    st.fail(0);
    $('install-error').textContent = String(e?.message || e);
  } finally {
    lineSink = null;
    $('btn-install-close').disabled = false;
    if (action === 'uninstall' || action === 'reboot') return;
    renderTab();
  }
}

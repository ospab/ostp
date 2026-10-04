import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/servers.dart';
import 'ssh_setup.dart';

const _green = Color(0xFF2EE66D);
const _amber = Color(0xFFF0B840);

/// Settings → Server management: the servers this app installed or added.
class ServersScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const ServersScreen({super.key, required this.prefs});

  @override
  State<ServersScreen> createState() => _ServersScreenState();
}

class _ServersScreenState extends State<ServersScreen> {
  late Future<ServersList> _list;

  @override
  void initState() {
    super.initState();
    _list = ServersApi.list();
  }

  void _reload() => setState(() => _list = ServersApi.list());

  Future<void> _add() async {
    final server = await Navigator.push<Map<String, dynamic>>(
      context,
      MaterialPageRoute(builder: (_) => AddServerScreen(prefs: widget.prefs)),
    );
    _reload();
    if (server != null && mounted) _open(server);
  }

  Future<void> _open(Map<String, dynamic> server) async {
    await Navigator.push(context, MaterialPageRoute(builder: (_) => ServerScreen(prefs: widget.prefs, server: server)));
    _reload();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Servers'), actions: [IconButton(icon: const Icon(Icons.add), onPressed: _add)]),
      body: FutureBuilder<ServersList>(
        future: _list,
        builder: (context, snap) {
          if (snap.hasError) return _Message(snap.error.toString(), onRetry: _reload);
          if (!snap.hasData) return const Center(child: CircularProgressIndicator());
          final servers = snap.data!.servers;
          if (servers.isEmpty) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  const Icon(Icons.dns_outlined, size: 48, color: Colors.white24),
                  const SizedBox(height: 16),
                  const Text('No servers yet', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 8),
                  const Text('Install OSTP on your own VPS over SSH: all it takes is its address and login.',
                      textAlign: TextAlign.center, style: TextStyle(color: Colors.white54)),
                  const SizedBox(height: 20),
                  FilledButton.icon(onPressed: _add, icon: const Icon(Icons.add), label: const Text('Add a server')),
                ]),
              ),
            );
          }
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              for (final s in servers)
                Card(
                  margin: const EdgeInsets.only(bottom: 10),
                  child: ListTile(
                    leading: const Icon(Icons.dns),
                    title: Text(s['name'] as String, style: const TextStyle(fontWeight: FontWeight.w600)),
                    subtitle: Text('${s['user']}@${s['host']}${s['port'] != 22 ? ':${s['port']}' : ''}',
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _open(s),
                  ),
                ),
            ],
          );
        },
      ),
    );
  }
}

class AddServerScreen extends StatelessWidget {
  final SharedPreferences prefs;
  const AddServerScreen({super.key, required this.prefs});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Add a server')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: SshSetupForm(prefs: prefs, onInstalled: (s) => Navigator.pop(context, s)),
      ),
    );
  }
}

class _Message extends StatelessWidget {
  final String text;
  final VoidCallback? onRetry;
  const _Message(this.text, {this.onRetry});

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Text(text, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white70)),
            if (onRetry != null) ...[
              const SizedBox(height: 16),
              OutlinedButton(onPressed: onRetry, child: const Text('Try again')),
            ],
          ]),
        ),
      );
}

/// One server: Status, Users, Connection, Management.
class ServerScreen extends StatefulWidget {
  final SharedPreferences prefs;
  final Map<String, dynamic> server;
  const ServerScreen({super.key, required this.prefs, required this.server});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  late Map<String, dynamic> _server = widget.server;
  int _generation = 0; // bumped to reload every tab

  String get _id => _server['id'] as String;

  Future<dynamic> _call(Map<String, dynamic> req) => ServersApi.call(context, {...req, 'id': _id}, server: _server);

  Future<Map<String, dynamic>> _manage(List<String> args) async =>
      await _call({'op': 'manage', 'args': args}) as Map<String, dynamic>;

  void _refresh() => setState(() => _generation++);

  void _toast(String text, {bool error = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(text),
      backgroundColor: error ? Colors.red.shade900 : null,
    ));
  }

  Future<bool> _confirm(String title, String text, {String ok = 'Continue', bool danger = true}) async {
    final r = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Text(text),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(
            style: danger ? FilledButton.styleFrom(backgroundColor: Colors.red.shade700, foregroundColor: Colors.white) : null,
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(ok),
          ),
        ],
      ),
    );
    return r ?? false;
  }

  /// fields: name → (label, obscure, initial)
  Future<Map<String, String>?> _prompt(String title, String? text, Map<String, (String, bool, String)> fields) async {
    final ctrls = {for (final e in fields.entries) e.key: TextEditingController(text: e.value.$3)};
    final r = await showDialog<Map<String, String>>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            if (text != null) Text(text, style: const TextStyle(color: Colors.white54, fontSize: 13)),
            for (final e in fields.entries)
              TextField(
                controller: ctrls[e.key],
                obscureText: e.value.$2,
                decoration: InputDecoration(labelText: e.value.$1),
              ),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, {for (final e in ctrls.entries) e.key: e.value.text}),
            child: const Text('OK'),
          ),
        ],
      ),
    );
    return r;
  }

  static const _titles = {
    'update': 'Updating OSTP', 'restart': 'Restarting OSTP', 'reboot': 'Rebooting', 'uninstall': 'Removing OSTP',
    'panel-enable': 'Turning on the panel', 'panel-disable': 'Turning off the panel', 'cert-issue': 'Getting a certificate',
    'sub-enable': 'Turning on subscriptions', 'sub-disable': 'Turning off subscriptions',
    'overnet-install': 'Installing the overnet gateway', 'overnet-enable': 'Turning .ov on', 'overnet-disable': 'Turning .ov off',
    'overnet-exit-on': 'Opening the overnet exit', 'overnet-exit-off': 'Closing the overnet exit',
  };

  /// Runs a change on the server with its output shown live. Changes that
  /// restart the service are refused while the VPN goes through this server.
  Future<void> _action(String action, {String? confirmTitle, String? confirmText, Map<String, dynamic>? params}) async {
    const disruptive = {
      'restart', 'update', 'reboot', 'uninstall', 'panel-enable', 'panel-disable', 'cert-issue',
      'overnet-enable', 'overnet-disable', 'overnet-exit-on', 'overnet-exit-off',
    };
    if (disruptive.contains(action) && await ServersApi.connectedThrough(widget.prefs, _server['host'] as String)) {
      if (!mounted) return;
      await _confirm('Disconnect first',
          'The VPN goes through this server, and this change interrupts it. Disconnect, then try again.',
          ok: 'OK', danger: false);
      return;
    }
    if (confirmTitle != null && !await _confirm(confirmTitle, confirmText ?? '')) return;
    if (!mounted) return;
    await showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => _ActionDialog(
        title: _titles[action] ?? action,
        run: () => _call({'op': 'action', 'action': action, 'params': params}),
        serverId: _id,
      ),
    );
    if (action == 'uninstall' && mounted) {
      Navigator.pop(context);
      return;
    }
    _refresh();
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 4,
      child: Scaffold(
        appBar: AppBar(
          title: Text(_server['name'] as String),
          actions: [IconButton(icon: const Icon(Icons.refresh), onPressed: _refresh)],
          bottom: const TabBar(labelPadding: EdgeInsets.symmetric(horizontal: 4), labelStyle: TextStyle(fontSize: 13, fontWeight: FontWeight.w600), tabs: [
            Tab(text: 'Status'),
            Tab(text: 'Users'),
            Tab(text: 'Connection'),
            Tab(text: 'Management'),
          ]),
        ),
        body: TabBarView(children: [
          _Loader(key: ValueKey('s$_generation'), load: () => _manage(['status']), build: _status),
          _Loader(key: ValueKey('u$_generation'), load: () => _manage(['users']), build: _users),
          _Loader(key: ValueKey('c$_generation'), load: () => _manage(['status']), build: _connection),
          _Loader(key: ValueKey('m$_generation'), load: () => _manage(['status']), build: _management),
        ]),
      ),
    );
  }

  // ── Status ────────────────────────────────────────────────────────────
  Widget _status(Map<String, dynamic> s) {
    final sys = (s['system'] as Map?)?.cast<String, dynamic>() ?? {};
    final service = (s['service'] as Map?)?.cast<String, dynamic>() ?? {};
    final active = service['active'] == true;
    final now = DateTime.now().millisecondsSinceEpoch / 1000;
    final memTotal = sys['mem_total'] as num?, memAvail = sys['mem_available'] as num?;
    final diskTotal = sys['disk_total'] as num?, diskFree = sys['disk_free'] as num?;
    final memUsed = memTotal != null && memAvail != null ? memTotal - memAvail : null;
    final diskUsed = diskTotal != null && diskFree != null ? diskTotal - diskFree : null;
    final load = (sys['load'] as List?)?.map((x) => (x as num).toStringAsFixed(2)).join(' · ');
    return ListView(padding: const EdgeInsets.all(16), children: [
      _Card([
        _Row('OSTP service', pill: active ? ('running', _green) : ('stopped', Colors.redAccent)),
        _Row('Version', value: s['version']?.toString()),
        _Row('Running for', value: active && service['started_at'] != null ? fmtDuration(now - (service['started_at'] as num)) : '—'),
        _Row('Connected sessions', value: s['sessions']?.toString() ?? '—'),
        _Row('Users', value: s['users']?.toString()),
        _Row('Listens on', value: s['listen']?.toString(), mono: true),
      ]),
      _Card([
        _Row('System', value: sys['os']?.toString() ?? '—'),
        _Row('Uptime', value: fmtDuration(sys['uptime_secs'] as num?)),
        _Row('Load', value: load == null ? '—' : '$load${sys['cpus'] != null ? ' / ${sys['cpus']} CPU' : ''}'),
        _Meter('Memory', memUsed, memTotal),
        _Meter('Disk', diskUsed, diskTotal),
      ]),
      Row(children: [
        Expanded(
          child: OutlinedButton(
            onPressed: () => _action('restart', confirmTitle: 'Restart OSTP?', confirmText: 'Every connected client is disconnected for a few seconds.'),
            child: const Text('Restart OSTP'),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: OutlinedButton(
            onPressed: () => _action('update',
                confirmTitle: 'Update OSTP?',
                confirmText: "The newest release of this app's channel is installed and the service restarts. The config is kept."),
            child: const Text('Update OSTP'),
          ),
        ),
      ]),
      const _Note('Restarting or updating drops every active connection.'),
    ]);
  }

  // ── Users ─────────────────────────────────────────────────────────────
  Widget _users(Map<String, dynamic> r) {
    final users = (r['users'] as List? ?? const []).cast<Map<String, dynamic>>();
    final newName = TextEditingController();
    Future<void> add() async {
      final name = newName.text.trim();
      if (name.isEmpty) return;
      try {
        final r = await _manage(['user-add', name]);
        _toast('User $name added');
        // The new user may be for someone else: "Not now" leaves the app as is.
        final user = r['user'];
        if (user is Map<String, dynamic> && mounted) {
          final n = await ServersApi.addUserToApp(context, widget.prefs, _server['name'] as String, user, cancelLabel: 'Not now');
          if (n != null && n > 0) _toast('Added $n profile(s)');
        }
        _refresh();
      } catch (e) {
        _toast(e.toString(), error: true);
      }
    }

    return ListView(padding: const EdgeInsets.all(16), children: [
      Row(children: [
        Expanded(
          child: TextField(
            controller: newName,
            decoration: const InputDecoration(hintText: "New user's name, e.g. phone", isDense: true),
            onSubmitted: (_) => add(),
          ),
        ),
        const SizedBox(width: 10),
        FilledButton(onPressed: add, child: const Text('Add')),
      ]),
      const SizedBox(height: 14),
      for (final u in users) _userCard(u),
      _Note('Traffic is kept across restarts and updates'
          '${r['stats_at'] != null ? ', as of ${TimeOfDay.fromDateTime(DateTime.fromMillisecondsSinceEpoch(((r['stats_at'] as num) * 1000).toInt())).format(context)}' : ''}.'),
    ]);
  }

  Widget _userCard(Map<String, dynamic> u) {
    final name = (u['name'] as String?)?.isNotEmpty == true ? u['name'] as String : 'user ${u['number']}';
    final traffic = u['bytes_down'] != null ? '↓ ${fmtBytes(u['bytes_down'] as num)} · ↑ ${fmtBytes(u['bytes_up'] as num?)}' : 'no traffic yet';
    final who = '${u['number']}';
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 6, 4, 10),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(Icons.circle, size: 9, color: u['online'] == true ? _green : Colors.white24),
            const SizedBox(width: 8),
            Expanded(child: Text(name, style: const TextStyle(fontWeight: FontWeight.w600), overflow: TextOverflow.ellipsis)),
            IconButton(
              tooltip: 'Add to this app',
              icon: const Icon(Icons.download, size: 20),
              onPressed: () async {
                final n = await ServersApi.addUserToApp(context, widget.prefs, _server['name'] as String, u);
                if (n != null) _toast(n > 0 ? 'Added $n profile(s)' : 'Already in the app');
              },
            ),
            IconButton(tooltip: 'Share', icon: const Icon(Icons.qr_code, size: 20), onPressed: () => _share(name, u)),
            PopupMenuButton<String>(
              onSelected: (a) async {
                if (a == 'rename') {
                  final v = await _prompt('Rename user', null, {'name': ('Name', false, (u['name'] as String?) ?? '')});
                  if (v == null || v['name']!.trim().isEmpty) return;
                  try {
                    await _manage(['user-rename', who, v['name']!.trim()]);
                    _refresh();
                  } catch (e) {
                    _toast(e.toString(), error: true);
                  }
                } else if (a == 'revoke') {
                  if (!await _confirm('Revoke $name?', 'Their key stops working at once. Profiles made from it stop connecting.', ok: 'Revoke')) {
                    return;
                  }
                  try {
                    await _manage(['user-remove', u['key'] as String]);
                    _refresh();
                  } catch (e) {
                    _toast(e.toString(), error: true);
                  }
                }
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'rename', child: Text('Rename')),
                PopupMenuItem(value: 'revoke', child: Text('Revoke', style: TextStyle(color: Colors.redAccent))),
              ],
            ),
          ]),
          Padding(
            padding: const EdgeInsets.only(left: 17),
            child: Text(
              '$traffic${u['limit_bytes'] != null ? ' · limit ${fmtBytes(u['limit_bytes'] as num)}' : ''}',
              style: const TextStyle(color: Colors.white54, fontSize: 12),
            ),
          ),
        ]),
      ),
    );
  }

  void _share(String name, Map<String, dynamic> u) {
    final links = (u['links'] as List? ?? const []).cast<Map<String, dynamic>>();
    final text = (u['subscription'] as String?) ?? (links.isNotEmpty ? links.first['uri'] as String : null);
    if (text == null) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Share: $name'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
            color: Colors.white,
            padding: const EdgeInsets.all(10),
            child: QrImageView(data: text, version: QrVersions.auto, size: 220),
          ),
          const SizedBox(height: 12),
          SelectableText(text, style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
        ]),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: text));
              Navigator.pop(ctx);
              _toast('Link copied');
            },
            child: const Text('Copy link'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close')),
        ],
      ),
    );
  }

  // ── Connection ────────────────────────────────────────────────────────
  Widget _connection(Map<String, dynamic> s) {
    final tls = (s['tls'] as Map?)?.cast<String, dynamic>() ?? {};
    final enabled = tls['enabled'] == true;
    final days = tls['cert_days_left'] as num?;
    final (String, Color) cert = !enabled
        ? ('not set up', _amber)
        : tls['cert_self_signed'] == true
            ? ('not issued yet', _amber)
            : days == null
                ? ('by the web server', _green)
                : ('$days days left', days < 10 ? Colors.redAccent : _green);
    final sub = s['subscription'] == true;
    return ListView(padding: const EdgeInsets.all(16), children: [
      _Card([
        _Row('UDP / TCP port', value: s['udp_port']?.toString()),
        _Row('TLS on 443', pill: enabled ? ('on', _green) : ('off', _amber)),
        _Row('Domain', value: tls['domain']?.toString() ?? '—'),
        _Row('Certificate', pill: cert),
        _Row('Subscriptions', pill: sub ? ('on', _green) : ('off', _amber)),
      ]),
      const _Note('TLS makes OSTP look like an ordinary HTTPS site on port 443, which gets through where UDP is blocked. '
          'It needs a domain whose A record points at this server.'),
      FilledButton(
        onPressed: () async {
          final v = await _prompt('TLS certificate', "A free Let's Encrypt certificate. Port 80 must be reachable for the check.", {
            'domain': ('Domain', false, tls['domain']?.toString() ?? ''),
            'email': ('Email for expiry notices (optional)', false, ''),
          });
          if (v == null || v['domain']!.trim().isEmpty) return;
          _action('cert-issue', params: {'domain': v['domain']!.trim(), 'email': v['email']!.trim()});
        },
        child: Text(enabled ? 'Change domain' : 'Set up TLS'),
      ),
      const SizedBox(height: 10),
      OutlinedButton(
        onPressed: enabled
            ? () => _action(sub ? 'sub-disable' : 'sub-enable',
                confirmTitle: sub ? 'Turn subscriptions off?' : null,
                confirmText: sub ? 'Subscription links stop updating in the apps.' : null)
            : null,
        child: Text(sub ? 'Turn subscriptions off' : 'Turn subscriptions on'),
      ),
    ]);
  }

  // ── overnet ───────────────────────────────────────────────────────────
  // .ov sites for this server's clients through the overnet gateway on the
  // server (github.com/ospab/overnet). Off until the owner turns it on.
  List<Widget> _overnet(Map<String, dynamic>? ov) {
    if (ov == null) return const []; // a server older than 0.4.7
    final entry = ov['entry'] == true, exit = ov['exit'] == true;
    final installed = ov['installed'] == true, up = ov['gateway_up'] == true;
    const restart = 'The OSTP service restarts; connected clients drop for a few seconds.';
    return [
      const _Section('overnet'),
      _Card([
        _Row('.ov sites for clients', pill: entry ? ('on', _green) : ('off', _amber)),
        _Row('overnet gateway', pill: !installed ? ('not installed', _amber) : up ? ('answers', _green) : ('not answering', _amber)),
        _Row('Exit', pill: exit ? ('on', _green) : ('off', _amber)),
      ]),
      if (!installed) ...[
        OutlinedButton(
          onPressed: () => _action('overnet-install',
              confirmTitle: 'Install the overnet gateway?',
              confirmText: "Runs overnet's installer from github.com/ospab/overnet on the server and starts the overnet-gateway service. "
                  'OSTP settings do not change.'),
          child: const Text('Install overnet gateway'),
        ),
        const SizedBox(height: 8),
      ],
      entry
          ? OutlinedButton(
              onPressed: () => _action('overnet-disable', confirmTitle: 'Turn .ov off?', confirmText: restart),
              child: const Text('Turn .ov off'),
            )
          : FilledButton(
              onPressed: () => _action('overnet-enable',
                  confirmTitle: 'Turn .ov on?',
                  confirmText: up ? restart : 'The overnet gateway is not answering yet: clients get "not found" for .ov until it runs. $restart'),
              child: const Text('Turn .ov on'),
            ),
      const SizedBox(height: 8),
      OutlinedButton(
        onPressed: () => _action(exit ? 'overnet-exit-off' : 'overnet-exit-on',
            confirmTitle: exit ? 'Close the exit?' : 'Open an overnet exit?',
            confirmText: exit ? restart : "overnet users' internet traffic will leave from this server's IP, and you answer for it. $restart"),
        child: Text(exit ? 'Close the exit' : 'Open an exit'),
      ),
      const _Note('With .ov on, devices connected through this server open .ov sites (try http://search.ov/) in any browser. '
          "The gateway is overnet's own program; nothing is installed until you press the button."),
    ];
  }

  // ── Management ────────────────────────────────────────────────────────
  Widget _management(Map<String, dynamic> s) {
    final panel = (s['panel'] as Map?)?.cast<String, dynamic>() ?? {};
    final on = panel['enabled'] == true;
    return ListView(padding: const EdgeInsets.all(16), children: [
      const _Section('Web panel'),
      _Card([
        _Row('Panel', pill: on ? ('on', _green) : ('off', _amber)),
        _Row('Sign-in', value: panel['login'] == true ? 'set' : 'not set'),
      ]),
      if (on) ...[
        FilledButton.icon(icon: const Icon(Icons.open_in_browser), label: const Text('Open the panel'), onPressed: _openPanel),
        const SizedBox(height: 8),
        _vpnPanelLink(panel),
        const SizedBox(height: 8),
        OutlinedButton(
          onPressed: () => _action('panel-disable',
              confirmTitle: 'Turn off the panel?', confirmText: 'The OSTP service restarts; connected clients drop for a few seconds.'),
          child: const Text('Turn off'),
        ),
      ] else
        FilledButton(
          onPressed: () async {
            final v = await _prompt('Turn on the panel', 'The OSTP service restarts; connected clients drop for a few seconds.', {
              'user': ('Sign-in name', false, 'admin'),
              'password': ('Password (8+ characters)', true, ''),
            });
            if (v == null) return;
            _action('panel-enable', params: {'user': v['user'], 'password': v['password']});
          },
          child: const Text('Turn on the panel'),
        ),
      const _Note('"Open the panel" goes through this SSH connection and needs no open port; it works while this app stays open. '
          'The VPN address works in any browser on a device connected through this server.'),
      ..._overnet((s['overnet'] as Map?)?.cast<String, dynamic>()),
      const _Section('Server log'),
      _LogView(load: () async => ((await _manage(['logs', '-n', '300']))['lines'] as List? ?? const []).cast<String>()),
      const _Section('This server'),
      _Card([
        _Row('SSH', value: '${_server['user']}@${_server['host']}:${_server['port']}', mono: true),
        _Row('Host key', value: _server['host_key']?.toString(), mono: true),
      ]),
      Row(children: [
        Expanded(
          child: OutlinedButton(
            onPressed: () async {
              final v = await _prompt('Rename server', null, {'name': ('Name', false, _server['name'] as String)});
              if (v == null || v['name']!.trim().isEmpty) return;
              await ServersApi.raw({'op': 'rename', 'id': _id, 'name': v['name']!.trim()});
              setState(() => _server = {..._server, 'name': v['name']!.trim()});
            },
            child: const Text('Rename'),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: OutlinedButton(
            onPressed: () => _action('reboot', confirmTitle: 'Reboot the server?', confirmText: 'It is back in about a minute. Every connection drops until then.'),
            child: const Text('Reboot server'),
          ),
        ),
      ]),
      const SizedBox(height: 10),
      Row(children: [
        Expanded(
          child: OutlinedButton(
            style: OutlinedButton.styleFrom(foregroundColor: Colors.redAccent),
            onPressed: () => _action('uninstall',
                confirmTitle: 'Remove OSTP from the server?',
                confirmText: 'The service, the config and every user key are deleted. Nobody can connect to this server afterwards.'),
            child: const Text('Uninstall OSTP'),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: OutlinedButton(
            style: OutlinedButton.styleFrom(foregroundColor: Colors.redAccent),
            onPressed: () async {
              if (!await _confirm('Forget this server?', 'Only this app forgets it and its saved password or key. OSTP keeps running on it.', ok: 'Forget')) {
                return;
              }
              await ServersApi.raw({'op': 'remove', 'id': _id});
              ServersApi.typedAuth.remove(_id);
              if (mounted) Navigator.pop(context);
            },
            child: const Text('Forget server'),
          ),
        ),
      ]),
      const SizedBox(height: 24),
    ]);
  }

  /// The panel's address inside the tunnel: 10.1.0.1 is the server as
  /// connected clients see it, so any browser on a phone connected through
  /// this server opens it, no SSH needed.
  Widget _vpnPanelLink(Map<String, dynamic> panel) {
    final port = (panel['bind'] as String? ?? '').split(':').last;
    // An empty webpath means /panel/ (servers older than 0.4.6 report it empty).
    final path = (panel['webpath'] as String? ?? '').replaceAll(RegExp(r'^/+|/+$'), '');
    final url = 'http://10.1.0.1:$port/${path.isEmpty ? 'panel' : path}/';
    return Card(
      margin: const EdgeInsets.only(bottom: 4),
      child: ListTile(
        dense: true,
        title: const Text('Through the VPN', style: TextStyle(fontSize: 13)),
        subtitle: Text(url, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
        trailing: Row(mainAxisSize: MainAxisSize.min, children: [
          IconButton(
            tooltip: 'Copy',
            icon: const Icon(Icons.copy, size: 18),
            onPressed: () {
              Clipboard.setData(ClipboardData(text: url));
              _toast('Panel address copied');
            },
          ),
          IconButton(
            tooltip: 'Open',
            icon: const Icon(Icons.open_in_new, size: 18),
            onPressed: () => launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication),
          ),
        ]),
      ),
    );
  }

  /// The panel in the browser through a local SSH forward. An in-app browser
  /// tab keeps this app in the foreground, so Android does not freeze the
  /// forward while the panel is open.
  Future<void> _openPanel() async {
    try {
      final r = await _call({'op': 'panel_url'}) as Map<String, dynamic>;
      final url = Uri.parse(r['url'] as String);
      if (!await launchUrl(url, mode: LaunchMode.inAppBrowserView)) {
        await launchUrl(url, mode: LaunchMode.externalApplication);
      }
    } catch (e) {
      _toast(e.toString() == 'PANEL_OFF' ? 'The panel is off' : e.toString(), error: true);
    }
  }
}

/// Loads [load] and shows it with [build], or the error with a retry.
class _Loader extends StatefulWidget {
  final Future<Map<String, dynamic>> Function() load;
  final Widget Function(Map<String, dynamic>) build;
  const _Loader({super.key, required this.load, required this.build});

  @override
  State<_Loader> createState() => _LoaderState();
}

class _LoaderState extends State<_Loader> with AutomaticKeepAliveClientMixin {
  late Future<Map<String, dynamic>> _f = widget.load();

  @override
  bool get wantKeepAlive => true;

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return FutureBuilder<Map<String, dynamic>>(
      future: _f,
      builder: (context, snap) {
        if (snap.hasError) {
          return _Message(snap.error.toString(), onRetry: () => setState(() => _f = widget.load()));
        }
        if (!snap.hasData) {
          return const Center(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              CircularProgressIndicator(),
              SizedBox(height: 14),
              Text('Talking to the server…', style: TextStyle(color: Colors.white54)),
            ]),
          );
        }
        return widget.build(snap.data!);
      },
    );
  }
}

class _LogView extends StatefulWidget {
  final Future<List<String>> Function() load;
  const _LogView({required this.load});

  @override
  State<_LogView> createState() => _LogViewState();
}

class _LogViewState extends State<_LogView> {
  String? _text;
  bool _busy = false;

  Future<void> _show() async {
    setState(() => _busy = true);
    try {
      final lines = await widget.load();
      _text = lines.isEmpty ? '(empty)' : lines.join('\n');
    } catch (e) {
      _text = e.toString();
    }
    if (mounted) setState(() => _busy = false);
  }

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      OutlinedButton(onPressed: _busy ? null : _show, child: Text(_busy ? 'Loading…' : 'Show the last 300 lines')),
      if (_text != null)
        Container(
          margin: const EdgeInsets.only(top: 10),
          constraints: const BoxConstraints(maxHeight: 360),
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(10), border: Border.all(color: Colors.white12)),
          child: SingleChildScrollView(
            reverse: true,
            child: SelectableText(_text!, style: const TextStyle(fontFamily: 'monospace', fontSize: 10.5, color: Colors.white70)),
          ),
        ),
    ]);
  }
}

class _Card extends StatelessWidget {
  final List<Widget> rows;
  const _Card(this.rows);

  @override
  Widget build(BuildContext context) => Card(
        margin: const EdgeInsets.only(bottom: 14),
        child: Column(children: [
          for (var i = 0; i < rows.length; i++) ...[
            if (i > 0) const Divider(height: 1, color: Colors.white10),
            rows[i],
          ],
        ]),
      );
}

class _Row extends StatelessWidget {
  final String label;
  final String? value;
  final (String, Color)? pill;
  final bool mono;
  const _Row(this.label, {this.value, this.pill, this.mono = false});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        child: Row(children: [
          Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13)),
          const SizedBox(width: 12),
          Expanded(
            child: Align(
              alignment: Alignment.centerRight,
              child: pill != null
                  ? Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(color: pill!.$2.withValues(alpha: 0.13), borderRadius: BorderRadius.circular(20)),
                      child: Text(pill!.$1.toUpperCase(),
                          style: TextStyle(color: pill!.$2, fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.4)),
                    )
                  : Text(value ?? '—',
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(fontSize: mono ? 11 : 13, fontFamily: mono ? 'monospace' : null)),
            ),
          ),
        ]),
      );
}

class _Meter extends StatelessWidget {
  final String label;
  final num? used, total;
  const _Meter(this.label, this.used, this.total);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
        child: Column(children: [
          Row(children: [
            Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13)),
            const SizedBox(width: 12),
            Expanded(
              child: Text('${fmtBytes(used)} / ${fmtBytes(total)}',
                  textAlign: TextAlign.right, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 13)),
            ),
          ]),
          if (used != null && total != null && total! > 0) ...[
            const SizedBox(height: 6),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(value: (used! / total!).clamp(0.0, 1.0).toDouble(), minHeight: 4, color: Colors.white, backgroundColor: Colors.white12),
            ),
          ],
        ]),
      );
}

class _Section extends StatelessWidget {
  final String text;
  const _Section(this.text);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(2, 10, 2, 8),
        child: Text(text.toUpperCase(), style: const TextStyle(color: Colors.white38, fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 1.4)),
      );
}

class _Note extends StatelessWidget {
  final String text;
  const _Note(this.text);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(2, 8, 2, 14),
        child: Text(text, style: const TextStyle(color: Colors.white38, fontSize: 12, height: 1.4)),
      );
}

/// A change running on the server, with its output as it comes.
class _ActionDialog extends StatefulWidget {
  final String title;
  final Future<dynamic> Function() run;
  final String serverId;
  const _ActionDialog({required this.title, required this.run, required this.serverId});

  @override
  State<_ActionDialog> createState() => _ActionDialogState();
}

class _ActionDialogState extends State<_ActionDialog> {
  final _log = <String>[];
  String? _error;
  bool _done = false;
  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _start();
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _start() async {
    var since = 0;
    try {
      since = (await ServersApi.lines(0)).$2;
    } catch (_) {}
    _poll = Timer.periodic(const Duration(milliseconds: 600), (_) async {
      try {
        final (lines, next) = await ServersApi.lines(since);
        since = next;
        if (!mounted) return;
        setState(() => _log.addAll(lines.where((l) => l['id'] == widget.serverId).map((l) => l['line'] as String)));
      } catch (_) {}
    });
    try {
      await widget.run();
    } catch (e) {
      _error = e.toString();
    }
    await Future.delayed(const Duration(milliseconds: 700)); // the last lines
    _poll?.cancel();
    if (mounted) setState(() => _done = true);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Row(children: [
        if (!_done) const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
        if (_done) Icon(_error == null ? Icons.check_circle : Icons.error, color: _error == null ? _green : Colors.redAccent),
        const SizedBox(width: 12),
        Expanded(child: Text(_done && _error == null ? '${widget.title}: done' : widget.title)),
      ]),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          if (_log.isNotEmpty)
            Container(
              constraints: const BoxConstraints(maxHeight: 260),
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(8)),
              child: SingleChildScrollView(
                reverse: true,
                child: SelectableText(_log.join('\n'), style: const TextStyle(fontFamily: 'monospace', fontSize: 10.5, color: Colors.white70)),
              ),
            ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: Text(_error!, style: const TextStyle(color: Colors.redAccent, fontSize: 13)),
            ),
        ]),
      ),
      actions: [TextButton(onPressed: _done ? () => Navigator.pop(context) : null, child: const Text('Close'))],
    );
  }
}

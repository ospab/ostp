import 'dart:async';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../services/servers.dart';

/// "I have a server": address, SSH login, password or private key. On
/// submit it adds the server, installs OSTP and imports the first user's
/// links as profiles. [onInstalled] gets the server afterwards.
class SshSetupForm extends StatefulWidget {
  final SharedPreferences prefs;
  final void Function(Map<String, dynamic> server) onInstalled;
  final String submitLabel;

  const SshSetupForm({super.key, required this.prefs, required this.onInstalled, this.submitLabel = 'Install OSTP'});

  @override
  State<SshSetupForm> createState() => _SshSetupFormState();
}

class _SshSetupFormState extends State<SshSetupForm> {
  final _host = TextEditingController();
  final _port = TextEditingController(text: '22');
  final _user = TextEditingController(text: 'root');
  final _password = TextEditingController();
  final _key = TextEditingController();
  final _passphrase = TextEditingController();
  bool _useKey = false;
  bool _remember = true;
  bool _canRemember = true;
  bool _busy = false;
  bool _hidePassword = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    ServersApi.list().then((l) {
      if (mounted) setState(() => _canRemember = l.canRemember);
    }).catchError((_) {});
  }

  @override
  void dispose() {
    for (final c in [_host, _port, _user, _password, _key, _passphrase]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() => _error = null);
    var host = _host.text.trim();
    var port = int.tryParse(_port.text.trim()) ?? 22;
    // "host:port" in the address field wins over the port field.
    final m = RegExp(r'^\[?([^\]]+?)\]?:(\d+)$').firstMatch(host);
    if (m != null && !host.contains('::')) {
      host = m.group(1)!;
      port = int.parse(m.group(2)!);
    }
    final secret = _useKey ? _key.text.trim() : _password.text;
    if (host.isEmpty) return setState(() => _error = 'Enter the server address');
    if (secret.isEmpty) return setState(() => _error = _useKey ? 'Paste the private key' : 'Enter the password');
    final auth = {
      'kind': _useKey ? 'key' : 'password',
      'secret': secret,
      'passphrase': _useKey && _passphrase.text.isNotEmpty ? _passphrase.text : null,
    };
    setState(() => _busy = true);
    try {
      final server = await showDialog<Map<String, dynamic>>(
        context: context,
        barrierDismissible: false,
        builder: (_) => InstallDialog(
          prefs: widget.prefs,
          host: host,
          port: port,
          user: _user.text.trim().isEmpty ? 'root' : _user.text.trim(),
          auth: auth,
          remember: _remember && _canRemember,
        ),
      );
      if (server != null) widget.onInstalled(server);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  InputDecoration _dec(String label, {String? hint, Widget? suffix}) => InputDecoration(
        labelText: label,
        hintText: hint,
        hintStyle: const TextStyle(color: Colors.white24),
        filled: true,
        fillColor: Theme.of(context).colorScheme.surface,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
        suffixIcon: suffix,
      );

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Expanded(
          child: TextField(
            controller: _host,
            keyboardType: TextInputType.url,
            autocorrect: false,
            decoration: _dec('Server address', hint: '203.0.113.10'),
          ),
        ),
        const SizedBox(width: 10),
        SizedBox(
          width: 90,
          child: TextField(controller: _port, keyboardType: TextInputType.number, decoration: _dec('SSH port')),
        ),
      ]),
      const SizedBox(height: 12),
      TextField(controller: _user, autocorrect: false, decoration: _dec('Login')),
      const SizedBox(height: 12),
      SegmentedButton<bool>(
        segments: const [
          ButtonSegment(value: false, label: Text('Password'), icon: Icon(Icons.password)),
          ButtonSegment(value: true, label: Text('Private key'), icon: Icon(Icons.key)),
        ],
        selected: {_useKey},
        onSelectionChanged: (s) => setState(() => _useKey = s.first),
      ),
      const SizedBox(height: 12),
      if (!_useKey)
        TextField(
          controller: _password,
          obscureText: _hidePassword,
          decoration: _dec('SSH password',
              suffix: IconButton(
                icon: Icon(_hidePassword ? Icons.visibility : Icons.visibility_off),
                onPressed: () => setState(() => _hidePassword = !_hidePassword),
              )),
        )
      else ...[
        TextField(
          controller: _key,
          maxLines: 5,
          autocorrect: false,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          decoration: _dec('Private key', hint: '-----BEGIN OPENSSH PRIVATE KEY-----\n…'),
        ),
        const SizedBox(height: 6),
        const Text('OpenSSH, PEM or PuTTY (.ppk): paste the whole key, including the BEGIN and END lines.',
            style: TextStyle(color: Colors.white38, fontSize: 12)),
        const SizedBox(height: 12),
        TextField(controller: _passphrase, obscureText: true, decoration: _dec('Key passphrase (if it has one)')),
      ],
      const SizedBox(height: 8),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        value: _remember && _canRemember,
        onChanged: _canRemember ? (v) => setState(() => _remember = v) : null,
        title: const Text('Remember the password or key', style: TextStyle(fontSize: 14)),
        subtitle: Text(
          _canRemember ? 'Encrypted with a key from the Android Keystore' : 'This device has no usable keystore: asked each time',
          style: const TextStyle(fontSize: 12, color: Colors.white38),
        ),
      ),
      if (_error != null)
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Text(_error!, style: const TextStyle(color: Colors.redAccent, fontSize: 13)),
        ),
      FilledButton(
        onPressed: _busy ? null : _submit,
        style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 14)),
        child: Text(widget.submitLabel),
      ),
    ]);
  }
}

enum InstallStep { waiting, running, done, failed }

/// Live progress of adding a server and installing OSTP on it. Pops with
/// the server when everything worked.
class InstallDialog extends StatefulWidget {
  final SharedPreferences prefs;
  final String host;
  final int port;
  final String user;
  final Map<String, dynamic> auth;
  final bool remember;

  const InstallDialog({
    super.key,
    required this.prefs,
    required this.host,
    required this.port,
    required this.user,
    required this.auth,
    required this.remember,
  });

  @override
  State<InstallDialog> createState() => _InstallDialogState();
}

class _InstallDialogState extends State<InstallDialog> {
  static const _steps = ['Connecting over SSH', 'Checking the system', 'Installing OSTP', 'Adding the connection to this app'];
  final _states = List.filled(_steps.length, InstallStep.waiting);
  final _log = <String>[];
  String? _error;
  bool _finished = false;
  Map<String, dynamic>? _server;
  String _stepLabel2 = _steps[2];

  @override
  void initState() {
    super.initState();
    _run();
  }

  void _set(int i, InstallStep s) {
    if (!mounted) return;
    setState(() => _states[i] = s);
  }
  void _line(String l) {
    if (!mounted) return;
    setState(() {
      _log.add(l);
      if (_log.length > 500) _log.removeRange(0, _log.length - 500);
    });
  }

  Future<void> _run() async {
    var step = 0;
    Timer? poll;
    try {
      _set(0, InstallStep.running);
      final server = await ServersApi.raw({
        'op': 'add',
        'name': widget.host,
        'host': widget.host,
        'port': widget.port,
        'user': widget.user,
        'auth': widget.auth,
        'remember': widget.remember,
      }) as Map<String, dynamic>;
      _server = server;
      final id = server['id'] as String;
      if (server['remembered'] != true) ServersApi.typedAuth[id] = widget.auth;
      _line('Connected to ${widget.user}@${widget.host}:${widget.port}. Host key ${server['host_key']}');
      _set(0, InstallStep.done);

      step = 1;
      _set(1, InstallStep.running);
      if (!mounted) return;
      final probe = await ServersApi.call(context, {'op': 'probe', 'id': id}, server: server) as Map<String, dynamic>;
      _line('System: ${probe['os']} (${probe['arch']}); '
          '${probe['installed'] == true ? 'OSTP ${probe['version']} is installed' : 'OSTP is not installed'}');
      if (probe['systemd'] != true) throw ServerError('This system has no systemd; OSTP needs it to run as a service');
      _set(1, InstallStep.done);

      step = 2;
      // OSTP already there: nothing on the server changes unless the user says so.
      var mode = 'install';
      if (probe['installed'] == true) {
        if (!mounted) return;
        final picked = await ServersApi.choose(context, 'OSTP ${probe['version']} is already on this server',
            'Nothing on the server changes unless you choose to update it.', [
          ('keep', 'Add it as it is', "OSTP is left untouched; the app takes the users' links from it"),
          ('install', 'Update OSTP', "The newest release of this app's channel; the config and users are kept, the service restarts"),
        ]);
        if (picked == null) {
          _line('Nothing was changed on the server. It stays in Server management.');
          setState(() => _finished = true);
          return;
        }
        mode = picked;
      }
      setState(() => _stepLabel2 = mode == 'keep' ? 'Reading the users' : (probe['installed'] == true ? 'Updating OSTP' : _steps[2]));
      _set(2, InstallStep.running);
      var since = (await ServersApi.lines(0)).$2;
      var busy = false;
      poll = Timer.periodic(const Duration(milliseconds: 600), (_) async {
        if (busy) return;
        busy = true;
        try {
          final (lines, next) = await ServersApi.lines(since);
          since = next;
          for (final l in lines) {
            if (l['id'] == id && mounted) _line(l['line'] as String);
          }
        } catch (_) {
        } finally {
          busy = false;
        }
      });
      if (!mounted) return;
      final result = await ServersApi.call(
          context,
          mode == 'keep' ? {'op': 'manage', 'id': id, 'args': ['users']} : {'op': 'install', 'id': id, 'port': 50000},
          server: server) as Map<String, dynamic>;
      poll.cancel();
      _set(2, InstallStep.done);

      step = 3;
      _set(3, InstallStep.running);
      final users = (result['users'] as List? ?? const []).cast<Map<String, dynamic>>();
      if (!mounted) return;
      final n = users.isEmpty ? 0 : await ServersApi.addUserToApp(context, widget.prefs, server['name'] as String, users.first);
      _line(n == null ? 'No connection was added to this app.' : 'Added $n connection profile(s).');
      _set(3, InstallStep.done);
      setState(() => _finished = true);
    } catch (e) {
      poll?.cancel();
      _set(step, InstallStep.failed);
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _finished = true;
      });
      // A server that never connected is not kept.
      if (step == 0 && _server != null) {
        ServersApi.raw({'op': 'remove', 'id': _server!['id']}).catchError((_) => null);
      }
    }
  }

  Widget _stepIcon(InstallStep s) {
    switch (s) {
      case InstallStep.running:
        return const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2));
      case InstallStep.done:
        return const Icon(Icons.check_circle, size: 18, color: Color(0xFF2EE66D));
      case InstallStep.failed:
        return const Icon(Icons.error, size: 18, color: Colors.redAccent);
      case InstallStep.waiting:
        return const Icon(Icons.radio_button_unchecked, size: 18, color: Colors.white24);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ok = _finished && _error == null;
    return AlertDialog(
      title: Text(ok ? 'Your server is ready' : 'Setting up your server'),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            for (var i = 0; i < _steps.length; i++)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 5),
                child: Row(children: [
                  _stepIcon(_states[i]),
                  const SizedBox(width: 12),
                  Expanded(child: Text(i == 2 ? _stepLabel2 : _steps[i], style: TextStyle(color: _states[i] == InstallStep.waiting ? Colors.white38 : null))),
                ]),
              ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: Text(_error!, style: const TextStyle(color: Colors.redAccent, fontSize: 13)),
              ),
            Theme(
              data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
              child: ExpansionTile(
                tilePadding: EdgeInsets.zero,
                title: const Text('Server output', style: TextStyle(fontSize: 13, color: Colors.white54)),
                children: [
                  Container(
                    constraints: const BoxConstraints(maxHeight: 220),
                    width: double.infinity,
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(8)),
                    child: SingleChildScrollView(
                      reverse: true,
                      child: SelectableText(_log.join('\n'),
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white70)),
                    ),
                  ),
                ],
              ),
            ),
          ]),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _finished ? () => Navigator.pop(context, ok ? _server : null) : null,
          child: Text(ok ? 'Done' : 'Close'),
        ),
      ],
    );
  }
}

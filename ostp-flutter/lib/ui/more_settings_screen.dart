import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../services/updates.dart' as updates;
import 'app_routing_screen.dart';
import 'logs_screen.dart';
import 'servers_screen.dart';

/// Everything that is not profiles, subscriptions or the connection itself:
/// the app's own behaviour, exclusions, logs, server management, updates.
/// Split out of Configuration so that screen stays about connecting.
class MoreSettingsScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const MoreSettingsScreen({super.key, required this.prefs});

  @override
  State<MoreSettingsScreen> createState() => _MoreSettingsScreenState();
}

class _MoreSettingsScreenState extends State<MoreSettingsScreen> {
  late final TextEditingController _domainsCtrl;
  late final TextEditingController _ipsCtrl;
  late bool _debugMode;
  late bool _showSpeed;
  late bool _showRtt;
  late bool _autoUpdateCheck;
  bool _isCheckingUpdates = false;

  @override
  void initState() {
    super.initState();
    final p = widget.prefs;
    _domainsCtrl = TextEditingController(text: p.getString('ex_domains') ?? '');
    _ipsCtrl = TextEditingController(text: p.getString('ex_ips') ?? '');
    _debugMode = p.getBool('debug_mode') ?? false;
    _showSpeed = p.getBool('show_speed') ?? true;
    _showRtt = p.getBool('show_rtt') ?? true;
    _autoUpdateCheck = p.getBool(updates.autoUpdateCheckKey) ?? true;
  }

  @override
  void dispose() {
    _save();
    _domainsCtrl.dispose();
    _ipsCtrl.dispose();
    super.dispose();
  }

  void _save() {
    final p = widget.prefs;
    p.setString('ex_domains', _domainsCtrl.text.trim());
    p.setString('ex_ips', _ipsCtrl.text.trim());
    p.setBool('debug_mode', _debugMode);
    p.setBool('show_speed', _showSpeed);
    p.setBool('show_rtt', _showRtt);
    p.setBool(updates.autoUpdateCheckKey, _autoUpdateCheck);
  }

  Future<void> _checkForUpdates() async {
    if (_isCheckingUpdates) return;
    setState(() => _isCheckingUpdates = true);
    try {
      await updates.checkForUpdates(context, widget.prefs, manual: true);
    } finally {
      if (mounted) setState(() => _isCheckingUpdates = false);
    }
  }

  static const _sectionStyle = TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0);

  BoxDecoration get _card => BoxDecoration(
        color: Colors.white.withValues(alpha: 0.02),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
      );

  Widget _toggle(String title, String subtitle, bool value, ValueChanged<bool> onChanged) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 20),
      child: Row(children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            Text(subtitle, style: const TextStyle(fontSize: 13, color: Colors.white54)),
          ]),
        ),
        Switch(
          value: value,
          onChanged: (v) {
            setState(() => onChanged(v));
            _save();
          },
          activeThumbColor: Theme.of(context).colorScheme.secondary,
        ),
      ]),
    );
  }

  Widget _field(String label, TextEditingController controller, String hint) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(label, style: _sectionStyle),
        const SizedBox(height: 10),
        TextField(
          controller: controller,
          maxLines: 3,
          // Roughly a thousand entries; the config sent to the core has its own limit.
          inputFormatters: [LengthLimitingTextInputFormatter(30000)],
          style: const TextStyle(fontSize: 16),
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: const TextStyle(color: Colors.white30),
            filled: true,
            fillColor: Theme.of(context).colorScheme.surface,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
            contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
          ),
        ),
      ]),
    );
  }

  Widget _navTile(IconData icon, String title, String subtitle, VoidCallback? onTap, {Widget? trailing}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.02),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
          ),
          child: Row(children: [
            Icon(icon, color: Colors.white70, size: 24),
            const SizedBox(width: 16),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(title, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white)),
                const SizedBox(height: 4),
                Text(subtitle, style: const TextStyle(fontSize: 13, color: Colors.white54)),
              ]),
            ),
            trailing ?? const Icon(Icons.arrow_forward_ios_rounded, color: Colors.white54, size: 16),
          ]),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('More settings', style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        children: [
          _navTile(Icons.dns, 'Server Management', 'Install and manage your own OSTP server over SSH', () {
            Navigator.push(context, MaterialPageRoute(builder: (_) => ServersScreen(prefs: widget.prefs)));
          }),
          const SizedBox(height: 20),

          const Text('EXCLUSIONS', style: _sectionStyle),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(24),
            decoration: _card,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Padding(
                padding: EdgeInsets.only(bottom: 16),
                child: Text('Traffic that goes around the tunnel. One per line.', style: TextStyle(fontSize: 13, color: Colors.white54)),
              ),
              _field('Bypass Domains', _domainsCtrl, 'example.com\n*.google.com'),
              _field('Bypass IPs / CIDR', _ipsCtrl, '192.168.1.0/24\n10.0.0.1'),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  icon: const Icon(Icons.route),
                  label: const Text('Configure Split Tunneling'),
                  onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => AppRoutingScreen(prefs: widget.prefs))),
                ),
              ),
            ]),
          ),
          const SizedBox(height: 28),

          const Text('APPLICATION', style: _sectionStyle),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 4),
            decoration: _card,
            child: Column(children: [
              _toggle('Check for updates', 'When the app opens: stable and beta releases', _autoUpdateCheck, (v) => _autoUpdateCheck = v),
              _toggle('Show Speed', 'Live download/upload speed on the home screen', _showSpeed, (v) => _showSpeed = v),
              _toggle('Show RTT', 'Live server ping on the home screen', _showRtt, (v) => _showRtt = v),
              _toggle('Debug Mode', 'Verbose logging', _debugMode, (v) => _debugMode = v),
            ]),
          ),
          const SizedBox(height: 28),

          _navTile(Icons.article, 'View Logs', 'What the tunnel did, for troubleshooting',
              () => Navigator.push(context, MaterialPageRoute(builder: (_) => const LogsScreen()))),
          _navTile(
            Icons.system_update_rounded,
            'Check for Updates',
            _isCheckingUpdates ? 'Checking...' : 'Stable and beta releases on GitHub',
            _isCheckingUpdates ? null : _checkForUpdates,
            trailing: _isCheckingUpdates
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white54))
                : null,
          ),
          const SizedBox(height: 40),
        ],
      ),
    );
  }
}

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'app_routing_screen.dart';
import 'logs_screen.dart';
import 'qr_scanner_screen.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../models/ostp_profile.dart';

/// Picks readable black/white text for a given (opaque) background color.
/// The monochrome theme's `primary` is pure white — hardcoded white text on
/// top of it was invisible; this picks the contrasting color instead.
Color _onColor(Color bg) {
  return ThemeData.estimateBrightnessForColor(bg) == Brightness.light ? Colors.black : Colors.white;
}

class SettingsScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const SettingsScreen({super.key, required this.prefs});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _localBindCtrl;
  late TextEditingController _dnsCtrl;
  late TextEditingController _mtuCtrl;
  late TextEditingController _domainsCtrl;
  late TextEditingController _ipsCtrl;
  late TextEditingController _muxSessionsCtrl;

  bool _debugMode = false;
  bool _muxEnabled = false;
  bool _isCheckingUpdates = false;
  bool _showSpeed = true;
  bool _showRtt = true;

  List<OstpProfile> _profiles = [];

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  void _loadSettings() {
    _localBindCtrl = TextEditingController(text: widget.prefs.getString('local_bind') ?? '127.0.0.1:1088');
    _dnsCtrl = TextEditingController(text: widget.prefs.getString('dns_server') ?? '1.1.1.1');
    _mtuCtrl = TextEditingController(text: widget.prefs.getString('mtu') ?? '1140');
    _domainsCtrl = TextEditingController(text: widget.prefs.getString('ex_domains') ?? '');
    _ipsCtrl = TextEditingController(text: widget.prefs.getString('ex_ips') ?? '');
    // No "Bypass Processes" field on mobile — Android per-app selection
    // (Configure Split Tunneling) already covers this; a process-name field
    // doesn't map to anything meaningful on Android the way it does on desktop.
    _debugMode = widget.prefs.getBool('debug_mode') ?? false;
    _muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    _showSpeed = widget.prefs.getBool('show_speed') ?? true;
    _showRtt = widget.prefs.getBool('show_rtt') ?? true;
    _muxSessionsCtrl = TextEditingController(text: widget.prefs.getString('mux_sessions') ?? '2');
    _profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
  }

  @override
  void dispose() {
    _saveSettings();
    _localBindCtrl.dispose();
    _dnsCtrl.dispose();
    _mtuCtrl.dispose();
    _domainsCtrl.dispose();
    _ipsCtrl.dispose();
    _muxSessionsCtrl.dispose();
    super.dispose();
  }

  void _saveSettings() {
    widget.prefs.setString('local_bind', _localBindCtrl.text.trim());
    widget.prefs.setString('dns_server', _dnsCtrl.text.trim());
    widget.prefs.setString('mtu', _mtuCtrl.text.trim());
    widget.prefs.setString('ex_domains', _domainsCtrl.text.trim());
    widget.prefs.setString('ex_ips', _ipsCtrl.text.trim());
    widget.prefs.setBool('debug_mode', _debugMode);
    widget.prefs.setBool('mux_enabled', _muxEnabled);
    widget.prefs.setBool('show_speed', _showSpeed);
    widget.prefs.setBool('show_rtt', _showRtt);
    widget.prefs.setString('mux_sessions', _muxSessionsCtrl.text.trim());
    widget.prefs.setString('profiles_json', encodeProfiles(_profiles));
  }

  void _saveProfiles() {
    widget.prefs.setString('profiles_json', encodeProfiles(_profiles));
  }

  // ── Profile CRUD ─────────────────────────────────────────────────────────

  void _selectActive(OstpProfile p) {
    setState(() {
      for (final other in _profiles) {
        other.active = other.id == p.id;
      }
      _saveProfiles();
    });
  }

  void _importFromLink(String link) {
    if (link.isEmpty) return;
    try {
      if (!link.startsWith('ostp://')) {
        throw Exception('Link must start with ostp://');
      }
      final uri = Uri.parse(link);
      final key = Uri.decodeComponent(uri.userInfo);
      final host = uri.authority.replaceFirst('${uri.userInfo}@', '');
      if (key.isEmpty || host.isEmpty) {
        throw Exception('Incomplete link parameters');
      }
      final type = uri.queryParameters['type'];
      final transportMode = (type == 'tcp' || type == 'http') ? 'uot' : 'udp';
      final name = uri.queryParameters['name'] ?? host;
      final wasEmpty = _profiles.isEmpty;

      setState(() {
        _profiles.add(OstpProfile(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: name,
          serverAddr: host,
          accessKey: key,
          transportMode: transportMode,
          active: wasEmpty,
        ));
        _saveProfiles();
      });
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Imported successfully')));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e')));
    }
  }

  void _showAddProfileMenu() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Theme.of(context).colorScheme.surface,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code_scanner, color: Colors.white),
              title: const Text('Import from QR code'),
              onTap: () async {
                Navigator.pop(context);
                final result = await Navigator.push(
                  context,
                  MaterialPageRoute(builder: (context) => const QRScannerScreen()),
                );
                if (result != null && result is String && result.startsWith('ostp://')) {
                  _importFromLink(result);
                }
              },
            ),
            ListTile(
              leading: const Icon(Icons.link, color: Colors.white),
              title: const Text('Import from link'),
              onTap: () {
                Navigator.pop(context);
                _showImportLinkDialog();
              },
            ),
            ListTile(
              leading: const Icon(Icons.edit, color: Colors.white),
              title: const Text('Insert manually'),
              onTap: () {
                Navigator.pop(context);
                _showEditProfileDialog(null);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _showImportLinkDialog() {
    final linkCtrl = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Link'),
        backgroundColor: Theme.of(context).colorScheme.surface,
        content: TextField(
          controller: linkCtrl,
          decoration: const InputDecoration(hintText: 'ostp://...'),
          autofocus: true,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              _importFromLink(linkCtrl.text.trim());
            },
            child: const Text('Import'),
          ),
        ],
      ),
    );
  }

  void _showEditProfileDialog(OstpProfile? profile) {
    final isNew = profile == null;
    final nameCtrl = TextEditingController(text: profile?.name ?? '');
    final serverCtrl = TextEditingController(text: profile?.serverAddr ?? '');
    final keyCtrl = TextEditingController(text: profile?.accessKey ?? '');
    final fragChunkCtrl = TextEditingController(text: (profile?.fragChunk ?? 2).toString());
    final fragSleepCtrl = TextEditingController(text: (profile?.fragSleep ?? 2).toString());
    final junkPcMinCtrl = TextEditingController(text: (profile?.junkPcMin ?? 2).toString());
    final junkPcMaxCtrl = TextEditingController(text: (profile?.junkPcMax ?? 5).toString());
    final junkPsMinCtrl = TextEditingController(text: (profile?.junkPsMin ?? 100).toString());
    final junkPsMaxCtrl = TextEditingController(text: (profile?.junkPsMax ?? 1000).toString());
    String transportMode = profile?.transportMode ?? 'udp';
    bool tcpFragmentation = profile?.tcpFragmentation ?? false;
    bool ttlDesync = profile?.ttlDesync ?? false;
    bool obscureKey = true;

    showDialog(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) => AlertDialog(
            title: Text(isNew ? 'New Profile' : 'Edit Profile'),
            backgroundColor: Theme.of(context).colorScheme.surface,
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(controller: nameCtrl, decoration: const InputDecoration(labelText: 'Name')),
                  const SizedBox(height: 12),
                  TextField(controller: serverCtrl, decoration: const InputDecoration(labelText: 'Server Address (host:port)')),
                  const SizedBox(height: 12),
                  TextField(
                    controller: keyCtrl,
                    obscureText: obscureKey,
                    decoration: InputDecoration(
                      labelText: 'Access Key',
                      suffixIcon: IconButton(
                        icon: Icon(obscureKey ? Icons.visibility : Icons.visibility_off, size: 18),
                        onPressed: () => setDialogState(() => obscureKey = !obscureKey),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  DropdownButtonFormField<String>(
                    value: transportMode,
                    decoration: const InputDecoration(labelText: 'Transport'),
                    items: const [
                      DropdownMenuItem(value: 'udp', child: Text('UDP')),
                      DropdownMenuItem(value: 'uot', child: Text('TCP (UoT)')),
                    ],
                    onChanged: (v) {
                      if (v != null) setDialogState(() => transportMode = v);
                    },
                  ),
                  // Junk packets and TCP fragmentation only take effect on the
                  // UoT (TCP) transport — the UDP path applies neither — so the
                  // whole section is hidden under UDP instead of shown with a
                  // "UoT only" caveat. Reactive: switching Transport above calls
                  // setDialogState, which rebuilds this and shows/hides it.
                  if (transportMode == 'uot') ...[
                    const Divider(height: 32),
                    const Text('DPI OBFUSCATION', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white54, letterSpacing: 1.0)),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton.icon(
                            icon: const Icon(Icons.shuffle_rounded, size: 18),
                            label: const Text('Junk Packets'),
                            onPressed: () => _showJunkPacketsModal(
                              context, junkPcMinCtrl, junkPcMaxCtrl, junkPsMinCtrl, junkPsMaxCtrl,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: OutlinedButton.icon(
                            icon: Icon(tcpFragmentation ? Icons.call_split_rounded : Icons.horizontal_rule_rounded, size: 18),
                            label: Text(tcpFragmentation ? 'TCP Frag: On' : 'TCP Frag: Off'),
                            onPressed: () => _showTcpFragModal(
                              context,
                              tcpFragmentation,
                              (v) => setDialogState(() => tcpFragmentation = v),
                              fragChunkCtrl, fragSleepCtrl,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('TTL Desync', style: TextStyle(fontSize: 14)),
                    subtitle: const Text('Decoy packets that die before the server (UDP, auto-tuned)', style: TextStyle(fontSize: 12, color: Colors.white54)),
                    value: ttlDesync,
                    onChanged: (v) => setDialogState(() => ttlDesync = v),
                  ),
                ],
              ),
            ),
            actions: [
              if (!isNew)
                TextButton(
                  onPressed: () {
                    setState(() {
                      final wasActive = profile.active;
                      _profiles.removeWhere((p) => p.id == profile.id);
                      if (wasActive && _profiles.isNotEmpty) {
                        _profiles.first.active = true;
                      }
                      _saveProfiles();
                    });
                    Navigator.pop(context);
                  },
                  child: const Text('Delete', style: TextStyle(color: Colors.redAccent)),
                ),
              TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
              TextButton(
                onPressed: () {
                  final server = serverCtrl.text.trim();
                  final key = keyCtrl.text.trim();
                  if (server.isEmpty || key.isEmpty) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Server and Access Key are required')),
                    );
                    return;
                  }
                  setState(() {
                    if (isNew) {
                      final wasEmpty = _profiles.isEmpty;
                      _profiles.add(OstpProfile(
                        id: DateTime.now().millisecondsSinceEpoch.toString(),
                        name: nameCtrl.text.trim().isNotEmpty ? nameCtrl.text.trim() : server,
                        serverAddr: server,
                        accessKey: key,
                        transportMode: transportMode,
                        active: wasEmpty,
                        tcpFragmentation: tcpFragmentation,
                        fragChunk: int.tryParse(fragChunkCtrl.text) ?? 2,
                        fragSleep: int.tryParse(fragSleepCtrl.text) ?? 2,
                        junkPcMin: int.tryParse(junkPcMinCtrl.text) ?? 2,
                        junkPcMax: int.tryParse(junkPcMaxCtrl.text) ?? 5,
                        junkPsMin: int.tryParse(junkPsMinCtrl.text) ?? 100,
                        junkPsMax: int.tryParse(junkPsMaxCtrl.text) ?? 1000,
                        ttlDesync: ttlDesync,
                      ));
                    } else {
                      profile.name = nameCtrl.text.trim().isNotEmpty ? nameCtrl.text.trim() : server;
                      profile.serverAddr = server;
                      profile.accessKey = key;
                      profile.transportMode = transportMode;
                      profile.tcpFragmentation = tcpFragmentation;
                      profile.fragChunk = int.tryParse(fragChunkCtrl.text) ?? 2;
                      profile.fragSleep = int.tryParse(fragSleepCtrl.text) ?? 2;
                      profile.junkPcMin = int.tryParse(junkPcMinCtrl.text) ?? 2;
                      profile.junkPcMax = int.tryParse(junkPcMaxCtrl.text) ?? 5;
                      profile.junkPsMin = int.tryParse(junkPsMinCtrl.text) ?? 100;
                      profile.junkPsMax = int.tryParse(junkPsMaxCtrl.text) ?? 1000;
                      profile.ttlDesync = ttlDesync;
                    }
                    _saveProfiles();
                  });
                  Navigator.pop(context);
                },
                child: const Text('Save'),
              ),
            ],
          ),
        );
      },
    );
  }

  // The numeric fields below all edit the SAME TextEditingControllers that
  // the outer profile-edit dialog already holds — no extra propagation is
  // needed for them, closing this modal just leaves the shared controllers
  // updated. Only the `tcpFragmentation` bool (not a controller) needs an
  // explicit callback to reach back into the outer dialog's state.

  void _showJunkPacketsModal(
    BuildContext context,
    TextEditingController pcMin,
    TextEditingController pcMax,
    TextEditingController psMin,
    TextEditingController psMax,
  ) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        title: const Text('Junk Packets'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Sends random-size filler packets before the handshake so DPI can\'t fingerprint its size or timing.',
                style: TextStyle(fontSize: 12, color: Colors.white54),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(child: TextField(controller: pcMin, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Count (min)'))),
                  const SizedBox(width: 12),
                  Expanded(child: TextField(controller: pcMax, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Count (max)'))),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: TextField(controller: psMin, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Size min (bytes)'))),
                  const SizedBox(width: 12),
                  Expanded(child: TextField(controller: psMax, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Size max (bytes)'))),
                ],
              ),
            ],
          ),
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Done'))],
      ),
    );
  }

  void _showTcpFragModal(
    BuildContext context,
    bool initialEnabled,
    ValueChanged<bool> onChanged,
    TextEditingController chunkCtrl,
    TextEditingController sleepCtrl,
  ) {
    bool enabled = initialEnabled;
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setModalState) => AlertDialog(
          backgroundColor: Theme.of(context).colorScheme.surface,
          title: const Text('TCP Fragmentation'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Enabled', style: TextStyle(fontSize: 14)),
                  subtitle: const Text('Split the handshake into small chunks', style: TextStyle(fontSize: 12, color: Colors.white54)),
                  value: enabled,
                  onChanged: (v) => setModalState(() => enabled = v),
                ),
                if (enabled) ...[
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(child: TextField(controller: chunkCtrl, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Chunk size (bytes)'))),
                      const SizedBox(width: 12),
                      Expanded(child: TextField(controller: sleepCtrl, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Delay (ms)'))),
                    ],
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                onChanged(enabled);
                Navigator.pop(context);
              },
              child: const Text('Done'),
            ),
          ],
        ),
      ),
    );
  }

  void _showShareModal(OstpProfile p) {
    final key = Uri.encodeComponent(p.accessKey);
    if (p.serverAddr.isEmpty || p.accessKey.isEmpty) return;
    final queryParams = <String>[];
    if (p.transportMode != 'udp') queryParams.add('type=${p.transportMode}');
    final queryString = queryParams.isEmpty ? '' : '?${queryParams.join('&')}';
    final url = 'ostp://$key@${p.serverAddr}$queryString';

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        // Deliberately generic — not "Share {name}": when a profile has no
        // custom name, `name` falls back to the raw server address, and this
        // dialog is exactly the wrong place to be casually displaying that
        // (screenshots, screen recordings, shoulder-surfing).
        title: const Text('Share Profile', textAlign: TextAlign.center),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
              child: QrImageView(data: url, version: QrVersions.auto, size: 200.0),
            ),
            const SizedBox(height: 20),
            Builder(builder: (context) {
              final bg = Theme.of(context).colorScheme.primary;
              final fg = _onColor(bg);
              return ElevatedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: url));
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Copied to clipboard')));
                  Navigator.pop(context);
                },
                icon: Icon(Icons.copy_rounded, color: fg),
                label: Text('Copy Link', style: TextStyle(color: fg)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: bg,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
              );
            }),
          ],
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))],
      ),
    );
  }

  // ── Widgets ──────────────────────────────────────────────────────────────

  Widget _buildTextField(String label, TextEditingController controller, {String? hint, int maxLines = 1}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
          const SizedBox(height: 10),
          TextField(
            controller: controller,
            maxLines: maxLines,
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
        ],
      ),
    );
  }

  Widget _buildToggle(String title, String subtitle, bool value, ValueChanged<bool> onChanged) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text(subtitle, style: const TextStyle(fontSize: 13, color: Colors.white54)),
              ],
            ),
          ),
          Switch(
            value: value,
            onChanged: (v) {
              setState(() => onChanged(v));
              _saveSettings();
            },
            activeColor: Theme.of(context).colorScheme.secondary,
          )
        ],
      ),
    );
  }

  List<Widget> _buildProfileCards() {
    String? activeId;
    for (final x in _profiles) {
      if (x.active) { activeId = x.id; break; }
    }
    return _profiles.map((p) => Card(
      color: p.active
          ? Theme.of(context).colorScheme.primary.withOpacity(0.12)
          : Theme.of(context).colorScheme.surface,
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: p.active ? BorderSide(color: Theme.of(context).colorScheme.primary.withOpacity(0.4)) : BorderSide.none,
      ),
      child: ListTile(
        leading: Radio<String>(
          value: p.id,
          groupValue: activeId,
          onChanged: (_) => _selectActive(p),
        ),
        title: Text(p.name, style: const TextStyle(fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
        // If the profile was never given a distinct name, `name` falls back
        // to the raw server address (see the editor below) — showing it a
        // second time here would just repeat the title verbatim, so only
        // add it when it's actually different information.
        subtitle: Text(
          p.name == p.serverAddr
              ? p.transportMode.toUpperCase()
              : '${p.serverAddr} · ${p.transportMode.toUpperCase()}',
          style: const TextStyle(fontSize: 12),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          softWrap: false,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              icon: const Icon(Icons.share_rounded, size: 20, color: Colors.white54),
              onPressed: () => _showShareModal(p),
            ),
            IconButton(
              icon: const Icon(Icons.edit, size: 20, color: Colors.white54),
              onPressed: () => _showEditProfileDialog(p),
            ),
          ],
        ),
        onTap: () => _selectActive(p),
      ),
    )).toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Configuration', style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.add_rounded),
            tooltip: 'Add Profile',
            onPressed: _showAddProfileMenu,
          ),
        ],
      ),
      body: Stack(
        children: [
          Positioned.fill(
            child: Opacity(
              opacity: 0.1,
              child: Center(
                child: Image.asset(
                  'assets/logo.png',
                  width: MediaQuery.of(context).size.shortestSide * 0.6,
                  // No color tint needed — the asset now carries real alpha
                  // (background pixels' luminance was baked into alpha, see
                  // git history), so it's already a pure white silhouette.
                ),
              ),
            ),
          ),
          ListView(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
            children: [
              const Text('PROFILES', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
              const SizedBox(height: 16),
              if (_profiles.isEmpty)
                Center(
                  child: Padding(
                    padding: const EdgeInsets.all(32.0),
                    child: Text('Create a new profile', style: TextStyle(color: Colors.white54, fontSize: 18)),
                  ),
                )
              else
                ..._buildProfileCards(),

          const SizedBox(height: 32),
          const Text('CLIENT SETTINGS', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
          const SizedBox(height: 16),

          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.02),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withOpacity(0.05)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildToggle('MUX (Multiplexing)', 'Multiple sessions over single connection', _muxEnabled, (v) => _muxEnabled = v),
                if (_muxEnabled)
                  _buildTextField('MUX Sessions', _muxSessionsCtrl, hint: 'e.g. 2, 4, 8'),

                _buildToggle('Debug Mode', 'Verbose logging', _debugMode, (v) => _debugMode = v),
                _buildToggle('Show Speed', 'Live download/upload speed on the home screen', _showSpeed, (v) => _showSpeed = v),
                _buildToggle('Show RTT', 'Live server ping on the home screen', _showRtt, (v) => _showRtt = v),

                _buildTextField('Local Proxy Bind', _localBindCtrl, hint: '127.0.0.1:1088'),
                _buildTextField('Custom DNS Server', _dnsCtrl, hint: '1.1.1.1 (e.g. 8.8.8.8)'),
                _buildTextField('MTU (Packet Size)', _mtuCtrl, hint: '1140 (decrease if connection drops)'),

                const Padding(
                  padding: EdgeInsets.only(bottom: 16),
                  child: Row(
                    children: [
                      Text('Exclusions', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                      SizedBox(width: 10),
                      Text('one per line', style: TextStyle(fontSize: 13, color: Colors.white30)),
                    ],
                  ),
                ),
                _buildTextField('Bypass Domains', _domainsCtrl, hint: 'example.com\n*.google.com', maxLines: 3),
                _buildTextField('Bypass IPs / CIDR', _ipsCtrl, hint: '192.168.1.0/24\n10.0.0.1', maxLines: 3),

                const SizedBox(height: 8),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.route),
                    label: const Text('Configure Split Tunneling'),
                    onPressed: () {
                      Navigator.push(context, MaterialPageRoute(builder: (context) => AppRoutingScreen(prefs: widget.prefs)));
                    },
                  ),
                ),
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.article),
                    label: const Text('View Logs'),
                    onPressed: () {
                      Navigator.push(context, MaterialPageRoute(builder: (context) => const LogsScreen()));
                    },
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          InkWell(
            onTap: _isCheckingUpdates ? null : _checkForUpdates,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.02),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: Colors.white.withOpacity(0.05)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.system_update_rounded, color: Colors.white70, size: 24),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('Check for Updates', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white)),
                        const SizedBox(height: 4),
                        Text(
                          _isCheckingUpdates ? 'Checking...' : 'Check latest release on GitHub',
                          style: const TextStyle(fontSize: 13, color: Colors.white54),
                        ),
                      ],
                    ),
                  ),
                  if (_isCheckingUpdates)
                    const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white54))
                  else
                    const Icon(Icons.arrow_forward_ios_rounded, color: Colors.white54, size: 16),
                ],
              ),
            ),
          ),

          const SizedBox(height: 40),
        ],
      ),
      ],
      ),
    );
  }

  Future<void> _checkForUpdates() async {
    if (_isCheckingUpdates) return;
    setState(() { _isCheckingUpdates = true; });
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      final currentVersion = packageInfo.version;

      final response = await http.get(Uri.parse('https://api.github.com/repos/ospab/ostp/releases/latest'));
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        final latestVersion = (data['tag_name'] as String).replaceAll('v', '');
        final hasUpdate = latestVersion != currentVersion;

        if (!mounted) return;
        showDialog(
          context: context,
          builder: (context) {
            return AlertDialog(
              backgroundColor: Theme.of(context).colorScheme.surface,
              title: Text(hasUpdate ? 'Update Available!' : 'Up to Date'),
              content: Text(hasUpdate
                  ? 'A new version ($latestVersion) is available on GitHub. You are currently running version $currentVersion.'
                  : 'You are running the latest version ($currentVersion).'),
              actions: [
                TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
                if (hasUpdate)
                  TextButton(
                    onPressed: () {
                      Navigator.pop(context);
                      final url = Uri.parse(data['html_url'] ?? 'https://github.com/ospab/ostp/releases/latest');
                      launchUrl(url, mode: LaunchMode.externalApplication);
                    },
                    child: const Text('Download'),
                  )
              ],
            );
          },
        );
      } else {
        throw Exception('HTTP ${response.statusCode}');
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error checking updates: $e')));
    } finally {
      if (mounted) setState(() { _isCheckingUpdates = false; });
    }
  }
}

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'app_routing_screen.dart';
import 'logs_screen.dart';
import 'qr_scanner_screen.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../models/ostp_profile.dart';
import '../models/share_link.dart';
import '../models/subscription.dart';
import '../services/updates.dart' as updates;

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
  bool _autoUpdateCheck = true;

  List<OstpProfile> _profiles = [];
  List<OstpSubscription> _subs = [];
  final Set<String> _refreshing = {};

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
    _autoUpdateCheck = widget.prefs.getBool(updates.autoUpdateCheckKey) ?? true;
    _muxSessionsCtrl = TextEditingController(text: widget.prefs.getString('mux_sessions') ?? '2');
    _profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
    _subs = SubscriptionStore(widget.prefs).load();
  }

  void _reloadProfilesAndSubs() {
    setState(() {
      _profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
      _subs = SubscriptionStore(widget.prefs).load();
    });
  }

  // ── Subscriptions ────────────────────────────────────────────────────────

  Future<void> _importSubscription(String url) async {
    final messenger = ScaffoldMessenger.of(context);
    messenger.showSnackBar(const SnackBar(content: Text('Fetching subscription...'), duration: Duration(seconds: 2)));
    try {
      final n = await SubscriptionStore(widget.prefs).add(url);
      _reloadProfilesAndSubs();
      messenger.showSnackBar(SnackBar(content: Text('Subscription added: $n profile(s)')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Subscription error: ${e.toString().replaceFirst('Exception: ', '')}')));
    }
  }

  Future<void> _refreshSubscription(OstpSubscription s) async {
    setState(() => _refreshing.add(s.id));
    final messenger = ScaffoldMessenger.of(context);
    try {
      final n = await SubscriptionStore(widget.prefs).refresh(s.id);
      messenger.showSnackBar(SnackBar(content: Text('Updated: $n profile(s)')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Update failed: ${e.toString().replaceFirst('Exception: ', '')}')));
    } finally {
      _refreshing.remove(s.id);
      if (mounted) _reloadProfilesAndSubs();
    }
  }

  void _confirmRemoveSubscription(OstpSubscription s) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        title: const Text('Remove subscription?'),
        content: Text('"${s.name}" and its profiles will be removed from this device.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              await SubscriptionStore(widget.prefs).remove(s.id);
              _reloadProfilesAndSubs();
            },
            child: const Text('Remove', style: TextStyle(color: Colors.redAccent)),
          ),
        ],
      ),
    );
  }

  String _ago(int ms) {
    if (ms == 0) return 'never';
    final d = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(ms));
    if (d.inMinutes < 1) return 'just now';
    if (d.inHours < 1) return '${d.inMinutes} min ago';
    if (d.inDays < 1) return '${d.inHours} h ago';
    return '${d.inDays} d ago';
  }

  List<Widget> _buildSubscriptionCards() {
    return _subs.map((s) {
      final used = s.usedBytes;
      final limit = s.limitBytes;
      final usage = used == null
          ? null
          : limit != null && limit > 0
              ? '${formatBytes(used)} of ${formatBytes(limit)}'
              : '${formatBytes(used)} used';
      final busy = _refreshing.contains(s.id);
      return Card(
        color: Theme.of(context).colorScheme.surface,
        margin: const EdgeInsets.only(bottom: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 8, 12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.rss_feed_rounded, size: 18, color: Colors.white54),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(s.name.isEmpty ? s.url : s.name,
                        style: const TextStyle(fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
                  ),
                  busy
                      ? const Padding(
                          padding: EdgeInsets.all(12),
                          child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
                        )
                      : IconButton(
                          icon: const Icon(Icons.refresh_rounded, size: 20, color: Colors.white54),
                          tooltip: 'Update',
                          onPressed: () => _refreshSubscription(s),
                        ),
                  IconButton(
                    icon: const Icon(Icons.delete_outline_rounded, size: 20, color: Colors.white54),
                    tooltip: 'Remove',
                    onPressed: () => _confirmRemoveSubscription(s),
                  ),
                ],
              ),
              if (limit != null && limit > 0 && used != null) ...[
                const SizedBox(height: 4),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(value: (used / limit).clamp(0.0, 1.0), minHeight: 4),
                ),
              ],
              const SizedBox(height: 6),
              Text(
                [
                  if (usage != null) usage,
                  'updated ${_ago(s.updatedAt)}',
                  'every ${s.intervalHours} h',
                ].join(' · '),
                style: const TextStyle(fontSize: 12, color: Colors.white54),
              ),
              if (s.lastError != null)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(s.lastError!, style: const TextStyle(fontSize: 12, color: Colors.redAccent)),
                ),
              // The subscription's own profiles live here, not among the
              // ones added by hand: a refresh rewrites them.
              const SizedBox(height: 6),
              ..._profiles.where((p) => p.subId == s.id).map((p) => _profileTile(p, dense: true)),
            ],
          ),
        ),
      );
    }).toList();
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
    widget.prefs.setBool(updates.autoUpdateCheckKey, _autoUpdateCheck);
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
    if (isSubscriptionUrl(link)) {
      _importSubscription(link);
      return;
    }
    try {
      final l = ShareLink.parse(link);
      final wasEmpty = _profiles.isEmpty;

      setState(() {
        _profiles.add(OstpProfile(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: l.name ?? l.host,
          serverAddr: l.server,
          accessKey: l.key,
          transportMode: l.transport,
          active: wasEmpty,
          tls: l.tls,
          tlsSni: l.sni ?? '',
          tlsInsecure: l.insecure,
          wsPath: l.path ?? '',
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
                if (result != null && result is String && (result.toLowerCase().startsWith('ostp://') || isSubscriptionUrl(result))) {
                  _importFromLink(result);
                }
              },
            ),
            ListTile(
              leading: const Icon(Icons.link, color: Colors.white),
              title: const Text('Import link or subscription'),
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
        title: const Text('Import'),
        backgroundColor: Theme.of(context).colorScheme.surface,
        content: TextField(
          controller: linkCtrl,
          decoration: const InputDecoration(
            hintText: 'ostp://... or https://.../sub/...',
            helperText: 'A subscription keeps its profiles up to date',
          ),
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

  /// Host part of "host:port" / "[v6]:port" — the TLS name used when SNI is empty.
  String _hostOf(String server) {
    final s = server.trim();
    if (s.startsWith('[')) {
      final end = s.indexOf(']');
      return end > 0 ? s.substring(1, end) : s;
    }
    final c = s.lastIndexOf(':');
    return c > 0 ? s.substring(0, c) : (s.isEmpty ? 'the server host' : s);
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
    bool tls = profile?.tls ?? false;
    bool tlsInsecure = profile?.tlsInsecure ?? false;
    final sniCtrl = TextEditingController(text: profile?.tlsSni ?? '');
    final wsPathCtrl = TextEditingController(text: profile?.wsPath ?? '');
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
                    const Text('TLS', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white54, letterSpacing: 1.0)),
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('TLS (HTTPS)', style: TextStyle(fontSize: 14)),
                      subtitle: const Text('Real TLS to the server\'s domain certificate', style: TextStyle(fontSize: 12, color: Colors.white54)),
                      value: tls,
                      onChanged: (v) => setDialogState(() => tls = v),
                    ),
                    if (tls) ...[
                      TextField(
                        controller: sniCtrl,
                        decoration: InputDecoration(
                          labelText: 'Server name (SNI)',
                          hintText: _hostOf(serverCtrl.text),
                          helperText: 'Name sent in the TLS handshake and checked against the certificate. '
                              'Empty = ${_hostOf(serverCtrl.text)} from the address; set only for another name on the same certificate.',
                          helperMaxLines: 3,
                        ),
                      ),
                      const SizedBox(height: 8),
                      TextField(
                        controller: wsPathCtrl,
                        decoration: const InputDecoration(labelText: 'Upgrade path', hintText: 'only through nginx/apache/caddy'),
                      ),
                      SwitchListTile(
                        contentPadding: EdgeInsets.zero,
                        title: const Text("Don't verify certificate", style: TextStyle(fontSize: 14, color: Colors.redAccent)),
                        subtitle: const Text('Insecure: anyone on the path can impersonate the server. Testing only.', style: TextStyle(fontSize: 12, color: Colors.redAccent)),
                        value: tlsInsecure,
                        onChanged: (v) => setDialogState(() => tlsInsecure = v),
                      ),
                    ],
                  ],
                  // Inside TLS junk and fragmentation are encrypted and hide
                  // nothing, so the engine skips them; hide their controls too.
                  if (transportMode == 'uot' && !tls) ...[
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
                        tls: transportMode == 'uot' && tls,
                        tlsSni: sniCtrl.text.trim(),
                        tlsInsecure: tlsInsecure,
                        wsPath: wsPathCtrl.text.trim(),
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
                      profile.tls = transportMode == 'uot' && tls;
                      profile.tlsSni = sniCtrl.text.trim();
                      profile.tlsInsecure = tlsInsecure;
                      profile.wsPath = wsPathCtrl.text.trim();
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
    if (p.serverAddr.isEmpty || p.accessKey.isEmpty) return;
    final ShareLink link;
    try {
      // serverAddr is "host:port"; reuse the codec to split it.
      link = ShareLink.parse('ostp://x@${p.serverAddr}');
    } catch (_) {
      return;
    }
    link.key = p.accessKey;
    link.transport = p.transportMode;
    link.tls = p.transportMode == 'uot' && p.tls;
    if (link.tls) {
      link.sni = p.tlsSni.isEmpty ? null : p.tlsSni;
      link.insecure = p.tlsInsecure;
    }
    link.path = p.wsPath.isEmpty ? null : p.wsPath;
    final url = link.toUri();

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

  String? get _activeId {
    for (final x in _profiles) {
      if (x.active) return x.id;
    }
    return null;
  }

  /// One selectable profile row; `dense` inside a subscription card.
  Widget _profileTile(OstpProfile p, {bool dense = false}) {
    return ListTile(
      dense: dense,
      contentPadding: dense ? EdgeInsets.zero : null,
      leading: Radio<String>(
        value: p.id,
        groupValue: _activeId,
        onChanged: (_) => _selectActive(p),
      ),
      title: Text(p.name, style: TextStyle(fontWeight: FontWeight.bold, fontSize: dense ? 14 : null), maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(
        [
          if (p.name != p.serverAddr) p.serverAddr,
          p.tls ? 'TLS' : p.transportMode.toUpperCase(),
        ].join(' · '),
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
    );
  }

  List<Widget> _buildProfileCards(List<OstpProfile> list) {
    final activeId = _activeId;
    return list.map((p) => Card(
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
          [
            if (p.name != p.serverAddr) p.serverAddr,
            p.tls ? 'TLS' : p.transportMode.toUpperCase(),
            if (p.subId.isNotEmpty) 'subscription',
          ].join(' · '),
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
              if (_subs.isNotEmpty) ...[
                const Text('SUBSCRIPTIONS', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
                const SizedBox(height: 16),
                ..._buildSubscriptionCards(),
                const SizedBox(height: 20),
              ],
              Text(_subs.isEmpty ? 'PROFILES' : 'MY PROFILES',
                  style: const TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
              const SizedBox(height: 16),
              if (_profiles.every((p) => p.subId.isNotEmpty))
                Center(
                  child: Padding(
                    padding: EdgeInsets.all(_subs.isEmpty ? 32.0 : 12.0),
                    child: Text(
                      _subs.isEmpty ? 'Create a new profile' : 'Profiles you add by hand appear here',
                      style: TextStyle(color: Colors.white54, fontSize: _subs.isEmpty ? 18 : 13),
                    ),
                  ),
                )
              else
                ..._buildProfileCards(_profiles.where((p) => p.subId.isEmpty).toList()),

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

                _buildToggle('Check for updates', 'When the app opens: stable and beta releases', _autoUpdateCheck, (v) => _autoUpdateCheck = v),
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
                          _isCheckingUpdates ? 'Checking...' : 'Stable and beta releases on GitHub',
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
      await updates.checkForUpdates(context, widget.prefs, manual: true);
    } finally {
      if (mounted) setState(() { _isCheckingUpdates = false; });
    }
  }
}

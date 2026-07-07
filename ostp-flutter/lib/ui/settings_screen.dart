import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'app_routing_screen.dart';
import 'logs_screen.dart';
import 'qr_scanner_screen.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/ostp_profile.dart';

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
  late TextEditingController _processesCtrl;
  late TextEditingController _dnsDomainCtrl;
  late TextEditingController _pbkCtrl;
  late TextEditingController _sidCtrl;
  late TextEditingController _muxSessionsCtrl;

  bool _debugMode = false;
  String _tunStack = 'ostp';
  bool _muxEnabled = false;
  bool _tcpFragmentation = false;

  List<OstpProfile> _profiles = [];

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  void _loadSettings() {
    _localBindCtrl = TextEditingController(text: widget.prefs.getString('local_bind') ?? '127.0.0.1:1088');
    _dnsCtrl = TextEditingController(text: widget.prefs.getString('dns_server') ?? '');
    _mtuCtrl = TextEditingController(text: widget.prefs.getString('mtu') ?? '1140');
    _tcpFragmentation = widget.prefs.getBool('tcp_fragmentation') ?? false;
    _domainsCtrl = TextEditingController(text: widget.prefs.getString('ex_domains') ?? '');
    _ipsCtrl = TextEditingController(text: widget.prefs.getString('ex_ips') ?? '');
    _processesCtrl = TextEditingController(text: widget.prefs.getString('ex_processes') ?? '');
    _dnsDomainCtrl = TextEditingController(text: widget.prefs.getString('dns_domain') ?? '');
    _pbkCtrl = TextEditingController(text: widget.prefs.getString('tun_pbk') ?? '');
    _sidCtrl = TextEditingController(text: widget.prefs.getString('sid') ?? '');
    _tunStack = widget.prefs.getString('tun_stack') ?? 'ostp';
    _debugMode = widget.prefs.getBool('debug_mode') ?? false;
    _muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    _muxSessionsCtrl = TextEditingController(text: widget.prefs.getString('mux_sessions') ?? '2');

    final profilesJson = widget.prefs.getString('profiles_json');
    if (profilesJson != null && profilesJson.isNotEmpty) {
      try {
        final List<dynamic> decoded = jsonDecode(profilesJson);
        _profiles = decoded.map((e) => OstpProfile.fromJson(e)).toList();
      } catch (e) {
        debugPrint('Error loading profiles: $e');
      }
    }
  }

  @override
  void dispose() {
    _saveSettings();
    _localBindCtrl.dispose();
    _dnsCtrl.dispose();
    _mtuCtrl.dispose();
    _domainsCtrl.dispose();
    _ipsCtrl.dispose();
    _processesCtrl.dispose();
    _dnsDomainCtrl.dispose();
    _pbkCtrl.dispose();
    _sidCtrl.dispose();
    _muxSessionsCtrl.dispose();
    super.dispose();
  }

  void _saveSettings() {
    widget.prefs.setString('local_bind', _localBindCtrl.text.trim());
    widget.prefs.setString('dns_server', _dnsCtrl.text.trim());
    widget.prefs.setString('mtu', _mtuCtrl.text.trim());
    widget.prefs.setBool('tcp_fragmentation', _tcpFragmentation);
    widget.prefs.setString('ex_domains', _domainsCtrl.text.trim());
    widget.prefs.setString('ex_ips', _ipsCtrl.text.trim());
    widget.prefs.setString('ex_processes', _processesCtrl.text.trim());
    widget.prefs.setBool('debug_mode', _debugMode);
    widget.prefs.setString('tun_stack', _tunStack);
    widget.prefs.setString('dns_domain', _dnsDomainCtrl.text.trim());
    widget.prefs.setString('tun_pbk', _pbkCtrl.text.trim());
    widget.prefs.setString('sid', _sidCtrl.text.trim());
    widget.prefs.setBool('mux_enabled', _muxEnabled);
    widget.prefs.setString('mux_sessions', _muxSessionsCtrl.text.trim());
    
    final profilesJson = jsonEncode(_profiles.map((e) => e.toJson()).toList());
    widget.prefs.setString('profiles_json', profilesJson);
  }

  void _importFromLink(String link) {
    if (link.isEmpty) return;
    try {
      if (!link.startsWith('ostp://')) {
        throw Exception('Link must start with ostp://');
      }
      final uri = Uri.parse(link);
      final key = Uri.decodeComponent(uri.userInfo);
      final host = uri.authority.replaceFirst(uri.userInfo + '@', '');
      if (key.isEmpty || host.isEmpty) {
        throw Exception('Incomplete link parameters');
      }
      final type = uri.queryParameters['type'];
      final transportMode = type == 'tcp' || type == 'http' ? 'uot' : (type == 'dns' ? 'dns' : 'udp');
      final name = uri.queryParameters['name'] ?? host;
      
      setState(() {
        _profiles.add(OstpProfile(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: name,
          serverAddr: host,
          accessKey: key,
          transportMode: transportMode,
        ));
        _saveSettings();
      });
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Imported successfully')));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: ${e.toString()}')));
    }
  }

  String _buildShareLink(OstpProfile p) {
    final type = p.transportMode == 'uot' ? 'tcp' : 'udp';
    final key = Uri.encodeComponent(p.accessKey);
    final name = Uri.encodeComponent(p.name);
    return 'ostp://$key@${p.serverAddr}?type=$type#$name';
  }

  void _shareProfile(OstpProfile p) {
    final link = _buildShareLink(p);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: Theme.of(ctx).colorScheme.surface,
        title: const Text('Share profile'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              child: QrImageView(
                data: link,
                size: 200,
                backgroundColor: Colors.white,
              ),
            ),
            const SizedBox(height: 16),
            SelectableText(
              link,
              textAlign: TextAlign.center,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: link));
              ScaffoldMessenger.of(ctx).showSnackBar(
                const SnackBar(content: Text('Copied')),
              );
            },
            child: const Text('Copy link'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
        ],
      ),
    );
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
    final TextEditingController linkCtrl = TextEditingController();
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
            child: const Text('Import')
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
    String transportMode = profile?.transportMode ?? 'udp';

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
                children: [
                  TextField(controller: nameCtrl, decoration: const InputDecoration(labelText: 'Name')),
                  TextField(controller: serverCtrl, decoration: const InputDecoration(labelText: 'Server Address (host:port)')),
                  TextField(controller: keyCtrl, decoration: const InputDecoration(labelText: 'Access Key')),
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
                ],
              ),
            ),
            actions: [
              if (!isNew)
                TextButton(
                  onPressed: () {
                    setState(() {
                      _profiles.removeWhere((p) => p.id == profile.id);
                      _saveSettings();
                    });
                    Navigator.pop(context);
                  },
                  child: const Text('Delete', style: TextStyle(color: Colors.redAccent)),
                ),
              TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
              TextButton(
                onPressed: () {
                  setState(() {
                    if (isNew) {
                      _profiles.add(OstpProfile(
                        id: DateTime.now().millisecondsSinceEpoch.toString(),
                        name: nameCtrl.text.trim(),
                        serverAddr: serverCtrl.text.trim(),
                        accessKey: keyCtrl.text.trim(),
                        transportMode: transportMode,
                        active: true,
                      ));
                    } else {
                      profile.name = nameCtrl.text.trim();
                      profile.serverAddr = serverCtrl.text.trim();
                      profile.accessKey = keyCtrl.text.trim();
                      profile.transportMode = transportMode;
                    }
                    _saveSettings();
                  });
                  Navigator.pop(context);
                }, 
                child: const Text('Save')
              ),
            ],
          ),
        );
      },
    );
  }

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
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        children: [
          const Text('PROFILES', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
          const SizedBox(height: 16),
          if (_profiles.isEmpty)
            Center(
              child: Padding(
                padding: const EdgeInsets.all(32.0),
                child: Text('Create a new profile', style: TextStyle(color: Colors.white.withOpacity(0.5), fontSize: 18)),
              ),
            )
          else
            ..._profiles.map((p) => Card(
              color: Theme.of(context).colorScheme.surface,
              margin: const EdgeInsets.only(bottom: 12),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              child: ListTile(
                leading: Checkbox(
                  value: p.active,
                  onChanged: (val) {
                    setState(() {
                      p.active = val ?? false;
                      _saveSettings();
                    });
                  },
                ),
                title: Text(p.name, style: const TextStyle(fontWeight: FontWeight.bold)),
                subtitle: Text('${p.serverAddr} (${p.transportMode.toUpperCase()})', style: const TextStyle(fontSize: 12)),
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.qr_code_2, size: 20, color: Colors.white54),
                      tooltip: 'Share',
                      onPressed: () => _shareProfile(p),
                    ),
                    IconButton(
                      icon: const Icon(Icons.edit, size: 20, color: Colors.white54),
                      onPressed: () => _showEditProfileDialog(p),
                    ),
                  ],
                ),
                onTap: () {
                  setState(() {
                    p.active = !p.active;
                    _saveSettings();
                  });
                },
              ),
            )).toList(),
          
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
                
                _buildToggle('TCP Fragmentation', 'Break TLS Hello into small pieces', _tcpFragmentation, (v) => _tcpFragmentation = v),
                _buildToggle('Debug Mode', 'Verbose logging', _debugMode, (v) => _debugMode = v),
                
                _buildTextField('Local Proxy Bind', _localBindCtrl, hint: '127.0.0.1:1088'),
                _buildTextField('Custom DNS Server', _dnsCtrl, hint: '1.1.1.1 (e.g. 8.8.8.8)'),
                _buildTextField('MTU (Packet Size)', _mtuCtrl, hint: '1140 (decrease if connection drops)'),
                
                const SizedBox(height: 24),
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
          )
        ],
      ),
    );
  }
}

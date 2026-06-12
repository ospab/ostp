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

class SettingsScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const SettingsScreen({super.key, required this.prefs});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _importCtrl;
  late TextEditingController _serverCtrl;
  late TextEditingController _localBindCtrl;
  late TextEditingController _keyCtrl;
  late TextEditingController _dnsCtrl;
  late TextEditingController _mtuCtrl;
  late TextEditingController _domainsCtrl;
  late TextEditingController _ipsCtrl;
  late TextEditingController _processesCtrl;
  late TextEditingController _stealthSniCtrl;
  late TextEditingController _pbkCtrl;
  late TextEditingController _sidCtrl;

  bool _obscureKey = true;
  bool _debugMode = false;
  bool _wss = false;
  String _transportMode = 'udp'; // 'udp' | 'uot'
  String _tunStack = 'ostp'; // 'system' | 'ostp'
  bool _muxEnabled = false;
  late TextEditingController _muxSessionsCtrl;


  @override
  void initState() {
    super.initState();
    _importCtrl = TextEditingController();
    _serverCtrl = TextEditingController(text: widget.prefs.getString('server_addr') ?? '127.0.0.1:443');
    _localBindCtrl = TextEditingController(text: widget.prefs.getString('local_bind') ?? '127.0.0.1:1088');
    _keyCtrl = TextEditingController(text: widget.prefs.getString('access_key') ?? '');
    _dnsCtrl = TextEditingController(text: widget.prefs.getString('dns_server') ?? '1.1.1.1');
    _mtuCtrl = TextEditingController(text: widget.prefs.getString('mtu') ?? '1140');
    _domainsCtrl = TextEditingController(text: widget.prefs.getString('ex_domains') ?? '');
    _ipsCtrl = TextEditingController(text: widget.prefs.getString('ex_ips') ?? '');
    _processesCtrl = TextEditingController(text: widget.prefs.getString('ex_processes') ?? '');
    _stealthSniCtrl = TextEditingController(text: widget.prefs.getString('stealth_sni') ?? '');
    _pbkCtrl = TextEditingController(text: widget.prefs.getString('pbk') ?? '');
    _sidCtrl = TextEditingController(text: widget.prefs.getString('sid') ?? '');
    _wss = widget.prefs.getBool('wss') ?? false;
    _transportMode = widget.prefs.getString('transport_mode') ?? 'udp';
    _tunStack = widget.prefs.getString('tun_stack') ?? 'ostp';
    _debugMode = widget.prefs.getBool('debug_mode') ?? false;
    _muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    _muxSessionsCtrl = TextEditingController(text: widget.prefs.getString('mux_sessions') ?? '2');
  }

  @override
  void dispose() {
    _saveSettings();
    _importCtrl.dispose();
    _serverCtrl.dispose();
    _localBindCtrl.dispose();
    _keyCtrl.dispose();
    _dnsCtrl.dispose();
    _mtuCtrl.dispose();
    _domainsCtrl.dispose();
    _ipsCtrl.dispose();
    _processesCtrl.dispose();
    _stealthSniCtrl.dispose();
    _pbkCtrl.dispose();
    _sidCtrl.dispose();
    _muxSessionsCtrl.dispose();
    super.dispose();
  }

  void _saveSettings() {
    widget.prefs.setString('server_addr', _serverCtrl.text.trim());
    widget.prefs.setString('local_bind', _localBindCtrl.text.trim());
    widget.prefs.setString('access_key', _keyCtrl.text.trim());
    widget.prefs.setString('dns_server', _dnsCtrl.text.trim());
    widget.prefs.setString('mtu', _mtuCtrl.text.trim());
    widget.prefs.setString('ex_domains', _domainsCtrl.text.trim());
    widget.prefs.setString('ex_ips', _ipsCtrl.text.trim());
    widget.prefs.setString('ex_processes', _processesCtrl.text.trim());
    widget.prefs.setBool('debug_mode', _debugMode);
    widget.prefs.setBool('wss', _wss);
    widget.prefs.setString('transport_mode', _transportMode);
    widget.prefs.setString('tun_stack', _tunStack);
    widget.prefs.setString('stealth_sni', _stealthSniCtrl.text.trim());
    widget.prefs.setString('pbk', _pbkCtrl.text.trim());
    widget.prefs.setString('sid', _sidCtrl.text.trim());
    widget.prefs.setBool('mux_enabled', _muxEnabled);
    widget.prefs.setString('mux_sessions', _muxSessionsCtrl.text.trim());
  }
  Widget _buildTextField(String label, TextEditingController controller, {String? hint, bool isPassword = false, int maxLines = 1, bool isMono = false}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
        const SizedBox(height: 10),
        TextField(
          controller: controller,
          obscureText: isPassword && _obscureKey,
          maxLines: maxLines,
          style: TextStyle(fontSize: 16, fontFamily: isMono ? 'monospace' : 'Inter'),
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: const TextStyle(color: Colors.white30),
            filled: true,
            fillColor: Theme.of(context).colorScheme.surface,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
            contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
            suffixIcon: isPassword ? IconButton(
              icon: Icon(_obscureKey ? Icons.visibility : Icons.visibility_off, color: Colors.white54),
              onPressed: () => setState(() => _obscureKey = !_obscureKey),
            ) : null,
          ),
        ),
        const SizedBox(height: 24),
      ],
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
              onChanged(v);
              _saveSettings();
            },
            activeColor: Theme.of(context).colorScheme.secondary,
            activeTrackColor: Theme.of(context).colorScheme.secondary.withOpacity(0.3),
            inactiveTrackColor: Colors.white10,
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
            icon: const Icon(Icons.qr_code_scanner_rounded),
            onPressed: () async {
              final result = await Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => const QRScannerScreen()),
              );
              if (result != null && result is String && result.startsWith('ostp://')) {
                setState(() {
                  _importCtrl.text = result;
                });
              }
            },
          )
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        children: [
          // Quick Import Row
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _importCtrl,
                  decoration: InputDecoration(
                    hintText: 'Paste ostp:// share link...',
                    hintStyle: const TextStyle(color: Colors.white30, fontSize: 14),
                    filled: true,
                    fillColor: Colors.white.withOpacity(0.05),
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              ElevatedButton(
                onPressed: () {
                  final raw = _importCtrl.text.trim();
                  if (raw.isEmpty) return;
                  try {
                    if (!raw.startsWith('ostp://')) {
                      throw Exception('Link must start with ostp://');
                    }
                    final uri = Uri.parse(raw);
                    final key = Uri.decodeComponent(uri.userInfo);
                    final host = uri.authority.replaceFirst(uri.userInfo + '@', '');
                    if (key.isEmpty || host.isEmpty) {
                      throw Exception('Incomplete link parameters');
                    }
                    setState(() {
                      _serverCtrl.text = host;
                      _keyCtrl.text = key;
                      _stealthSniCtrl.text = uri.queryParameters['sni'] ?? '';
                      _pbkCtrl.text = uri.queryParameters['pbk'] ?? '';
                      _sidCtrl.text = uri.queryParameters['sid'] ?? '';
                      _wss = uri.queryParameters['wss'] == 'true';
                      final type = uri.queryParameters['type'] ?? 'udp';
                      _transportMode = type == 'tcp' || type == 'http' ? 'uot' : 'udp';
                      _importCtrl.clear();

                      _saveSettings();
                    });
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Imported successfully')));
                  } catch (e) {
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: ${e.toString()}')));
                  }
                },
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                  backgroundColor: Theme.of(context).colorScheme.primary,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                ),
                child: const Text('Import', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white)),
              )
            ],
          ),
          
          const SizedBox(height: 30),
          
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
                _buildTextField('Server Address', _serverCtrl, hint: 'host:port'),
                _buildTextField('Local Proxy Bind', _localBindCtrl, hint: '127.0.0.1:1088'),
                _buildTextField('Access Key', _keyCtrl, hint: 'Secure access key', isPassword: true),
                _buildTextField('Custom DNS Server', _dnsCtrl, hint: '1.1.1.1 (e.g. 8.8.8.8)'),
                _buildTextField('MTU (Packet Size)', _mtuCtrl, hint: '1140 (decrease if connection drops)'),

                // ── Transport Mode ───────────────────────────────────────
                const Text('Transport Mode', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
                const SizedBox(height: 10),
                Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surface,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Column(
                    children: [
                      RadioListTile<String>(
                        value: 'udp',
                        groupValue: _transportMode,
                        title: const Text('UDP (по умолчанию)', style: TextStyle(fontWeight: FontWeight.w600)),
                        subtitle: const Text('Быстро, работает через Wi-Fi и большинство сетей', style: TextStyle(color: Colors.white54, fontSize: 12)),
                        activeColor: Theme.of(context).colorScheme.secondary,
                        onChanged: (v) => setState(() { _transportMode = v!; _saveSettings(); }),
                      ),
                      Divider(color: Colors.white.withOpacity(0.05), height: 1),
                      RadioListTile<String>(
                        value: 'uot',
                        groupValue: _transportMode,
                        title: Wrap(
                          crossAxisAlignment: WrapCrossAlignment.center,
                          spacing: 8,
                          children: [
                            const Text('UoT (UDP-over-TCP)', style: TextStyle(fontWeight: FontWeight.w600)),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                              decoration: BoxDecoration(
                                color: const Color(0xFF6C72FF).withOpacity(0.2),
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: const Text('xHTTP Стелс', style: TextStyle(fontSize: 10, color: Color(0xFF6C72FF), fontWeight: FontWeight.bold)),
                            ),
                          ],
                        ),
                        subtitle: const Text('Маскировка под HTTP-поток, обходит белые списки (уровень 1)', style: TextStyle(color: Colors.white54, fontSize: 12)),
                        activeColor: Theme.of(context).colorScheme.primary,
                        onChanged: (v) => setState(() { _transportMode = v!; _saveSettings(); }),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                _buildToggle('WebSocket (WSS)', 'Инкапсулировать транспорт в RFC 6455 (для строгого DPI)', _wss, (val) {
                  setState(() {
                    _wss = val;
                  });
                }),
                const SizedBox(height: 16),

                // Stealth parameters
                AnimatedCrossFade(
                  duration: const Duration(milliseconds: 250),
                  crossFadeState: _transportMode == 'uot' ? CrossFadeState.showFirst : CrossFadeState.showSecond,
                  firstChild: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF6C72FF).withOpacity(0.06),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: const Color(0xFF6C72FF).withOpacity(0.2)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.security, size: 16, color: Color(0xFF6C72FF)),
                            const SizedBox(width: 8),
                            const Text('Стелс параметры', style: TextStyle(fontWeight: FontWeight.bold, color: Color(0xFF6C72FF), fontSize: 14)),
                          ],
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Укажи домен из белого списка. OSTP подключится к серверу и подделает SNI / HTTP Host.',
                          style: TextStyle(fontSize: 12, color: Colors.white38),
                        ),
                        const SizedBox(height: 16),
                        Builder(builder: (context) {
                          final List<String> domains = [
                            'yastatic.net', 'mc.yandex.ru', 'st.mycdn.me',
                            'top-fwz1.mail.ru', 'sso.passport.yandex.ru',
                            'sberbank.ru', 'ad.mail.ru', 'ads.vk.com',
                            'login.vk.com', 'api.sberbank.ru', 'ok.ru',
                            'rostelecom.ru', 'rt.ru', 'tinkoff.ru',
                            'x5.ru', 'ozon.ru', 'wildberries.ru', 'gosuslugi.ru', 'vk.com'
                          ];
                          String currentVal = _stealthSniCtrl.text.trim();
                          if (currentVal.isEmpty) currentVal = 'vk.com';
                          if (!domains.contains(currentVal)) {
                            domains.add(currentVal);
                          }
                          return DropdownButtonFormField<String>(
                            value: currentVal,
                            dropdownColor: const Color(0xFF1E1E2C),
                            style: const TextStyle(color: Colors.white, fontSize: 14),
                            decoration: InputDecoration(
                              labelText: 'Стелс Домен (Автоподставление)',
                              labelStyle: const TextStyle(color: Colors.white54, fontSize: 13),
                              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                            ),
                            items: domains.map((String domain) {
                              return DropdownMenuItem<String>(
                                value: domain,
                                child: Text(domain),
                              );
                            }).toList(),
                            onChanged: (String? newValue) {
                              if (newValue != null) {
                                setState(() {
                                  _stealthSniCtrl.text = newValue;
                                  _saveSettings();
                                });
                              }
                            },
                          );
                        }),
                        const SizedBox(height: 16),
                        _buildToggle('XTLS-Reality', 'Подделка TLS-сессии (Stealth-домен должен быть TLS 1.3)', _realityEnabled, (val) {
                          setState(() {
                            _realityEnabled = val;
                          });
                        }),
                        const SizedBox(height: 16),
                      ],
                    ),
                  ),
                  secondChild: const SizedBox.shrink(),
                ),


                const SizedBox(height: 16),
                _buildToggle('Multiplexing (Mux)', 'Combine multiple TCP streams to bypass throttling', _muxEnabled, (v) => setState(() => _muxEnabled = v)),
                AnimatedCrossFade(
                  duration: const Duration(milliseconds: 200),
                  crossFadeState: _muxEnabled ? CrossFadeState.showFirst : CrossFadeState.showSecond,
                  firstChild: Padding(
                    padding: const EdgeInsets.only(top: 12.0),
                    child: _buildTextField('Mux Sessions', _muxSessionsCtrl, hint: '4'),
                  ),
                  secondChild: const SizedBox.shrink(),
                ),

                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Expanded(child: _buildToggle('Debug Logs', 'Verbose output', _debugMode, (v) => setState(() => _debugMode = v))),
                    Padding(
                      padding: const EdgeInsets.only(bottom: 24.0, left: 10),
                      child: IconButton(
                        icon: const Icon(Icons.receipt_long_rounded),
                        color: Theme.of(context).colorScheme.primary,
                        tooltip: 'View Logs',
                        onPressed: () {
                          Navigator.push(context, MaterialPageRoute(builder: (context) => const LogsScreen()));
                        },
                      ),
                    ),
                  ],
                ),

                
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 16),
                  child: Row(
                    children: [
                      Text('Exclusions', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                      SizedBox(width: 10),
                      Text('one per line', style: TextStyle(fontSize: 13, color: Colors.white30)),
                    ],
                  ),
                ),
                
                _buildTextField('Bypass Domains', _domainsCtrl, hint: 'example.com\n*.google.com', maxLines: 3, isMono: true),
                _buildTextField('Bypass IPs / CIDR', _ipsCtrl, hint: '192.168.1.0/24\n10.0.0.1', maxLines: 3, isMono: true),
                
                // Premium app routing trigger button
                InkWell(
                  onTap: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (context) => AppRoutingScreen(prefs: widget.prefs)),
                    );
                  },
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: Theme.of(context).colorScheme.primary.withOpacity(0.2)),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.apps_rounded, color: Theme.of(context).colorScheme.primary, size: 24),
                        const SizedBox(width: 16),
                        const Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Per-App Connection Rules',
                                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white),
                              ),
                              SizedBox(height: 4),
                              Text(
                                'Choose which apps bypass or use VPN',
                                style: TextStyle(fontSize: 13, color: Colors.white54),
                              ),
                            ],
                          ),
                        ),
                        const Icon(Icons.arrow_forward_ios_rounded, color: Colors.white54, size: 16),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 10),
              ],
            ),
          ),
          
          const SizedBox(height: 40),
        ],
      ),
    );
  }
}


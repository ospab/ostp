import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final prefs = await SharedPreferences.getInstance();
  runApp(OstpApp(prefs: prefs));
}

class OstpApp extends StatelessWidget {
  final SharedPreferences prefs;
  const OstpApp({super.key, required this.prefs});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OSTP Client',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF08080F),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF6C72FF),
          secondary: Color(0xFF22D3A5),
          surface: Color(0xFF151522),
        ),
        fontFamily: 'Inter',
        useMaterial3: true,
      ),
      home: HomeScreen(prefs: prefs),
    );
  }
}

class HomeScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const HomeScreen({super.key, required this.prefs});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

enum ConnectionStateEnum { disconnected, connecting, connected }

class _HomeScreenState extends State<HomeScreen> with TickerProviderStateMixin {
  static const platform = MethodChannel('com.ospab.ostp/vpn');
  
  ConnectionStateEnum _state = ConnectionStateEnum.disconnected;
  Timer? _pollTimer;
  Timer? _uptimeTimer;
  int _uptimeSecs = 0;
  
  String _serverAddr = '127.0.0.1:443';
  String _accessKey = 'default_key';
  
  String _download = '0 B';
  String _upload = '0 B';

  late AnimationController _pulseController;
  late AnimationController _spinController;

  bool _isCheckingPing = false;
  String _pingText = 'Target Ping: -- ms';
  Color _pingColor = Colors.white54;

  @override
  void initState() {
    super.initState();
    _loadSettings();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );
    _spinController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 4),
    );
    _checkInitialState();
  }

  Future<void> _checkInitialState() async {
    try {
      final isRunning = await platform.invokeMethod('isRunning');
      if (isRunning == true && mounted) {
        _setConnected();
      }
    } catch (e) {
      debugPrint("Failed to check initial state: $e");
    }
  }
  
  void _loadSettings() {
    setState(() {
      _serverAddr = widget.prefs.getString('server_addr') ?? '127.0.0.1:443';
      _accessKey = widget.prefs.getString('access_key') ?? '';
    });
    _updateLatestConfigJson();
  }

  void _updateLatestConfigJson() {
    final bool owndns = widget.prefs.getBool('owndns') ?? false;
    final dnsServer = owndns ? '10.1.0.1' : (widget.prefs.getString('dns_server') ?? '1.1.1.1');
    final exDomains = widget.prefs.getString('ex_domains') ?? '';
    final exIps = widget.prefs.getString('ex_ips') ?? '';
    final exProcesses = widget.prefs.getString('ex_processes') ?? '';
    final debugMode = widget.prefs.getBool('debug_mode') ?? false;
    final transportMode = widget.prefs.getString('transport_mode') ?? 'udp';
    final stealthSni = widget.prefs.getString('stealth_sni') ?? 'vk.com';
    final stealthPort = widget.prefs.getString('stealth_port') ?? '443';
    final mtu = widget.prefs.getString('mtu') ?? '1350';
    final muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    final muxSessions = widget.prefs.getString('mux_sessions') ?? '2';
    final tunStack = widget.prefs.getString('tun_stack') ?? 'ostp';

    final appRoutingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
    final appRoutingPackages = widget.prefs.getStringList('app_routing_packages') ?? [];

    final localBind = widget.prefs.getString('local_bind') ?? '127.0.0.1:1088';
    final configMap = {
      "mode": "client",
      "debug": debugMode,
      "ostp": {
        "server_addr": _serverAddr,
        "local_bind_addr": "0.0.0.0:0",
        "access_key": _accessKey,
        "handshake_timeout_ms": 10000,
        "io_timeout_ms": 5000,
        "mtu": int.tryParse(mtu) ?? 1350,
      },
      "local_proxy": {
        "bind_addr": localBind,
        "connect_timeout_ms": 15000,
      },
      "transport": {
        "mode": transportMode,
        "stealth_sni": stealthSni,
        "stealth_port": int.tryParse(stealthPort) ?? 443,
      },
      "multiplex": {
        "enabled": muxEnabled,
        "sessions": int.tryParse(muxSessions) ?? 2,
      },
      "reality": {
        "enabled": widget.prefs.getString('pbk')?.isNotEmpty ?? false,
        "dest": "",
        "private_key": "",
        "pbk": widget.prefs.getString('pbk') ?? "",
        "sid": widget.prefs.getString('sid') ?? "",
        "sni_list": []
      },
      "tun": {
        "enable": true,
        "stack": tunStack
      },
      "exclusions": {
        "domains": exDomains.split('\n').where((s) => s.trim().isNotEmpty).toList(),
        "ips": exIps.split('\n').where((s) => s.trim().isNotEmpty).toList(),
        "processes": exProcesses.split('\n').where((s) => s.trim().isNotEmpty).toList(),
      },
      "app_rules": {
        "mode": appRoutingMode,
        "packages": appRoutingPackages,
      },
      "dns_server": dnsServer,
      "tun_stack": tunStack
    };
    widget.prefs.setString('latest_config_json', jsonEncode(configMap));
    platform.invokeMethod('saveConfig', {
      "configJson": jsonEncode(configMap)
    });
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _uptimeTimer?.cancel();
    _pulseController.dispose();
    _spinController.dispose();
    super.dispose();
  }

  Future<void> _toggleConnection() async {
    if (_state == ConnectionStateEnum.disconnected) {
      if (_serverAddr.isEmpty || _accessKey.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Please configure Server and Key in Settings')),
        );
        return;
      }
      
      setState(() {
        _state = ConnectionStateEnum.connecting;
      });
      _pulseController.repeat(reverse: true);
      _spinController.repeat();

      final bool owndns = widget.prefs.getBool('owndns') ?? false;
      final dnsServer = owndns ? '10.1.0.1' : (widget.prefs.getString('dns_server') ?? '1.1.1.1');
      final exDomains = widget.prefs.getString('ex_domains') ?? '';
      final exIps = widget.prefs.getString('ex_ips') ?? '';
      final exProcesses = widget.prefs.getString('ex_processes') ?? '';
      final debugMode = widget.prefs.getBool('debug_mode') ?? false;
      final transportMode = widget.prefs.getString('transport_mode') ?? 'udp';
      final stealthSni = widget.prefs.getString('stealth_sni') ?? 'vk.com';
      final stealthPort = widget.prefs.getString('stealth_port') ?? '443';
      final mtu = widget.prefs.getString('mtu') ?? '1350';
      final muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
      final muxSessions = widget.prefs.getString('mux_sessions') ?? '2';
      final tunStack = widget.prefs.getString('tun_stack') ?? 'ostp';

      final appRoutingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
      final appRoutingPackages = widget.prefs.getStringList('app_routing_packages') ?? [];

      final localBind = widget.prefs.getString('local_bind') ?? '127.0.0.1:1088';
      final configMap = {
        "mode": "client",
        "debug": debugMode,
        "ostp": {
          "server_addr": _serverAddr,
          "local_bind_addr": "0.0.0.0:0",
          "access_key": _accessKey,
          "handshake_timeout_ms": 10000,
          "io_timeout_ms": 5000,
          "mtu": int.tryParse(mtu) ?? 1350,
        },
        "local_proxy": {
          "bind_addr": localBind,
          "connect_timeout_ms": 15000,
        },
        "transport": {
          "mode": transportMode,
          "stealth_sni": stealthSni,
          "stealth_port": int.tryParse(stealthPort) ?? 443,
        },
        "multiplex": {
          "enabled": muxEnabled,
          "sessions": int.tryParse(muxSessions) ?? 2,
        },
        "reality": {
          "enabled": widget.prefs.getString('pbk')?.isNotEmpty ?? false,
          "dest": "",
          "private_key": "",
          "pbk": widget.prefs.getString('pbk') ?? "",
          "sid": widget.prefs.getString('sid') ?? "",
          "sni_list": []
        },
        "tun": {
          "enable": true,
          "stack": tunStack
        },
        "exclusions": {
          "domains": exDomains.split('\n').where((s) => s.trim().isNotEmpty).toList(),
          "ips": exIps.split('\n').where((s) => s.trim().isNotEmpty).toList(),
          "processes": exProcesses.split('\n').where((s) => s.trim().isNotEmpty).toList(),
        },
        "app_rules": {
          "mode": appRoutingMode,
          "packages": appRoutingPackages,
        },
        "dns_server": dnsServer,
        "tun_stack": tunStack
      };
      
      widget.prefs.setString('latest_config_json', jsonEncode(configMap));


      try {
        await platform.invokeMethod('saveConfig', {
          "configJson": jsonEncode(configMap)
        });
        await platform.invokeMethod('startTunnel', {
          "configJson": jsonEncode(configMap)
        });
        
        bool started = false;
        for (int i = 0; i < 10; i++) {
          await Future.delayed(const Duration(milliseconds: 500));
          final isRunning = await platform.invokeMethod('isRunning');
          if (isRunning == true) {
            started = true;
            break;
          }
        }
        
        if (started) {
          _setConnected();
        } else {
          _setDisconnected();
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Failed to connect. Check logs for details.')),
            );
          }
        }
      } catch (e, stackTrace) {
        debugPrint("Failed to start tunnel: $e\n$stackTrace");
        _setDisconnected();
        if (mounted) {
          showDialog(
            context: context,
            builder: (ctx) => AlertDialog(
              title: const Text('Error', style: TextStyle(color: Colors.redAccent)),
              content: SingleChildScrollView(
                child: SelectableText(e.toString(), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: e.toString()));
                    ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: Text('Copied!')));
                  },
                  child: const Text('Copy'),
                ),
                TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: const Text('Close'),
                ),
              ],
            ),
          );
        }
      }
    } else {
      try {
        await platform.invokeMethod('stopTunnel');
      } catch (e) {
        debugPrint("Stop error: $e");
      }
      _setDisconnected();
    }
  }

  void _setConnected() {
    if (!mounted) return;
    setState(() {
      _state = ConnectionStateEnum.connected;
    });
    _pulseController.stop();
    _pulseController.value = 1.0; 
    
    _uptimeSecs = 0;
    _uptimeTimer?.cancel();
    _uptimeTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted) return;
      setState(() => _uptimeSecs++);
    });

    _startPollingMetrics();
  }

  void _startPollingMetrics() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (timer) async {
      if (!mounted) return;
      try {
        final metricsJson = await platform.invokeMethod('getMetrics');
        if (metricsJson != null && metricsJson.isNotEmpty) {
          final Map<String, dynamic> parsed = jsonDecode(metricsJson);
          final bytesSent = parsed['bytes_sent'] as int? ?? 0;
          final bytesRecv = parsed['bytes_recv'] as int? ?? 0;
          final connState = parsed['connection_state'] as int? ?? 2;
          final rttMs = parsed['rtt_ms'] as int? ?? 0;
          
          if (connState == 0 && _state != ConnectionStateEnum.disconnected) {
            try {
              await platform.invokeMethod('stopTunnel');
            } catch (e) {
              debugPrint("Failed to stop background tunnel: $e");
            }
            _setDisconnected();
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Connection failed. Check logs for details.')),
              );
            }
            return;
          }
          
          if (mounted) {
            setState(() {
              _download = _formatBytes(bytesRecv);
              _upload = _formatBytes(bytesSent);
              if (rttMs > 0 && !_isCheckingPing) {
                _pingText = 'Server Ping: $rttMs ms';
                if (rttMs < 100) {
                  _pingColor = const Color(0xFF22D3A5);
                } else if (rttMs < 250) {
                  _pingColor = Colors.amberAccent;
                } else {
                  _pingColor = Colors.redAccent;
                }
              }
            });
          }
        }
      } catch (e) {
        debugPrint("Failed to get metrics: $e");
      }
    });
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  Future<void> _checkConnectionLatency() async {
    if (_state != ConnectionStateEnum.connected) return;
    
    setState(() {
      _isCheckingPing = true;
      _pingText = 'Updating...';
      _pingColor = Colors.white70;
    });
    
    await Future.delayed(const Duration(milliseconds: 500));
    
    if (mounted) {
      setState(() {
        _isCheckingPing = false;
      });
    }
  }

  void _setDisconnected() {
    if (!mounted) return;
    setState(() {
      _state = ConnectionStateEnum.disconnected;
      _download = '0 B';
      _upload = '0 B';
      _pingText = 'Target Ping: -- ms';
      _pingColor = Colors.white54;
      _isCheckingPing = false;
    });
    _pulseController.stop();
    _pulseController.value = 0.0;
    _spinController.stop();
    _uptimeTimer?.cancel();
    _pollTimer?.cancel();
  }

  String _formatTime(int s) {
    final h = s ~/ 3600;
    final m = (s % 3600) ~/ 60;
    final sec = s % 60;
    final pad = (int n) => n.toString().padLeft(2, '0');
    return h > 0 ? '$h:${pad(m)}:${pad(sec)}' : '${pad(m)}:${pad(sec)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return Scaffold(
      body: Stack(
        children: [
          Positioned(
            top: -150, right: -100,
            child: Container(
              width: 400, height: 400,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: theme.colorScheme.primary.withOpacity(0.15),
              ),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 100, sigmaY: 100),
                child: Container(),
              ),
            ),
          ),
          Positioned(
            bottom: -100, left: -100,
            child: Container(
              width: 350, height: 350,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: theme.colorScheme.secondary.withOpacity(0.1),
              ),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 100, sigmaY: 100),
                child: Container(),
              ),
            ),
          ),
          
          SafeArea(
            child: LayoutBuilder(
              builder: (context, constraints) {
                return SingleChildScrollView(
                  child: ConstrainedBox(
                    constraints: BoxConstraints(minHeight: constraints.maxHeight),
                    child: IntrinsicHeight(
                      child: Column(
                        children: [
                          _buildTopBar(theme),
                          Expanded(child: _buildStage(theme)),
                          _buildMetricsBar(theme),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTopBar(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                width: 12, height: 12,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(4),
                  color: _state == ConnectionStateEnum.connected 
                      ? theme.colorScheme.secondary 
                      : theme.colorScheme.primary,
                  boxShadow: [
                    BoxShadow(
                      color: _state == ConnectionStateEnum.connected 
                          ? theme.colorScheme.secondary.withOpacity(0.5) 
                          : theme.colorScheme.primary.withOpacity(0.5),
                      blurRadius: 10,
                    )
                  ]
                ),
              ),
              const SizedBox(width: 12),
              const Text(
                'OSTP',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 2.5,
                  color: Colors.white,
                ),
              ),
            ],
          ),
          IconButton(
            iconSize: 30,
            icon: const Icon(Icons.settings_outlined, color: Colors.white),
            onPressed: () async {
              await Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => SettingsScreen(prefs: widget.prefs)),
              );
              _loadSettings();
            },
          )
        ],
      ),
    );
  }

  Widget _buildStage(ThemeData theme) {
    Color getAccentColor() {
      if (_state == ConnectionStateEnum.connected) return theme.colorScheme.secondary;
      return theme.colorScheme.primary;
    }

    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        SizedBox(
          width: 260, height: 260,
          child: Stack(
            alignment: Alignment.center,
            children: [
              if (_state != ConnectionStateEnum.disconnected)
                RotationTransition(
                  turns: _spinController,
                  child: Container(
                    width: 240, height: 240,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: getAccentColor().withOpacity(0.25),
                        width: 2.0,
                      ),
                    ),
                  ),
                ),
              if (_state != ConnectionStateEnum.disconnected)
                RotationTransition(
                  turns: ReverseAnimation(_spinController),
                  child: Container(
                    width: 200, height: 200,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: getAccentColor().withOpacity(0.15),
                        width: 1.5,
                      ),
                    ),
                  ),
                ),
              
              AnimatedBuilder(
                animation: _pulseController,
                builder: (context, child) {
                  return Container(
                    width: 140, height: 140,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: theme.colorScheme.surface,
                      border: Border.all(
                        color: _state == ConnectionStateEnum.disconnected
                            ? Colors.white.withOpacity(0.15)
                            : getAccentColor(),
                        width: 3,
                      ),
                      boxShadow: [
                        if (_state != ConnectionStateEnum.disconnected)
                          BoxShadow(
                            color: getAccentColor().withOpacity(0.4 * (_state == ConnectionStateEnum.connected ? 1.0 : _pulseController.value)),
                            blurRadius: 40,
                            spreadRadius: 8,
                          )
                      ]
                    ),
                    child: child,
                  );
                },
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    customBorder: const CircleBorder(),
                    onTap: _toggleConnection,
                    child: Icon(
                      Icons.power_settings_new_rounded,
                      size: 60,
                      color: _state == ConnectionStateEnum.disconnected
                          ? Colors.white54
                          : getAccentColor(),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
        
        const SizedBox(height: 40),
        
        Text(
          _state == ConnectionStateEnum.disconnected ? 'Disconnected' :
          _state == ConnectionStateEnum.connecting ? 'Connecting...' : 'Connected',
          style: TextStyle(
            fontSize: 26,
            fontWeight: FontWeight.w700,
            color: _state == ConnectionStateEnum.disconnected ? Colors.white70 : getAccentColor(),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          _state == ConnectionStateEnum.connected ? _formatTime(_uptimeSecs) : 'Tap to protect your traffic',
          style: const TextStyle(
            fontSize: 16,
            color: Colors.white54,
          ),
        ),
        
        const SizedBox(height: 30),
        
        AnimatedOpacity(
          opacity: _state == ConnectionStateEnum.connected ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 300),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(30),
                  border: Border.all(color: Colors.white.withOpacity(0.15)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.dns_rounded, size: 18, color: Colors.white70),
                    const SizedBox(width: 10),
                    Text(
                      _serverAddr,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                        color: Colors.white70,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 32),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.03),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withOpacity(0.06)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'CONNECTION TEST',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.white38,
                            letterSpacing: 0.8,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          _pingText,
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                            color: _pingColor,
                          ),
                        ),
                      ],
                    ),
                    _isCheckingPing
                        ? const SizedBox(
                            width: 20, height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white70),
                          )
                        : TextButton.icon(
                            onPressed: _checkConnectionLatency,
                            icon: Icon(Icons.speed_rounded, size: 16, color: theme.colorScheme.primary),
                            label: Text(
                              'Test Ping',
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
                                color: theme.colorScheme.primary,
                              ),
                            ),
                            style: TextButton.styleFrom(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              backgroundColor: theme.colorScheme.primary.withOpacity(0.1),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                            ),
                          ),
                  ],
                ),
              ),
            ],
          ),
        )
      ],
    );
  }

  Widget _buildMetricsBar(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 20),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.04),
        border: Border(top: BorderSide(color: Colors.white.withOpacity(0.08))),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          _buildMetricItem(Icons.arrow_downward_rounded, 'Download', _download, theme.colorScheme.secondary),
          Container(width: 1, height: 40, color: Colors.white.withOpacity(0.15)),
          _buildMetricItem(Icons.arrow_upward_rounded, 'Upload', _upload, theme.colorScheme.primary),
        ],
      ),
    );
  }

  Widget _buildMetricItem(IconData icon, String label, String value, Color color) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.15),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, size: 20, color: color),
        ),
        const SizedBox(width: 12),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: Colors.white54,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 16,
                fontWeight: FontWeight.w700,
                color: Colors.white,
              ),
            ),
          ],
        )
      ],
    );
  }
}

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
  late TextEditingController _stealthPortCtrl;
  late TextEditingController _pbkCtrl;
  late TextEditingController _sidCtrl;

  bool _obscureKey = true;
  bool _debugMode = false;
  String _transportMode = 'udp'; // 'udp' | 'wss'
  String _tunStack = 'ostp'; // 'system' | 'ostp'
  bool _muxEnabled = false;
  late TextEditingController _muxSessionsCtrl;
  bool _owndns = false;

  @override
  void initState() {
    super.initState();
    _importCtrl = TextEditingController();
    _serverCtrl = TextEditingController(text: widget.prefs.getString('server_addr') ?? '127.0.0.1:443');
    _localBindCtrl = TextEditingController(text: widget.prefs.getString('local_bind') ?? '127.0.0.1:1088');
    _keyCtrl = TextEditingController(text: widget.prefs.getString('access_key') ?? '');
    _dnsCtrl = TextEditingController(text: widget.prefs.getString('dns_server') ?? '1.1.1.1');
    _mtuCtrl = TextEditingController(text: widget.prefs.getString('mtu') ?? '1350');
    _domainsCtrl = TextEditingController(text: widget.prefs.getString('ex_domains') ?? '');
    _ipsCtrl = TextEditingController(text: widget.prefs.getString('ex_ips') ?? '');
    _processesCtrl = TextEditingController(text: widget.prefs.getString('ex_processes') ?? '');
    _stealthSniCtrl = TextEditingController(text: widget.prefs.getString('stealth_sni') ?? '');
    _stealthPortCtrl = TextEditingController(text: widget.prefs.getString('stealth_port') ?? '443');
    _pbkCtrl = TextEditingController(text: widget.prefs.getString('pbk') ?? '');
    _sidCtrl = TextEditingController(text: widget.prefs.getString('sid') ?? '');
    _transportMode = widget.prefs.getString('transport_mode') ?? 'udp';
    _tunStack = widget.prefs.getString('tun_stack') ?? 'ostp';
    _debugMode = widget.prefs.getBool('debug_mode') ?? false;
    _muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    _muxSessionsCtrl = TextEditingController(text: widget.prefs.getString('mux_sessions') ?? '2');
    _owndns = widget.prefs.getBool('owndns') ?? false;
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
    _stealthPortCtrl.dispose();
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
    widget.prefs.setString('transport_mode', _transportMode);
    widget.prefs.setString('tun_stack', _tunStack);
    widget.prefs.setString('stealth_sni', _stealthSniCtrl.text.trim());
    widget.prefs.setString('stealth_port', _stealthPortCtrl.text.trim());
    widget.prefs.setString('pbk', _pbkCtrl.text.trim());
    widget.prefs.setString('sid', _sidCtrl.text.trim());
    widget.prefs.setBool('mux_enabled', _muxEnabled);
    widget.prefs.setString('mux_sessions', _muxSessionsCtrl.text.trim());
    widget.prefs.setBool('owndns', _owndns);
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
                      final type = uri.queryParameters['type'] ?? 'udp';
                      _transportMode = type == 'tcp' || type == 'http' ? 'uot' : 'udp';
                      _owndns = uri.queryParameters['owndns'] == 'true';
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
                _buildToggle('Built-in Server DNS', 'Route DNS queries to the VPN server', _owndns, (val) {
                  setState(() {
                    _owndns = val;
                  });
                }),
                if (!_owndns) ...[
                  _buildTextField('Custom DNS Server', _dnsCtrl, hint: '1.1.1.1 (e.g. 8.8.8.8)'),
                ],
                _buildTextField('MTU (Packet Size)', _mtuCtrl, hint: '1350 (decrease if connection drops)'),

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
                const SizedBox(height: 24),

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
                                  _stealthPortCtrl.text = '443';
                                  _saveSettings();
                                });
                              }
                            },
                          );
                        }),
                        const SizedBox(height: 16),
                        _buildTextField('Reality PublicKey (pbk)', _pbkCtrl, hint: 'Оставьте пустым для отключения Reality'),
                        _buildTextField('Reality ShortId (sid)', _sidCtrl, hint: 'Опционально (необязательно)'),
                      ],
                    ),
                  ),
                  secondChild: const SizedBox.shrink(),
                ),

                const SizedBox(height: 16),
                const Text('TUN Stack (Desktop only)', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
                const SizedBox(height: 10),
                Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surface,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Column(
                    children: [
                      RadioListTile<String>(
                        value: 'system',
                        groupValue: _tunStack,
                        title: const Text('System (tun2socks)', style: TextStyle(fontWeight: FontWeight.w600)),
                        activeColor: Theme.of(context).colorScheme.secondary,
                        onChanged: (v) => setState(() { _tunStack = v!; _saveSettings(); }),
                      ),
                      Divider(color: Colors.white.withOpacity(0.05), height: 1),
                      RadioListTile<String>(
                        value: 'ostp',
                        groupValue: _tunStack,
                        title: const Text('OSTP (Native)', style: TextStyle(fontWeight: FontWeight.w600)),
                        activeColor: Theme.of(context).colorScheme.primary,
                        onChanged: (v) => setState(() { _tunStack = v!; _saveSettings(); }),
                      ),
                    ],
                  ),
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

class LogsScreen extends StatefulWidget {
  const LogsScreen({super.key});

  @override
  State<LogsScreen> createState() => _LogsScreenState();
}

class _LogsScreenState extends State<LogsScreen> {
  static const platform = MethodChannel('com.ospab.ostp/vpn');
  Timer? _pollTimer;
  final List<String> _logs = [];
  final ScrollController _scrollCtrl = ScrollController();

  @override
  void initState() {
    super.initState();
    _fetchLogs();
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (_) => _fetchLogs());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _scrollCtrl.dispose();
    super.dispose();
  }

  Future<void> _fetchLogs() async {
    try {
      final String logsJson = await platform.invokeMethod('getLogs');
      if (logsJson.isNotEmpty && logsJson != "[]") {
        final List<dynamic> parsed = jsonDecode(logsJson);
        if (parsed.isNotEmpty) {
          setState(() {
            _logs.addAll(parsed.map((e) => e.toString()));
          });
          Future.delayed(const Duration(milliseconds: 100), () {
            if (_scrollCtrl.hasClients) {
              _scrollCtrl.animateTo(_scrollCtrl.position.maxScrollExtent, duration: const Duration(milliseconds: 200), curve: Curves.easeOut);
            }
          });
        }
      }
    } catch (e, stackTrace) {
      debugPrint("Failed to fetch logs: $e\n$stackTrace");
      if (mounted) {
        Navigator.of(context).popUntil((route) => route.isFirst);
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('Logs Error', style: TextStyle(color: Colors.redAccent)),
            content: SingleChildScrollView(
              child: SelectableText(e.toString(), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            ),
            actions: [
              TextButton(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: e.toString()));
                  ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: Text('Copied!')));
                },
                child: const Text('Copy'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Close'),
              ),
            ],
          ),
        );
      }
    }
  }

  Future<void> _clearLogs() async {
    await platform.invokeMethod('clearLogs');
    setState(() {
      _logs.clear();
    });
  }

  Future<void> _copyLogs() async {
    final text = _logs.join('\n');
    await Clipboard.setData(ClipboardData(text: text));
    if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Logs copied to clipboard')));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('System Logs', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 0,
        actions: [
          IconButton(icon: const Icon(Icons.delete_outline), onPressed: _clearLogs, tooltip: 'Clear'),
          IconButton(icon: const Icon(Icons.copy_rounded), onPressed: _copyLogs, tooltip: 'Copy All'),
        ],
      ),
      body: Container(
        color: Colors.black,
        padding: const EdgeInsets.all(12),
        child: ListView.builder(
          controller: _scrollCtrl,
          itemCount: _logs.length,
          itemBuilder: (context, index) {
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 2.0),
              child: Text(
                _logs[index],
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: Colors.greenAccent,
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

class AppRoutingScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const AppRoutingScreen({super.key, required this.prefs});

  @override
  State<AppRoutingScreen> createState() => _AppRoutingScreenState();
}

class _AppRoutingScreenState extends State<AppRoutingScreen> {
  static const platform = MethodChannel('com.ospab.ostp/vpn');
  
  List<Map<String, dynamic>> _allApps = [];
  List<Map<String, dynamic>> _filteredApps = [];
  Set<String> _selectedPackages = {};
  String _routingMode = 'bypass';
  bool _hideSystemApps = true;
  bool _isLoading = true;
  String _searchQuery = '';
  
  final TextEditingController _searchCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadSavedConfig();
    _fetchInstalledApps();
  }

  void _loadSavedConfig() {
    setState(() {
      _routingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
      _selectedPackages = (widget.prefs.getStringList('app_routing_packages') ?? []).toSet();
    });
  }

  Future<void> _fetchInstalledApps() async {
    try {
      final List<dynamic>? rawApps = await platform.invokeMethod('getInstalledApps');
      if (rawApps != null) {
        final List<Map<String, dynamic>> apps = rawApps.map((e) {
          final Map<dynamic, dynamic> m = e as Map<dynamic, dynamic>;
          return {
            "name": m["name"] as String? ?? "Unknown",
            "package": m["package"] as String? ?? "",
            "isSystem": m["isSystem"] as bool? ?? false,
            "icon": m["icon"] as String? ?? "",
          };
        }).toList();
        
        apps.sort((a, b) => (a["name"] as String).toLowerCase().compareTo((b["name"] as String).toLowerCase()));
        
        setState(() {
          _allApps = apps;
          _isLoading = false;
        });
        _filterApps();
      }
    } catch (e) {
      debugPrint("Error fetching apps: $e");
      setState(() => _isLoading = false);
    }
  }

  void _filterApps() {
    setState(() {
      _filteredApps = _allApps.where((app) {
        final name = (app["name"] as String).toLowerCase();
        final package = (app["package"] as String).toLowerCase();
        final query = _searchQuery.toLowerCase();
        
        final matchesSearch = name.contains(query) || package.contains(query);
        final matchesSystemFilter = !_hideSystemApps || !(app["isSystem"] as bool);
        
        return matchesSearch && matchesSystemFilter;
      }).toList();
    });
  }

  void _saveConfig() {
    widget.prefs.setString('app_routing_mode', _routingMode);
    widget.prefs.setStringList('app_routing_packages', _selectedPackages.toList());
  }

  void _resetConfig() {
    setState(() {
      _selectedPackages.clear();
      _routingMode = 'bypass';
      _hideSystemApps = true;
      _searchCtrl.clear();
      _searchQuery = '';
    });
    _saveConfig();
    _filterApps();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('App routing rules reset successfully')),
    );
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('App Routing Rules', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
        backgroundColor: theme.colorScheme.surface,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            tooltip: 'Reset Rules',
            onPressed: _resetConfig,
          ),
        ],
      ),
      body: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            color: theme.colorScheme.surface.withOpacity(0.5),
            child: Column(
              children: [
                Row(
                  children: [
                    Expanded(
                      child: GestureDetector(
                        onTap: () {
                          setState(() {
                            _routingMode = 'bypass';
                          });
                          _saveConfig();
                        },
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          decoration: BoxDecoration(
                            color: _routingMode == 'bypass' ? theme.colorScheme.primary : Colors.white.withOpacity(0.05),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: _routingMode == 'bypass' ? theme.colorScheme.primary : Colors.white.withOpacity(0.1),
                            ),
                          ),
                          child: const Center(
                            child: Text(
                              'Bypass Mode',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: GestureDetector(
                        onTap: () {
                          setState(() {
                            _routingMode = 'proxy';
                          });
                          _saveConfig();
                        },
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          decoration: BoxDecoration(
                            color: _routingMode == 'proxy' ? theme.colorScheme.secondary : Colors.white.withOpacity(0.05),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: _routingMode == 'proxy' ? theme.colorScheme.secondary : Colors.white.withOpacity(0.1),
                            ),
                          ),
                          child: const Center(
                            child: Text(
                              'Proxy Mode',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  _routingMode == 'bypass' 
                      ? 'Selected apps bypass the VPN (direct connection).' 
                      : 'Only selected apps are routed through the VPN.',
                  style: const TextStyle(fontSize: 13, color: Colors.white54),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
          
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _searchCtrl,
                    onChanged: (val) {
                      setState(() {
                        _searchQuery = val;
                      });
                      _filterApps();
                    },
                    decoration: InputDecoration(
                      hintText: 'Search apps...',
                      prefixIcon: const Icon(Icons.search_rounded, color: Colors.white54),
                      suffixIcon: _searchQuery.isNotEmpty ? IconButton(
                        icon: const Icon(Icons.clear_rounded, color: Colors.white54),
                        onPressed: () {
                          _searchCtrl.clear();
                          setState(() {
                            _searchQuery = '';
                          });
                          _filterApps();
                        },
                      ) : null,
                      filled: true,
                      fillColor: Colors.white.withOpacity(0.05),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                InkWell(
                  onTap: () {
                    setState(() {
                      _hideSystemApps = !_hideSystemApps;
                    });
                    _filterApps();
                  },
                  child: Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: _hideSystemApps ? theme.colorScheme.primary.withOpacity(0.15) : Colors.white.withOpacity(0.05),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: _hideSystemApps ? theme.colorScheme.primary.withOpacity(0.4) : Colors.white.withOpacity(0.1),
                      ),
                    ),
                    child: Icon(
                      _hideSystemApps ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                      color: _hideSystemApps ? theme.colorScheme.primary : Colors.white70,
                    ),
                  ),
                ),
              ],
            ),
          ),
          
          Expanded(
            child: _isLoading 
                ? const Center(child: CircularProgressIndicator())
                : _filteredApps.isEmpty
                    ? const Center(child: Text('No applications found', style: TextStyle(color: Colors.white54)))
                    : ListView.builder(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        itemCount: _filteredApps.length,
                        itemBuilder: (context, index) {
                          final app = _filteredApps[index];
                          final pkg = app["package"] as String;
                          final name = app["name"] as String;
                          final isSystem = app["isSystem"] as bool;
                          final isSelected = _selectedPackages.contains(pkg);
                          final String? iconBase64 = app["icon"] as String?;
                          
                          final String initial = name.isNotEmpty ? name[0].toUpperCase() : '?';
                          final int colorHash = pkg.hashCode.abs();
                          final double hue = (colorHash % 360).toDouble();
                          
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            decoration: BoxDecoration(
                              color: isSelected 
                                  ? (_routingMode == 'bypass' 
                                      ? theme.colorScheme.primary.withOpacity(0.08) 
                                      : theme.colorScheme.secondary.withOpacity(0.08))
                                  : Colors.white.withOpacity(0.02),
                              borderRadius: BorderRadius.circular(16),
                              border: Border.all(
                                color: isSelected 
                                  ? (_routingMode == 'bypass' 
                                      ? theme.colorScheme.primary.withOpacity(0.3) 
                                      : theme.colorScheme.secondary.withOpacity(0.3))
                                  : Colors.white.withOpacity(0.05),
                              ),
                            ),
                            child: ListTile(
                              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                              leading: iconBase64 != null && iconBase64.isNotEmpty
                                  ? ClipRRect(
                                      borderRadius: BorderRadius.circular(10),
                                      child: Image.memory(
                                        base64Decode(iconBase64),
                                        width: 40, height: 40,
                                        fit: BoxFit.cover,
                                        errorBuilder: (context, error, stackTrace) => Container(
                                          width: 40, height: 40,
                                          decoration: BoxDecoration(
                                            shape: BoxShape.circle,
                                            gradient: LinearGradient(
                                              colors: [
                                                HSVColor.fromAHSV(1.0, hue, 0.7, 0.8).toColor(),
                                                HSVColor.fromAHSV(1.0, (hue + 40) % 360, 0.8, 0.9).toColor(),
                                              ],
                                              begin: Alignment.topLeft,
                                              end: Alignment.bottomRight,
                                            ),
                                          ),
                                          child: Center(
                                            child: Text(
                                              initial,
                                              style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 16),
                                            ),
                                          ),
                                        ),
                                      ),
                                    )
                                  : Container(
                                      width: 40, height: 40,
                                      decoration: BoxDecoration(
                                        shape: BoxShape.circle,
                                        gradient: LinearGradient(
                                          colors: [
                                            HSVColor.fromAHSV(1.0, hue, 0.7, 0.8).toColor(),
                                            HSVColor.fromAHSV(1.0, (hue + 40) % 360, 0.8, 0.9).toColor(),
                                          ],
                                          begin: Alignment.topLeft,
                                          end: Alignment.bottomRight,
                                        ),
                                      ),
                                      child: Center(
                                        child: Text(
                                          initial,
                                          style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 16),
                                        ),
                                      ),
                                    ),
                              title: Row(
                                children: [
                                  Expanded(
                                    child: Text(
                                      name,
                                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
                                      maxLines: 1, overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                  if (isSystem) ...[
                                    const SizedBox(width: 8),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: Colors.white.withOpacity(0.1),
                                        borderRadius: BorderRadius.circular(4),
                                      ),
                                      child: const Text(
                                        'SYS',
                                        style: TextStyle(fontSize: 9, color: Colors.white60, fontWeight: FontWeight.bold),
                                      ),
                                    )
                                  ]
                                ],
                              ),
                              subtitle: Text(
                                pkg,
                                style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white38),
                                maxLines: 1, overflow: TextOverflow.ellipsis,
                              ),
                              trailing: Switch(
                                value: isSelected,
                                activeColor: _routingMode == 'bypass' ? theme.colorScheme.primary : theme.colorScheme.secondary,
                                onChanged: (val) {
                                  setState(() {
                                    if (val) {
                                      _selectedPackages.add(pkg);
                                    } else {
                                      _selectedPackages.remove(pkg);
                                    }
                                  });
                                  _saveConfig();
                                },
                              ),
                            ),
                          );
                        },
                      ),
          ),
        ],
      ),
    );
  }
}

class QRScannerScreen extends StatefulWidget {
  const QRScannerScreen({super.key});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  final MobileScannerController controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.normal,
    facing: CameraFacing.back,
  );

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  DateTime? lastErrorTime;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR Code'),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: Stack(
        alignment: Alignment.center,
        children: [
          MobileScanner(
            controller: controller,
            onDetect: (capture) {
              final List<Barcode> barcodes = capture.barcodes;
              for (final barcode in barcodes) {
                if (barcode.rawValue != null) {
                  if (barcode.rawValue!.startsWith('ostp://')) {
                    controller.stop();
                    Navigator.pop(context, barcode.rawValue);
                    return;
                  } else {
                    final now = DateTime.now();
                    if (lastErrorTime == null || now.difference(lastErrorTime!) > const Duration(seconds: 3)) {
                      lastErrorTime = now;
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Invalid QR Code. Must be an OSTP connection link.'),
                          backgroundColor: Colors.redAccent,
                          duration: Duration(seconds: 2),
                        ),
                      );
                    }
                  }
                }
              }
            },
          ),
          Container(
            decoration: ShapeDecoration(
              shape: QrScannerOverlayShape(
                borderColor: Theme.of(context).colorScheme.primary,
                borderRadius: 10,
                borderLength: 30,
                borderWidth: 10,
                cutOutSize: 300,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class QrScannerOverlayShape extends ShapeBorder {
  final Color borderColor;
  final double borderWidth;
  final double borderRadius;
  final double borderLength;
  final double cutOutSize;

  const QrScannerOverlayShape({
    this.borderColor = Colors.red,
    this.borderWidth = 3.0,
    this.borderRadius = 0.0,
    this.borderLength = 20.0,
    this.cutOutSize = 250.0,
  });

  @override
  EdgeInsetsGeometry get dimensions => const EdgeInsets.all(10);

  @override
  Path getInnerPath(Rect rect, {TextDirection? textDirection}) {
    return Path()
      ..fillType = PathFillType.evenOdd
      ..addPath(getOuterPath(rect), Offset.zero);
  }

  @override
  Path getOuterPath(Rect rect, {TextDirection? textDirection}) {
    Path path = Path()..addRect(rect);
    rect = Rect.fromCenter(
      center: rect.center,
      width: cutOutSize,
      height: cutOutSize,
    );
    path.addRect(rect);
    return path;
  }

  @override
  void paint(Canvas canvas, Rect rect, {TextDirection? textDirection}) {
    final borderPaint = Paint()
      ..color = borderColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = borderWidth;
      
    final backgroundPaint = Paint()
      ..color = Colors.black54
      ..style = PaintingStyle.fill;

    final cutOutRect = Rect.fromCenter(
      center: rect.center,
      width: cutOutSize,
      height: cutOutSize,
    );

    final backgroundPath = Path()
      ..addRect(rect)
      ..addRect(cutOutRect)
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(backgroundPath, backgroundPaint);

    final path = Path();
    // Top left
    path.moveTo(cutOutRect.left, cutOutRect.top + borderLength);
    path.lineTo(cutOutRect.left, cutOutRect.top + borderRadius);
    path.arcToPoint(
      Offset(cutOutRect.left + borderRadius, cutOutRect.top),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(cutOutRect.left + borderLength, cutOutRect.top);

    // Top right
    path.moveTo(cutOutRect.right - borderLength, cutOutRect.top);
    path.lineTo(cutOutRect.right - borderRadius, cutOutRect.top);
    path.arcToPoint(
      Offset(cutOutRect.right, cutOutRect.top + borderRadius),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(cutOutRect.right, cutOutRect.top + borderLength);

    // Bottom left
    path.moveTo(cutOutRect.left, cutOutRect.bottom - borderLength);
    path.lineTo(cutOutRect.left, cutOutRect.bottom - borderRadius);
    path.arcToPoint(
      Offset(cutOutRect.left + borderRadius, cutOutRect.bottom),
      radius: Radius.circular(borderRadius),
      clockwise: false,
    );
    path.lineTo(cutOutRect.left + borderLength, cutOutRect.bottom);

    // Bottom right
    path.moveTo(cutOutRect.right - borderLength, cutOutRect.bottom);
    path.lineTo(cutOutRect.right - borderRadius, cutOutRect.bottom);
    path.arcToPoint(
      Offset(cutOutRect.right, cutOutRect.bottom - borderRadius),
      radius: Radius.circular(borderRadius),
      clockwise: false,
    );
    path.lineTo(cutOutRect.right, cutOutRect.bottom - borderLength);

    canvas.drawPath(path, borderPaint);
    
    // Line in the middle
    final linePaint = Paint()
      ..color = borderColor.withOpacity(0.8)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.0;
    
    canvas.drawLine(
      Offset(cutOutRect.left + 20, cutOutRect.center.dy),
      Offset(cutOutRect.right - 20, cutOutRect.center.dy),
      linePaint,
    );
  }

  @override
  ShapeBorder scale(double t) {
    return QrScannerOverlayShape(
      borderColor: borderColor,
      borderWidth: borderWidth * t,
      borderRadius: borderRadius * t,
      borderLength: borderLength * t,
      cutOutSize: cutOutSize * t,
    );
  }
}

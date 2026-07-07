import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:flutter_svg/flutter_svg.dart';
import '../models/connection_state_enum.dart';
import '../models/ostp_profile.dart';
import 'settings_screen.dart';
import 'logs_screen.dart';
import 'app_routing_screen.dart';
import 'qr_scanner_screen.dart';

class HomeScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const HomeScreen({super.key, required this.prefs});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with TickerProviderStateMixin {
  static const platform = MethodChannel('com.ospab.ostp/vpn');
  
  ConnectionStateEnum _state = ConnectionStateEnum.disconnected;
  Timer? _pollTimer;
  Timer? _uptimeTimer;
  int _uptimeSecs = 0;
  
  List<OstpProfile> _activeProfiles = [];
  
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
    _startPolling();
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
      final profilesJson = widget.prefs.getString('profiles_json');
      if (profilesJson != null && profilesJson.isNotEmpty) {
        try {
          final List<dynamic> decoded = jsonDecode(profilesJson);
          final profiles = decoded.map((e) => OstpProfile.fromJson(e)).toList();
          _activeProfiles = profiles.where((p) => p.active).toList();
        } catch (e) {
          debugPrint('Error loading profiles: $e');
        }
      } else {
        final oldServer = widget.prefs.getString('server_addr');
        final oldKey = widget.prefs.getString('access_key');
        if (oldServer != null && oldServer.isNotEmpty) {
          final p = OstpProfile(
            id: DateTime.now().millisecondsSinceEpoch.toString(),
            name: 'Profile 1',
            serverAddr: oldServer,
            accessKey: oldKey ?? '',
            transportMode: widget.prefs.getString('transport_mode') ?? 'udp',
            stealthSni: widget.prefs.getString('stealth_sni') ?? '',
            wss: widget.prefs.getBool('wss') ?? false,
            active: true
          );
          _activeProfiles = [p];
          widget.prefs.setString('profiles_json', jsonEncode([p.toJson()]));
        } else {
          _activeProfiles = [];
        }
      }
    });
    _updateLatestConfigJson();
  }

  void _updateLatestConfigJson() {
    final exDomains = widget.prefs.getString('ex_domains') ?? '';
    final exIps = widget.prefs.getString('ex_ips') ?? '';
    final exProcesses = widget.prefs.getString('ex_processes') ?? '';
    final debugMode = widget.prefs.getBool('debug_mode') ?? false;
    final mtu = widget.prefs.getString('mtu') ?? '1140';
    final muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    final muxSessions = widget.prefs.getString('mux_sessions') ?? '2';
    final tcpFrag = widget.prefs.getBool('tcp_fragmentation') ?? false;
    final dnsServer = widget.prefs.getString('dns_server');
    final effectiveDnsServer = (dnsServer == null || dnsServer.isEmpty) ? '1.1.1.1' : dnsServer;
    final tunStack = 'ostp';
    final appRoutingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
    final appRoutingPackages = widget.prefs.getStringList('app_routing_packages') ?? [];
    final localBind = widget.prefs.getString('local_bind') ?? '127.0.0.1:1088';
    final localParts = localBind.split(':');
    final localListen = localParts.isNotEmpty ? localParts[0] : '127.0.0.1';
    final localPort = localParts.length > 1 ? (int.tryParse(localParts[1]) ?? 1088) : 1088;

    List<Map<String, dynamic>> inbounds = [
      {
        "type": "local_proxy",
        "tag": "socks-in",
        "protocol": "socks",
        "listen": localListen,
        "port": localPort
      },
      {
        "type": "tun",
        "tag": "tun-in",
        "auto_route": true,
        "mtu": int.tryParse(mtu) ?? 1140
      }
    ];

    List<Map<String, dynamic>> outbounds = [];
    List<String> ostpTags = [];

    for (int i = 0; i < _activeProfiles.length; i++) {
      final p = _activeProfiles[i];
      final tag = _activeProfiles.length > 1 ? 'proxy-$i' : 'proxy';
      ostpTags.add(tag);
      
      final parts = p.serverAddr.split(':');
      final host = parts.isNotEmpty ? parts[0] : '127.0.0.1';
      final port = parts.length > 1 ? (int.tryParse(parts[1]) ?? 50000) : 50000;

      outbounds.add({
        "type": "ostp",
        "tag": tag,
        "server": host,
        "port": port,
        "access_key": p.accessKey,
        "transport": {
          "type": p.transportMode,
          "stealth_sni": p.stealthSni,
          "wss": p.wss,
          "tcp_fragmentation": tcpFrag
        },
        "multiplex": {
          "enabled": muxEnabled,
          "sessions": int.tryParse(muxSessions) ?? 2
        }
      });
    }

    if (_activeProfiles.length > 1) {
      outbounds.add({
        "type": "urltest",
        "tag": "proxy",
        "outbounds": ostpTags,
        "url": "http://cp.cloudflare.com",
        "interval": "3m"
      });
    }

    outbounds.add({"type": "direct", "tag": "direct"});
    outbounds.add({"type": "block", "tag": "block"});

    // Exclusions → "direct". Keys MUST match the Rust RoutingRule fields
    // (domain_suffix / ip_cidr / process_name). The old "domains/ips/processes"
    // keys did not match the struct and were silently dropped, so exclusions
    // never applied. Only push a rule that actually has entries — a rule with an
    // empty list never matches anyway.
    final exDomainsList = exDomains.split('\n').where((s) => s.trim().isNotEmpty).toList();
    final exIpsList = exIps.split('\n').where((s) => s.trim().isNotEmpty).toList();
    final exProcessesList = exProcesses.split('\n').where((s) => s.trim().isNotEmpty).toList();
    final List<Map<String, dynamic>> routingRules = [];
    if (exDomainsList.isNotEmpty) routingRules.add({"domain_suffix": exDomainsList, "outbound": "direct"});
    if (exIpsList.isNotEmpty) routingRules.add({"ip_cidr": exIpsList, "outbound": "direct"});
    if (exProcessesList.isNotEmpty) routingRules.add({"process_name": exProcessesList, "outbound": "direct"});

    final configMap = {
      "mode": "client",
      "version": "0.3.20",
      "log": {
        "level": debugMode ? "debug" : "info"
      },
      "inbounds": inbounds,
      "outbounds": outbounds,
      "routing": {
        "rules": routingRules,
        "default_outbound": "proxy"
      },
      "app_rules": {
        "mode": appRoutingMode,
        "packages": appRoutingPackages,
      },
      "dns_server": effectiveDnsServer,
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
      if (_activeProfiles.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Please select at least one profile in Settings')),
        );
        return;
      }
      
      setState(() {
        _state = ConnectionStateEnum.connecting;
      });
      _pulseController.repeat(reverse: true);
      _spinController.repeat();

      final dnsServer = widget.prefs.getString('dns_server');
      final effectiveDnsServer = (dnsServer == null || dnsServer.isEmpty) ? '1.1.1.1' : dnsServer;
      final exDomains = widget.prefs.getString('ex_domains') ?? '';
      final exIps = widget.prefs.getString('ex_ips') ?? '';
      final exProcesses = widget.prefs.getString('ex_processes') ?? '';
      final debugMode = widget.prefs.getBool('debug_mode') ?? false;
      final transportMode = widget.prefs.getString('transport_mode') ?? 'udp';
      final stealthSni = widget.prefs.getString('stealth_sni') ?? 'vk.com';
      final wss = widget.prefs.getBool('wss') ?? false;
      _updateLatestConfigJson();
      final configStr = widget.prefs.getString('latest_config_json') ?? '{}';

      try {
        await platform.invokeMethod('startTunnel', {
          "configJson": configStr
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

  Future<void> _runAutoMode() async {
    final mtus = [1500, 1350, 1280, 1140];
    final modes = [
      {'t': 'udp', 'w': false, 'r': false},
      {'t': 'uot', 'w': false, 'r': false},
      {'t': 'uot', 'w': true,  'r': false},
      {'t': 'uot', 'w': false, 'r': true},
    ];

    if (_activeProfiles.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please select at least one profile first')),
      );
      return;
    }

    for (var mode in modes) {
      for (var mtu in mtus) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Testing: ${mode['t']} | WSS: ${mode['w']} | XTLS: ${mode['r']} | MTU: $mtu'), duration: const Duration(seconds: 2)),
        );

        // Update prefs and active profile
        await widget.prefs.setString('mtu', mtu.toString());
        setState(() {
          for (var p in _activeProfiles) {
            p.transportMode = mode['t'] as String;
            p.wss = mode['w'] as bool;
          }
        });
        _updateLatestConfigJson();

        setState(() {
          _state = ConnectionStateEnum.connecting;
        });
        _pulseController.repeat(reverse: true);
        _spinController.repeat();

        try {
          final configJson = widget.prefs.getString('latest_config_json') ?? '{}';
          await platform.invokeMethod('startTunnel', {"configJson": configJson});

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
            // Wait to see if connection is stable and ping is successful
            await Future.delayed(const Duration(seconds: 3));
            try {
              final metricsJson = await platform.invokeMethod('getMetrics');
              if (metricsJson != null && metricsJson.isNotEmpty) {
                final Map<String, dynamic> parsed = jsonDecode(metricsJson);
                final rttMs = parsed['rtt_ms'] as int? ?? 0;
                if (rttMs > 0) {
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Success! Found working config: ${mode['t']} (MTU $mtu)')),
                    );
                  }
                  return; // Stop on first working config
                }
              }
            } catch (e) {
              // Ignore metrics error
            }

            // Connection seems unstable or no ping, stop and try next
            await platform.invokeMethod('stopTunnel');
            _setDisconnected();
          } else {
            _setDisconnected();
          }
        } catch (e) {
          _setDisconnected();
        }
      }
    }

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Auto search finished. No working config found.')),
      );
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
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (timer) async {
      if (!mounted) return;
      try {
        final isRunning = await platform.invokeMethod('isRunning');
        
        if (isRunning == true && _state == ConnectionStateEnum.disconnected) {
          _setConnected();
        } else if (isRunning == false && _state == ConnectionStateEnum.connected) {
          _setDisconnected();
        }

        if (_state == ConnectionStateEnum.connected) {
          final metricsJson = await platform.invokeMethod('getMetrics');
          if (metricsJson != null && metricsJson.isNotEmpty) {
            final Map<String, dynamic> parsed = jsonDecode(metricsJson);
            final bytesSent = parsed['bytes_sent'] as int? ?? 0;
            final bytesRecv = parsed['bytes_recv'] as int? ?? 0;
            final connState = parsed['connection_state'] as int? ?? 2;
            final rttMs = parsed['rtt_ms'] as int? ?? 0;
            
            if (connState == 0) {
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
        }
      } catch (e) {
        debugPrint("Failed to get state/metrics: $e");
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
    // Do NOT cancel _pollTimer, so we keep checking if VPN starts externally!
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
          Center(
            child: Opacity(
              opacity: theme.brightness == Brightness.dark ? 0.05 : 0.06,
              child: Platform.isIOS
                  ? ClipRRect(
                      borderRadius: BorderRadius.circular(32),
                      child: SvgPicture.asset(
                        'assets/logo.svg',
                        width: MediaQuery.of(context).size.width * 0.8,
                        fit: BoxFit.contain,
                        colorFilter: theme.brightness == Brightness.light 
                            ? const ColorFilter.mode(Colors.black, BlendMode.srcIn) 
                            : null,
                      ),
                    )
                  : ClipOval(
                      child: SvgPicture.asset(
                        'assets/logo.svg',
                        width: MediaQuery.of(context).size.width * 0.8,
                        fit: BoxFit.contain,
                        colorFilter: theme.brightness == Brightness.light 
                            ? const ColorFilter.mode(Colors.black, BlendMode.srcIn) 
                            : null,
                      ),
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
          Row(
            children: [
              IconButton(
                iconSize: 30,
                icon: const Icon(Icons.auto_mode_rounded, color: Colors.white),
                onPressed: () {
                  if (_state != ConnectionStateEnum.disconnected) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Disconnect first to run Auto mode')),
                    );
                    return;
                  }
                  _runAutoMode();
                },
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
                      _activeProfiles.isNotEmpty ? _activeProfiles.map((e)=>e.name).join(', ') : 'No profile selected',
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
                margin: const EdgeInsets.symmetric(horizontal: 16),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.03),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withOpacity(0.06)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Expanded(
                      child: Column(
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
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 15,
                              fontWeight: FontWeight.bold,
                              color: _pingColor,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
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
    return Expanded(
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
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
          Flexible(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label.toUpperCase(),
                  overflow: TextOverflow.ellipsis,
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
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
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


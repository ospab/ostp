import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../models/connection_state_enum.dart';
import '../models/ostp_profile.dart';
import '../models/share_link.dart';
import '../models/subscription.dart';
import '../services/updates.dart' as updates;
import 'prober_screen.dart';
import 'settings_screen.dart';

/// Success green for the "connected" state — the button aura/border/icon and
/// the top-bar status dot. The theme's `secondary` (#AAAAAA) reads as plain
/// white here, which gave no visual confirmation that the tunnel actually came
/// up. Reuses the same green already used for a healthy ping value, so
/// "green = good" stays consistent across the UI.
const Color kConnectedGreen = Color(0xFF22D3A5);

class HomeScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const HomeScreen({super.key, required this.prefs});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with TickerProviderStateMixin, WidgetsBindingObserver {
  static const platform = MethodChannel('com.ospab.ostp/vpn');

  ConnectionStateEnum _state = ConnectionStateEnum.disconnected;
  Timer? _pollTimer;
  Timer? _uptimeTimer;
  int _uptimeSecs = 0;

  // True while _toggleConnection waits for the service to start, so the poll
  // does not read "not running yet" as a failure.
  bool _starting = false;
  // The core reported connecting/connected at least once since the tunnel
  // started: a later "not connected" is then a real failure, not start-up.
  bool _coreActive = false;
  DateTime _startedAt = DateTime.now();
  // A stop is being carried out; taps and polls wait for it.
  bool _stopping = false;
  // One poll at a time: a slow platform call must not pile up behind the 1 s timer.
  bool _polling = false;
  // Bumped on every user start/stop. A poll that began before it holds a stale
  // picture of the service and drops it instead of overwriting the new state.
  int _epoch = 0;
  // The profile the running tunnel was started with; the active profile can be
  // changed in Settings meanwhile, which only takes effect on the next connect.
  String? _sessionProfileName;

  static const _callTimeout = Duration(seconds: 5);
  // The system VPN consent dialog waits for the user, so startTunnel gets longer.
  static const _consentTimeout = Duration(seconds: 120);

  Future<T?> _call<T>(String method, [dynamic args, Duration timeout = _callTimeout]) =>
      platform.invokeMethod<T>(method, args).timeout(timeout);

  // Single active profile — the core only ever connects to one server at a
  // time (no multi-server/urltest failover since the 0.4.x flat config),
  // matching how the desktop GUI picks exactly one profile as `activeId`.
  OstpProfile? _activeProfile;

  String _download = '0 B';
  String _upload = '0 B';

  // Live throughput (bytes/sec, computed from deltas between polls) and RTT
  // are optional, same as the desktop GUI's "Show Speed" / "Show RTT" toggles
  // in client settings — default on, persisted in prefs.
  bool _showSpeed = true;
  bool _showRtt = true;
  String _downSpeed = '0 B/s';
  String _upSpeed = '0 B/s';
  int _prevBytesRecv = 0;
  int _prevBytesSent = 0;

  late AnimationController _pulseController;
  late AnimationController _spinController;

  String _pingText = '-- ms';
  Color _pingColor = Colors.white54;

  // App version, shown at the bottom of the home screen. Read from the build
  // (pubspec) via package_info rather than hardcoded, so it never drifts.
  String _version = '';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _loadSettings();
    _loadVersion();
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
    _refreshSubscriptions();
    // Once per app start (initState does not run again when the app comes
    // back from the background).
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && (widget.prefs.getBool(updates.autoUpdateCheckKey) ?? true)) {
        updates.checkForUpdates(context, widget.prefs, manual: false);
      }
    });
  }

  /// Subscriptions whose update interval has passed are fetched in the
  /// background; failures are shown on the subscription card, not here.
  Future<void> _refreshSubscriptions() async {
    try {
      if (await SubscriptionStore(widget.prefs).refreshDue() && mounted) _loadSettings();
    } catch (_) {}
  }

  Future<void> _loadVersion() async {
    try {
      final info = await PackageInfo.fromPlatform();
      if (mounted) {
        final tag = await updates.buildTag();
        if (!mounted) return;
        setState(() => _version = '${tag ?? 'v${info.version}'} (${info.buildNumber})');
      }
    } catch (_) {
      // Non-fatal: just leave the version line blank if it can't be read.
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Back from the background (or from the system VPN/battery dialogs): the
    // 1 s timer may not have run for a while, so refresh the state right away.
    if (state == AppLifecycleState.resumed) _pollOnce();
  }

  Future<void> _checkInitialState() async {
    try {
      final isRunning = await _call<bool>('isRunning');
      if (isRunning == true && mounted) {
        // The service is up, but whether the handshake finished is for the
        // poll to say (connection_state), not for us to assume.
        _setConnecting(resumed: true);
      }
    } catch (e) {
      debugPrint("Failed to check initial state: $e");
    }
  }

  void _loadSettings() {
    setState(() {
      final profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
      // Single-select: if more than one is somehow marked active (shouldn't
      // happen — the editor enforces exclusivity — but don't crash on stale data).
      final actives = profiles.where((p) => p.active).toList();
      _activeProfile = actives.isNotEmpty ? actives.first : null;
      _showSpeed = widget.prefs.getBool('show_speed') ?? true;
      _showRtt = widget.prefs.getBool('show_rtt') ?? true;
    });
    _updateLatestConfigJson();
  }

  /// Builds the exact JSON the native core (ostp-jni) deserializes as
  /// `ostp_client::config::ClientConfig`. Field names/nesting must match that
  /// struct precisely — unknown keys are silently ignored by serde, so a typo
  /// here doesn't fail loudly, it just quietly does nothing.
  Map<String, dynamic> _buildConfigMap() {
    final p = _activeProfile;
    final exDomains = widget.prefs.getString('ex_domains') ?? '';
    final exIps = widget.prefs.getString('ex_ips') ?? '';
    final debugMode = widget.prefs.getBool('debug_mode') ?? false;
    final mtu = (int.tryParse(widget.prefs.getString('mtu') ?? '') ?? 1140).clamp(576, 1500);
    final muxEnabled = widget.prefs.getBool('mux_enabled') ?? false;
    final muxSessions = widget.prefs.getString('mux_sessions') ?? '2';
    final dnsServer = widget.prefs.getString('dns_server');
    // The VPN builder throws on anything but an IP literal, which would fail the start.
    final effectiveDnsServer =
        (dnsServer != null && InternetAddress.tryParse(dnsServer.trim()) != null) ? dnsServer.trim() : '1.1.1.1';
    const tunStack = 'ostp';
    final appRoutingMode = widget.prefs.getString('app_routing_mode') ?? 'bypass';
    final appRoutingPackages = widget.prefs.getStringList('app_routing_packages') ?? [];
    final localBind = _validBind(widget.prefs.getString('local_bind')) ?? '127.0.0.1:1088';

    return {
      "mode": "client",
      "debug": debugMode,
      "ostp": {
        "server_addr": p?.serverAddr ?? '',
        "local_bind_addr": "0.0.0.0:0",
        "access_key": p?.accessKey ?? '',
        "handshake_timeout_ms": 10000,
        "io_timeout_ms": 5000,
        "mtu": mtu,
      },
      "local_proxy": {
        "bind_addr": localBind,
        "connect_timeout_ms": 15000,
      },
      // Junk packets + TCP fragmentation are per-profile settings — same
      // shape as the desktop GUI's profile object — not global toggles.
      "transport": {
        "mode": p?.transportMode ?? 'udp',
        "tcp_fragmentation": p?.tcpFragmentation ?? false,
        // The core reads these as unsigned: a negative or absurd value would fail the whole config.
        "frag_chunk": (p?.fragChunk ?? 2).clamp(1, 1400),
        "frag_sleep": (p?.fragSleep ?? 2).clamp(0, 1000),
        "junk_pc": _range(p?.junkPcMin ?? 2, p?.junkPcMax ?? 5, 30),
        "junk_ps": _range(p?.junkPsMin ?? 100, p?.junkPsMax ?? 1000, 1400),
        "ttl_desync": p?.ttlDesync ?? false,
        "ttl_desync_auto": true,
        "tls": (p?.transportMode == 'uot') && (p?.tls ?? false),
        "tls_sni": (p?.tlsSni ?? '').isEmpty ? null : p!.tlsSni,
        "tls_insecure": p?.tlsInsecure ?? false,
        "ws_path": (p?.wsPath ?? '').isEmpty ? null : p!.wsPath,
      },
      "multiplex": {
        "enabled": muxEnabled,
        "sessions": (int.tryParse(muxSessions) ?? 2).clamp(1, 16),
      },
      "exclusions": {
        "domains": exDomains.split('\n').map((s) => s.trim()).where((s) => s.isNotEmpty).take(2000).toList(),
        "ips": exIps.split('\n').map((s) => s.trim()).where((s) => s.isNotEmpty).take(2000).toList(),
        // No per-process exclusion field on mobile — Android's per-app
        // selection (app_rules below) is the equivalent, and correct, control.
        "processes": const [],
      },
      "app_rules": {
        "mode": appRoutingMode,
        "packages": appRoutingPackages.take(2000).toList(),
      },
      "dns_server": effectiveDnsServer,
      "tun_stack": tunStack,
    };
  }

  // The native side refuses larger configs; huge exclusion lists are cut at the source.
  static const _maxConfigChars = 200000;

  static String? _validBind(String? v) {
    final s = v?.trim() ?? '';
    final c = s.lastIndexOf(':');
    if (c <= 0) return null;
    final port = int.tryParse(s.substring(c + 1));
    if (port == null || port < 1 || port > 65535) return null;
    final host = s.substring(0, c).replaceAll(RegExp(r'^\[|\]$'), '');
    return InternetAddress.tryParse(host) == null ? null : s;
  }

  static List<int> _range(int a, int b, int max) {
    final lo = a.clamp(0, max), hi = b.clamp(0, max);
    return lo <= hi ? [lo, hi] : [hi, lo];
  }

  void _updateLatestConfigJson() {
    final configMap = _buildConfigMap();
    widget.prefs.setString('latest_config_json', jsonEncode(configMap));
    final json = jsonEncode(configMap);
    if (json.length > _maxConfigChars) return;
    _call('saveConfig', {"configJson": json}).catchError((e) {
      debugPrint('saveConfig failed: $e');
      return null;
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _pollTimer?.cancel();
    _uptimeTimer?.cancel();
    _pulseController.dispose();
    _spinController.dispose();
    super.dispose();
  }

  void _snack(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(text)));
  }

  Future<void> _toggleConnection() async {
    // A start or stop in progress owns the tunnel until it finishes; a second tap would race it.
    if (_starting || _stopping) return;
    if (_state == ConnectionStateEnum.disconnected) {
      final profile = _activeProfile;
      if (profile == null || profile.serverAddr.isEmpty || profile.accessKey.isEmpty) {
        _snack('No profile selected. Add or choose one in Settings.');
        return;
      }
      try {
        ShareLink.parse('ostp://x@${profile.serverAddr}');
      } on FormatException {
        _snack('The server address of this profile is not valid. Use host:port.');
        return;
      }

      // Android treats an empty allow-list as "every app", the opposite of what this mode says.
      if (widget.prefs.getString('app_routing_mode') == 'proxy' &&
          (widget.prefs.getStringList('app_routing_packages') ?? const []).isEmpty) {
        _snack('App routing is set to proxy but no apps are selected. Choose apps or switch the mode.');
        return;
      }

      final configStr = jsonEncode(_buildConfigMap());
      if (configStr.length > _maxConfigChars) {
        _snack('The settings are too large to start. Shorten the exclusion lists.');
        return;
      }

      _starting = true;
      _epoch++;
      _sessionProfileName = profile.name;
      _setConnecting();
      widget.prefs.setString('latest_config_json', configStr);

      try {
        await _call('saveConfig', {"configJson": configStr});
        final granted = await _call<bool>('startTunnel', {"configJson": configStr}, _consentTimeout);
        if (granted != true) {
          _setDisconnected();
          _snack('The VPN permission was not granted, so the VPN did not start.');
          return;
        }

        bool started = false;
        for (int i = 0; i < 10 && mounted; i++) {
          await Future.delayed(const Duration(milliseconds: 500));
          final isRunning = await _call<bool>('isRunning');
          if (isRunning == true) {
            started = true;
            break;
          }
        }

        if (started) {
          // Stays "Connecting" until the core reports the handshake done.
          _startedAt = DateTime.now();
        } else {
          _setDisconnected();
          _snack('The VPN service did not start. See Logs for the reason.');
        }
      } on TimeoutException {
        _setDisconnected();
        _snack('The system did not answer in time. Try again.');
      } catch (e, stackTrace) {
        debugPrint("Failed to start tunnel: $e\n$stackTrace");
        _setDisconnected();
        if (mounted) {
          showDialog(
            context: context,
            builder: (ctx) => AlertDialog(
              title: const Text('Could not start the VPN', style: TextStyle(color: Colors.redAccent)),
              content: SingleChildScrollView(
                child: SelectableText(e.toString(), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: e.toString()));
                    ScaffoldMessenger.of(ctx).showSnackBar(const SnackBar(content: Text('Copied')));
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
      } finally {
        _starting = false;
      }
    } else {
      await _stopTunnel();
    }
  }

  Future<void> _stopTunnel() async {
    _stopping = true;
    _epoch++;
    try {
      await _call('stopTunnel');
    } catch (e) {
      debugPrint("Stop error: $e");
    } finally {
      _stopping = false;
    }
    _setDisconnected();
  }

  void _setConnecting({bool resumed = false}) {
    if (!mounted) return;
    setState(() {
      _state = ConnectionStateEnum.connecting;
    });
    _uptimeTimer?.cancel();
    // A service found already running has an unknown start time, so the
    // start-up grace period for a silent core does not apply to it.
    _coreActive = resumed;
    _startedAt = DateTime.now();
    _pulseController.repeat(reverse: true);
    _spinController.repeat();
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
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (_) => _pollOnce());
  }

  Future<void> _pollOnce() async {
    if (!mounted || _polling || _starting || _stopping) return;
    _polling = true;
    final epoch = _epoch;
    try {
      final isRunning = await _call<bool>('isRunning');
      if (!mounted || epoch != _epoch) return;

      if (isRunning == true && _state == ConnectionStateEnum.disconnected) {
        _setConnecting(resumed: true);
      } else if (isRunning == false && _state != ConnectionStateEnum.disconnected) {
        // Not a stop from this screen (that sets the state itself): the service
        // ended on its own, another VPN app took over, or the system stopped it.
        _setDisconnected();
        _snack('The VPN stopped. See Logs for the reason.');
        return;
      }

      if (_state == ConnectionStateEnum.disconnected) return;
      final metricsJson = await _call<String>('getMetrics');
      if (!mounted || epoch != _epoch || metricsJson == null || metricsJson.isEmpty) return;

      final parsed = jsonDecode(metricsJson) as Map<String, dynamic>;
      final bytesSent = (parsed['bytes_sent'] as num?)?.toInt() ?? 0;
      final bytesRecv = (parsed['bytes_recv'] as num?)?.toInt() ?? 0;
      // 0 = not connected, 1 = handshake or reconnect in progress, 2 = connected.
      final connState = (parsed['connection_state'] as num?)?.toInt() ?? 0;
      final rttMs = (parsed['rtt_ms'] as num?)?.toInt() ?? 0;

      if (connState != 0) _coreActive = true;

      // Zero right after start is normal; the core gets 20 s to report anything.
      final grace = DateTime.now().difference(_startedAt) < const Duration(seconds: 20);
      if (connState == 0 && (_coreActive || !grace)) {
        _stopping = true;
        _epoch++;
        try {
          await _call('stopTunnel');
        } catch (e) {
          debugPrint("Failed to stop background tunnel: $e");
        } finally {
          _stopping = false;
        }
        _setDisconnected();
        _snack('Could not connect to the server. See Logs for the reason.');
        return;
      }

      if (connState == 2 && _state != ConnectionStateEnum.connected) {
        _setConnected();
      } else if (connState == 1 && _state == ConnectionStateEnum.connected) {
        // The link dropped and the core is bringing it back: do not keep showing "Connected".
        _setConnecting(resumed: true);
      }

      setState(() {
        _download = formatBytes(bytesRecv);
        _upload = formatBytes(bytesSent);
        final dRecv = bytesRecv > _prevBytesRecv ? bytesRecv - _prevBytesRecv : 0;
        final dSent = bytesSent > _prevBytesSent ? bytesSent - _prevBytesSent : 0;
        _prevBytesRecv = bytesRecv;
        _prevBytesSent = bytesSent;
        _downSpeed = '${formatBytes(dRecv)}/s';
        _upSpeed = '${formatBytes(dSent)}/s';
        if (rttMs > 0) {
          _pingText = '$rttMs ms';
          if (rttMs < 100) {
            _pingColor = const Color(0xFF22D3A5);
          } else if (rttMs < 250) {
            _pingColor = Colors.amberAccent;
          } else {
            _pingColor = Colors.redAccent;
          }
        }
      });
    } catch (e) {
      debugPrint("Failed to get state/metrics: $e");
    } finally {
      _polling = false;
    }
  }

  void _setDisconnected() {
    if (!mounted) return;
    setState(() {
      _state = ConnectionStateEnum.disconnected;
      _download = '0 B';
      _upload = '0 B';
      _downSpeed = '0 B/s';
      _upSpeed = '0 B/s';
      _prevBytesRecv = 0;
      _prevBytesSent = 0;
      _pingText = '-- ms';
      _pingColor = Colors.white54;
      _sessionProfileName = null;
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
                          Padding(
                            padding: const EdgeInsets.only(top: 8, bottom: 10),
                            child: Text(
                              _version.isEmpty ? 'OSTP' : 'OSTP · $_version',
                              style: TextStyle(
                                fontSize: 11,
                                letterSpacing: 0.5,
                                color: Colors.white.withOpacity(0.28),
                              ),
                            ),
                          ),
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
                      ? kConnectedGreen
                      : theme.colorScheme.primary,
                  boxShadow: [
                    BoxShadow(
                      color: _state == ConnectionStateEnum.connected
                          ? kConnectedGreen.withOpacity(0.5)
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
                icon: const Icon(Icons.network_check_rounded, color: Colors.white),
                tooltip: 'Network Prober',
                onPressed: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(builder: (context) => ProberScreen(prefs: widget.prefs)),
                  );
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
      if (_state == ConnectionStateEnum.connected) return kConnectedGreen;
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
          _state == ConnectionStateEnum.connecting ? 'Connecting…' : 'Connected',
          style: TextStyle(
            fontSize: 26,
            fontWeight: FontWeight.w700,
            color: _state == ConnectionStateEnum.disconnected ? Colors.white70 : getAccentColor(),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          _state == ConnectionStateEnum.connected
              ? _formatTime(_uptimeSecs)
              : _state == ConnectionStateEnum.connecting ? 'Tap to cancel' : 'Tap to connect',
          style: const TextStyle(
            fontSize: 16,
            color: Colors.white54,
          ),
        ),

        const SizedBox(height: 30),

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
              Flexible(
                child: Text(
                (_state != ConnectionStateEnum.disconnected ? _sessionProfileName : null) ??
                    _activeProfile?.name ??
                    'No profile selected',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                  color: Colors.white70,
                ),
              ),
              ),
            ],
          ),
        ),

        if (_showRtt)
        AnimatedOpacity(
          opacity: _state == ConnectionStateEnum.connected ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 300),
          child: Padding(
            padding: const EdgeInsets.only(top: 10),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.03),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white.withOpacity(0.06)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.speed_rounded, size: 13, color: _pingColor),
                  const SizedBox(width: 6),
                  Text(
                    _pingText,
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: _pingColor,
                    ),
                  ),
                ],
              ),
            ),
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
          _buildMetricItem(Icons.arrow_downward_rounded, 'Download', _download, theme.colorScheme.secondary, _showSpeed ? _downSpeed : null),
          Container(width: 1, height: 40, color: Colors.white.withOpacity(0.15)),
          _buildMetricItem(Icons.arrow_upward_rounded, 'Upload', _upload, theme.colorScheme.primary, _showSpeed ? _upSpeed : null),
        ],
      ),
    );
  }

  Widget _buildMetricItem(IconData icon, String label, String value, Color color, [String? speed]) {
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
                if (speed != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    speed,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: color,
                    ),
                  ),
                ],
              ],
            ),
          )
        ],
      ),
    );
  }
}

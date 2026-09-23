import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/ostp_profile.dart';

/// Network diagnostics, in two parts:
///
///  - ostp-specific: which resolved address x transport combination for the
///    active profile actually completes a real, authenticated handshake
///    (using the profile's own access key — no separate/anonymous probe
///    endpoint), and — for a chosen combo — roughly where along the path a
///    middlebox (e.g. a Russian TSPU) starts answering in place of the real
///    server.
///  - generic: the same differential SNI/DNS/CONNECT DPI battery the
///    standalone ostp-prober desktop tool runs against fixed public hosts,
///    to tell whether the network filters in general.
class ProberScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const ProberScreen({super.key, required this.prefs});

  @override
  State<ProberScreen> createState() => _ProberScreenState();
}

class _ProberScreenState extends State<ProberScreen> {
  static const platform = MethodChannel('com.ospab.ostp/vpn');

  OstpProfile? _profile;
  bool _matrixRunning = false;
  String? _matrixError;
  List<dynamic> _matrixResults = [];

  Map<String, dynamic>? _selectedEntry;
  final TextEditingController _maxTtlCtrl = TextEditingController(text: '20');
  bool _ttlRunning = false;
  String? _ttlError;
  Map<String, dynamic>? _ttlReport;

  bool _dpiRunning = false;
  String? _dpiError;
  Map<String, dynamic>? _dpiReport;

  @override
  void initState() {
    super.initState();
    final profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
    _profile = profiles.where((p) => p.active).isNotEmpty ? profiles.firstWhere((p) => p.active) : null;
  }

  @override
  void dispose() {
    _maxTtlCtrl.dispose();
    super.dispose();
  }

  /// TLS profiles are probed the way they connect: UoT inside TLS.
  Map<String, dynamic>? _tlsRequest(OstpProfile p) {
    if (p.transportMode != 'uot' || !p.tls) return null;
    return {
      'sni': p.tlsSni,
      'insecure': p.tlsInsecure,
      'ws_path': p.wsPath.isEmpty ? null : p.wsPath,
    };
  }

  Future<void> _runMatrix() async {
    final profile = _profile;
    if (profile == null || profile.serverAddr.isEmpty || profile.accessKey.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Select a profile with a server and key first')),
      );
      return;
    }
    setState(() {
      _matrixRunning = true;
      _matrixError = null;
      _matrixResults = [];
      _selectedEntry = null;
      _ttlReport = null;
    });
    try {
      final requestJson = jsonEncode({
        'server_addr': profile.serverAddr,
        'access_key': profile.accessKey,
        if (_tlsRequest(profile) != null) 'tls': _tlsRequest(profile),
      });
      final String raw = await platform.invokeMethod('runProberMatrix', {'requestJson': requestJson});
      final decoded = jsonDecode(raw);
      if (decoded is Map && decoded.containsKey('error')) {
        setState(() => _matrixError = decoded['error'].toString());
      } else if (decoded is List) {
        setState(() => _matrixResults = decoded);
        // Persisted so the Logs screen can bundle it into a support export
        // without this screen needing to still be open.
        await widget.prefs.setString('last_prober_matrix', raw);
      }
    } catch (e) {
      setState(() => _matrixError = e.toString());
    } finally {
      if (mounted) setState(() => _matrixRunning = false);
    }
  }

  Future<void> _runTtlScan() async {
    final profile = _profile;
    final entry = _selectedEntry;
    if (profile == null || entry == null) return;
    final maxTtl = int.tryParse(_maxTtlCtrl.text.trim()) ?? 20;
    setState(() {
      _ttlRunning = true;
      _ttlError = null;
      _ttlReport = null;
    });
    try {
      final requestJson = jsonEncode({
        'address': entry['address'],
        'port': entry['port'],
        'transport': entry['transport'],
        'access_key': profile.accessKey,
        'max_ttl': maxTtl.clamp(1, 64),
        if (_tlsRequest(profile) != null) 'tls': _tlsRequest(profile),
      });
      final String raw = await platform.invokeMethod('runProberTtlScan', {'requestJson': requestJson});
      final decoded = jsonDecode(raw);
      if (decoded is Map && decoded.containsKey('error') && !decoded.containsKey('steps')) {
        setState(() => _ttlError = decoded['error'].toString());
      } else if (decoded is Map<String, dynamic>) {
        setState(() => _ttlReport = decoded);
        await widget.prefs.setString('last_prober_ttl', raw);
      }
    } catch (e) {
      setState(() => _ttlError = e.toString());
    } finally {
      if (mounted) setState(() => _ttlRunning = false);
    }
  }

  Future<void> _runDpiBattery() async {
    setState(() {
      _dpiRunning = true;
      _dpiError = null;
      _dpiReport = null;
    });
    try {
      final String raw = await platform.invokeMethod('runProberDpiBattery');
      final decoded = jsonDecode(raw);
      if (decoded is Map && decoded.containsKey('error') && !decoded.containsKey('dpi_score')) {
        setState(() => _dpiError = decoded['error'].toString());
      } else if (decoded is Map<String, dynamic>) {
        setState(() => _dpiReport = decoded);
        // Persisted so the Logs screen can bundle it into a support export
        // without this screen needing to still be open.
        await widget.prefs.setString('last_prober_dpi', raw);
      }
    } catch (e) {
      setState(() => _dpiError = e.toString());
    } finally {
      if (mounted) setState(() => _dpiRunning = false);
    }
  }

  Color _outcomeColor(bool success, bool hasForeign) {
    if (success) return Colors.greenAccent;
    if (hasForeign) return Colors.orangeAccent;
    return Colors.redAccent;
  }

  Widget _buildMatrixTable() {
    if (_matrixResults.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: _matrixResults.map<Widget>((raw) {
        final entry = raw as Map<String, dynamic>;
        final outcome = entry['outcome'] as Map<String, dynamic>;
        final success = outcome['success'] == true;
        final foreign = outcome['foreign_bytes'];
        final hasForeign = foreign != null;
        final selected = identical(_selectedEntry, entry) ||
            (_selectedEntry != null &&
                _selectedEntry!['address'] == entry['address'] &&
                _selectedEntry!['transport'] == entry['transport']);
        return Card(
          color: selected ? Colors.white.withOpacity(0.08) : Colors.white.withOpacity(0.03),
          margin: const EdgeInsets.symmetric(vertical: 4),
          child: ListTile(
            enabled: !success,
            onTap: success
                ? null
                : () => setState(() {
                      _selectedEntry = entry;
                      _ttlReport = null;
                      _ttlError = null;
                    }),
            leading: Icon(
              success ? Icons.check_circle : (hasForeign ? Icons.warning_amber_rounded : Icons.cancel),
              color: _outcomeColor(success, hasForeign),
            ),
            title: Text(
              '${entry['address']} (${entry['address_kind']}) · ${entry['transport']}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13, color: Colors.white),
            ),
            subtitle: Text(
              success
                  ? 'OK · ${(outcome['rtt_ms'] as num?)?.toStringAsFixed(0) ?? '?'} ms'
                  : (hasForeign
                      ? 'Foreign response — tap to locate the middlebox (TTL scan)'
                      : (outcome['error']?.toString() ?? 'failed')),
              style: TextStyle(fontSize: 12, color: _outcomeColor(success, hasForeign)),
            ),
            trailing: (!success) ? const Icon(Icons.chevron_right, color: Colors.white38) : null,
          ),
        );
      }).toList(),
    );
  }

  Widget _buildTtlSection() {
    final entry = _selectedEntry;
    if (entry == null) return const SizedBox.shrink();
    return Container(
      margin: const EdgeInsets.only(top: 20),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.02),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withOpacity(0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Locate the middlebox — ${entry['address']} · ${entry['transport']}',
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15, color: Colors.white),
          ),
          const SizedBox(height: 6),
          const Text(
            'Repeats the real handshake at increasing IP_TTL/hop-limit values. '
            'This is a heuristic, not an exact hop count — asymmetric routing, '
            'load-balanced paths and multiple stacked middleboxes can all make '
            'the picture noisier than a single clean number.',
            style: TextStyle(fontSize: 12, color: Colors.white54),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              SizedBox(
                width: 100,
                child: TextField(
                  controller: _maxTtlCtrl,
                  keyboardType: TextInputType.number,
                  style: const TextStyle(color: Colors.white),
                  decoration: const InputDecoration(labelText: 'Max TTL', isDense: true),
                ),
              ),
              const SizedBox(width: 16),
              ElevatedButton.icon(
                icon: _ttlRunning
                    ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.route),
                label: Text(_ttlRunning ? 'Scanning…' : 'Run TTL scan'),
                onPressed: _ttlRunning ? null : _runTtlScan,
              ),
            ],
          ),
          if (_ttlError != null) ...[
            const SizedBox(height: 12),
            Text(_ttlError!, style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
          ],
          if (_ttlReport != null) ...[
            const SizedBox(height: 16),
            _buildTtlSummary(_ttlReport!),
            const SizedBox(height: 8),
            ..._buildTtlSteps(_ttlReport!),
          ],
        ],
      ),
    );
  }

  Widget _buildTtlSummary(Map<String, dynamic> report) {
    final firstForeign = report['first_foreign_ttl'];
    final firstGenuine = report['first_genuine_ttl'];
    String text;
    Color color;
    if (firstForeign != null && firstGenuine != null && (firstForeign as num) < (firstGenuine as num)) {
      text = 'Foreign responses start at TTL $firstForeign, genuine ones at TTL $firstGenuine — '
          'the middlebox is likely around hop $firstForeign.';
      color = Colors.orangeAccent;
    } else if (firstForeign != null && firstGenuine == null) {
      text = 'Only foreign responses seen (from TTL $firstForeign) — the real server was not '
          'reached within the scanned TTL range.';
      color = Colors.orangeAccent;
    } else if (firstGenuine != null && firstForeign == null) {
      text = 'No foreign responses at any scanned TTL — the real server answered directly '
          'at TTL $firstGenuine. No interception detected on this path.';
      color = Colors.greenAccent;
    } else {
      text = 'No response at any scanned TTL. Try a higher Max TTL.';
      color = Colors.white54;
    }
    return Text(text, style: TextStyle(color: color, fontSize: 13, fontWeight: FontWeight.w600));
  }

  List<Widget> _buildTtlSteps(Map<String, dynamic> report) {
    final steps = (report['steps'] as List<dynamic>? ?? []);
    return steps.map((raw) {
      final step = raw as Map<String, dynamic>;
      final outcome = step['outcome'] as String;
      final color = outcome == 'genuine'
          ? Colors.greenAccent
          : (outcome == 'foreign' ? Colors.orangeAccent : Colors.white38);
      final preview = step['preview'] as String?;
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'TTL ${step['ttl']}: $outcome'
              '${step['rtt_ms'] != null ? ' (${(step['rtt_ms'] as num).toStringAsFixed(0)} ms)' : ''}',
              style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: color),
            ),
            if (preview != null)
              Padding(
                padding: const EdgeInsets.only(left: 12, top: 2),
                child: Text(
                  preview,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white38),
                ),
              ),
          ],
        ),
      );
    }).toList();
  }

  Widget _dpiFindingRow(String label, bool triggered, String verdict, String method) {
    final color = triggered ? Colors.orangeAccent : Colors.greenAccent;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(triggered ? Icons.warning_amber_rounded : Icons.check_circle, color: color, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('$label — $verdict', style: TextStyle(color: color, fontSize: 13, fontWeight: FontWeight.w600)),
                Text(method, style: const TextStyle(color: Colors.white38, fontSize: 11)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDpiSection() {
    return Container(
      margin: const EdgeInsets.only(top: 20),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.02),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withOpacity(0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'DPI / TSPU fingerprint',
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15, color: Colors.white),
          ),
          const SizedBox(height: 6),
          const Text(
            'Differential tests against fixed public hosts (not your server) — the same '
            'checks the standalone ostp-prober desktop tool runs: SNI/HTTP-Host filtering, '
            'DNS hijack/injection, CONNECT hijacking, RST injection, UDP throttling. Tells '
            'you whether the network filters in general, independent of whether your own '
            'server works. Takes about 10 seconds; safe to run while connected.',
            style: TextStyle(fontSize: 12, color: Colors.white54),
          ),
          const SizedBox(height: 12),
          ElevatedButton.icon(
            icon: _dpiRunning
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.radar),
            label: Text(_dpiRunning ? 'Probing…' : 'Run DPI/TSPU check'),
            onPressed: _dpiRunning ? null : _runDpiBattery,
          ),
          if (_dpiError != null) ...[
            const SizedBox(height: 12),
            Text(_dpiError!, style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
          ],
          if (_dpiReport != null) ...[
            const SizedBox(height: 16),
            Builder(builder: (context) {
              final report = _dpiReport!;
              final score = ((report['dpi_score'] as num?) ?? 0).toDouble();
              final pct = (score * 100).round();
              final color = pct >= 60 ? Colors.redAccent : (pct >= 25 ? Colors.orangeAccent : Colors.greenAccent);
              return Text(
                'Filtering score: $pct% ${pct >= 60 ? '(heavy)' : (pct >= 25 ? '(moderate)' : '(clean)')}',
                style: TextStyle(color: color, fontSize: 14, fontWeight: FontWeight.bold),
              );
            }),
            const SizedBox(height: 12),
            _dpiFindingRow('SNI filter', _dpiReport!['sni_blocked'] == true,
                _dpiReport!['sni_blocked'] == true ? 'blocks by domain name' : 'clean',
                'differential TLS to clean RU hosts: blocked SNI gets RST/drop faster than RTT'),
            _dpiFindingRow('HTTP Host filter', _dpiReport!['http_host_blocked'] == true,
                _dpiReport!['http_host_blocked'] == true ? 'blocks by Host header' : 'clean',
                'differential HTTP GET to vk.com / ya.ru: blocked Host gets cut off'),
            _dpiFindingRow(
                'DNS hijack',
                _dpiReport!['dns_hijacked'] == true,
                _dpiReport!['dns_hijacked'] == true
                    ? 'intercepted, answered by ${_dpiReport!['dns_hijacker_ip'] ?? '?'}'
                    : 'clean',
                'query to 8.8.8.8:53 — checking who actually answered'),
            _dpiFindingRow(
                'DNS injection',
                _dpiReport!['dns_injected'] == true,
                (_dpiReport!['dns_injected'] == true ? _dpiReport!['dns_injection_msg']?.toString() : null) ?? 'clean',
                'blocked-domain query to a non-DNS host: any answer is a forged one'),
            _dpiFindingRow('CONNECT hijack', _dpiReport!['connect_hijacked'] == true,
                _dpiReport!['connect_hijacked'] == true ? 'block page injected' : 'clean',
                'CONNECT to a blocked domain — looking for an injected 403/451'),
            _dpiFindingRow('Transparent proxy', _dpiReport!['transparent_proxy_detected'] == true,
                _dpiReport!['transparent_proxy_detected'] == true ? 'detected' : 'clean',
                'CONNECT to a clean host intercepted by a proxy'),
            _dpiFindingRow('RST injection', _dpiReport!['rst_injection_detected'] == true,
                _dpiReport!['rst_injection_detected'] == true ? 'middlebox on path' : 'not seen',
                'RST on a closed port arrived faster than RTT — timing heuristic'),
            _dpiFindingRow('Whitelist DPI', _dpiReport!['random_payload_blocked'] == true,
                _dpiReport!['random_payload_blocked'] == true ? 'cuts unknown protocols on :443' : 'not seen',
                'random bytes on :443 get an instant RST — heuristic'),
            _dpiFindingRow('UDP throttling', _dpiReport!['udp_throttled'] == true,
                _dpiReport!['udp_throttled'] == true ? 'abnormal latency spread' : 'not seen',
                'UDP/53 RTT variance — heuristic, can false-positive'),
            if (_dpiReport!['sni_blocked'] == true)
              _dpiFindingRow('Split-TLS bypass', _dpiReport!['vulnerable_to_fragmentation'] != true,
                  _dpiReport!['vulnerable_to_fragmentation'] == true ? 'works — DPI does not reassemble' : 'did not help',
                  'splitting ClientHello at byte 5 to slip past the DPI box'),
            const SizedBox(height: 8),
            const Text('DNS servers', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white)),
            ...((_dpiReport!['dns_servers'] as List<dynamic>? ?? []).map((raw) {
              final s = raw as Map<String, dynamic>;
              final reachable = s['reachable'] == true;
              final intercepted = s['intercepted'] == true;
              final color = !reachable ? Colors.redAccent : (intercepted ? Colors.orangeAccent : Colors.greenAccent);
              final text = !reachable
                  ? 'unreachable'
                  : (intercepted ? 'intercepted, answered by ${s['actual_responder']}' : '${s['rtt_ms']} ms');
              return Padding(
                padding: const EdgeInsets.symmetric(vertical: 2),
                child: Text('${s['server']}  —  $text',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: color)),
              );
            })),
          ],
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Network Prober', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 0,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              _profile == null
                  ? 'No active profile selected.'
                  : 'Testing ${_profile!.serverAddr} with a real, authenticated handshake — '
                    'the server only answers requests carrying your access key.',
              style: const TextStyle(fontSize: 13, color: Colors.white54),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              icon: _matrixRunning
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.network_check),
              label: Text(_matrixRunning ? 'Testing…' : 'Run diagnostics'),
              onPressed: (_matrixRunning || _profile == null) ? null : _runMatrix,
            ),
            if (_matrixError != null) ...[
              const SizedBox(height: 12),
              Text(_matrixError!, style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
            ],
            const SizedBox(height: 16),
            _buildMatrixTable(),
            _buildTtlSection(),
            _buildDpiSection(),
          ],
        ),
      ),
    );
  }
}

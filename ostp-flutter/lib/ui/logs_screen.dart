import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

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
            title: const Text('Could not read the logs', style: TextStyle(color: Colors.redAccent)),
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
    }
  }

  Future<void> _clearLogs() async {
    await platform.invokeMethod('clearLogs');
    setState(() {
      _logs.clear();
    });
  }

  /// Copies the log lines plus, when present, the last prober run's results
  /// (`prober_screen.dart` persists these after each run) — one bundle a
  /// user can paste into a support request without having to separately
  /// screenshot the Prober screen.
  Future<void> _copyLogs() async {
    final buffer = StringBuffer(_logs.join('\n'));

    final prefs = await SharedPreferences.getInstance();
    final matrix = prefs.getString('last_prober_matrix');
    final ttl = prefs.getString('last_prober_ttl');
    final dpi = prefs.getString('last_prober_dpi');
    if (matrix != null || ttl != null || dpi != null) {
      buffer.writeln();
      buffer.writeln('--- Network Prober results ---');
      if (matrix != null) {
        buffer.writeln('Address x transport matrix:');
        buffer.writeln(matrix);
      }
      if (ttl != null) {
        buffer.writeln('TTL / middlebox scan:');
        buffer.writeln(ttl);
      }
      if (dpi != null) {
        buffer.writeln('DPI / TSPU fingerprint:');
        buffer.writeln(dpi);
      }
    }

    await Clipboard.setData(ClipboardData(text: buffer.toString()));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(matrix != null || ttl != null
            ? 'Logs + prober results copied to clipboard'
            : 'Logs copied to clipboard'),
      ));
    }
  }

  /// A line this app itself flagged as not looking like it came from the
  /// ostp server (see `describe_foreign_bytes` on the Rust side) — surfaced
  /// distinctly so it isn't lost among routine connection-status lines.
  bool _isDpiLine(String line) => line.contains('[debug]') && line.toLowerCase().contains('dpi');

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Logs', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 0,
        actions: [
          IconButton(icon: const Icon(Icons.delete_outline), onPressed: _clearLogs, tooltip: 'Clear'),
          IconButton(icon: const Icon(Icons.copy_rounded), onPressed: _copyLogs, tooltip: 'Copy all'),
        ],
      ),
      body: Container(
        color: Colors.black,
        padding: const EdgeInsets.all(12),
        child: ListView.builder(
          controller: _scrollCtrl,
          itemCount: _logs.length,
          itemBuilder: (context, index) {
            final line = _logs[index];
            final isDpi = _isDpiLine(line);
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 2.0),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (isDpi) const Padding(
                    padding: EdgeInsets.only(right: 6, top: 1),
                    child: Icon(Icons.warning_amber_rounded, size: 14, color: Colors.orangeAccent),
                  ),
                  Expanded(
                    child: Text(
                      line,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                        color: isDpi ? Colors.orangeAccent : Colors.greenAccent,
                        fontWeight: isDpi ? FontWeight.w600 : FontWeight.normal,
                      ),
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}


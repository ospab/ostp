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


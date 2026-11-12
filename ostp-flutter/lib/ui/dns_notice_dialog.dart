import 'dart:async';

import 'package:flutter/material.dart';

/// The notice shown once before the first connection to a server that
/// filters DNS. It has no way out except a choice (the back button does
/// nothing) and its buttons stay disabled for the first seconds, so the text
/// is not skipped by accident. Returns 'operator', 'public' or 'mine'.
Future<String> askDnsNotice(BuildContext context, {required bool dnsAll}) async {
  final choice = await showDialog<String>(
    context: context,
    barrierDismissible: false,
    builder: (_) => _DnsNoticeDialog(dnsAll: dnsAll),
  );
  return choice ?? 'mine';
}

class _DnsNoticeDialog extends StatefulWidget {
  final bool dnsAll;
  const _DnsNoticeDialog({required this.dnsAll});

  static const seconds = 5;

  @override
  State<_DnsNoticeDialog> createState() => _DnsNoticeDialogState();
}

class _DnsNoticeDialogState extends State<_DnsNoticeDialog> {
  int _left = _DnsNoticeDialog.seconds;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (t) {
      setState(() => _left -= 1);
      if (_left <= 0) t.cancel();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Widget _button(String value, String label) {
    return SizedBox(
      width: double.infinity,
      child: OutlinedButton(
        onPressed: _left > 0 ? null : () => Navigator.pop(context, value),
        child: Text(_left > 0 ? '$label ($_left)' : label),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      child: AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        title: const Text('This server filters DNS'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                "The operator's resolver filters domain names by block lists and sees the names you look up.",
                style: TextStyle(fontSize: 14, color: Colors.white70),
              ),
              if (widget.dnsAll) ...[
                const SizedBox(height: 10),
                const Text(
                  'This server also answers DNS queries sent to any resolver and blocks encrypted DNS (DoT, DoH). '
                  'Choosing a public DNS does not change that on this server.',
                  style: TextStyle(fontSize: 14, color: Colors.white70),
                ),
              ],
              const SizedBox(height: 16),
              _button('operator', "Use the operator's DNS"),
              const SizedBox(height: 8),
              _button('public', 'Use a public DNS'),
              const SizedBox(height: 8),
              _button('mine', 'Keep my settings'),
            ],
          ),
        ),
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/server_info.dart';
import '../models/subscription.dart';
import 'markdown_view.dart';

/// The subscription whose profile the running tunnel was started with; set by
/// the home screen, null while disconnected. Server information read from the
/// core belongs to this subscription.
String? sessionSubscriptionId;

/// Reads what the core has for the running tunnel and keeps it with its
/// subscription. [ask] first asks the server for a fresh copy. Returns the
/// information, or null when nothing came.
Future<ServerInfo?> pullServerInfo(SharedPreferences prefs, {bool ask = false}) async {
  final subId = sessionSubscriptionId;
  if (subId == null) return null;
  if (ask) await ServerInfoCore.request();
  final info = await ServerInfoCore.read();
  if (info != null && sessionSubscriptionId == subId) await SubscriptionStore(prefs).setServerInfo(subId, info);
  return info;
}

/// The "i" window of a subscription: the operator's words, what the server
/// reports and the key, from the last copy the app kept.
Future<void> showServerInfo(BuildContext context, SharedPreferences prefs, String subId) {
  return showDialog(context: context, builder: (_) => _ServerInfoDialog(prefs: prefs, subId: subId));
}

class _ServerInfoDialog extends StatefulWidget {
  final SharedPreferences prefs;
  final String subId;
  const _ServerInfoDialog({required this.prefs, required this.subId});

  @override
  State<_ServerInfoDialog> createState() => _ServerInfoDialogState();
}

class _ServerInfoDialogState extends State<_ServerInfoDialog> {
  OstpSubscription? _sub;
  String? _status;
  // The core answered that the server sends no information (an older server).
  bool _unsupported = false;

  @override
  void initState() {
    super.initState();
    _load();
    if (sessionSubscriptionId == widget.subId) {
      _status = 'Asking the server for fresh information…';
      _askFresh();
    }
  }

  void _load() => _sub = SubscriptionStore(widget.prefs).load().where((s) => s.id == widget.subId).firstOrNull;

  /// The answer comes over the tunnel; the core may need a moment.
  Future<void> _askFresh() async {
    ServerInfo? fresh;
    final sent = await ServerInfoCore.request();
    for (var i = 0; i < 6 && fresh == null; i++) {
      fresh = await pullServerInfo(widget.prefs);
      if (!mounted) return;
      if (fresh == null) await Future<void>.delayed(const Duration(seconds: 1));
    }
    if (!mounted) return;
    setState(() {
      _load();
      _unsupported = fresh == null && !sent;
      _status = fresh == null && sent ? 'The server did not answer; this is the last copy.' : null;
    });
  }

  Future<void> _openLink(String url) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Open this link?'),
        content: SelectableText(url, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Open link')),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('No app on this device opens this link.')));
      }
    }
  }

  static Widget _section(String text) => Padding(
        padding: const EdgeInsets.fromLTRB(0, 16, 0, 6),
        child: Text(text.toUpperCase(),
            style: const TextStyle(color: Colors.white38, fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 1.4)),
      );

  static Widget _note(String text, {Color color = Colors.white38}) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(text, style: TextStyle(color: color, fontSize: 12, height: 1.4)),
      );

  /// An operator field: what they wrote, or a muted note that they gave nothing.
  static Widget _opRow(String label, String? value) {
    if (value != null && value.isNotEmpty) return _row(label, value);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(width: 104, child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13))),
        const Expanded(child: Text('Not given by the operator', style: TextStyle(fontSize: 13, color: Colors.white38))),
      ]),
    );
  }

  static Widget _row(String label, String? value, {Color? color, bool mono = false}) {
    if (value == null || value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(width: 104, child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13))),
        Expanded(
          child: SelectableText(value,
              style: TextStyle(fontSize: mono ? 12 : 13, color: color, fontFamily: mono ? 'monospace' : null)),
        ),
      ]),
    );
  }

  static String? _yesNo(bool? v) => v == null ? null : (v ? 'yes' : 'no');

  @override
  Widget build(BuildContext context) {
    final s = _sub;
    final info = s?.serverInfo;
    final op = info?.operator, srv = info?.server, key = info?.key;
    final used = key != null ? key.usedBytes : s?.usedBytes;
    final limit = key != null ? key.limitBytes : s?.limitBytes;
    final exp = s?.expiry;
    final children = <Widget>[
      if (_status != null) _note(_status!, color: Colors.white54),
      if (s == null) _note('This subscription is no longer in the app.'),
      if (s != null) ...[
        _section('Operator'),
        _note('Written by the operator of this server, in their own words. The app does not check it.'),
        _opRow('Name', op?.name),
        _opRow('Location', op?.location),
        _opRow('Contact', op?.contact),
        if (op?.about != null) ...[
          const SizedBox(height: 8),
          MarkdownView(text: op!.about!, onLink: _openLink),
        ] else
          _opRow('About', null),
      ],
      if (srv != null) ...[
        _section('Reported by the server'),
        _row('Version', srv.version, mono: true),
        _row('Carriers', srv.carriers.isEmpty ? null : srv.carriers.map((c) => c.toUpperCase()).join(', ')),
        _row('Log privacy', srv.logPrivacy, color: srv.logPrivacy == 'debug' ? Colors.amberAccent : null),
        if (srv.logPrivacy != null)
          _note(logPrivacyText[srv.logPrivacy]!, color: srv.logPrivacy == 'debug' ? Colors.amberAccent : Colors.white38),
        _row('IPv6', _yesNo(srv.ipv6)),
        _row('DNS filtering', _yesNo(srv.dnsFiltering)),
      ],
      if (s != null && (used != null || limit != null || exp != null || key != null)) ...[
        _section('Your key'),
        _row('Traffic', used == null ? null : limit != null && limit > 0 ? '${formatBytes(used)} of ${formatBytes(limit)}' : '${formatBytes(used)}, no limit'),
        if (exp != null)
          _row('Valid', exp.expired ? (exp.date != null ? 'expired on ${exp.date}' : 'expired') : exp.label,
              color: exp.expired ? Colors.redAccent : exp.daysLeft < 7 ? Colors.amberAccent : null)
        else if (key != null)
          _row('Valid', 'no end date'),
        if (key != null) _row('Devices', key.maxDevices != null ? 'up to ${key.maxDevices}' : 'no limit'),
      ],
      if (s != null && info == null)
        Padding(
          padding: const EdgeInsets.only(top: 14),
          child: _note(
              _unsupported && sessionSubscriptionId == widget.subId
                  ? 'This server does not send information about itself. It needs OSTP 0.5.0-beta.1 or newer.'
                  : "Connect once to see the server's information.",
              color: Colors.white54),
        )
      else if (s != null && s.infoAt > 0)
        Padding(
          padding: const EdgeInsets.only(top: 14),
          child: _note('As of ${DateTime.fromMillisecondsSinceEpoch(s.infoAt).toString().substring(0, 16)}.'),
        ),
    ];
    return AlertDialog(
      backgroundColor: Theme.of(context).colorScheme.surface,
      title: Text(s == null ? 'Server' : (s.name.isEmpty ? s.url : s.name), maxLines: 2, overflow: TextOverflow.ellipsis),
      content: SizedBox(
        width: 440,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: children),
        ),
      ),
      actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))],
    );
  }
}

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/ostp_profile.dart';
import '../models/share_link.dart';
import '../models/subscription.dart';
import 'device_id_dialog.dart';
import 'home_screen.dart';
import 'qr_scanner_screen.dart';
import 'ssh_setup.dart';

const welcomedKey = 'welcomed';

/// Whether to open on the welcome screen: never set up, nothing to connect to.
bool needsWelcome(SharedPreferences prefs) =>
    prefs.getBool(welcomedKey) != true &&
    decodeProfiles(prefs.getString('profiles_json')).isEmpty &&
    SubscriptionStore(prefs).load().isEmpty;

/// First run: first a choice (a link, a QR code, your own server, or the
/// project's repository), then a page for just that choice.
class WelcomeScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const WelcomeScreen({super.key, required this.prefs});

  @override
  State<WelcomeScreen> createState() => _WelcomeScreenState();
}

const repoUrl = 'https://github.com/ospab/ostp';

enum _Step { choose, link, server }

class _WelcomeScreenState extends State<WelcomeScreen> {
  final _link = TextEditingController();
  bool _busy = false;
  _Step _step = _Step.choose;

  @override
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  Future<void> _finish() async {
    await widget.prefs.setBool(welcomedKey, true);
    if (!mounted) return;
    Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => HomeScreen(prefs: widget.prefs)));
  }

  Future<void> _addLink([String? scanned]) async {
    final raw = (scanned ?? _link.text).trim();
    if (raw.isEmpty) return;
    final messenger = ScaffoldMessenger.of(context);
    setState(() => _busy = true);
    try {
      if (isSubscriptionUrl(raw)) {
        final n = await SubscriptionStore(widget.prefs).add(raw, askSend: () => askSendDeviceId(context));
        messenger.showSnackBar(SnackBar(content: Text('Subscription added: $n profile(s)')));
      } else {
        final l = ShareLink.parse(raw);
        final profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
        profiles.add(OstpProfile(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: l.name ?? l.host,
          serverAddr: l.server,
          accessKey: l.key,
          transportMode: l.transport,
          active: !profiles.any((p) => p.active),
          tls: l.tls,
          tlsSni: l.sni ?? '',
          tlsInsecure: l.insecure,
          wsPath: l.path ?? '',
          owndns: l.owndns,
          dnsall: l.dnsall,
        ));
        await widget.prefs.setString('profiles_json', encodeProfiles(profiles));
      }
      await _finish();
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(e.toString().replaceFirst('Exception: ', '').replaceFirst('FormatException: ', ''))));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _scanQr() async {
    final v = await Navigator.push<String>(context, MaterialPageRoute(builder: (_) => const QRScannerScreen()));
    if (v != null && v.isNotEmpty) {
      _link.text = v;
      await _addLink(v);
    }
  }

  Future<void> _openRepo() async {
    if (!await launchUrl(Uri.parse(repoUrl), mode: LaunchMode.externalApplication) && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('No browser to open $repoUrl')));
    }
  }

  Widget _choice(IconData icon, String title, String hint, VoidCallback onTap) => Card(
        margin: const EdgeInsets.only(bottom: 12),
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Icon(icon, size: 22),
              const SizedBox(width: 14),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 2),
                  Text(hint, style: const TextStyle(color: Colors.white54, fontSize: 12)),
                ]),
              ),
              const Icon(Icons.chevron_right, color: Colors.white54),
            ]),
          ),
        ),
      );

  List<Widget> _chooseStep() => [
        const Text("Let's get started", style: TextStyle(fontSize: 26, fontWeight: FontWeight.w800)),
        const SizedBox(height: 8),
        const Text('How will you connect?', style: TextStyle(color: Colors.white54, height: 1.4)),
        const SizedBox(height: 20),
        _choice(Icons.link, 'I have a link', 'Someone gave me an ostp:// link or a subscription URL',
            () => setState(() => _step = _Step.link)),
        _choice(Icons.qr_code_scanner, 'I have a QR code', 'Scan the code of a link or a subscription', _scanQr),
        _choice(Icons.dns_outlined, 'I have a server', 'A VPS and its SSH login; OSTP is set up for me',
            () => setState(() => _step = _Step.server)),
        _choice(Icons.code, 'The project on GitHub', 'Source code, documentation, releases', _openRepo),
      ];

  List<Widget> _linkStep() => [
        const Text('Add a link', style: TextStyle(fontSize: 26, fontWeight: FontWeight.w800)),
        const SizedBox(height: 8),
        const Text('Paste the ostp:// link or the subscription URL (https://…/sub/…) you were given.',
            style: TextStyle(color: Colors.white54, height: 1.4)),
        const SizedBox(height: 20),
        TextField(
          controller: _link,
          maxLines: 4,
          minLines: 2,
          autocorrect: false,
          autofocus: true,
          style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
          decoration: InputDecoration(
            hintText: 'ostp://… or https://…/sub/…',
            hintStyle: const TextStyle(color: Colors.white24),
            filled: true,
            fillColor: Theme.of(context).colorScheme.surface,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
          ),
        ),
        const SizedBox(height: 12),
        Row(children: [
          OutlinedButton.icon(
            icon: const Icon(Icons.content_paste, size: 18),
            label: const Text('Paste'),
            onPressed: () async {
              final d = await Clipboard.getData(Clipboard.kTextPlain);
              if (d?.text != null) _link.text = d!.text!.trim();
            },
          ),
          const Spacer(),
          FilledButton(onPressed: _busy ? null : () => _addLink(), child: const Text('Add')),
        ]),
      ];

  List<Widget> _serverStep() => [
        const Text('Your server', style: TextStyle(fontSize: 26, fontWeight: FontWeight.w800)),
        const SizedBox(height: 8),
        const Text('The app signs in over SSH and installs OSTP; no Linux knowledge needed. '
            'If OSTP is already there, you choose whether to update it.',
            style: TextStyle(color: Colors.white54, height: 1.4)),
        const SizedBox(height: 20),
        SshSetupForm(prefs: widget.prefs, onInstalled: (_) => _finish()),
      ];

  @override
  Widget build(BuildContext context) {
    final onChoose = _step == _Step.choose;
    return PopScope(
      // Back from a step returns to the choice, not out of the app.
      canPop: onChoose,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) setState(() => _step = _Step.choose);
      },
      child: Scaffold(
        appBar: AppBar(
          leading: onChoose ? null : IconButton(icon: const Icon(Icons.arrow_back), onPressed: () => setState(() => _step = _Step.choose)),
          automaticallyImplyLeading: false,
          title: const Text('OSTP', style: TextStyle(fontWeight: FontWeight.w800, letterSpacing: 2.5)),
          actions: [TextButton(onPressed: _finish, child: const Text('Skip'))],
        ),
        body: SafeArea(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(20, 8, 20, 24),
            children: switch (_step) {
              _Step.choose => _chooseStep(),
              _Step.link => _linkStep(),
              _Step.server => _serverStep(),
            },
          ),
        ),
      ),
    );
  }
}

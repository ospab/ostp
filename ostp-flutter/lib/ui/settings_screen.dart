import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'device_id_dialog.dart';
import 'more_settings_screen.dart';
import 'qr_scanner_screen.dart';
import 'server_info_sheet.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../models/dns_notice.dart';
import '../models/ostp_profile.dart';
import '../models/share_link.dart';
import '../models/subscription.dart';

/// Picks readable black/white text for a given (opaque) background color.
/// The monochrome theme's `primary` is pure white — hardcoded white text on
/// top of it was invisible; this picks the contrasting color instead.
Color _onColor(Color bg) {
  return ThemeData.estimateBrightnessForColor(bg) == Brightness.light ? Colors.black : Colors.white;
}

/// Shown for a profile without the server's key (protocol v5).
const unverifiedServerText =
    'The server is not verified (protocol v5): anyone who has this key can pose as this server. Ask the operator for a new link.';

class SettingsScreen extends StatefulWidget {
  final SharedPreferences prefs;
  const SettingsScreen({super.key, required this.prefs});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _localBindCtrl;
  late TextEditingController _dnsCtrl;
  late TextEditingController _mtuCtrl;


  List<OstpProfile> _profiles = [];
  List<OstpSubscription> _subs = [];
  final Set<String> _refreshing = {};
  bool _importing = false;

  static const _maxProfiles = 100;
  static const _maxSubscriptions = 20;
  static const _vpn = MethodChannel('com.ospab.ostp/vpn');
  // Digits only, five at most: ports, sizes, delays.

  /// Profile changes do not touch a running tunnel; say so instead of letting the user wonder.
  Future<void> _noteIfRunning() async {
    try {
      final running = await _vpn.invokeMethod<bool>('isRunning').timeout(const Duration(seconds: 3));
      if (running == true && mounted) {
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(const SnackBar(content: Text('The VPN is running. The change applies after Reconnect on the main screen.')));
      }
    } catch (_) {}
  }

  /// Why a profile for this server cannot be added, or null when it can.
  String? _addProblem(String server, String key, String carrier, {String? exceptId}) {
    if (_profiles.length >= _maxProfiles) return 'Too many profiles. Remove some first.';
    final dup = _profiles.any((p) =>
        p.id != exceptId &&
        p.accessKey == key &&
        p.serverAddr == server &&
        (p.tls ? 'tls' : p.transportMode) == carrier);
    return dup ? 'This server is already in the list.' : null;
  }

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  void _loadSettings() {
    _localBindCtrl = TextEditingController(text: widget.prefs.getString('local_bind') ?? '127.0.0.1:1088');
    _dnsCtrl = TextEditingController(text: widget.prefs.getString('dns_server') ?? '1.1.1.1');
    // Empty is Auto: the session finds the packet size. A number fixes it.
    _mtuCtrl = TextEditingController(text: widget.prefs.getString('mtu') ?? '');
    // Exclusions, app options, logs, server management and updates live on
    // MoreSettingsScreen; this screen only saves what it shows, so it never
    // writes back stale copies of those.
    _profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
    _subs = SubscriptionStore(widget.prefs).load();
  }

  void _reloadProfilesAndSubs() {
    if (!mounted) return;
    setState(() {
      _profiles = decodeProfiles(widget.prefs.getString('profiles_json'));
      _subs = SubscriptionStore(widget.prefs).load();
    });
  }

  // ── Subscriptions ────────────────────────────────────────────────────────

  Future<void> _importSubscription(String url) async {
    final messenger = ScaffoldMessenger.of(context);
    if (_importing) {
      messenger.showSnackBar(const SnackBar(content: Text('Another import is still running.')));
      return;
    }
    if (url.length > 2048) {
      messenger.showSnackBar(const SnackBar(content: Text('The subscription link is too long.')));
      return;
    }
    if (_subs.length >= _maxSubscriptions && !_subs.any((x) => x.url == url.trim())) {
      messenger.showSnackBar(const SnackBar(content: Text('Too many subscriptions. Remove some first.')));
      return;
    }
    _importing = true;
    messenger.showSnackBar(const SnackBar(content: Text('Fetching subscription…'), duration: Duration(seconds: 2)));
    try {
      final n = await SubscriptionStore(widget.prefs).add(url, askSend: () => askSendDeviceId(context));
      _reloadProfilesAndSubs();
      messenger.showSnackBar(SnackBar(content: Text('Subscription added: $n profile(s)')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not add the subscription: ${e.toString().replaceFirst('Exception: ', '')}')));
    } finally {
      _importing = false;
    }
  }

  Future<void> _refreshSubscription(OstpSubscription s) async {
    if (_refreshing.contains(s.id)) return;
    setState(() => _refreshing.add(s.id));
    final messenger = ScaffoldMessenger.of(context);
    try {
      final n = await SubscriptionStore(widget.prefs).refresh(s.id, askSend: () => askSendDeviceId(context));
      messenger.showSnackBar(SnackBar(content: Text('Updated: $n profile(s)')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not update the subscription: ${e.toString().replaceFirst('Exception: ', '')}')));
    } finally {
      _refreshing.remove(s.id);
      if (mounted) _reloadProfilesAndSubs();
    }
  }

  Future<void> _acceptNewKey(OstpSubscription s) async {
    await SubscriptionStore(widget.prefs).acceptKeys(s.id);
    if (mounted) _reloadProfilesAndSubs();
    // The rest of the new links come with the next refresh.
    if (mounted) await _refreshSubscription(s);
  }

  Future<void> _keepOldKey(OstpSubscription s) async {
    await SubscriptionStore(widget.prefs).keepOldKeys(s.id);
    if (mounted) _reloadProfilesAndSubs();
  }

  /// The question after a refresh brought another key for a known server.
  Widget _keyChangeNotice(OstpSubscription s) => Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          border: Border.all(color: Colors.amberAccent.withOpacity(0.6)),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text(
            "The server's key changed in this subscription. If the operator did not tell you about a new key, someone may be intercepting the subscription.",
            style: TextStyle(fontSize: 12, height: 1.4, color: Colors.amberAccent),
          ),
          const SizedBox(height: 6),
          Wrap(spacing: 8, children: [
            FilledButton(onPressed: () => _acceptNewKey(s), child: const Text('Accept the new key')),
            OutlinedButton(onPressed: () => _keepOldKey(s), child: const Text('Keep the old one')),
          ]),
        ]),
      );

  void _confirmRemoveSubscription(OstpSubscription s) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        title: const Text('Remove subscription?'),
        content: Text('"${s.name}" and its profiles will be removed from this device.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          TextButton(
            onPressed: () async {
              Navigator.pop(context);
              await SubscriptionStore(widget.prefs).remove(s.id);
              _reloadProfilesAndSubs();
              _noteIfRunning();
            },
            child: const Text('Remove', style: TextStyle(color: Colors.redAccent)),
          ),
        ],
      ),
    );
  }

  String _ago(int ms) {
    if (ms == 0) return 'never';
    final d = DateTime.now().difference(DateTime.fromMillisecondsSinceEpoch(ms));
    if (d.inMinutes < 1) return 'just now';
    if (d.inHours < 1) return '${d.inMinutes} min ago';
    if (d.inDays < 1) return '${d.inHours} h ago';
    return '${d.inDays} d ago';
  }

  // ── Groups ───────────────────────────────────────────────────────────────
  // With subscriptions, each one is a group of its profiles (a refresh
  // rewrites them) and the profiles added by hand are one more group. A group
  // folds to its header; it starts folded unless it holds the selected
  // profile, and remembers what the user chose. A search field appears when
  // the list is long.

  static const _groupsKey = 'profile_groups_open';
  static const _manualGroup = 'manual';
  static const _searchFrom = 9; // profiles and subscriptions together
  final _searchCtrl = TextEditingController();
  String get _query => _searchCtrl.text.trim().toLowerCase();

  Map<String, bool> _openGroups() {
    try {
      final v = jsonDecode(widget.prefs.getString(_groupsKey) ?? '{}');
      if (v is Map) return {for (final e in v.entries) if (e.key is String && e.value is bool) e.key as String: e.value as bool};
    } catch (_) {}
    return {};
  }

  void _setGroupOpen(String id, bool open) {
    final v = _openGroups()..[id] = open;
    // Forget groups that are gone, so the stored map does not grow.
    final known = {_manualGroup, ..._subs.map((s) => s.id)};
    v.removeWhere((k, _) => !known.contains(k));
    widget.prefs.setString(_groupsKey, jsonEncode(v));
    setState(() {});
  }

  bool _groupOpen(String id, List<OstpProfile> members) =>
      _openGroups()[id] ?? members.any((p) => p.active);

  bool _matches(OstpProfile p, String q) =>
      p.name.toLowerCase().contains(q) || p.serverAddr.toLowerCase().contains(q);

  Widget _searchField() => Padding(
        padding: const EdgeInsets.only(bottom: 14),
        child: TextField(
          controller: _searchCtrl,
          onChanged: (_) => setState(() {}),
          inputFormatters: [LengthLimitingTextInputFormatter(100)],
          decoration: InputDecoration(
            hintText: 'Search by name or server',
            isDense: true,
            filled: true,
            fillColor: Theme.of(context).colorScheme.surface,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
            prefixIcon: const Icon(Icons.search, size: 20, color: Colors.white54),
            suffixIcon: _query.isEmpty
                ? null
                : IconButton(icon: const Icon(Icons.close, size: 18), onPressed: () => setState(_searchCtrl.clear)),
          ),
        ),
      );

  /// One foldable group: header (name, count, actions), a summary line, and
  /// its profiles when open. [unavailable] marks every profile of the group.
  Widget _group({
    required String id,
    required String title,
    required int count,
    required List<OstpProfile> members,
    required bool open,
    String summary = '',
    Color summaryColor = Colors.white54,
    String? error,
    Widget? notice,
    Widget? bar,
    List<Widget> actions = const [],
    String? unavailable,
  }) {
    return Card(
      color: Theme.of(context).colorScheme.surface,
      margin: const EdgeInsets.only(bottom: 8),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(4, 2, 2, 6),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Expanded(
                child: InkWell(
                  borderRadius: BorderRadius.circular(10),
                  // A search shows every match unfolded.
                  onTap: _query.isEmpty ? () => _setGroupOpen(id, !open) : null,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 10),
                    child: Row(children: [
                      Icon(open ? Icons.expand_more_rounded : Icons.chevron_right_rounded, size: 20, color: Colors.white54),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(title,
                            style: const TextStyle(fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
                      ),
                      const SizedBox(width: 8),
                      Text('$count', style: const TextStyle(fontSize: 12, color: Colors.white38, fontFamily: 'monospace')),
                    ]),
                  ),
                ),
              ),
              ...actions,
            ]),
            if (bar != null) Padding(padding: const EdgeInsets.fromLTRB(32, 0, 12, 4), child: bar),
            if (summary.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(32, 0, 12, 2),
                child: Text(summary, style: TextStyle(fontSize: 12, color: summaryColor)),
              ),
            if (error != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(32, 2, 12, 2),
                child: Text(error, style: const TextStyle(fontSize: 12, color: Colors.redAccent)),
              ),
            if (notice != null) Padding(padding: const EdgeInsets.fromLTRB(32, 6, 12, 4), child: notice),
            if (open)
              Padding(
                padding: const EdgeInsets.only(left: 12),
                child: Column(children: [for (final p in members) _profileTile(p, dense: true, unavailable: unavailable)]),
              ),
          ],
        ),
      ),
    );
  }

  Widget _subAction(IconData icon, String tooltip, VoidCallback onPressed) => IconButton(
        icon: Icon(icon, size: 20, color: Colors.white54),
        tooltip: tooltip,
        visualDensity: VisualDensity.compact,
        onPressed: onPressed,
      );

  List<Widget> _buildGroups() {
    final q = _query;
    final out = <Widget>[];
    for (final s in _subs) {
      final all = _profiles.where((p) => p.subId == s.id).toList();
      final nameHit = q.isEmpty || (s.name.isEmpty ? s.url : s.name).toLowerCase().contains(q);
      final members = nameHit ? all : all.where((p) => _matches(p, q)).toList();
      if (q.isNotEmpty && members.isEmpty && !nameHit) continue;
      final used = s.usedBytes;
      final limit = s.limitBytes;
      final usage = used == null
          ? null
          : limit != null && limit > 0
              ? '${formatBytes(used)} of ${formatBytes(limit)}'
              : '${formatBytes(used)} used';
      final exp = s.expiry;
      final busy = _refreshing.contains(s.id);
      out.add(_group(
        id: s.id,
        title: s.name.isEmpty ? s.url : s.name,
        count: all.length,
        members: members,
        open: q.isNotEmpty || _groupOpen(s.id, all),
        summary: [
          if (usage != null) usage,
          if (exp != null) exp.label,
          'updated ${_ago(s.updatedAt)}',
        ].join(' · '),
        summaryColor: exp?.expired == true ? Colors.redAccent : exp != null && exp.daysLeft < 7 ? Colors.amberAccent : Colors.white54,
        error: s.lastError,
        notice: s.pendingKeys.isEmpty ? null : _keyChangeNotice(s),
        bar: limit != null && limit > 0 && used != null
            ? ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(value: (used / limit).clamp(0.0, 1.0), minHeight: 3),
              )
            : null,
        unavailable: exp?.expired == true ? 'Unavailable: the key of this subscription expired' : null,
        actions: [
          _subAction(Icons.info_outline_rounded, 'Server information', () async {
            await showServerInfo(context, widget.prefs, s.id);
            _reloadProfilesAndSubs();
          }),
          busy
              ? const Padding(
                  padding: EdgeInsets.all(10),
                  child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
                )
              : _subAction(Icons.refresh_rounded, 'Update', () => _refreshSubscription(s)),
          _subAction(
            Icons.qr_code_rounded,
            'Share',
            () => _showQrDialog(
              'Share Subscription',
              s.url,
              note: 'Anyone with this link connects as you and uses your traffic. Share it only with your own devices.',
            ),
          ),
          _subAction(Icons.delete_outline_rounded, 'Remove', () => _confirmRemoveSubscription(s)),
        ],
      ));
    }
    final manual = _profiles.where((p) => p.subId.isEmpty).toList();
    final manualShown = q.isEmpty ? manual : manual.where((p) => _matches(p, q)).toList();
    if (manualShown.isNotEmpty) {
      out.add(_group(
        id: _manualGroup,
        title: 'Added by hand',
        count: manual.length,
        members: manualShown,
        open: q.isNotEmpty || _groupOpen(_manualGroup, manual),
      ));
    }
    if (q.isNotEmpty && out.isEmpty) {
      out.add(Padding(
        padding: const EdgeInsets.symmetric(vertical: 20),
        child: Text('Nothing named like "${_searchCtrl.text.trim()}".',
            textAlign: TextAlign.center, style: const TextStyle(color: Colors.white54)),
      ));
    }
    return out;
  }

  @override
  void dispose() {
    _saveSettings();
    _localBindCtrl.dispose();
    _dnsCtrl.dispose();
    _mtuCtrl.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  void _saveSettings() {
    widget.prefs.setString('local_bind', _localBindCtrl.text.trim());
    widget.prefs.setString('dns_server', _dnsCtrl.text.trim());
    final mtu = _mtuCtrl.text.trim();
    widget.prefs.setString('mtu', mtu.toLowerCase() == 'auto' ? '' : mtu);
    // The profile list is saved by each change to it. Writing it here as well
    // would overwrite a subscription refresh that finished while this screen was open.
  }

  void _saveProfiles() {
    widget.prefs.setString('profiles_json', encodeProfiles(_profiles));
  }

  // ── Profile CRUD ─────────────────────────────────────────────────────────

  void _selectActive(OstpProfile p) {
    setState(() {
      for (final other in _profiles) {
        other.active = other.id == p.id;
      }
      _saveProfiles();
    });
    _noteIfRunning();
  }

  void _importFromLink(String link) {
    if (link.isEmpty || !mounted) return;
    if (isSubscriptionUrl(link)) {
      _importSubscription(link);
      return;
    }
    try {
      final l = ShareLink.parse(link);
      final problem = _addProblem(l.server, l.key, l.tls ? 'tls' : l.transport);
      if (problem != null) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(problem)));
        return;
      }
      final wasEmpty = _profiles.isEmpty;

      setState(() {
        _profiles.add(OstpProfile(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: l.name ?? l.host,
          serverAddr: l.server,
          accessKey: l.key,
          transportMode: l.transport,
          active: wasEmpty,
          tls: l.tls,
          tlsSni: l.sni ?? '',
          tlsInsecure: l.insecure,
          wsPath: l.path ?? '',
          serverPk: l.pk ?? '',
          owndns: l.owndns,
          dnsall: l.dnsall,
        ));
        _saveProfiles();
      });
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Profile imported')));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Could not import: ${e.toString().replaceFirst('Exception: ', '').replaceFirst('FormatException: ', '')}')));
    }
  }

  void _showAddProfileMenu() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Theme.of(context).colorScheme.surface,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code_scanner, color: Colors.white),
              title: const Text('Import from QR code'),
              onTap: () async {
                Navigator.pop(context);
                final result = await Navigator.push(
                  context,
                  MaterialPageRoute(builder: (context) => const QRScannerScreen()),
                );
                if (!mounted) return;
                if (result != null && result is String && (result.toLowerCase().startsWith('ostp://') || isSubscriptionUrl(result))) {
                  _importFromLink(result);
                }
              },
            ),
            ListTile(
              leading: const Icon(Icons.link, color: Colors.white),
              title: const Text('Import link or subscription'),
              onTap: () {
                Navigator.pop(context);
                _showImportLinkDialog();
              },
            ),
            ListTile(
              leading: const Icon(Icons.edit, color: Colors.white),
              title: const Text('Insert manually'),
              onTap: () {
                Navigator.pop(context);
                _showEditProfileDialog(null);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _showImportLinkDialog() {
    final linkCtrl = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import'),
        backgroundColor: Theme.of(context).colorScheme.surface,
        content: TextField(
          controller: linkCtrl,
          // A pasted document is cut here; ShareLink.parse rejects what is still too long.
          inputFormatters: [LengthLimitingTextInputFormatter(ShareLink.maxLength + 1)],
          decoration: const InputDecoration(
            hintText: 'ostp://... or https://...',
            helperText: 'A subscription keeps its profiles up to date',
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              _importFromLink(linkCtrl.text.trim());
            },
            child: const Text('Import'),
          ),
        ],
      ),
    );
  }

  /// Host part of "host:port" / "[v6]:port" — the TLS name used when SNI is empty.
  String _hostOf(String server) {
    final s = server.trim();
    if (s.startsWith('[')) {
      final end = s.indexOf(']');
      return end > 0 ? s.substring(1, end) : s;
    }
    final c = s.lastIndexOf(':');
    return c > 0 ? s.substring(0, c) : (s.isEmpty ? 'the server host' : s);
  }

  void _showEditProfileDialog(OstpProfile? profile) {
    final isNew = profile == null;
    final nameCtrl = TextEditingController(text: profile?.name ?? '');
    final serverCtrl = TextEditingController(text: profile?.serverAddr ?? '');
    final keyCtrl = TextEditingController(text: profile?.accessKey ?? '');
    String transportMode = profile?.transportMode ?? 'udp';
    bool ttlDesync = profile?.ttlDesync ?? false;
    bool tls = profile?.tls ?? false;
    bool tlsInsecure = profile?.tlsInsecure ?? false;
    final sniCtrl = TextEditingController(text: profile?.tlsSni ?? '');
    final wsPathCtrl = TextEditingController(text: profile?.wsPath ?? '');
    String dnsChoice = dnsChoices.contains(profile?.dnsChoice) ? profile!.dnsChoice : '';
    bool obscureKey = true;

    showDialog(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) => AlertDialog(
            title: Text(isNew ? 'New Profile' : 'Edit Profile'),
            backgroundColor: Theme.of(context).colorScheme.surface,
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: nameCtrl,
                    inputFormatters: [LengthLimitingTextInputFormatter(64)],
                    decoration: const InputDecoration(labelText: 'Name'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: serverCtrl,
                    inputFormatters: [LengthLimitingTextInputFormatter(260)],
                    decoration: const InputDecoration(labelText: 'Server Address (host:port)'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: keyCtrl,
                    obscureText: obscureKey,
                    inputFormatters: [LengthLimitingTextInputFormatter(512)],
                    decoration: InputDecoration(
                      labelText: 'Access Key',
                      suffixIcon: IconButton(
                        icon: Icon(obscureKey ? Icons.visibility : Icons.visibility_off, size: 18),
                        onPressed: () => setDialogState(() => obscureKey = !obscureKey),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  DropdownButtonFormField<String>(
                    value: transportMode,
                    decoration: const InputDecoration(labelText: 'Carrier'),
                    items: const [
                      DropdownMenuItem(value: 'udp', child: Text('UDP')),
                      DropdownMenuItem(value: 'uot', child: Text('TCP (UoT)')),
                    ],
                    onChanged: (v) {
                      if (v != null) setDialogState(() => transportMode = v);
                    },
                  ),
                  // The protocol follows the server's key, which comes from the
                  // link and is not edited here.
                  Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: Text('Protocol: ${profile?.protocol ?? 'v5'}',
                        style: const TextStyle(fontSize: 12, color: Colors.white54)),
                  ),
                  if (profile != null && profile.serverPk.isEmpty)
                    const Padding(
                      padding: EdgeInsets.only(top: 4),
                      child: Text(unverifiedServerText,
                          style: TextStyle(fontSize: 12, height: 1.4, color: Colors.amberAccent)),
                    ),
                  // TLS only applies to the UoT (TCP) carrier, so the section
                  // is hidden under UDP. Reactive: switching Carrier above
                  // calls setDialogState, which rebuilds this.
                  if (transportMode == 'uot') ...[
                    const Divider(height: 32),
                    const Text('TLS', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white54, letterSpacing: 1.0)),
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('TLS (HTTPS)', style: TextStyle(fontSize: 14)),
                      subtitle: const Text('Real TLS to the server\'s domain certificate', style: TextStyle(fontSize: 12, color: Colors.white54)),
                      value: tls,
                      onChanged: (v) => setDialogState(() => tls = v),
                    ),
                    if (tls) ...[
                      TextField(
                        controller: sniCtrl,
                        inputFormatters: [LengthLimitingTextInputFormatter(255)],
                        decoration: InputDecoration(
                          labelText: 'Server name (SNI)',
                          hintText: _hostOf(serverCtrl.text),
                          helperText: 'Name sent in the TLS handshake and checked against the certificate. '
                              'Empty = ${_hostOf(serverCtrl.text)} from the address; set only for another name on the same certificate.',
                          helperMaxLines: 3,
                        ),
                      ),
                      const SizedBox(height: 8),
                      TextField(
                        controller: wsPathCtrl,
                        inputFormatters: [LengthLimitingTextInputFormatter(255)],
                        decoration: const InputDecoration(labelText: 'Upgrade path', hintText: 'only through nginx/apache/caddy'),
                      ),
                      SwitchListTile(
                        contentPadding: EdgeInsets.zero,
                        title: const Text("Don't verify certificate", style: TextStyle(fontSize: 14, color: Colors.redAccent)),
                        subtitle: const Text('Insecure: anyone on the path can impersonate the server. Testing only.', style: TextStyle(fontSize: 12, color: Colors.redAccent)),
                        value: tlsInsecure,
                        onChanged: (v) => setDialogState(() => tlsInsecure = v),
                      ),
                    ],
                  ],
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('TTL Desync', style: TextStyle(fontSize: 14)),
                    subtitle: const Text('Decoy packets that die before the server (UDP, auto-tuned)', style: TextStyle(fontSize: 12, color: Colors.white54)),
                    value: ttlDesync,
                    onChanged: (v) => setDialogState(() => ttlDesync = v),
                  ),
                  // Offered only for a server whose link says it filters DNS.
                  if (filtersDns(profile)) ...[
                    const SizedBox(height: 8),
                    DropdownButtonFormField<String>(
                      value: dnsChoice,
                      decoration: const InputDecoration(labelText: 'DNS of this server'),
                      items: const [
                        DropdownMenuItem(value: '', child: Text('Ask on the next connection')),
                        DropdownMenuItem(value: 'operator', child: Text("Operator's DNS")),
                        DropdownMenuItem(value: 'public', child: Text('Public DNS')),
                        DropdownMenuItem(value: 'mine', child: Text('My settings')),
                      ],
                      onChanged: (v) {
                        if (v != null) setDialogState(() => dnsChoice = v);
                      },
                    ),
                  ],
                ],
              ),
            ),
            actions: [
              if (!isNew)
                TextButton(
                  onPressed: () {
                    setState(() {
                      final wasActive = profile.active;
                      _profiles.removeWhere((p) => p.id == profile.id);
                      if (wasActive && _profiles.isNotEmpty) {
                        _profiles.first.active = true;
                      }
                      _saveProfiles();
                    });
                    Navigator.pop(context);
                    _noteIfRunning();
                  },
                  child: const Text('Delete', style: TextStyle(color: Colors.redAccent)),
                ),
              TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
              TextButton(
                onPressed: () {
                  final server = serverCtrl.text.trim();
                  final key = keyCtrl.text.trim();
                  if (server.isEmpty || key.isEmpty) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Server and Access Key are required')),
                    );
                    return;
                  }
                  try {
                    ShareLink.parse('ostp://x@$server');
                  } on FormatException {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('The server address must look like host:port')),
                    );
                    return;
                  }
                  final problem = _addProblem(server, key, tls && transportMode == 'uot' ? 'tls' : transportMode,
                      exceptId: profile?.id);
                  if (problem != null && (isNew || problem.startsWith('This'))) {
                    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(problem)));
                    return;
                  }
                  setState(() {
                    if (isNew) {
                      final wasEmpty = _profiles.isEmpty;
                      _profiles.add(OstpProfile(
                        id: DateTime.now().millisecondsSinceEpoch.toString(),
                        name: nameCtrl.text.trim().isNotEmpty ? nameCtrl.text.trim() : server,
                        serverAddr: server,
                        accessKey: key,
                        transportMode: transportMode,
                        active: wasEmpty,
                        ttlDesync: ttlDesync,
                        tls: transportMode == 'uot' && tls,
                        tlsSni: sniCtrl.text.trim(),
                        tlsInsecure: tlsInsecure,
                        wsPath: wsPathCtrl.text.trim(),
                      ));
                    } else {
                      profile.name = nameCtrl.text.trim().isNotEmpty ? nameCtrl.text.trim() : server;
                      profile.serverAddr = server;
                      profile.accessKey = key;
                      profile.transportMode = transportMode;
                      profile.ttlDesync = ttlDesync;
                      profile.tls = transportMode == 'uot' && tls;
                      profile.tlsSni = sniCtrl.text.trim();
                      profile.tlsInsecure = tlsInsecure;
                      profile.wsPath = wsPathCtrl.text.trim();
                      if (filtersDns(profile)) profile.dnsChoice = dnsChoice;
                    }
                    _saveProfiles();
                  });
                  Navigator.pop(context);
                  _noteIfRunning();
                },
                child: const Text('Save'),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showShareModal(OstpProfile p) {
    if (p.serverAddr.isEmpty || p.accessKey.isEmpty) return;
    final ShareLink link;
    try {
      // serverAddr is "host:port"; reuse the codec to split it.
      link = ShareLink.parse('ostp://x@${p.serverAddr}');
    } catch (_) {
      return;
    }
    link.key = p.accessKey;
    link.transport = p.transportMode;
    link.tls = p.transportMode == 'uot' && p.tls;
    if (link.tls) {
      link.sni = p.tlsSni.isEmpty ? null : p.tlsSni;
      link.insecure = p.tlsInsecure;
    }
    link.path = p.wsPath.isEmpty ? null : p.wsPath;
    link.owndns = p.owndns;
    link.dnsall = p.dnsall;
    link.pk = p.serverPk.isEmpty ? null : p.serverPk;
    // Deliberately generic title — not "Share {name}": when a profile has no
    // custom name, `name` falls back to the raw server address, and this
    // dialog is exactly the wrong place to be casually displaying that
    // (screenshots, screen recordings, shoulder-surfing).
    _showQrDialog('Share Profile', link.toUri());
  }

  /// QR code, the text itself and a copy button: profiles and subscriptions.
  void _showQrDialog(String title, String url, {String? note}) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(title, textAlign: TextAlign.center),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
              child: QrImageView(data: url, version: QrVersions.auto, size: 200.0),
            ),
            const SizedBox(height: 12),
            SelectableText(
              url,
              textAlign: TextAlign.center,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.white70),
            ),
            if (note != null) ...[
              const SizedBox(height: 8),
              Text(note, textAlign: TextAlign.center, style: const TextStyle(fontSize: 12, color: Colors.orangeAccent)),
            ],
            const SizedBox(height: 16),
            Builder(builder: (context) {
              final bg = Theme.of(context).colorScheme.primary;
              final fg = _onColor(bg);
              return ElevatedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: url));
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Copied to clipboard')));
                  Navigator.pop(context);
                },
                icon: Icon(Icons.copy_rounded, color: fg),
                label: Text('Copy Link', style: TextStyle(color: fg)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: bg,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
              );
            }),
          ],
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))],
      ),
    );
  }

  // ── Widgets ──────────────────────────────────────────────────────────────

  Widget _buildTextField(String label, TextEditingController controller, {String? hint, int maxLines = 1}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
          const SizedBox(height: 10),
          TextField(
            controller: controller,
            maxLines: maxLines,
            inputFormatters: [LengthLimitingTextInputFormatter(255)],
            style: const TextStyle(fontSize: 16),
            decoration: InputDecoration(
              hintText: hint,
              hintStyle: const TextStyle(color: Colors.white30),
              filled: true,
              fillColor: Theme.of(context).colorScheme.surface,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
            ),
          ),
        ],
      ),
    );
  }

  String? get _activeId {
    for (final x in _profiles) {
      if (x.active) return x.id;
    }
    return null;
  }

  /// One selectable profile row; `dense` inside a group. [unavailable]: why it
  /// cannot connect now (its key expired), shown in place of the address.
  Widget _profileTile(OstpProfile p, {bool dense = false, String? unavailable}) {
    return ListTile(
      dense: dense,
      visualDensity: dense ? VisualDensity.compact : null,
      contentPadding: dense ? EdgeInsets.zero : null,
      leading: Radio<String>(
        value: p.id,
        groupValue: _activeId,
        onChanged: (_) => _selectActive(p),
      ),
      title: Text(p.name,
          style: TextStyle(fontWeight: FontWeight.bold, fontSize: dense ? 14 : null, color: unavailable != null ? Colors.white54 : null),
          maxLines: 1,
          overflow: TextOverflow.ellipsis),
      subtitle: Text(
        unavailable ??
            [
              if (p.name != p.serverAddr) p.serverAddr,
              p.tls ? 'TLS' : p.transportMode.toUpperCase(),
            ].join(' · '),
        style: TextStyle(fontSize: 12, color: unavailable != null ? Colors.redAccent : null),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        softWrap: false,
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (p.serverPk.isEmpty)
            const Tooltip(
              message: unverifiedServerText,
              triggerMode: TooltipTriggerMode.tap,
              child: Padding(
                padding: EdgeInsets.symmetric(horizontal: 6),
                child: Icon(Icons.warning_amber_rounded, size: 20, color: Colors.amberAccent),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.share_rounded, size: 20, color: Colors.white54),
            onPressed: () => _showShareModal(p),
          ),
          IconButton(
            icon: const Icon(Icons.edit, size: 20, color: Colors.white54),
            onPressed: () => _showEditProfileDialog(p),
          ),
        ],
      ),
      onTap: () => _selectActive(p),
    );
  }

  List<Widget> _buildProfileCards(List<OstpProfile> list) {
    final activeId = _activeId;
    return list.map((p) => Card(
      color: p.active
          ? Theme.of(context).colorScheme.primary.withOpacity(0.12)
          : Theme.of(context).colorScheme.surface,
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: p.active ? BorderSide(color: Theme.of(context).colorScheme.primary.withOpacity(0.4)) : BorderSide.none,
      ),
      child: ListTile(
        leading: Radio<String>(
          value: p.id,
          groupValue: activeId,
          onChanged: (_) => _selectActive(p),
        ),
        title: Text(p.name, style: const TextStyle(fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
        // If the profile was never given a distinct name, `name` falls back
        // to the raw server address (see the editor below) — showing it a
        // second time here would just repeat the title verbatim, so only
        // add it when it's actually different information.
        subtitle: Text(
          [
            if (p.name != p.serverAddr) p.serverAddr,
            p.tls ? 'TLS' : p.transportMode.toUpperCase(),
            if (p.subId.isNotEmpty) 'subscription',
          ].join(' · '),
          style: const TextStyle(fontSize: 12),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          softWrap: false,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              icon: const Icon(Icons.share_rounded, size: 20, color: Colors.white54),
              onPressed: () => _showShareModal(p),
            ),
            IconButton(
              icon: const Icon(Icons.edit, size: 20, color: Colors.white54),
              onPressed: () => _showEditProfileDialog(p),
            ),
          ],
        ),
        onTap: () => _selectActive(p),
      ),
    )).toList();
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
            icon: const Icon(Icons.add_rounded),
            tooltip: 'Add Profile',
            onPressed: _showAddProfileMenu,
          ),
        ],
      ),
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
          ListView(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
            children: [
              const Text('PROFILES', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
              const SizedBox(height: 16),
              if (_profiles.length + _subs.length >= _searchFrom) _searchField(),
              if (_subs.isNotEmpty)
                ..._buildGroups()
              else if (_profiles.isEmpty)
                const Center(
                  child: Padding(
                    padding: EdgeInsets.all(32.0),
                    child: Text('Create a new profile', style: TextStyle(color: Colors.white54, fontSize: 18)),
                  ),
                )
              else
                ..._buildProfileCards(_profiles.where((p) => _query.isEmpty || _matches(p, _query)).toList()),

          const SizedBox(height: 32),
          const Text('CONNECTION', style: TextStyle(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.bold, letterSpacing: 1.0)),
          const SizedBox(height: 16),

          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.02),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildTextField('Local Proxy Bind', _localBindCtrl, hint: '127.0.0.1:1088'),
                _buildTextField('Custom DNS Server', _dnsCtrl, hint: '1.1.1.1 (e.g. 8.8.8.8)'),
                _buildTextField('MTU (Packet Size)', _mtuCtrl, hint: 'Auto (leave empty). A number fixes the size; lower it if the connection drops'),
              ],
            ),
          ),

          const SizedBox(height: 16),

          InkWell(
            borderRadius: BorderRadius.circular(16),
            onTap: () async {
              _saveSettings();
              await Navigator.push(context, MaterialPageRoute(builder: (_) => MoreSettingsScreen(prefs: widget.prefs)));
              // Users added to the app from Server management become profiles.
              _reloadProfilesAndSubs();
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.02),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.tune_rounded, color: Colors.white70, size: 24),
                  SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('More settings', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white)),
                        SizedBox(height: 4),
                        Text('Server management, exclusions, app options, logs, updates', style: TextStyle(fontSize: 13, color: Colors.white54)),
                      ],
                    ),
                  ),
                  Icon(Icons.arrow_forward_ios_rounded, color: Colors.white54, size: 16),
                ],
              ),
            ),
          ),

          const SizedBox(height: 40),
        ],
      ),
      ],
      ),
    );
  }

}

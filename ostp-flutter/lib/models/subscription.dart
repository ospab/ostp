import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'app_traffic.dart';
import 'device_limit.dart';
import 'key_pin.dart';
import 'ostp_profile.dart';
import 'server_info.dart';
import 'share_link.dart';

/// A subscription URL (`https://<domain>/<path>/<token>`) and what it last
/// returned. Its profiles carry `subId` and are replaced on every refresh,
/// so server-side changes (port, path, certificate settings) reach the app
/// without a new link.
class OstpSubscription {
  String id;
  String url;
  String name;
  int updatedAt; // ms since epoch, 0 = never
  int intervalHours;
  int? usedBytes;
  int? limitBytes;
  String? lastError;
  // What the server reported over the tunnel the last time the app was
  // connected through this subscription, and when (ms, 0 = never).
  ServerInfo? serverInfo;
  int infoAt;
  // The server closed a session because the key expired.
  bool keyExpired;
  // Keys the refresh found different from the pinned one, by pinKey(): the
  // new key ('' = the link lost its key), waiting for the person's decision.
  // keptKeys: the new key the person refused ("Keep the old one"), so the
  // question is not asked again for the same key.
  Map<String, String> pendingKeys;
  Map<String, String> keptKeys;

  OstpSubscription({
    required this.id,
    required this.url,
    this.name = '',
    this.updatedAt = 0,
    this.intervalHours = 12,
    this.usedBytes,
    this.limitBytes,
    this.lastError,
    this.serverInfo,
    this.infoAt = 0,
    this.keyExpired = false,
    Map<String, String>? pendingKeys,
    Map<String, String>? keptKeys,
  })  : pendingKeys = pendingKeys ?? {},
        keptKeys = keptKeys ?? {};

  bool get isDue =>
      DateTime.now().millisecondsSinceEpoch - updatedAt >= intervalHours * 3600 * 1000;

  /// The key's end as last reported, or null when not known.
  Expiry? get expiry => expiryOf(serverInfo?.key?.expiresAt, keyExpired: keyExpired);
  bool get isExpired => expiry?.expired ?? false;

  Map<String, dynamic> toJson() => {
        'id': id,
        'url': url,
        'name': name,
        'updatedAt': updatedAt,
        'intervalHours': intervalHours,
        'usedBytes': usedBytes,
        'limitBytes': limitBytes,
        'lastError': lastError,
        'serverInfo': serverInfo?.toJson(),
        'infoAt': infoAt,
        'keyExpired': keyExpired,
        'pendingKeys': pendingKeys,
        'keptKeys': keptKeys,
      };

  static Map<String, String> _strMap(Object? v) =>
      v is Map ? {for (final e in v.entries) if (e.key is String && e.value is String) e.key as String: e.value as String} : {};

  factory OstpSubscription.fromJson(Map<String, dynamic> j) => OstpSubscription(
        id: j['id'] as String? ?? '',
        url: j['url'] as String? ?? '',
        name: j['name'] as String? ?? '',
        updatedAt: j['updatedAt'] as int? ?? 0,
        intervalHours: j['intervalHours'] as int? ?? 12,
        usedBytes: j['usedBytes'] as int?,
        limitBytes: j['limitBytes'] as int?,
        lastError: j['lastError'] as String?,
        serverInfo: ServerInfo.parse(j['serverInfo']),
        infoAt: j['infoAt'] is int ? j['infoAt'] as int : 0,
        keyExpired: j['keyExpired'] == true,
        pendingKeys: _strMap(j['pendingKeys']),
        keptKeys: _strMap(j['keptKeys']),
      );
}

List<OstpSubscription> decodeSubscriptions(String? json) {
  if (json == null || json.isEmpty) return [];
  try {
    final out = <OstpSubscription>[];
    for (final e in jsonDecode(json) as List) {
      try {
        out.add(OstpSubscription.fromJson(e as Map<String, dynamic>));
      } catch (_) {}
    }
    return out;
  } catch (_) {
    return [];
  }
}

String encodeSubscriptions(List<OstpSubscription> subs) =>
    jsonEncode(subs.map((e) => e.toJson()).toList());

/// Binary units (1 KiB = 1024 B), the one byte formatter of the app.
String formatBytes(num n) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  var v = n.toDouble();
  var i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i == 0 ? '${n.toInt()} B' : '${v.toStringAsFixed(1)} ${units[i]}';
}

bool isSubscriptionUrl(String s) => s.trim().toLowerCase().startsWith('https://');

/// Asks the person whether to send a device ID; true = send it and retry.
typedef AskToSend = Future<bool> Function();

class SubscriptionStore {
  static const _channel = MethodChannel('com.ospab.ostp/vpn');
  static const _subsKey = 'subscriptions_json';
  static const _profilesKey = 'profiles_json';

  final SharedPreferences prefs;
  SubscriptionStore(this.prefs);

  // Each operation reads the stored lists, waits for the network and writes them
  // back. Two at once (the background refresh on start and a manual import)
  // would overwrite each other, so they run one after another.
  static Future<void> _tail = Future.value();

  static Future<T> _serialized<T>(Future<T> Function() body) {
    final done = Completer<T>();
    final prev = _tail;
    _tail = done.future.then((_) {}, onError: (_) {});
    prev.then((_) async {
      try {
        done.complete(await body());
      } catch (e, st) {
        done.completeError(e, st);
      }
    });
    return done.future;
  }

  // More links than this in one document is not a server list.
  static const _maxLinks = 50;

  List<OstpSubscription> load() => decodeSubscriptions(prefs.getString(_subsKey));

  Future<void> _save(List<OstpSubscription> subs) => prefs.setString(_subsKey, encodeSubscriptions(subs));

  bool get sendHwid => prefs.getBool(sendHwidKey) ?? false;

  bool get viaTunnel => appViaTunnel(prefs);

  /// The native core downloads it (verified TLS, same parser as the CLI). The device
  /// ID is sent only when "Send a device ID to subscriptions" is on.
  Future<Map<String, dynamic>> _fetch(String url) async {
    final String? raw;
    try {
      raw = await _channel
          .invokeMethod<String>('fetchSubscription', {'url': url.trim(), 'sendHwid': sendHwid, 'viaTunnel': viaTunnel})
          .timeout(const Duration(seconds: 45));
    } on TimeoutException {
      throw Exception('the server did not answer in time');
    }
    if (raw == null) throw Exception('no answer from the native core');
    final doc = jsonDecode(raw) as Map<String, dynamic>;
    final err = doc['error'];
    if (err != null) {
      final e = classifyFetchError(err.toString());
      if (e.kind != FetchErrorKind.other) throw DeviceLimitException(e);
      throw Exception(err);
    }
    return doc;
  }

  /// [_fetch], and when the server wants a device ID that is not being sent, a fetch
  /// the person started ([askSend] given) asks once and retries. Background
  /// refreshes pass no [askSend]: they never open a dialog.
  Future<Map<String, dynamic>> _fetchAsking(String url, AskToSend? askSend) async {
    try {
      return await _fetch(url);
    } on DeviceLimitException catch (e) {
      if (askSend == null || !shouldAskToSend(error: e.error, manual: true, sendOn: sendHwid)) rethrow;
      if (!await askSend()) rethrow;
      await prefs.setBool(sendHwidKey, true);
      return _fetch(url);
    }
  }

  /// Adds a subscription (or refreshes it if the URL is already known).
  /// Returns how many profiles it produced.
  Future<int> add(String url, {AskToSend? askSend}) => _serialized(() => _add(url, askSend));

  Future<int> _add(String url, AskToSend? askSend) async {
    final subs = load();
    final existing = subs.where((s) => s.url == url.trim()).toList();
    final sub = existing.isNotEmpty
        ? existing.first
        : OstpSubscription(id: 'sub${DateTime.now().millisecondsSinceEpoch}', url: url.trim());
    final n = await _refreshOne(sub, askSend);
    if (existing.isEmpty) subs.add(sub);
    await _save(subs);
    return n;
  }

  Future<int> refresh(String id, {AskToSend? askSend}) => _serialized(() => _refresh(id, askSend));

  Future<int> _refresh(String id, AskToSend? askSend) async {
    final subs = load();
    final sub = subs.firstWhere((s) => s.id == id);
    try {
      return await _refreshOne(sub, askSend);
    } catch (e) {
      sub.lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      await _save(subs);
    }
  }

  /// Refreshes every subscription whose interval has passed; errors are
  /// recorded on the subscription, never thrown.
  Future<bool> refreshDue() => _serialized(_refreshDue);

  Future<bool> _refreshDue() async {
    final subs = load();
    var changed = false;
    for (final sub in subs.where((s) => s.isDue)) {
      try {
        await _refreshOne(sub);
        changed = true;
      } catch (e) {
        sub.lastError = e.toString().replaceFirst('Exception: ', '');
      }
    }
    await _save(subs);
    return changed;
  }

  /// Keeps what the server reported over the tunnel with subscription [id].
  /// Returns whether anything shown changed.
  Future<bool> setServerInfo(String id, ServerInfo info) => _serialized(() async {
        final subs = load();
        final sub = subs.where((s) => s.id == id).firstOrNull;
        if (sub == null) return false;
        final before = jsonEncode([sub.serverInfo?.toJson(), sub.keyExpired]);
        sub.serverInfo = info;
        sub.infoAt = DateTime.now().millisecondsSinceEpoch;
        final at = info.key?.expiresAt;
        if (at == null || at * 1000 > DateTime.now().millisecondsSinceEpoch) sub.keyExpired = false;
        await _save(subs);
        return before != jsonEncode([sub.serverInfo?.toJson(), sub.keyExpired]);
      });

  /// The server closed a session of subscription [id] because its key expired.
  Future<void> markKeyExpired(String id) => _serialized(() async {
        final subs = load();
        final sub = subs.where((s) => s.id == id).firstOrNull;
        if (sub == null || sub.keyExpired) return;
        sub.keyExpired = true;
        await _save(subs);
      });

  /// "Accept the new key": the pinned profiles of subscription [id] take the
  /// new keys that were waiting. A refresh afterwards brings the rest of the
  /// new links.
  Future<void> acceptKeys(String id) => _serialized(() async {
        final subs = load();
        final sub = subs.where((s) => s.id == id).firstOrNull;
        if (sub == null || sub.pendingKeys.isEmpty) return;
        final profiles = decodeProfiles(prefs.getString(_profilesKey));
        for (final p in profiles.where((p) => p.subId == id)) {
          final pk = sub.pendingKeys[pinKey(p.serverAddr, p.tls ? 'tls' : p.transportMode)];
          if (pk != null) p.serverPk = pk;
        }
        sub.pendingKeys = {};
        sub.keptKeys = {};
        await prefs.setString(_profilesKey, encodeProfiles(profiles));
        await _save(subs);
      });

  /// "Keep the old one": the waiting keys are refused and not asked about again.
  Future<void> keepOldKeys(String id) => _serialized(() async {
        final subs = load();
        final sub = subs.where((s) => s.id == id).firstOrNull;
        if (sub == null || sub.pendingKeys.isEmpty) return;
        sub.keptKeys = {...sub.keptKeys, ...sub.pendingKeys};
        sub.pendingKeys = {};
        await _save(subs);
      });

  Future<void> remove(String id) => _serialized(() => _remove(id));

  Future<void> _remove(String id) async {
    final subs = load()..removeWhere((s) => s.id == id);
    await _save(subs);
    final profiles = decodeProfiles(prefs.getString(_profilesKey));
    final wasActive = profiles.any((p) => p.subId == id && p.active);
    profiles.removeWhere((p) => p.subId == id);
    if (wasActive && profiles.isNotEmpty && !profiles.any((p) => p.active)) profiles.first.active = true;
    await prefs.setString(_profilesKey, encodeProfiles(profiles));
  }

  /// Replaces the subscription's profiles with the fetched links, keeping the
  /// active selection and per-profile tweaks (TTL desync) of
  /// the profile with the same carrier.
  Future<int> _refreshOne(OstpSubscription sub, [AskToSend? askSend]) async {
    final doc = await _fetchAsking(sub.url, askSend);
    final links = <ShareLink>[];
    String? badKey;
    for (final l in (doc['links'] as List? ?? const []).take(_maxLinks)) {
      try {
        links.add(ShareLink.parse(l as String));
      } on FormatException catch (e) {
        // A damaged server key is never turned into a v5 profile; if nothing
        // else is usable, the user is told why.
        if (e.message.contains('server key (pk)')) badKey ??= e.message;
      } catch (_) {}
    }
    if (links.isEmpty) throw Exception(badKey ?? 'the subscription has no usable links');

    final name = (doc['name'] as String?)?.trim() ?? '';
    final shown = name.isNotEmpty ? name : Uri.tryParse(sub.url)?.host ?? sub.url;
    sub.name = shown.length > 64 ? shown.substring(0, 64) : shown;
    sub.intervalHours = ((doc['update_interval_hours'] as num?)?.toInt() ?? 12).clamp(1, 720);
    final usage = doc['usage'] as Map<String, dynamic>?;
    sub.usedBytes = (usage?['used_bytes'] as num?)?.toInt();
    sub.limitBytes = (usage?['limit_bytes'] as num?)?.toInt();
    sub.updatedAt = DateTime.now().millisecondsSinceEpoch;
    sub.lastError = null;

    final profiles = decodeProfiles(prefs.getString(_profilesKey));
    final old = profiles.where((p) => p.subId == sub.id).toList();
    String carrier(bool tls, String mode) => tls ? 'tls' : mode;
    // Profiles added by hand for the same key and carrier are what this
    // subscription now provides: keep one copy, the subscription's.
    bool covered(OstpProfile p) =>
        p.subId.isEmpty &&
        links.any((l) => l.key == p.accessKey && l.server == p.serverAddr && carrier(l.tls, l.transport) == carrier(p.tls, p.transportMode));
    final activeCarrier = [...old, ...profiles.where(covered)]
        .where((p) => p.active)
        .map((p) => carrier(p.tls, p.transportMode))
        .firstOrNull;
    profiles.removeWhere(covered);
    final hadActive = profiles.any((p) => p.active) || activeCarrier != null;

    final fresh = <OstpProfile>[];
    final pending = <String, String>{};
    final kept = <String, String>{};
    for (var i = 0; i < links.length; i++) {
      final l = links[i];
      final c = carrier(l.tls, l.transport);
      final prev = old.where((p) => carrier(p.tls, p.transportMode) == c).firstOrNull;
      // The same server and carrier with another key (or none): keep the old
      // profile and ask the person.
      final k = pinKey(l.server, c);
      final same = old.where((p) => pinKey(p.serverAddr, carrier(p.tls, p.transportMode)) == k).firstOrNull;
      if (same != null) {
        final action = pinAction(same.serverPk, l.pk ?? '', keptPk: sub.keptKeys[k]);
        if (action != PinAction.accept) {
          if (action == PinAction.ask) {
            pending[k] = l.pk ?? '';
          } else {
            kept[k] = l.pk ?? '';
          }
          same.active = activeCarrier != null && activeCarrier == c;
          fresh.add(same);
          continue;
        }
      }
      fresh.add(OstpProfile(
        id: prev?.id ?? '${sub.id}-$i-${DateTime.now().microsecondsSinceEpoch}',
        name: l.name ?? '${sub.name} · ${c.toUpperCase()}',
        serverAddr: l.server,
        accessKey: l.key,
        transportMode: l.transport,
        active: activeCarrier != null ? activeCarrier == c : false,
        ttlDesync: prev?.ttlDesync ?? false,
        tls: l.tls,
        tlsSni: l.sni ?? '',
        tlsInsecure: l.insecure,
        wsPath: l.path ?? '',
        subId: sub.id,
        serverPk: l.pk ?? '',
        owndns: l.owndns,
        dnsall: l.dnsall,
        dnsChoice: prev?.dnsChoice ?? '',
      ));
    }
    sub.pendingKeys = pending;
    sub.keptKeys = kept;
    // The active carrier vanished from the subscription: fall back to its best link.
    if (activeCarrier != null && !fresh.any((p) => p.active)) fresh.first.active = true;
    if (!hadActive) fresh.first.active = true;

    final firstIdx = profiles.indexWhere((p) => p.subId == sub.id);
    profiles.removeWhere((p) => p.subId == sub.id);
    profiles.insertAll(firstIdx >= 0 ? firstIdx : profiles.length, fresh);
    await prefs.setString(_profilesKey, encodeProfiles(profiles));
    return fresh.length;
  }
}

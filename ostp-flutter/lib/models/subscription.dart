import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'ostp_profile.dart';
import 'share_link.dart';

/// A subscription URL (`https://<domain>/sub/<token>`) and what it last
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

  OstpSubscription({
    required this.id,
    required this.url,
    this.name = '',
    this.updatedAt = 0,
    this.intervalHours = 12,
    this.usedBytes,
    this.limitBytes,
    this.lastError,
  });

  bool get isDue =>
      DateTime.now().millisecondsSinceEpoch - updatedAt >= intervalHours * 3600 * 1000;

  Map<String, dynamic> toJson() => {
        'id': id,
        'url': url,
        'name': name,
        'updatedAt': updatedAt,
        'intervalHours': intervalHours,
        'usedBytes': usedBytes,
        'limitBytes': limitBytes,
        'lastError': lastError,
      };

  factory OstpSubscription.fromJson(Map<String, dynamic> j) => OstpSubscription(
        id: j['id'] as String? ?? '',
        url: j['url'] as String? ?? '',
        name: j['name'] as String? ?? '',
        updatedAt: j['updatedAt'] as int? ?? 0,
        intervalHours: j['intervalHours'] as int? ?? 12,
        usedBytes: j['usedBytes'] as int?,
        limitBytes: j['limitBytes'] as int?,
        lastError: j['lastError'] as String?,
      );
}

List<OstpSubscription> decodeSubscriptions(String? json) {
  if (json == null || json.isEmpty) return [];
  try {
    return (jsonDecode(json) as List).map((e) => OstpSubscription.fromJson(e)).toList();
  } catch (_) {
    return [];
  }
}

String encodeSubscriptions(List<OstpSubscription> subs) =>
    jsonEncode(subs.map((e) => e.toJson()).toList());

String formatBytes(int n) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  var v = n.toDouble();
  var i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i == 0 ? '$n B' : '${v.toStringAsFixed(1)} ${units[i]}';
}

bool isSubscriptionUrl(String s) => s.trim().toLowerCase().startsWith('https://');

class SubscriptionStore {
  static const _channel = MethodChannel('com.ospab.ostp/vpn');
  static const _subsKey = 'subscriptions_json';
  static const _profilesKey = 'profiles_json';

  final SharedPreferences prefs;
  SubscriptionStore(this.prefs);

  List<OstpSubscription> load() => decodeSubscriptions(prefs.getString(_subsKey));

  Future<void> _save(List<OstpSubscription> subs) => prefs.setString(_subsKey, encodeSubscriptions(subs));

  /// The native core downloads it (verified TLS, same parser as the CLI).
  static Future<Map<String, dynamic>> _fetch(String url) async {
    final String? raw = await _channel.invokeMethod('fetchSubscription', {'url': url.trim()});
    if (raw == null) throw Exception('no answer from the native core');
    final doc = jsonDecode(raw) as Map<String, dynamic>;
    if (doc['error'] != null) throw Exception(doc['error']);
    return doc;
  }

  /// Adds a subscription (or refreshes it if the URL is already known).
  /// Returns how many profiles it produced.
  Future<int> add(String url) async {
    final subs = load();
    final existing = subs.where((s) => s.url == url.trim()).toList();
    final sub = existing.isNotEmpty
        ? existing.first
        : OstpSubscription(id: 'sub${DateTime.now().millisecondsSinceEpoch}', url: url.trim());
    final n = await _refreshOne(sub);
    if (existing.isEmpty) subs.add(sub);
    await _save(subs);
    return n;
  }

  Future<int> refresh(String id) async {
    final subs = load();
    final sub = subs.firstWhere((s) => s.id == id);
    try {
      return await _refreshOne(sub);
    } catch (e) {
      sub.lastError = e.toString().replaceFirst('Exception: ', '');
      rethrow;
    } finally {
      await _save(subs);
    }
  }

  /// Refreshes every subscription whose interval has passed; errors are
  /// recorded on the subscription, never thrown.
  Future<bool> refreshDue() async {
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

  Future<void> remove(String id) async {
    final subs = load()..removeWhere((s) => s.id == id);
    await _save(subs);
    final profiles = decodeProfiles(prefs.getString(_profilesKey));
    final wasActive = profiles.any((p) => p.subId == id && p.active);
    profiles.removeWhere((p) => p.subId == id);
    if (wasActive && profiles.isNotEmpty && !profiles.any((p) => p.active)) profiles.first.active = true;
    await prefs.setString(_profilesKey, encodeProfiles(profiles));
  }

  /// Replaces the subscription's profiles with the fetched links, keeping the
  /// active selection and per-profile tweaks (junk, fragmentation, TTL) of
  /// the profile with the same carrier.
  Future<int> _refreshOne(OstpSubscription sub) async {
    final doc = await _fetch(sub.url);
    final links = <ShareLink>[];
    for (final l in (doc['links'] as List? ?? const [])) {
      try {
        links.add(ShareLink.parse(l as String));
      } catch (_) {}
    }
    if (links.isEmpty) throw Exception('the subscription has no usable links');

    final name = (doc['name'] as String?)?.trim() ?? '';
    sub.name = name.isNotEmpty ? name : Uri.tryParse(sub.url)?.host ?? sub.url;
    sub.intervalHours = ((doc['update_interval_hours'] as num?)?.toInt() ?? 12).clamp(1, 720);
    final usage = doc['usage'] as Map<String, dynamic>?;
    sub.usedBytes = (usage?['used_bytes'] as num?)?.toInt();
    sub.limitBytes = (usage?['limit_bytes'] as num?)?.toInt();
    sub.updatedAt = DateTime.now().millisecondsSinceEpoch;
    sub.lastError = null;

    final profiles = decodeProfiles(prefs.getString(_profilesKey));
    final old = profiles.where((p) => p.subId == sub.id).toList();
    String carrier(bool tls, String mode) => tls ? 'tls' : mode;
    final activeCarrier = old.where((p) => p.active).map((p) => carrier(p.tls, p.transportMode)).firstOrNull;
    final hadActive = profiles.any((p) => p.active);

    final fresh = <OstpProfile>[];
    for (var i = 0; i < links.length; i++) {
      final l = links[i];
      final c = carrier(l.tls, l.transport);
      final prev = old.where((p) => carrier(p.tls, p.transportMode) == c).firstOrNull;
      fresh.add(OstpProfile(
        id: prev?.id ?? '${sub.id}-$i-${DateTime.now().microsecondsSinceEpoch}',
        name: l.name ?? '${sub.name} · ${c.toUpperCase()}',
        serverAddr: l.server,
        accessKey: l.key,
        transportMode: l.transport,
        active: activeCarrier != null ? activeCarrier == c : false,
        tcpFragmentation: prev?.tcpFragmentation ?? false,
        fragChunk: prev?.fragChunk ?? 2,
        fragSleep: prev?.fragSleep ?? 2,
        junkPcMin: prev?.junkPcMin ?? 2,
        junkPcMax: prev?.junkPcMax ?? 5,
        junkPsMin: prev?.junkPsMin ?? 100,
        junkPsMax: prev?.junkPsMax ?? 1000,
        ttlDesync: prev?.ttlDesync ?? false,
        tls: l.tls,
        tlsSni: l.sni ?? '',
        tlsInsecure: l.insecure,
        wsPath: l.path ?? '',
        subId: sub.id,
      ));
    }
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

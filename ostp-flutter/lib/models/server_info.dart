/// What a server says about itself, its operator and the user's key. The
/// connected core reports it inside the tunnel (never in the subscription
/// document, which anyone with the URL can fetch). The app keeps the last
/// copy with the subscription, so the information window also works offline.
library;

import 'dart:convert';

import 'package:flutter/services.dart';

class OperatorInfo {
  final String? name, location, contact, about;
  const OperatorInfo({this.name, this.location, this.contact, this.about});
  bool get isEmpty => name == null && location == null && contact == null && about == null;
  Map<String, dynamic> toJson() => {'name': name, 'location': location, 'contact': contact, 'about': about};
}

class ReportedInfo {
  final String? version;
  final List<String> carriers;
  final String? logPrivacy; // strict | normal | debug
  final bool? ipv6, dnsFiltering;
  const ReportedInfo({this.version, this.carriers = const [], this.logPrivacy, this.ipv6, this.dnsFiltering});
  bool get isEmpty => version == null && carriers.isEmpty && logPrivacy == null && ipv6 == null && dnsFiltering == null;
  Map<String, dynamic> toJson() =>
      {'version': version, 'carriers': carriers, 'log_privacy': logPrivacy, 'ipv6': ipv6, 'dns_filtering': dnsFiltering};
}

class KeyInfo {
  final int? usedBytes, limitBytes, expiresAt, maxDevices; // expiresAt: Unix seconds
  const KeyInfo({this.usedBytes, this.limitBytes, this.expiresAt, this.maxDevices});
  bool get isEmpty => usedBytes == null && limitBytes == null && expiresAt == null && maxDevices == null;
  Map<String, dynamic> toJson() =>
      {'used_bytes': usedBytes, 'limit_bytes': limitBytes, 'expires_at': expiresAt, 'max_devices': maxDevices};
}

class ServerInfo {
  final OperatorInfo? operator;
  final ReportedInfo? server;
  final KeyInfo? key;
  const ServerInfo({this.operator, this.server, this.key});

  Map<String, dynamic> toJson() => {
        if (operator != null) 'operator': operator!.toJson(),
        if (server != null) 'server': server!.toJson(),
        if (key != null) 'key': key!.toJson(),
      };

  static String? _str(Object? v, int max) {
    if (v is! String) return null;
    final t = v.replaceAll(RegExp(r'[\x00-\x08\x0b-\x1f\x7f]'), '').trim();
    if (t.isEmpty) return null;
    return t.length > max ? t.substring(0, max) : t;
  }

  static int? _num(Object? v) => v is num && v.isFinite && v >= 0 ? v.floor() : null;
  static bool? _bool(Object? v) => v is bool ? v : null;

  /// Whatever the core sent (a JSON string or a decoded map) → only known
  /// fields of the right type; null when nothing is usable.
  static ServerInfo? parse(Object? raw) {
    var v = raw;
    if (v is String) {
      if (v.trim().isEmpty) return null;
      try {
        v = jsonDecode(v);
      } catch (_) {
        return null;
      }
    }
    if (v is! Map) return null;
    OperatorInfo? op;
    final o = v['operator'];
    if (o is Map) {
      op = OperatorInfo(
        name: _str(o['name'], 120),
        location: _str(o['location'], 120),
        contact: _str(o['contact'], 200),
        about: _str(o['about'], 8000),
      );
      if (op.isEmpty) op = null;
    }
    ReportedInfo? srv;
    final s = v['server'];
    if (s is Map) {
      final lp = s['log_privacy'];
      srv = ReportedInfo(
        version: _str(s['version'], 64),
        carriers: s['carriers'] is List
            ? (s['carriers'] as List).map((c) => _str(c, 16)).whereType<String>().take(8).toList()
            : const [],
        logPrivacy: const ['strict', 'normal', 'debug'].contains(lp) ? lp as String : null,
        ipv6: _bool(s['ipv6']),
        dnsFiltering: _bool(s['dns_filtering']),
      );
      if (srv.isEmpty) srv = null;
    }
    KeyInfo? key;
    final k = v['key'];
    if (k is Map) {
      key = KeyInfo(
        usedBytes: _num(k['used_bytes']),
        limitBytes: _num(k['limit_bytes']),
        expiresAt: _num(k['expires_at']),
        maxDevices: _num(k['max_devices']),
      );
      if (key.isEmpty) key = null;
    }
    if (op == null && srv == null && key == null) return null;
    return ServerInfo(operator: op, server: srv, key: key);
  }
}

/// When a key ends: the day (UTC, as the server counts it), days left, expired.
class Expiry {
  final bool expired;
  final int daysLeft;
  final String? date; // YYYY-MM-DD, null when only "expired" is known
  const Expiry(this.expired, this.daysLeft, this.date);

  /// "until 2026-12-31", "until 2026-12-31, 3 days left", "expired".
  String get label {
    if (expired) return 'expired';
    final left = daysLeft < 7 ? ', $daysLeft ${daysLeft == 1 ? 'day' : 'days'} left' : '';
    return 'until $date$left';
  }
}

/// "2026-12-31" for Unix seconds.
String expiryDate(int seconds) =>
    DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true).toIso8601String().substring(0, 10);

/// [expiresAt] from the server (Unix seconds); [keyExpired] when the server
/// closed a session because the key expired. Null when nothing is known.
Expiry? expiryOf(int? expiresAt, {bool keyExpired = false, DateTime? now}) {
  final t = (now ?? DateTime.now()).millisecondsSinceEpoch;
  if (expiresAt == null) return keyExpired ? const Expiry(true, 0, null) : null;
  final left = expiresAt * 1000 - t;
  final expired = left <= 0 || keyExpired;
  return Expiry(expired, expired ? 0 : (left / 86400000).ceil(), expiryDate(expiresAt));
}

/// A session closed by the server because the key is past its date, from the
/// reason the core reports.
bool isKeyExpiredReason(Object? text) => RegExp(
      r'\b(key|access)\b[^.]*\bexpired\b|\bexpired\b[^.]*\bkey\b|KeyExpired',
      caseSensitive: false,
    ).hasMatch(text is String ? text : '');

const logPrivacyText = {
  'strict': 'No destinations in the logs; your address is replaced by a daily tag.',
  'normal': 'No destinations in the logs; your address is cut to its network.',
  'debug': 'The server logs destinations: the sites and addresses you connect to.',
};

/// The running core's copy of the connected server's information.
class ServerInfoCore {
  static const _channel = MethodChannel('com.ospab.ostp/vpn');

  /// What the core has now, or null (nothing yet, no tunnel, an older core).
  static Future<ServerInfo?> read() async {
    try {
      final raw = await _channel.invokeMethod<String>('getServerInfo').timeout(const Duration(seconds: 5));
      return ServerInfo.parse(raw);
    } catch (_) {
      return null;
    }
  }

  /// Asks the server for a fresh copy; true when the request was sent.
  static Future<bool> request() async {
    try {
      return await _channel.invokeMethod<bool>('requestServerInfo').timeout(const Duration(seconds: 5)) ?? false;
    } catch (_) {
      return false;
    }
  }
}

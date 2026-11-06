import 'dart:convert';

/// A saved server profile. Field shape mirrors the desktop GUI's profile
/// object (ostp-gui/src/main.js) — server/key/transport/TLS — so behavior
/// matches across platforms. UoT can optionally run inside real TLS to the server's own
/// domain (`tls`), optionally through a web server on 443 (`wsPath`).
class OstpProfile {
  String id;
  String name;
  String serverAddr;
  String accessKey;
  String transportMode; // 'udp' | 'uot'
  bool active;

  bool ttlDesync; // TTL-desync decoys (UDP), auto-calibrated in the engine

  // TLS carrier (UoT only).
  bool tls;
  String tlsSni; // empty = host part of serverAddr
  bool tlsInsecure; // skip certificate verification (testing only)
  String wsPath; // secret upgrade path when a web server fronts OSTP

  // Subscription this profile came from ('' = added by hand); such profiles
  // are rewritten on every refresh of that subscription.
  String subId;

  OstpProfile({
    required this.id,
    required this.name,
    required this.serverAddr,
    required this.accessKey,
    this.transportMode = 'udp',
    this.active = false,
    this.ttlDesync = false,
    this.tls = false,
    this.tlsSni = '',
    this.tlsInsecure = false,
    this.wsPath = '',
    this.subId = '',
  });

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'serverAddr': serverAddr,
      'accessKey': accessKey,
      'transportMode': transportMode,
      'active': active,
      'ttlDesync': ttlDesync,
      'tls': tls,
      'tlsSni': tlsSni,
      'tlsInsecure': tlsInsecure,
      'wsPath': wsPath,
      'subId': subId,
    };
  }

  factory OstpProfile.fromJson(Map<String, dynamic> json) {
    return OstpProfile(
      id: json['id'] as String? ?? '',
      name: json['name'] as String? ?? 'Unnamed Profile',
      serverAddr: json['serverAddr'] as String? ?? '',
      accessKey: json['accessKey'] as String? ?? '',
      transportMode: json['transportMode'] as String? ?? 'udp',
      active: json['active'] as bool? ?? false,
      ttlDesync: json['ttlDesync'] as bool? ?? false,
      tls: json['tls'] as bool? ?? false,
      tlsSni: json['tlsSni'] as String? ?? '',
      tlsInsecure: json['tlsInsecure'] as bool? ?? false,
      wsPath: json['wsPath'] as String? ?? '',
      subId: json['subId'] as String? ?? '',
    );
  }
}

List<OstpProfile> decodeProfiles(String? json) {
  if (json == null || json.isEmpty) return [];
  try {
    final List<dynamic> decoded = jsonDecode(json);
    // One damaged entry must not make every profile disappear (and then be saved over).
    final out = <OstpProfile>[];
    for (final e in decoded) {
      try {
        out.add(OstpProfile.fromJson(e as Map<String, dynamic>));
      } catch (_) {}
    }
    return out;
  } catch (_) {
    return [];
  }
}

String encodeProfiles(List<OstpProfile> profiles) =>
    jsonEncode(profiles.map((e) => e.toJson()).toList());

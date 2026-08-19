import 'dart:convert';

/// A saved server profile. Field shape mirrors the desktop GUI's profile
/// object (ostp-gui/src/main.js) 1:1 — server/key/transport/tcp_fragmentation/
/// frag_chunk/frag_sleep/junk_pc/junk_ps — so behavior matches across
/// platforms. `wss` was dropped: the core no longer supports TLS-mimicry
/// transports (only plain UDP / UoT), so there is nothing left to carry it.
class OstpProfile {
  String id;
  String name;
  String serverAddr;
  String accessKey;
  String transportMode; // 'udp' | 'uot'
  bool active;

  // Junk packets + TCP fragmentation — per-profile, exactly like ostp-gui's
  // profile editor. Defaults match ostp_client::config::TransportConfig's
  // own defaults (frag_chunk=2, frag_sleep=2, junk_pc=[2,5], junk_ps=[100,1000]).
  bool tcpFragmentation;
  int fragChunk;
  int fragSleep;
  int junkPcMin;
  int junkPcMax;
  int junkPsMin;
  int junkPsMax;
  bool ttlDesync; // TTL-desync decoys (UDP), auto-calibrated in the engine

  OstpProfile({
    required this.id,
    required this.name,
    required this.serverAddr,
    required this.accessKey,
    this.transportMode = 'udp',
    this.active = false,
    this.tcpFragmentation = false,
    this.fragChunk = 2,
    this.fragSleep = 2,
    this.junkPcMin = 2,
    this.junkPcMax = 5,
    this.junkPsMin = 100,
    this.junkPsMax = 1000,
    this.ttlDesync = false,
  });

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'serverAddr': serverAddr,
      'accessKey': accessKey,
      'transportMode': transportMode,
      'active': active,
      'tcpFragmentation': tcpFragmentation,
      'fragChunk': fragChunk,
      'fragSleep': fragSleep,
      'junkPcMin': junkPcMin,
      'junkPcMax': junkPcMax,
      'junkPsMin': junkPsMin,
      'junkPsMax': junkPsMax,
      'ttlDesync': ttlDesync,
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
      tcpFragmentation: json['tcpFragmentation'] as bool? ?? false,
      fragChunk: json['fragChunk'] as int? ?? 2,
      fragSleep: json['fragSleep'] as int? ?? 2,
      junkPcMin: json['junkPcMin'] as int? ?? 2,
      junkPcMax: json['junkPcMax'] as int? ?? 5,
      junkPsMin: json['junkPsMin'] as int? ?? 100,
      junkPsMax: json['junkPsMax'] as int? ?? 1000,
      ttlDesync: json['ttlDesync'] as bool? ?? false,
    );
  }
}

List<OstpProfile> decodeProfiles(String? json) {
  if (json == null || json.isEmpty) return [];
  try {
    final List<dynamic> decoded = jsonDecode(json);
    return decoded.map((e) => OstpProfile.fromJson(e)).toList();
  } catch (_) {
    return [];
  }
}

String encodeProfiles(List<OstpProfile> profiles) =>
    jsonEncode(profiles.map((e) => e.toJson()).toList());

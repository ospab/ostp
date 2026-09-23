/// `ostp://` share-link codec — a port of ostp-core/src/share_link.rs.
/// Keep the two (and the desktop GUI's copy) in step: same parameters, same
/// order, same encoding.
///
/// `ostp://KEY@HOST:PORT?type=uot&tls=1&sni=..&insecure=1&path=%2F..&tun=true&dns=..&owndns=true&name=..`
class ShareLink {
  String key;
  String host;
  int port;
  String transport; // 'udp' | 'uot'
  bool tls;
  String? sni;
  bool insecure;
  String? path;
  bool tun;
  String? dns;
  bool owndns;
  String? name;

  ShareLink({
    required this.key,
    required this.host,
    required this.port,
    this.transport = 'udp',
    this.tls = false,
    this.sni,
    this.insecure = false,
    this.path,
    this.tun = false,
    this.dns,
    this.owndns = false,
    this.name,
  });

  /// `host:port`, bracketing IPv6 literals.
  String get server => host.contains(':') ? '[$host]:$port' : '$host:$port';

  static bool _truthy(String v) => const {'1', 'true', 'yes'}.contains(v.toLowerCase());

  static String _decode(String s) => Uri.decodeComponent(s.replaceAll('+', ' '));

  static String? _nonEmpty(String v) => v.isEmpty ? null : v;

  /// Throws [FormatException] with a readable message on a malformed link.
  static ShareLink parse(String input) {
    var rest = input.trim();
    if (!rest.toLowerCase().startsWith('ostp://')) {
      throw const FormatException('not an ostp:// link');
    }
    rest = rest.substring(7).split('#').first;
    final q = rest.indexOf('?');
    final authority = (q >= 0 ? rest.substring(0, q) : rest).replaceAll(RegExp(r'/+$'), '');
    final query = q >= 0 ? rest.substring(q + 1) : '';

    final at = authority.lastIndexOf('@');
    if (at < 0) throw const FormatException('link has no access key (expected KEY@HOST:PORT)');
    final key = _decode(authority.substring(0, at));
    if (key.isEmpty) throw const FormatException('link has an empty access key');
    final hostPort = authority.substring(at + 1);

    String host;
    String portStr;
    if (hostPort.startsWith('[')) {
      final end = hostPort.indexOf(']');
      if (end < 0) throw const FormatException('unterminated IPv6 address');
      host = hostPort.substring(1, end);
      final after = hostPort.substring(end + 1);
      if (!after.startsWith(':')) throw const FormatException('link has no port');
      portStr = after.substring(1);
    } else {
      final c = hostPort.lastIndexOf(':');
      if (c < 0) throw const FormatException('link has no port');
      host = hostPort.substring(0, c);
      portStr = hostPort.substring(c + 1);
    }
    if (host.isEmpty) throw const FormatException('link has no host');
    final port = int.tryParse(portStr);
    if (port == null || port < 0 || port > 65535) throw FormatException('invalid port "$portStr"');

    final link = ShareLink(key: key, host: host, port: port);
    for (final pair in query.split('&').where((p) => p.isNotEmpty)) {
      final eq = pair.indexOf('=');
      final k = eq >= 0 ? pair.substring(0, eq) : pair;
      final v = _decode(eq >= 0 ? pair.substring(eq + 1) : '');
      switch (k) {
        case 'type':
          link.transport = const {'uot', 'tcp', 'http'}.contains(v.toLowerCase()) ? 'uot' : 'udp';
          break;
        case 'tls':
          link.tls = _truthy(v);
          break;
        case 'sni':
          link.sni = _nonEmpty(v);
          break;
        case 'insecure':
          link.insecure = _truthy(v);
          break;
        case 'path':
          link.path = _nonEmpty(v);
          break;
        case 'tun':
          link.tun = _truthy(v);
          break;
        case 'dns':
          link.dns = _nonEmpty(v);
          break;
        case 'owndns':
          link.owndns = _truthy(v);
          break;
        case 'name':
          link.name = _nonEmpty(v);
          break;
      }
    }
    // TLS and the upgrade path only exist on the TCP carrier.
    if (link.tls || link.path != null) link.transport = 'uot';
    return link;
  }

  /// RFC 3986 unreserved characters stay, everything else is %-encoded
  /// (Uri.encodeComponent also leaves !'()* alone, the Rust side does not).
  static String _encode(String s) => Uri.encodeComponent(s).replaceAllMapped(
        RegExp(r"[!'()*]"),
        (m) => '%${m[0]!.codeUnitAt(0).toRadixString(16).toUpperCase()}',
      );

  String toUri() {
    final q = <String>['type=$transport'];
    if (tls) q.add('tls=1');
    if (sni != null) q.add('sni=${_encode(sni!)}');
    if (insecure) q.add('insecure=1');
    if (path != null) q.add('path=${_encode(path!)}');
    if (tun) q.add('tun=true');
    if (dns != null) q.add('dns=${_encode(dns!)}');
    if (owndns) q.add('owndns=true');
    if (name != null) q.add('name=${_encode(name!)}');
    return 'ostp://${_encode(key)}@$server?${q.join('&')}';
  }
}

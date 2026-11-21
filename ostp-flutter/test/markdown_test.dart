import 'package:flutter_test/flutter_test.dart';
import 'package:ostp_client/models/markdown.dart';
import 'package:ostp_client/models/server_info.dart';

void main() {
  test('headings, paragraphs, lists and code blocks', () {
    final b = parseMarkdown('# Title\n\nFirst line\nsame paragraph\n\n- one\n- two\n  more\n\n1. a\n2. b\n\n```\n<b>x</b>\n```\n### Small');
    expect(b.map((x) => x.kind).toList(), [
      MdBlockKind.heading,
      MdBlockKind.paragraph,
      MdBlockKind.bullets,
      MdBlockKind.numbered,
      MdBlockKind.code,
      MdBlockKind.heading,
    ]);
    expect(b[0].level, 1);
    expect(b[1].inlines.single.text, 'First line same paragraph');
    expect(b[2].items[1].single.text, 'two more');
    expect(b[4].code, '<b>x</b>');
    expect(b[5].level, 3);
  });

  test('bold, italic, code and links inline', () {
    final n = parseInline('a **b** *c* `d` [e](https://x.org/y)');
    expect(n.map((x) => x.kind).toList(), [
      MdInlineKind.text, MdInlineKind.text, MdInlineKind.text, MdInlineKind.text,
      MdInlineKind.text, MdInlineKind.code, MdInlineKind.text, MdInlineKind.link,
    ]);
    expect(n[1].bold, isTrue);
    expect(n[3].italic, isTrue);
    expect(n[7].url, 'https://x.org/y');
  });

  test('HTML and unknown syntax stay as text', () {
    final n = parseInline('<script>alert(1)</script> <img src=x onerror=y>');
    expect(n.single.text, '<script>alert(1)</script> <img src=x onerror=y>');
    expect(parseMarkdown('#### four').single.kind, MdBlockKind.paragraph);
    expect(parseInline('2 * 3 * 4').single.text, '2 * 3 * 4');
    expect(parseInline('**open').single.text, '**open');
  });

  test('only http, https, mailto and tg links become links', () {
    for (final u in ['https://a.b', 'http://a.b', 'mailto:x@y.z', 'tg://resolve?domain=x']) {
      expect(safeUrl(u), u);
    }
    for (final u in ['javascript:alert(1)', 'data:text/html,x', 'file:///etc', 'https://a b', 'vbscript:x', '//a.b']) {
      expect(safeUrl(u), isNull);
    }
    expect(parseInline('[x](javascript:alert(1))').every((x) => x.kind == MdInlineKind.text), isTrue);
  });

  test('server info keeps only known fields of the right type', () {
    expect(ServerInfo.parse(''), isNull);
    expect(ServerInfo.parse('{bad'), isNull);
    final v = ServerInfo.parse(
        '{"operator":{"name":"Op","about":5},"server":{"carriers":["udp",7],"ipv6":"yes","log_privacy":"loud"},'
        '"key":{"used_bytes":10,"limit_bytes":null,"expires_at":2000000000},"extra":1}')!;
    expect(v.operator!.name, 'Op');
    expect(v.operator!.about, isNull);
    expect(v.server!.carriers, ['udp']);
    expect(v.server!.ipv6, isNull);
    expect(v.server!.logPrivacy, isNull);
    expect(v.key!.expiresAt, 2000000000);
    // Stored and read back unchanged.
    expect(ServerInfo.parse(v.toJson())!.toJson(), v.toJson());
  });

  test('expiry: date, days left, expired', () {
    final now = DateTime.utc(2026, 12, 28, 12);
    final end = DateTime.utc(2026, 12, 31, 23, 59, 59).millisecondsSinceEpoch ~/ 1000;
    expect(expiryOf(end, now: now)!.label, 'until 2026-12-31, 4 days left');
    expect(expiryOf(end, now: now.subtract(const Duration(days: 30)))!.label, 'until 2026-12-31');
    expect(expiryOf(end, now: now.add(const Duration(days: 5)))!.label, 'expired');
    expect(expiryOf(null, now: now), isNull);
    expect(expiryOf(null, keyExpired: true, now: now)!.label, 'expired');
    expect(isKeyExpiredReason('The server closed the connection: this access key expired on 2026-12-31.'), isTrue);
    expect(isKeyExpiredReason('The server closed the connection: the traffic limit is used up.'), isFalse);
  });
}

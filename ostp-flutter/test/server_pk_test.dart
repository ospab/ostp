import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/ostp_profile.dart';
import 'package:ostp_client/models/server_key.dart';
import 'package:ostp_client/models/share_link.dart';

String _key(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

void main() {
  final good = _key(List.filled(32, 1));
  final other = _key(List.generate(32, (i) => i * 8 + 3));

  test('a key of 32 bytes in base64url is accepted as written', () {
    expect(good.length, 43);
    expect(checkServerKey(good), good);
    expect(checkServerKey(other), other);
    expect(checkServerKey('  $good\n'), good);
  });

  test('a damaged key is an error, never a quiet v5 profile', () {
    final lastB = '${good.substring(0, 42)}B'; // spare bits of the last character not zero
    for (final bad in [
      good.substring(0, 42),
      '${good}A',
      '${good.substring(0, 42)}!',
      '%%%',
      '',
      '$good=',
      lastB,
      base64.encode(List.filled(32, 1)), // standard alphabet with padding
    ]) {
      expect(() => checkServerKey(bad), throwsFormatException, reason: 'pk="$bad" should be refused');
      expect(() => ShareLink.parse('ostp://k@h:1?pk=$bad'), throwsFormatException, reason: 'link with pk="$bad"');
    }
  });

  test('the messages say what is wrong', () {
    expect(() => checkServerKey(good.substring(0, 42)), throwsA(predicate((e) => e.toString().contains('32 bytes'))));
    expect(() => checkServerKey('%%%'), throwsA(predicate((e) => e.toString().contains('base64url'))));
    expect(() => ShareLink.parse('ostp://k@h:1?pk=nope!'),
        throwsA(predicate((e) => e.toString().contains('invalid server key (pk)'))));
  });

  test('a link with pk keeps it and writes it back; one without has none', () {
    final l = ShareLink.parse('ostp://k1@vpn.example.com:443?type=uot&tls=1&path=%2Fx&name=A&pk=$good');
    expect(l.pk, good);
    expect(l.transport, 'uot');
    expect(l.toUri().endsWith('&pk=$good'), true, reason: l.toUri());
    expect(ShareLink.parse(l.toUri()).pk, good);

    final v5 = ShareLink.parse('ostp://k@h:1?type=udp');
    expect(v5.pk, isNull);
    expect(v5.toUri().contains('pk='), false);
    expect(ShareLink(key: 'k', host: 'h', port: 1, pk: good).toUri(), 'ostp://k@h:1?type=udp&pk=$good');
  });

  test('the profile keeps the key through storage, and says which protocol it is', () {
    final p = OstpProfile(id: 'a', name: 'n', serverAddr: 'h:1', accessKey: 'k', serverPk: good);
    expect(p.protocol, 'v6');
    final back = decodeProfiles(encodeProfiles([p])).single;
    expect(back.serverPk, good);
    expect(back.protocol, 'v6');

    // A profile saved by an older app has no key: it is v5 and stays so.
    final old = OstpProfile.fromJson({'id': 'b', 'serverAddr': 'h:1', 'accessKey': 'k'});
    expect(old.serverPk, '');
    expect(old.protocol, 'v5');
  });
}

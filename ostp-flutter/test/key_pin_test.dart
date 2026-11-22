import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/key_pin.dart';

void main() {
  test('the same key, or a key where there was none, is accepted', () {
    expect(pinAction('aaa', 'aaa'), PinAction.accept);
    expect(pinAction('', 'bbb'), PinAction.accept);
    expect(pinAction(null, 'bbb'), PinAction.accept);
    expect(pinAction('', ''), PinAction.accept);
  });

  test('a different key or a vanished key is asked about', () {
    expect(pinAction('aaa', 'bbb'), PinAction.ask);
    expect(pinAction('aaa', ''), PinAction.ask);
  });

  test('a refused key is not asked about again, another new key is', () {
    expect(pinAction('aaa', 'bbb', keptPk: 'bbb'), PinAction.keepOldSilently);
    expect(pinAction('aaa', 'ccc', keptPk: 'bbb'), PinAction.ask);
    expect(pinAction('aaa', '', keptPk: ''), PinAction.keepOldSilently);
    expect(pinAction('aaa', 'aaa', keptPk: 'bbb'), PinAction.accept);
  });

  test('the same server is host:port and carrier, case-insensitive', () {
    expect(pinKey('Example.com:443', 'tls'), pinKey(' example.com:443', 'tls'));
    expect(pinKey('example.com:443', 'tls'), isNot(pinKey('example.com:443', 'udp')));
    expect(pinKey('example.com:443', 'tls'), isNot(pinKey('example.com:444', 'tls')));
  });
}

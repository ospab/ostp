import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/server_dns.dart';

void main() {
  final off = <String, dynamic>{'enabled': false, 'takeover': false, 'block_doh_bypass': false, 'safe_search': false};
  final on = <String, dynamic>{'enabled': true, 'takeover': true, 'block_doh_bypass': true, 'safe_search': true};

  test('a switch flips the state into the manager action', () {
    expect(dnsToggle(off, 'filter').action, 'dns-enable');
    expect(dnsToggle(on, 'filter').action, 'dns-disable');
    expect(dnsToggle(off, 'takeover').action, 'dns-takeover-on');
    expect(dnsToggle(on, 'takeover').button, 'Turn off the takeover');
    expect(dnsToggle(off, 'safesearch').action, 'dns-safesearch-on');
    expect(dnsToggle(on, 'safesearch').action, 'dns-safesearch-off');
  });

  test('encrypted DNS needs the takeover', () {
    expect(dnsToggle(off, 'doh').disabled, true);
    expect(dnsToggle(off, 'doh').reason, isNotEmpty);
    final t = {...off, 'takeover': true};
    expect(dnsToggle(t, 'doh').disabled, false);
    expect(dnsToggle(t, 'doh').action, 'dns-doh-on');
    expect(dnsToggle(on, 'doh').action, 'dns-doh-off');
    expect(dnsStateLabel({...off, 'block_doh_bypass': true}, 'doh'), 'on, no effect');
    expect(dnsStateLabel(on, 'doh'), 'on');
  });

  test('every confirmation ends with the restart sentence and names a known action', () {
    for (final k in dnsKinds) {
      for (final d in [off, on]) {
        final t = dnsToggle(d, k);
        expect(t.text.endsWith(dnsRestart), true);
        expect(dnsActions.containsKey(t.action), true);
      }
    }
    expect(() => dnsToggle(off, 'nope'), throwsArgumentError);
  });

  test('an old server is recognised', () {
    expect(isOldServerError('the OSTP on the server is too old for the app; update it'), true);
    expect(isOldServerError("error: unrecognized subcommand 'dns'"), true);
    expect(isOldServerError('connection refused'), false);
  });
}

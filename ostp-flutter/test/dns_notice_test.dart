import 'package:flutter_test/flutter_test.dart';

import 'package:ostp_client/models/dns_notice.dart';
import 'package:ostp_client/models/ostp_profile.dart';
import 'package:ostp_client/models/share_link.dart';

OstpProfile _p({bool owndns = false, bool dnsall = false, String choice = ''}) => OstpProfile(
      id: 'a', name: 'n', serverAddr: 'h:1', accessKey: 'k', owndns: owndns, dnsall: dnsall, dnsChoice: choice);

void main() {
  test('the notice is asked only for servers that filter DNS and have no choice', () {
    expect(shouldAskDnsNotice(null), false);
    expect(shouldAskDnsNotice(_p()), false);
    expect(shouldAskDnsNotice(_p(choice: 'operator')), false);
    expect(shouldAskDnsNotice(_p(owndns: true)), true);
    expect(shouldAskDnsNotice(_p(dnsall: true)), true);
    expect(shouldAskDnsNotice(_p(owndns: true, choice: 'mine')), false);
    expect(shouldAskDnsNotice(_p(owndns: true, choice: 'bogus')), true);
  });

  test('effectiveDns', () {
    // profiles that do not filter DNS keep the previous behaviour
    expect(effectiveDns(_p(), null), '1.1.1.1');
    expect(effectiveDns(_p(), '9.9.9.9'), '9.9.9.9');
    expect(effectiveDns(_p(choice: 'operator'), '9.9.9.9'), '9.9.9.9');
    expect(effectiveDns(null, null), '1.1.1.1');
    expect(effectiveDns(_p(owndns: true, choice: 'operator'), '9.9.9.9'), '10.1.0.1');
    expect(effectiveDns(_p(dnsall: true, choice: 'public'), null), '1.1.1.1');
    expect(effectiveDns(_p(dnsall: true, choice: 'public'), '9.9.9.9'), '9.9.9.9');
    expect(effectiveDns(_p(owndns: true, choice: 'mine'), '9.9.9.9'), '9.9.9.9');
    expect(effectiveDns(_p(owndns: true), null), '1.1.1.1');
  });

  test('dnsall is parsed and written back like owndns', () {
    const uri = 'ostp://k1@vpn.example.com:443?type=uot&tls=1&sni=cdn.example.com&insecure=1&path=%2Fs3cr3t'
        '&tun=true&dns=1.1.1.1&owndns=true&dnsall=true&name=My%20VPN';
    final l = ShareLink.parse(uri);
    expect(l.owndns, true);
    expect(l.dnsall, true);
    expect(l.toUri(), uri);
    expect(ShareLink.parse('ostp://k@h:1').dnsall, false);
  });

  test('the profile keeps the flags and the choice through JSON', () {
    final back = OstpProfile.fromJson(_p(owndns: true, dnsall: true, choice: 'public').toJson());
    expect(back.owndns, true);
    expect(back.dnsall, true);
    expect(back.dnsChoice, 'public');
    final old = OstpProfile.fromJson({'id': 'x', 'serverAddr': 'h:1', 'accessKey': 'k'});
    expect(old.owndns, false);
    expect(old.dnsChoice, '');
  });
}

import 'ostp_profile.dart';

/// DNS notice of servers that filter DNS. Decision logic only, no UI.
/// A profile "filters DNS" when its share link carried `owndns` (the server
/// runs its own resolver, 10.1.0.1) or `dnsall` (the server answers every DNS
/// query and refuses DoT/DoH). Keep in step with ostp-gui/src/dns_notice.js.
const operatorDns = '10.1.0.1';
const publicDns = '1.1.1.1';
const dnsChoices = ['operator', 'public', 'mine'];

bool filtersDns(OstpProfile? p) => p != null && (p.owndns || p.dnsall);

/// True when the notice must be shown before connecting with this profile:
/// the server filters DNS and no choice is stored yet.
bool shouldAskDnsNotice(OstpProfile? p) => p != null && filtersDns(p) && !dnsChoices.contains(p.dnsChoice);

/// The DNS the tunnel gets. [settingsDns] is the app's own DNS setting once it
/// is checked to be an IP literal, or null when it is unset or invalid.
/// Without a setting the app has always used 1.1.1.1; profiles that do not
/// filter DNS, and "my settings" or no choice yet, keep exactly that.
String effectiveDns(OstpProfile? p, String? settingsDns) {
  final own = (settingsDns == null || settingsDns.isEmpty) ? publicDns : settingsDns;
  if (!filtersDns(p)) return own;
  if (p!.dnsChoice == 'operator') return operatorDns;
  return own; // 'public' is the app's own DNS or 1.1.1.1, which is `own`
}

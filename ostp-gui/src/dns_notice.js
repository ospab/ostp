// DNS notice of servers that filter DNS: the decision logic, free of the page
// so it can be run with plain node. A profile "filters DNS" when its share
// link carried owndns (the server runs its own resolver, 10.1.0.1) or dnsall
// (the server answers every DNS query and refuses DoT/DoH).

export const OPERATOR_DNS = '10.1.0.1';
export const PUBLIC_DNS = '1.1.1.1';
export const DNS_CHOICES = ['operator', 'public', 'mine'];

export const filtersDns = p => !!p && (!!p.owndns || !!p.dnsall);

// True when the notice must be shown before connecting with this profile:
// the server filters DNS and no choice is stored yet.
export function shouldAskDnsNotice(p) {
  return filtersDns(p) && !DNS_CHOICES.includes(p.dns_choice);
}

// The DNS the tunnel config gets. Profiles that do not filter DNS, and
// profiles with "my settings" or no choice yet, keep the app's setting.
export function effectiveDns(p, settingsDns) {
  const own = settingsDns || null;
  if (!filtersDns(p)) return own;
  if (p.dns_choice === 'operator') return OPERATOR_DNS;
  if (p.dns_choice === 'public') return own || PUBLIC_DNS;
  return own;
}

/// The DNS section of server management: which switches exist, which are
/// available, what each asks before it runs and which manager action it is.
/// Pure logic, no UI. Keep in step with ostp-gui/src/server_dns.js.
const dnsRestart = 'The service restarts and connected clients drop for a few seconds.';

/// The words of each action: the button that names it and the progress title.
const dnsActions = <String, ({String button, String busy})>{
  'dns-enable': (button: 'Turn the filter on', busy: 'Turning the DNS filter on'),
  'dns-disable': (button: 'Turn the filter off', busy: 'Turning the DNS filter off'),
  'dns-takeover-on': (button: 'Turn on the takeover', busy: 'Turning the DNS takeover on'),
  'dns-takeover-off': (button: 'Turn off the takeover', busy: 'Turning the DNS takeover off'),
  'dns-doh-on': (button: 'Block encrypted DNS', busy: 'Blocking encrypted DNS'),
  'dns-doh-off': (button: 'Allow encrypted DNS', busy: 'Allowing encrypted DNS'),
  'dns-safesearch-on': (button: 'Turn safe search on', busy: 'Turning safe search on'),
  'dns-safesearch-off': (button: 'Turn safe search off', busy: 'Turning safe search off'),
  'dns-update': (button: 'Update lists', busy: 'Updating the block lists'),
};

const dnsExplain = <String, String>{
  'filter': 'The DNS filter is a resolver on the server (block lists, safe search). By default it answers only queries sent to the '
      "server's own address, 10.1.0.1: a client gets the filter by using that address as its DNS, and every other resolver it asks is left alone.",
  'takeover': 'The takeover makes the server answer every DNS query of its clients, whichever resolver it was sent to. '
      'The apps of its users say so before their first connection.',
  'doh': 'Block encrypted DNS refuses DNS over TLS and HTTPS to public resolvers. It has an effect only while the takeover is on.',
  'safesearch': 'Safe search forces safe search on the big search engines.',
  'update': 'Update lists downloads the block lists now.',
};

const dnsKinds = ['filter', 'takeover', 'doh', 'safesearch'];

typedef _Switch = ({
  String flag,
  String on,
  String off,
  String askOn,
  String askOff,
  String noteOn,
  String noteOff,
});

const _switches = <String, _Switch>{
  'filter': (
    flag: 'enabled',
    on: 'dns-enable',
    off: 'dns-disable',
    askOn: 'Turn the DNS filter on?',
    askOff: 'Turn the DNS filter off?',
    noteOn: 'The server starts answering DNS queries sent to 10.1.0.1.',
    noteOff: 'Clients that use 10.1.0.1 as their DNS lose name resolution until they use another resolver.',
  ),
  'takeover': (
    flag: 'takeover',
    on: 'dns-takeover-on',
    off: 'dns-takeover-off',
    askOn: 'Turn on the takeover?',
    askOff: 'Turn off the takeover?',
    noteOn: 'The server will answer every DNS query of its clients, whichever resolver they ask. Their apps tell users about this before the first connection.',
    noteOff: 'The server goes back to answering only queries sent to its own address.',
  ),
  'doh': (
    flag: 'block_doh_bypass',
    on: 'dns-doh-on',
    off: 'dns-doh-off',
    askOn: 'Block encrypted DNS?',
    askOff: 'Allow encrypted DNS?',
    noteOn: 'DNS over TLS and HTTPS to public resolvers is refused while the takeover is on.',
    noteOff: 'Clients may use DNS over TLS and HTTPS again.',
  ),
  'safesearch': (
    flag: 'safe_search',
    on: 'dns-safesearch-on',
    off: 'dns-safesearch-off',
    askOn: 'Turn safe search on?',
    askOff: 'Turn safe search off?',
    noteOn: 'Big search engines get safe search for every client that uses the filter.',
    noteOff: 'Search engines stop being forced into safe search.',
  ),
};

/// What pressing a switch does: it flips the state in the `dns` object of
/// `ostp manage dns`. [disabled] and [reason] say when it cannot be pressed.
class DnsToggle {
  final String kind, action, button, title, text, reason;
  final bool on, disabled;
  const DnsToggle._(this.kind, this.action, this.button, this.title, this.text, this.reason, this.on, this.disabled);
}

DnsToggle dnsToggle(Map<String, dynamic> dns, String kind) {
  final sw = _switches[kind];
  if (sw == null) throw ArgumentError('unknown DNS switch $kind');
  final on = dns[sw.flag] == true;
  final action = on ? sw.off : sw.on;
  final blocked = kind == 'doh' && dns['takeover'] != true;
  return DnsToggle._(kind, action, dnsActions[action]!.button, on ? sw.askOff : sw.askOn,
      '${on ? sw.noteOff : sw.noteOn} $dnsRestart', blocked ? 'Works only while the takeover is on.' : '', on, blocked);
}

/// The status shown for a switch; blocking encrypted DNS has no effect
/// without the takeover.
String dnsStateLabel(Map<String, dynamic> dns, String kind) {
  final on = dns[_switches[kind]!.flag] == true;
  if (kind == 'doh' && on && dns['takeover'] != true) return 'on, no effect';
  return on ? 'on' : 'off';
}

/// A server older than the feature answers with the manager's "too old" error
/// or does not know the `dns` subcommand.
bool isOldServerError(String message) => message.contains('too old') || message.contains("unrecognized subcommand 'dns'");

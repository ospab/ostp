// The DNS section of server management: which switches exist, which are
// available, what each asks before it runs and which manager action it is.
// Pure logic, no DOM. Keep in step with ostp-flutter/lib/models/server_dns.dart.

export const DNS_RESTART = 'The service restarts and connected clients drop for a few seconds.';

// The words each action uses on its button (the confirmation button names the
// action) and in the progress window.
export const DNS_ACTIONS = {
  'dns-enable': { button: 'Turn the filter on', busy: 'Turning the DNS filter on' },
  'dns-disable': { button: 'Turn the filter off', busy: 'Turning the DNS filter off' },
  'dns-takeover-on': { button: 'Turn on the takeover', busy: 'Turning the DNS takeover on' },
  'dns-takeover-off': { button: 'Turn off the takeover', busy: 'Turning the DNS takeover off' },
  'dns-doh-on': { button: 'Block encrypted DNS', busy: 'Blocking encrypted DNS' },
  'dns-doh-off': { button: 'Allow encrypted DNS', busy: 'Allowing encrypted DNS' },
  'dns-safesearch-on': { button: 'Turn safe search on', busy: 'Turning safe search on' },
  'dns-safesearch-off': { button: 'Turn safe search off', busy: 'Turning safe search off' },
  'dns-update': { button: 'Update lists', busy: 'Updating the block lists' },
};

// The explanation shown with each switch, in plain words.
export const DNS_EXPLAIN = {
  filter: 'The DNS filter is a resolver on the server (block lists, safe search). By default it answers only queries sent to the '
    + 'server\'s own address, 10.1.0.1: a client gets the filter by using that address as its DNS, and every other resolver it asks is left alone.',
  takeover: 'The takeover makes the server answer every DNS query of its clients, whichever resolver it was sent to. '
    + 'The apps of its users say so before their first connection.',
  doh: 'Block encrypted DNS refuses DNS over TLS and HTTPS to public resolvers. It has an effect only while the takeover is on.',
  safesearch: 'Safe search forces safe search on the big search engines.',
  update: 'Update lists downloads the block lists now.',
};

const SWITCHES = {
  filter: {
    flag: d => d.enabled === true,
    on: 'dns-enable', off: 'dns-disable',
    askOn: 'Turn the DNS filter on?', askOff: 'Turn the DNS filter off?',
    noteOn: 'The server starts answering DNS queries sent to 10.1.0.1.',
    noteOff: 'Clients that use 10.1.0.1 as their DNS lose name resolution until they use another resolver.',
  },
  takeover: {
    flag: d => d.takeover === true,
    on: 'dns-takeover-on', off: 'dns-takeover-off',
    askOn: 'Turn on the takeover?', askOff: 'Turn off the takeover?',
    noteOn: 'The server will answer every DNS query of its clients, whichever resolver they ask. Their apps tell users about this before the first connection.',
    noteOff: 'The server goes back to answering only queries sent to its own address.',
  },
  doh: {
    flag: d => d.block_doh_bypass === true,
    on: 'dns-doh-on', off: 'dns-doh-off',
    askOn: 'Block encrypted DNS?', askOff: 'Allow encrypted DNS?',
    noteOn: 'DNS over TLS and HTTPS to public resolvers is refused while the takeover is on.',
    noteOff: 'Clients may use DNS over TLS and HTTPS again.',
  },
  safesearch: {
    flag: d => d.safe_search === true,
    on: 'dns-safesearch-on', off: 'dns-safesearch-off',
    askOn: 'Turn safe search on?', askOff: 'Turn safe search off?',
    noteOn: 'Big search engines get safe search for every client that uses the filter.',
    noteOff: 'Search engines stop being forced into safe search.',
  },
};

export const DNS_KINDS = Object.keys(SWITCHES);

// What pressing the switch `kind` does to the server state `dns` (the
// `dns` object of `ostp manage dns`): flips it. `disabled` and `reason` say
// when it cannot be pressed.
export function dnsToggle(dns, kind) {
  const sw = SWITCHES[kind];
  if (!sw) throw new Error(`unknown DNS switch ${kind}`);
  const on = sw.flag(dns || {});
  const action = on ? sw.off : sw.on;
  const blocked = kind === 'doh' && !(dns && dns.takeover === true);
  return {
    kind, on, action,
    button: DNS_ACTIONS[action].button,
    title: on ? sw.askOff : sw.askOn,
    text: `${on ? sw.noteOff : sw.noteOn} ${DNS_RESTART}`,
    disabled: blocked,
    reason: blocked ? 'Works only while the takeover is on.' : '',
  };
}

// The pressing of "Update lists".
export function dnsUpdate() {
  return {
    action: 'dns-update',
    button: DNS_ACTIONS['dns-update'].button,
    title: 'Update the block lists?',
    text: `The server downloads the lists now. ${DNS_RESTART}`,
  };
}

// `ostp manage dns` is missing on servers older than the feature: the manager
// says "too old", or the server's own parser says the subcommand is unknown.
export function isOldServerError(message) {
  const m = String(message || '');
  return m.includes('too old') || /unrecognized subcommand 'dns'/.test(m);
}

// The status shown for a switch: the doh switch has no effect without takeover.
export function dnsStateLabel(dns, kind) {
  const on = SWITCHES[kind].flag(dns || {});
  if (kind === 'doh' && on && !dns.takeover) return 'on, no effect';
  return on ? 'on' : 'off';
}

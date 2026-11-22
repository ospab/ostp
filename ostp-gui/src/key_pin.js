// Pinning of the server's key across subscription refreshes. A refresh must
// not swap the key of a server the app already knows for another one without
// the person's say: someone who can alter the subscription document could
// otherwise point the app at their own server. Same rule as the Android app's
// key_pin.dart.

// "The same server" across refreshes: host:port and carrier.
export const pinKey = (server, carrier) => `${String(server).trim().toLowerCase()}|${carrier}`;

// What to do with a fresh profile whose key is `newPk` ('' = none) when the
// stored profile of the same server and carrier has `oldPk`; `keptPk` is the
// new key the person already refused for this server.
//   'accept'          same key, or a key where there was none (v5 -> v6)
//   'keep-old-silent' the person already chose to keep the old key against this very key
//   'ask'             another key (or none any more) the person has not decided on
export function pinAction(oldPk, newPk, keptPk) {
  const old = oldPk || '';
  const now = newPk || '';
  if (!old || old === now) return 'accept';
  if (typeof keptPk === 'string' && keptPk === now) return 'keep-old-silent';
  return 'ask';
}

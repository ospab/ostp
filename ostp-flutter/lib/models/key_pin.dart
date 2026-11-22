/// Pinning of the server's key across subscription refreshes. A refresh must
/// not swap the key of a server the app already knows for another one without
/// the person's say: someone who can alter the subscription document could
/// otherwise point the app at their own server.
library;

enum PinAction {
  /// Take the fresh profile (same key, or a key where there was none: v5 -> v6).
  accept,

  /// The person already chose to keep the old key against this very new key.
  keepOldSilently,

  /// A different key (or none any more) the person has not decided on yet.
  ask,
}

/// Identifies "the same server" across refreshes: host:port and carrier.
String pinKey(String server, String carrier) => '${server.trim().toLowerCase()}|$carrier';

/// What to do with a freshly fetched profile whose key is [newPk] ('' = none)
/// when the stored profile of the same server and carrier has [oldPk].
/// [keptPk] is the new key the person already refused for this server.
PinAction pinAction(String? oldPk, String newPk, {String? keptPk}) {
  final old = oldPk ?? '';
  if (old.isEmpty || old == newPk) return PinAction.accept;
  if (keptPk != null && keptPk == newPk) return PinAction.keepOldSilently;
  return PinAction.ask;
}

/// The server's public key (`pk` of a link, protocol v6). Same rule as
/// ostp-core/src/server_key.rs `decode_key` and the desktop app's
/// server_pk.js: base64url without padding, exactly 32 bytes (43 characters).
/// A damaged key is an error and never a v5 profile, because that profile
/// would connect as v5 and fail against a server that speaks v6 only.
const serverKeyBytes = 32;

const _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const _notBase64Url = "a server key must be base64url (letters, digits, '-' and '_', no '=')";

/// The key as written (surrounding whitespace ignored). Throws
/// [FormatException] that says what is wrong.
String checkServerKey(String text) {
  final t = text.trim();
  if (!RegExp(r'^[A-Za-z0-9_-]*$').hasMatch(t) || t.length % 4 == 1) {
    throw const FormatException(_notBase64Url);
  }
  var bits = 0;
  var nbits = 0;
  var bytes = 0;
  for (final c in t.split('')) {
    bits = (bits << 6) | _alphabet.indexOf(c);
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      bytes += 1;
      bits &= (1 << nbits) - 1;
    }
  }
  // Leftover bits of the last character must be zero (canonical encoding).
  if (bits != 0) throw const FormatException(_notBase64Url);
  if (bytes != serverKeyBytes) {
    throw FormatException('a server key is $serverKeyBytes bytes (43 characters), this one is $bytes bytes');
  }
  return t;
}

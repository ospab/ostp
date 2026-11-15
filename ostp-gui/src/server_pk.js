// The server's public key (`pk` of a link, protocol v6): what a valid one
// looks like, free of the page so it can be run with plain node.
//
// Same rule as ostp-core/src/server_key.rs `decode_key`: base64url without
// padding, exactly 32 bytes (43 characters). A damaged key is an error and is
// never taken for a v5 profile, because that profile would connect as v5 and
// fail against a server that speaks v6 only.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export const SERVER_KEY_BYTES = 32;

const NOT_BASE64URL = "a server key must be base64url (letters, digits, '-' and '_', no '=')";

// The key as written (surrounding whitespace ignored), or throws an Error that
// says what is wrong.
export function checkServerKey(text) {
  const t = String(text ?? '').trim();
  if (!/^[A-Za-z0-9_-]*$/.test(t) || t.length % 4 === 1) throw new Error(NOT_BASE64URL);
  let bits = 0;
  let nbits = 0;
  let bytes = 0;
  for (const c of t) {
    bits = (bits << 6) | ALPHABET.indexOf(c);
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      bytes += 1;
      bits &= (1 << nbits) - 1;
    }
  }
  // Leftover bits of the last character must be zero (canonical encoding).
  if (bits !== 0) throw new Error(NOT_BASE64URL);
  if (bytes !== SERVER_KEY_BYTES) {
    throw new Error(`a server key is ${SERVER_KEY_BYTES} bytes (43 characters), this one is ${bytes} bytes`);
  }
  return t;
}

// The `pk=` value of a link: the key, or an Error that names the link.
export function linkPk(value) {
  try {
    return checkServerKey(value);
  } catch (e) {
    throw new Error(`The link has an invalid server key (pk): ${e.message}`);
  }
}

// What the profile editor says about the protocol of a profile.
export const protocolLabel = p => (p && p.server_pk ? 'v6' : 'v5');

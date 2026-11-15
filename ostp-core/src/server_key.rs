//! Text form of the server's static X25519 key (protocol v6).
//!
//! Both halves are 32 bytes written as unpadded base64url: the public half in
//! links and subscriptions (`pk=`), the private half in the server config
//! (`protocol.server_key`). One encoding for both keeps a pasted key easy to
//! check by eye: 43 characters.

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// 32 bytes as unpadded base64url (43 characters).
pub fn encode_key(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Reads a key written by [`encode_key`]. Surrounding whitespace is ignored;
/// anything that is not exactly 32 bytes of base64url is an error.
pub fn decode_key(text: &str) -> Result<[u8; 32]> {
    let text = text.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| anyhow!("a server key must be base64url (letters, digits, '-' and '_', no '=')"))?;
    if bytes.len() != 32 {
        bail!("a server key is 32 bytes (43 characters), this one is {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::{generate_server_key, server_public_key};

    #[test]
    fn a_key_round_trips_in_43_characters() {
        let (private, public) = generate_server_key();
        for k in [private, public] {
            let text = encode_key(&k);
            assert_eq!(text.len(), 43);
            assert!(!text.contains('=') && !text.contains('+') && !text.contains('/'));
            assert_eq!(decode_key(&text).unwrap(), k);
        }
        assert_eq!(server_public_key(&private), public);
    }

    #[test]
    fn a_wrong_length_or_alphabet_is_refused() {
        let good = encode_key(&[7u8; 32]);
        assert!(decode_key(&good).is_ok());
        assert!(decode_key(&good[..42]).is_err(), "too short");
        assert!(decode_key(&format!("{good}A")).is_err(), "too long");
        assert!(decode_key("").is_err());
        assert!(decode_key(&format!("{}!", &good[..42])).is_err(), "bad character");
        // The standard alphabet is not the one used here.
        let std_form = base64::engine::general_purpose::STANDARD.encode([0xfbu8; 32]);
        assert!(decode_key(&std_form).is_err());
    }
}

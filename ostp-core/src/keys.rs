//! Random keys, tokens and URL paths. All from the thread-local CSPRNG.

use rand::{Rng, RngCore};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const LOWER_ALNUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 128 random bits as 32 lowercase hex characters.
pub fn access_key_hex() -> String {
    let mut k = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut k);
    hex_of(&k)
}

/// 128 random bits as unpadded standard base64 (22 characters).
pub fn access_key_base64() -> String {
    use base64::Engine;
    let mut k = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut k);
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(k)
}

fn pick(alphabet: &[u8], n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

/// `n` characters from `A-Za-z0-9`.
pub fn random_alnum(n: usize) -> String {
    pick(ALNUM, n)
}

/// `n` characters from `a-z0-9`.
pub fn random_lower_alnum(n: usize) -> String {
    pick(LOWER_ALNUM, n)
}

/// `n` lowercase hex characters.
pub fn random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| char::from_digit(rng.gen_range(0..16u32), 16).unwrap()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_lengths() {
        let k = access_key_hex();
        assert_eq!(k.len(), 32);
        assert!(k.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(access_key_base64().len(), 22);
        assert_eq!(random_alnum(24).len(), 24);
        assert!(random_alnum(64).bytes().all(|b| b.is_ascii_alphanumeric()));
        assert!(random_lower_alnum(64).bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()));
        let h = random_hex(32);
        assert_eq!(h.len(), 32);
        assert!(h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(access_key_hex(), access_key_hex());
    }
}

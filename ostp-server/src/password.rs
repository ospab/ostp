//! Panel passwords: PBKDF2-HMAC-SHA256 with a random salt.
//!
//! Stored as `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`. Configs
//! written before 0.4.7 hold a bare SHA-256 hex digest; it is still accepted
//! at sign-in, and `ostp panel status` asks to set the password again, which
//! stores the new form.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "pbkdf2-sha256";
/// A sign-in costs a fraction of a second on a VPS and a few seconds on a
/// MIPS router; a leaked config costs an attacker the same per guess.
const ITERATIONS: u32 = 300_000;

fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    // One output block (32 bytes = one SHA-256), so T1 is the whole key.
    let base = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
    let mut mac = base.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..iterations {
        let mut mac = base.clone();
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// The string to store in `api.password_hash`.
pub fn hash(password: &str) -> String {
    let salt: [u8; 16] = rand::random();
    let key = pbkdf2(password.as_bytes(), &salt, ITERATIONS);
    format!("{PREFIX}${ITERATIONS}${}${}", hex::encode(salt), hex::encode(key))
}

/// A bare SHA-256 digest from before 0.4.7.
pub fn is_legacy(stored: &str) -> bool {
    !stored.starts_with(PREFIX) && stored.len() == 64 && stored.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn verify(password: &str, stored: &str) -> bool {
    if is_legacy(stored) {
        let digest = <Sha256 as sha2::Digest>::digest(password.as_bytes());
        return bool::from(hex::encode(digest).as_bytes().ct_eq(stored.to_ascii_lowercase().as_bytes()));
    }
    let mut parts = stored.split('$');
    let (Some(PREFIX), Some(iter), Some(salt), Some(expected), None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(iterations), Ok(salt), Ok(expected)) = (iter.parse::<u32>(), hex::decode(salt), hex::decode(expected)) else {
        return false;
    };
    if iterations == 0 || iterations > 10_000_000 {
        return false;
    }
    let key = pbkdf2(password.as_bytes(), &salt, iterations);
    bool::from(key.as_slice().ct_eq(&expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_vector() {
        // RFC 7914 §11, PBKDF2-HMAC-SHA256("passwd", "salt", 1), first 32 bytes.
        assert_eq!(
            hex::encode(pbkdf2(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn hash_then_verify() {
        let h = hash("correct horse");
        assert!(h.starts_with("pbkdf2-sha256$300000$"));
        assert!(verify("correct horse", &h));
        assert!(!verify("wrong", &h));
        assert_ne!(h, hash("correct horse"), "a fresh salt every time");
    }

    #[test]
    fn legacy_sha256_still_signs_in() {
        let legacy = hex::encode(<Sha256 as sha2::Digest>::digest(b"old password"));
        assert!(is_legacy(&legacy));
        assert!(verify("old password", &legacy));
        assert!(!verify("other", &legacy));
        assert!(!verify("x", "garbage"));
    }
}

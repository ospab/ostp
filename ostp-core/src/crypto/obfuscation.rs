use sha2::Sha256;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

pub fn derive_obfuscation_key(access_key: &[u8]) -> [u8; 8] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(access_key);
    let result = hasher.finalize();
    let mut key = [0u8; 8];
    key.copy_from_slice(&result[0..8]);
    key
}

pub fn derive_psk(access_key: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(access_key);
    hasher.update(b"-ostp-psk-salt");
    let result = hasher.finalize();
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&result);
    psk
}

/// Derives a unique 4-byte session_id mask using HMAC-SHA256(key, nonce).
/// Because nonce is strictly monotonic, each packet gets a cryptographically
/// independent mask — consecutive headers are indistinguishable from random noise.
fn derive_session_mask(key: &[u8; 8], nonce: u64) -> [u8; 4] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&nonce.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&result[..4]);
    mask
}

/// Wire layout for DATA packets:
///   [0..4]   = session_id XOR HMAC(obf_key, nonce)[0..4]   ← masked, unique per-packet
///   [4..12]  = nonce, plaintext                             ← needed by receiver to derive mask
///   [12..]   = AEAD ciphertext                              ← authenticates everything
///
/// The nonce is sent in plaintext but this is intentional and safe:
///   - It is authenticated by the AEAD tag; tampering is detected.
///   - The session_id mask changes with every packet, breaking header correlation.
///   - The ciphertext is fully opaque; only nonce sequence is visible.
pub fn obfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        // Read nonce from bytes 4..12 (plaintext on wire)
        let nonce = u64::from_be_bytes([
            raw[4], raw[5], raw[6], raw[7],
            raw[8], raw[9], raw[10], raw[11],
        ]);
        // Mask only session_id bytes using nonce-derived mask
        let mask = derive_session_mask(key, nonce);
        for i in 0..4 {
            raw[i] ^= mask[i];
        }
        // nonce bytes 4..12 remain as-is (plaintext, authenticated by AEAD)
    } else if raw.len() >= 4 {
        // Handshake packets: mask session_id with a fixed handshake-phase mask
        // u64::MAX used as sentinel to produce a distinct HMAC output from any data nonce
        let mask = derive_session_mask(key, u64::MAX);
        for i in 0..4 {
            raw[i] ^= mask[i];
        }
    }
}

pub fn deobfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        // Read nonce plaintext from bytes 4..12
        let nonce = u64::from_be_bytes([
            raw[4], raw[5], raw[6], raw[7],
            raw[8], raw[9], raw[10], raw[11],
        ]);
        // Derive same mask and unmask session_id
        let mask = derive_session_mask(key, nonce);
        for i in 0..4 {
            raw[i] ^= mask[i];
        }
    } else if raw.len() >= 4 {
        let mask = derive_session_mask(key, u64::MAX);
        for i in 0..4 {
            raw[i] ^= mask[i];
        }
    }
}

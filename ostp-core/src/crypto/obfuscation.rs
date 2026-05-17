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

/// Wire layout for DATA packets:
///   [0..4]   = session_id XOR mask[0..4]
///   [4..12]  = nonce XOR mask[4..12]
///   [12..]   = AEAD ciphertext
///   mask = HMAC-SHA256(obf_key, ciphertext_sample[0..32])
///
/// Wire layout for HANDSHAKE packets:
///   [0..6]   = (session_id || noise_len) XOR mask[0..6]
///   [6..]    = noise_payload || random_padding
///   mask = HMAC-SHA256(obf_key, noise_payload_sample[0..32])
///
/// In both cases, the mask is derived from the payload that follows the header.
/// Since the payload contains cryptographically random data (AEAD ciphertext
/// or Noise ephemeral key), the mask is unique per packet, making the entire
/// wire output indistinguishable from random noise.
pub fn obfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        let header_len = 12;
        if raw.len() > header_len {
            let ciphertext = &raw[header_len..];
            let mask = derive_payload_mask(key, ciphertext);

            for i in 0..12 {
                raw[i] ^= mask[i];
            }
        }
    } else if is_handshake && raw.len() > 6 {
        // Handshake: sample the Noise payload (starts at byte 6) to derive
        // a per-packet mask. The Noise payload begins with a random ephemeral
        // key, so the mask will be unique for every handshake.
        let payload = &raw[6..];
        let mask = derive_payload_mask(key, payload);

        for i in 0..6 {
            raw[i] ^= mask[i];
        }
    }
}

pub fn deobfuscate_header_inplace(
    header: &mut [u8; 12],
    ciphertext: &[u8],
    key: &[u8; 8],
    is_handshake: bool,
) {
    if !is_handshake {
        let mask = derive_payload_mask(key, ciphertext);
        for i in 0..12 {
            header[i] ^= mask[i];
        }
    }
    // Handshake deobfuscation is not done via this function — use deobfuscate_packet_inplace
}

pub fn deobfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        let (header_slice, ciphertext) = raw.split_at_mut(12);
        let mut header = [0u8; 12];
        header.copy_from_slice(header_slice);
        deobfuscate_header_inplace(&mut header, ciphertext, key, is_handshake);
        header_slice.copy_from_slice(&header);
    } else if is_handshake && raw.len() > 6 {
        // Handshake: the payload (Noise data) starts at byte 6,
        // and was NOT masked — only the header [0..6] was.
        // Derive the same mask from the unmasked payload.
        let payload = &raw[6..];
        let mask = derive_payload_mask(key, payload);

        for i in 0..6 {
            raw[i] ^= mask[i];
        }
    }
}

/// Derives a 32-byte mask from a payload sample using HMAC-SHA256.
/// Used by both data and handshake obfuscation to produce per-packet unique masks.
fn derive_payload_mask(key: &[u8; 8], payload: &[u8]) -> [u8; 32] {
    let mut sample = [0u8; 32];
    let take_len = payload.len().min(32);
    sample[..take_len].copy_from_slice(&payload[..take_len]);

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&sample);
    let result = mac.finalize().into_bytes();
    let mut mask = [0u8; 32];
    mask.copy_from_slice(&result);
    mask
}

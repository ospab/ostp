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
/// Used strictly for handshake phase obfuscation.
fn derive_session_mask(key: &[u8; 8], nonce: u64) -> [u8; 4] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&nonce.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut mask = [0u8; 4];
    mask.copy_from_slice(&result[..4]);
    mask
}

/// Wire layout for DATA packets:
///   [0..4]   = session_id XOR HMAC(obf_key, ciphertext_sample)[0..4]
///   [4..12]  = nonce XOR HMAC(obf_key, ciphertext_sample)[4..12]
///   [12..]   = AEAD ciphertext (at least 16 bytes tag)
///
/// Because the ciphertext sample is different for every packet, the derived
/// mask is cryptographically random and independent for each packet.
/// Thus, both session_id and nonce are completely masked and indistinguishable
/// from pure random noise on the wire.
pub fn obfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        let header_len = 12;
        if raw.len() > header_len {
            let ciphertext = &raw[header_len..];
            let mut sample = [0u8; 32];
            let take_len = ciphertext.len().min(32);
            sample[..take_len].copy_from_slice(&ciphertext[..take_len]);

            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(&sample);
            let mask_result = mac.finalize().into_bytes();

            // Mask the entire 12-byte header (session_id + nonce)
            for i in 0..12 {
                raw[i] ^= mask_result[i];
            }
        }
    } else if raw.len() >= 4 {
        // Handshake packets: mask session_id with a fixed handshake-phase mask
        let mask = derive_session_mask(key, u64::MAX);
        for i in 0..4 {
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
        let mut sample = [0u8; 32];
        let take_len = ciphertext.len().min(32);
        sample[..take_len].copy_from_slice(&ciphertext[..take_len]);

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&sample);
        let mask_result = mac.finalize().into_bytes();

        // Unmask the entire 12-byte header
        for i in 0..12 {
            header[i] ^= mask_result[i];
        }
    } else {
        let mask = derive_session_mask(key, u64::MAX);
        for i in 0..4 {
            header[i] ^= mask[i];
        }
    }
}

pub fn deobfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        let (header_slice, ciphertext) = raw.split_at_mut(12);
        let mut header = [0u8; 12];
        header.copy_from_slice(header_slice);
        deobfuscate_header_inplace(&mut header, ciphertext, key, is_handshake);
        header_slice.copy_from_slice(&header);
    } else if raw.len() >= 4 {
        let mask = derive_session_mask(key, u64::MAX);
        for i in 0..4 {
            raw[i] ^= mask[i];
        }
    }
}

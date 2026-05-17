// =============================================================================
// OSTP Key Derivation — Kerckhoffs's Principle
// =============================================================================
//
// All protocol secrets (PSK, obfuscation key, padding parameters) are derived
// exclusively from the access key using HKDF-SHA256. There are NO hardcoded
// salt strings, protocol identifiers, or magic constants in this module.
//
// An adversary who reverse-engineers the binary sees only generic HMAC/SHA-256
// operations with no protocol-specific strings to search for. Building a DPI
// filter requires knowledge of the access key.
// =============================================================================

use sha2::Sha256;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

// ── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────────────
// Implemented inline to avoid adding a dependency. Uses only hmac + sha2.

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    prk
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to `len` bytes.
/// T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        t = block.to_vec();
        okm.extend_from_slice(&t[..t.len().min(len - okm.len() + t.len()).min(t.len())]);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    okm
}

/// Derive all protocol secrets from a single access key.
/// Returns (obfuscation_key, psk, handshake_pad_min, handshake_pad_max).
///
/// The derivation uses the access key as both IKM and salt material,
/// split into two halves. No fixed strings are used — the access key
/// alone determines all derived values.
pub struct DerivedSecrets {
    pub obfuscation_key: [u8; 8],
    pub psk: [u8; 32],
    pub handshake_pad_min: usize,
    pub handshake_pad_max: usize,
}

pub fn derive_all_secrets(access_key: &[u8]) -> DerivedSecrets {
    // Split the key hash into two halves for salt/info separation.
    // This avoids using any hardcoded strings while still providing
    // domain separation between the derived values.
    use sha2::Digest;
    let key_hash = sha2::Sha256::digest(access_key);
    let salt = &key_hash[..16];
    let info_base = &key_hash[16..];

    // Extract PRK from access key using its own hash as salt
    let prk = hkdf_extract(salt, access_key);

    // Derive obfuscation key (8 bytes) — info = key_hash[16..] || 0x01
    let mut obf_info = info_base.to_vec();
    obf_info.push(0x01);
    let obf_bytes = hkdf_expand(&prk, &obf_info, 8);
    let mut obfuscation_key = [0u8; 8];
    obfuscation_key.copy_from_slice(&obf_bytes);

    // Derive PSK (32 bytes) — info = key_hash[16..] || 0x02
    let mut psk_info = info_base.to_vec();
    psk_info.push(0x02);
    let psk_bytes = hkdf_expand(&prk, &psk_info, 32);
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&psk_bytes);

    // Derive handshake padding range (2 bytes) — info = key_hash[16..] || 0x03
    // This makes different access keys produce different handshake sizes,
    // preventing DPI from building a universal size-based filter.
    let mut pad_info = info_base.to_vec();
    pad_info.push(0x03);
    let pad_bytes = hkdf_expand(&prk, &pad_info, 2);
    // Map to range: min ∈ [16..80], max ∈ [min+48..min+176]
    let pad_min = 16 + (pad_bytes[0] as usize % 64);       // 16-79
    let pad_max = pad_min + 48 + (pad_bytes[1] as usize % 128); // +48..+175

    DerivedSecrets {
        obfuscation_key,
        psk,
        handshake_pad_min: pad_min,
        handshake_pad_max: pad_max,
    }
}

// ── Legacy API (delegates to derive_all_secrets) ─────────────────────────────

pub fn derive_obfuscation_key(access_key: &[u8]) -> [u8; 8] {
    derive_all_secrets(access_key).obfuscation_key
}

pub fn derive_psk(access_key: &[u8]) -> [u8; 32] {
    derive_all_secrets(access_key).psk
}

// ── Wire Obfuscation ─────────────────────────────────────────────────────────

/// Derives a per-packet mask from the payload following the header.
/// Used by both data and handshake packets so every mask is unique.
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
}

pub fn deobfuscate_packet_inplace(raw: &mut [u8], key: &[u8; 8], is_handshake: bool) {
    if !is_handshake && raw.len() >= 12 {
        let (header_slice, ciphertext) = raw.split_at_mut(12);
        let mut header = [0u8; 12];
        header.copy_from_slice(header_slice);
        deobfuscate_header_inplace(&mut header, ciphertext, key, is_handshake);
        header_slice.copy_from_slice(&header);
    } else if is_handshake && raw.len() > 6 {
        let payload = &raw[6..];
        let mask = derive_payload_mask(key, payload);

        for i in 0..6 {
            raw[i] ^= mask[i];
        }
    }
}

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

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
#[derive(Clone)]
pub struct DerivedSecrets {
    pub obfuscation_key: [u8; 8],
    pub psk: [u8; 32],
    pub handshake_pad_min: usize,
    pub handshake_pad_max: usize,
}
// NOTE: the junk marker is NOT part of DerivedSecrets — it is time-rotating and
// derived separately per window via `derive_junk_marker` (see below), so it
// carries no static per-user signature.

/// OSTP wire protocol version. Mixed into key derivation (NOT sent on the
/// wire) so peers running incompatible versions derive entirely different
/// secrets and therefore cannot deobfuscate / decrypt each other's traffic.
///
/// This is a hard, deterministic version gate that needs NO plaintext version
/// byte on the wire — a constant marker would defeat the project's stealth
/// north-star ("no recognizable header"). A pre-0.4.0 client (which derived
/// without a version) produces a different obfuscation key, so a 0.4.0 server
/// cannot recover its handshake header and rejects it as an unauthorized probe.
///
/// Bump this on any wire-breaking protocol change. 0.4.0 = version 4;
/// version 5 (0.4.x hardening) moved transport keys from the handshake hash to
/// Noise's Split() output — a wire-breaking crypto change, so old peers must not
/// interop (they would derive different session keys and fail decryption).
pub const PROTOCOL_VERSION: u8 = 5;

pub fn derive_all_secrets(access_key: &[u8]) -> DerivedSecrets {
    derive_all_secrets_versioned(access_key, PROTOCOL_VERSION)
}

/// Version-parameterised derivation. `derive_all_secrets` always pins the
/// current `PROTOCOL_VERSION`; this form exists so tests can prove that a
/// different version yields incompatible secrets (the version gate).
pub(crate) fn derive_all_secrets_versioned(access_key: &[u8], version: u8) -> DerivedSecrets {
    // Split the key hash into two halves for salt/info separation; a
    // trailing byte per output separates the derived values. Public labels
    // would do the same job: the access key is the only secret here.
    use sha2::Digest;
    let key_hash = sha2::Sha256::digest(access_key);
    let salt = &key_hash[..16];
    let info_base = &key_hash[16..];

    // Mix the protocol version into the IKM so a different version produces a
    // completely different PRK → different obf_key / psk / padding. This is the
    // wire-version gate: it is invisible on the wire (only the derived output,
    // which is already indistinguishable from random, ever leaves the host).
    let mut ikm = Vec::with_capacity(access_key.len() + 1);
    ikm.extend_from_slice(access_key);
    ikm.push(version);

    // Extract PRK from version-tagged access key using its hash as salt
    let prk = hkdf_extract(salt, &ikm);

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

/// Window length (seconds) for the rotating junk marker. The marker changes
/// every window, so junk carries no static per-user fingerprint on the wire;
/// the server checks the current and previous window to absorb clock skew.
pub const JUNK_MARKER_WINDOW_SECS: u64 = 60;

/// The current junk-marker time window (unix seconds / window length).
pub fn current_junk_window() -> u64 {
    crate::sys::unix_secs() / JUNK_MARKER_WINDOW_SECS
}

/// Derive the 4-byte junk marker for a given time `window`.
///
/// Uses the same version-gated HKDF scheme as [`derive_all_secrets`], with the
/// window folded into the `info` (label byte `0x04`). Folding in the window
/// makes the marker rotate: to an on-path observer the junk prefix changes every
/// window (no fixed signature), and a captured marker is only valid for ~1
/// window. Only a holder of the access key can compute it, so an outsider cannot
/// forge a silently-dropped junk packet.
pub fn derive_junk_marker(access_key: &[u8], window: u64) -> [u8; 4] {
    derive_junk_marker_versioned(access_key, window, PROTOCOL_VERSION)
}

pub(crate) fn derive_junk_marker_versioned(access_key: &[u8], window: u64, version: u8) -> [u8; 4] {
    use sha2::Digest;
    let key_hash = sha2::Sha256::digest(access_key);
    let salt = &key_hash[..16];
    let info_base = &key_hash[16..];

    let mut ikm = Vec::with_capacity(access_key.len() + 1);
    ikm.extend_from_slice(access_key);
    ikm.push(version);
    let prk = hkdf_extract(salt, &ikm);

    // info = key_hash[16..] || 0x04 || window(LE) — same label byte as before,
    // now parameterised by the time window.
    let mut info = info_base.to_vec();
    info.push(0x04);
    info.extend_from_slice(&window.to_le_bytes());
    let bytes = hkdf_expand(&prk, &info, 4);
    let mut marker = [0u8; 4];
    marker.copy_from_slice(&bytes);
    marker
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

#[cfg(test)]
#[path = "obfuscation_tests.rs"]
mod obfuscation_tests;

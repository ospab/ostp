// =============================================================================
// OSTP key schedule and header protection
// =============================================================================
//
// Kerckhoffs's principle: everything in this file is public, the labels
// included. The only secret input is the user's access key; every value below
// is derived from it with HKDF-SHA256 (RFC 5869), and header protection
// follows QUIC's ChaCha20 construction (RFC 9001 §5.4.4).
// =============================================================================

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use sha2::Sha256;

/// OSTP wire protocol version. It is part of every HKDF label below, so
/// peers on different versions derive different keys: a handshake from an
/// older client does not unmask or decrypt on a newer server and is dropped
/// like any other unauthenticated packet. Nothing on the wire carries it.
///
/// History: 4 = 0.4.0; 5 = transport keys from Noise's Split(); 6 = RFC 5869
/// labels, 256-bit RFC 9001 header protection, Noise prologue, RFC 6455
/// frames after an HTTP upgrade.
pub const PROTOCOL_VERSION: u8 = 6;

/// Key for header protection (RFC 9001 §5.4): 256 bits for ChaCha20.
pub type HeaderKey = [u8; 32];

/// Every secret derived from one access key.
#[derive(Clone)]
pub struct DerivedSecrets {
    /// Header protection key (the historical field name is kept).
    pub obfuscation_key: HeaderKey,
    /// Noise pre-shared key (the `psk0` of `NNpsk0`).
    pub psk: [u8; 32],
    pub handshake_pad_min: usize,
    pub handshake_pad_max: usize,
}
// The junk marker is not part of DerivedSecrets: it rotates with time and is
// derived per window by `derive_junk_marker`.

/// `ostp v6 <purpose>`: the HKDF-Expand info label (RFC 5869 §3.2) for one
/// output. Labels separate the outputs from each other and from other versions.
fn label(version: u8, purpose: &str) -> Vec<u8> {
    format!("ostp v{version} {purpose}").into_bytes()
}

/// HKDF-Extract with no salt (RFC 5869 §2.2: a string of HashLen zeros),
/// the access key as input keying material. The access key is 128 random bits,
/// so a salt adds nothing.
fn prk(access_key: &[u8]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(None, access_key)
}

fn expand<const N: usize>(hk: &Hkdf<Sha256>, info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    hk.expand(info, &mut out).expect("HKDF-SHA256 output of at most 255 blocks");
    out
}

pub fn derive_all_secrets(access_key: &[u8]) -> DerivedSecrets {
    derive_all_secrets_versioned(access_key, PROTOCOL_VERSION)
}

/// [`derive_all_secrets`] for any version, so tests can show that another
/// version yields unrelated secrets.
pub(crate) fn derive_all_secrets_versioned(access_key: &[u8], version: u8) -> DerivedSecrets {
    let hk = prk(access_key);
    let obfuscation_key = expand::<32>(&hk, &label(version, "header protection"));
    let psk = expand::<32>(&hk, &label(version, "noise psk"));
    // Per-key handshake padding, so one size filter does not fit every user:
    // min in [16, 80), max in [min + 48, min + 176).
    let pad = expand::<2>(&hk, &label(version, "handshake padding"));
    let pad_min = 16 + (pad[0] as usize % 64);
    let pad_max = pad_min + 48 + (pad[1] as usize % 128);
    DerivedSecrets { obfuscation_key, psk, handshake_pad_min: pad_min, handshake_pad_max: pad_max }
}

/// Window length (seconds) for the rotating junk marker. The marker changes
/// every window, so junk carries no static per-user fingerprint on the wire;
/// the server checks the current and previous window to absorb clock skew.
pub const JUNK_MARKER_WINDOW_SECS: u64 = 60;

/// The current junk-marker time window (unix seconds / window length).
pub fn current_junk_window() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / JUNK_MARKER_WINDOW_SECS)
        .unwrap_or(0)
}

/// The 4-byte junk marker for a time `window`: `ostp v6 junk marker` with the
/// window (big-endian) appended to the label. It rotates every window and only
/// a holder of the access key can compute it, so an outsider cannot forge a
/// silently dropped junk packet.
pub fn derive_junk_marker(access_key: &[u8], window: u64) -> [u8; 4] {
    derive_junk_marker_versioned(access_key, window, PROTOCOL_VERSION)
}

pub(crate) fn derive_junk_marker_versioned(access_key: &[u8], window: u64, version: u8) -> [u8; 4] {
    let mut info = label(version, "junk marker");
    info.extend_from_slice(&window.to_be_bytes());
    expand::<4>(&prk(access_key), &info)
}

pub fn derive_obfuscation_key(access_key: &[u8]) -> HeaderKey {
    derive_all_secrets(access_key).obfuscation_key
}

pub fn derive_psk(access_key: &[u8]) -> [u8; 32] {
    derive_all_secrets(access_key).psk
}

// ── Header protection (RFC 9001 §5.4) ────────────────────────────────────────

/// Bytes of ciphertext sampled for the mask (RFC 9001 §5.4.2).
pub const HP_SAMPLE_LEN: usize = 16;

/// The header mask for a packet, from the 16 bytes of ciphertext right after
/// the header (RFC 9001 §5.4.4): the first 4 sample bytes are the ChaCha20
/// block counter (little-endian), the other 12 the nonce, and the mask is the
/// keystream for 5 zero bytes, here extended to the 12 header bytes OSTP masks.
/// `None` when there is not enough ciphertext: such a packet is invalid anyway
/// (an AEAD tag alone is 16 bytes).
fn header_mask(key: &HeaderKey, ciphertext: &[u8]) -> Option<[u8; 12]> {
    let sample = ciphertext.get(..HP_SAMPLE_LEN)?;
    let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
    let nonce: [u8; 12] = sample[4..].try_into().unwrap();
    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.seek(u64::from(counter) * 64);
    let mut mask = [0u8; 12];
    cipher.apply_keystream(&mut mask);
    Some(mask)
}

/// Header length: DATA packets `session_id (4) || nonce (8)`, HANDSHAKE
/// packets `session_id (4) || noise_len (2)`.
fn header_len(is_handshake: bool) -> usize {
    if is_handshake { 6 } else { 12 }
}

/// Masks (or unmasks: XOR is its own inverse) the header in place.
///
/// Wire layout:
///   DATA:      [session_id ^ m[0..4]] [nonce ^ m[4..12]] [AEAD ciphertext ...]
///   HANDSHAKE: [session_id ^ m[0..4]] [noise_len ^ m[4..6]] [Noise message || padding]
/// with m = header_mask(key, the 16 bytes after the header). Those bytes are
/// AEAD ciphertext or a Noise ephemeral key, so every packet gets a new mask
/// and the whole datagram is indistinguishable from random bytes.
fn protect_header(raw: &mut [u8], key: &HeaderKey, is_handshake: bool) {
    let hl = header_len(is_handshake);
    if raw.len() < hl + HP_SAMPLE_LEN {
        return;
    }
    let (header, rest) = raw.split_at_mut(hl);
    if let Some(mask) = header_mask(key, rest) {
        for (b, m) in header.iter_mut().zip(mask) {
            *b ^= m;
        }
    }
}

pub fn obfuscate_packet_inplace(raw: &mut [u8], key: &HeaderKey, is_handshake: bool) {
    protect_header(raw, key, is_handshake);
}

pub fn deobfuscate_packet_inplace(raw: &mut [u8], key: &HeaderKey, is_handshake: bool) {
    protect_header(raw, key, is_handshake);
}

/// Unmasks a DATA header that was copied out of the packet.
pub fn deobfuscate_header_inplace(header: &mut [u8; 12], ciphertext: &[u8], key: &HeaderKey, is_handshake: bool) {
    if is_handshake {
        return;
    }
    if let Some(mask) = header_mask(key, ciphertext) {
        for (b, m) in header.iter_mut().zip(mask) {
            *b ^= m;
        }
    }
}

#[cfg(test)]
#[path = "obfuscation_tests.rs"]
mod obfuscation_tests;

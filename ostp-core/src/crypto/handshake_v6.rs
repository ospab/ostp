//! The v6 handshake datagram as it appears on the wire.
//!
//! ```text
//! [nonce:12][tag:4][ ChaCha20(mask_key, nonce) XOR body ]
//! body = [session_id:4][noise_len:2][noise message][random padding]
//! ```
//!
//! In v5 the Noise message was sent as it is, so the ephemeral X25519 key sat
//! in clear at a fixed offset: 32 bytes that are always a curve point with the
//! top bit zero. Here nothing of the Noise message is visible: every byte after
//! the nonce is a keystream byte XOR data, and the nonce is random.
//!
//! The tag lets a server with many access keys find the right one with one
//! HMAC per key instead of one curve operation per key. It proves nothing by
//! itself (a captured datagram replays with its tag); the Noise message behind
//! it does the authentication.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub const HS_NONCE_LEN: usize = 12;
pub const HS_TAG_LEN: usize = 4;
/// Bytes in front of the masked body.
pub const HS_PREFIX_LEN: usize = HS_NONCE_LEN + HS_TAG_LEN;

/// Who sent the datagram. It goes into the tag and the keystream, so a
/// client's message sent back to it is not taken for the server's reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsDirection {
    ClientToServer,
    ServerToClient,
}

impl HsDirection {
    fn byte(self) -> u8 {
        match self {
            HsDirection::ClientToServer => 0x00,
            HsDirection::ServerToClient => 0x01,
        }
    }
}

/// The keys of the handshake's outer layer, both derived from the access key.
#[derive(Clone, Copy)]
pub struct HsKeys {
    pub mask_key: [u8; 32],
    pub tag_key: [u8; 32],
}

fn tag(keys: &HsKeys, dir: HsDirection, nonce: &[u8]) -> [u8; HS_TAG_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.tag_key).expect("HMAC accepts any key length");
    mac.update(&[dir.byte()]);
    mac.update(nonce);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; HS_TAG_LEN];
    out.copy_from_slice(&full[..HS_TAG_LEN]);
    out
}

/// The keystream of one datagram. The two directions use different keys
/// (the mask key with the direction mixed in), so the same nonce in both
/// directions never yields the same keystream.
fn apply_keystream(keys: &HsKeys, dir: HsDirection, nonce: &[u8], data: &mut [u8]) {
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.mask_key).expect("HMAC accepts any key length");
    mac.update(&[dir.byte()]);
    let key = mac.finalize().into_bytes();
    let mut cipher = ChaCha20::new(key.as_slice().into(), nonce.into());
    cipher.apply_keystream(data);
}

/// Wraps a handshake body for the wire.
pub fn seal(keys: &HsKeys, dir: HsDirection, body: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; HS_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut out = Vec::with_capacity(HS_PREFIX_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag(keys, dir, &nonce));
    out.extend_from_slice(body);
    apply_keystream(keys, dir, &nonce, &mut out[HS_PREFIX_LEN..]);
    out
}

/// Whether the datagram carries this key's tag: one HMAC, no curve operation.
pub fn tag_matches(keys: &HsKeys, dir: HsDirection, datagram: &[u8]) -> bool {
    if datagram.len() <= HS_PREFIX_LEN {
        return false;
    }
    let expected = tag(keys, dir, &datagram[..HS_NONCE_LEN]);
    // Constant time: the tag is a secret-keyed value an attacker probes for.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(&datagram[HS_NONCE_LEN..HS_PREFIX_LEN]) {
        diff |= a ^ b;
    }
    diff == 0
}

/// The body of a datagram whose tag matches, or `None`.
pub fn open(keys: &HsKeys, dir: HsDirection, datagram: &[u8]) -> Option<Vec<u8>> {
    if !tag_matches(keys, dir, datagram) {
        return None;
    }
    let mut body = datagram[HS_PREFIX_LEN..].to_vec();
    apply_keystream(keys, dir, &datagram[..HS_NONCE_LEN], &mut body);
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(seed: u8) -> HsKeys {
        HsKeys { mask_key: [seed; 32], tag_key: [seed.wrapping_add(1); 32] }
    }

    #[test]
    fn a_sealed_body_opens_with_the_same_keys_and_direction_only() {
        let body = b"session and noise message and padding".to_vec();
        let wire = seal(&keys(1), HsDirection::ClientToServer, &body);
        assert_eq!(wire.len(), HS_PREFIX_LEN + body.len());
        assert_eq!(open(&keys(1), HsDirection::ClientToServer, &wire), Some(body));
        assert_eq!(open(&keys(2), HsDirection::ClientToServer, &wire), None, "another key's tag");
        assert_eq!(open(&keys(1), HsDirection::ServerToClient, &wire), None, "a reflected message");
        assert_eq!(open(&keys(1), HsDirection::ClientToServer, &wire[..HS_PREFIX_LEN]), None, "no body");
    }

    /// The reason for the mask: a body that is the same every time (in v5, the
    /// fixed top bit of the ephemeral key) must not show on the wire.
    #[test]
    fn a_constant_body_leaves_no_constant_bit_on_the_wire() {
        let body = [0u8; 48];
        let mut ones = [0u32; (HS_PREFIX_LEN + 48) * 8];
        let rounds = 400;
        for _ in 0..rounds {
            let wire = seal(&keys(7), HsDirection::ClientToServer, &body);
            for (i, byte) in wire.iter().enumerate() {
                for bit in 0..8 {
                    ones[i * 8 + bit] += u32::from(byte >> bit & 1);
                }
            }
        }
        // Each bit is a fair coin: over 400 rounds the count stays far from
        // 0 and 400 (the chance of leaving 100..=300 by luck is below 1e-20).
        for (i, &n) in ones.iter().enumerate() {
            assert!((100..=300).contains(&n), "bit {i} was set {n} times of {rounds}");
        }
    }

    #[test]
    fn the_two_directions_use_different_keystreams() {
        // Same key, same nonce, same body: the masked bytes must differ.
        let k = keys(3);
        let nonce = [9u8; HS_NONCE_LEN];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        apply_keystream(&k, HsDirection::ClientToServer, &nonce, &mut a);
        apply_keystream(&k, HsDirection::ServerToClient, &nonce, &mut b);
        assert_ne!(a, b);
    }
}

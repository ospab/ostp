//! `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, the one pattern OSTP uses, written
//! directly on RustCrypto primitives so it works in `no_std + alloc` builds
//! (snow 0.9 needs `std`). It is the `NoiseSession` of builds without the `std`
//! feature; with `std` it is compiled only to be cross-checked against snow in
//! the tests, which is what keeps it wire-compatible.
//!
//! Only what OSTP needs is here: two messages, empty prologue, and the raw
//! `Split()` output (OSTP drives its own AEAD, see `crypto::aead`).

#![cfg_attr(feature = "std", allow(dead_code))]

#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

use super::noise::NoiseRole;
use crate::protocol::ProtocolError;

const NAME: &[u8] = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const DHLEN: usize = 32;
const TAG: usize = 16;
const BLOCK: usize = 64;

fn err(m: &str) -> ProtocolError {
    ProtocolError::Crypto(m.to_string())
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-BLAKE2s (RFC 2104, 64-byte block); keys here are always 32 bytes.
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner: [u8; 32] = inner.finalize().into();
    hash(&[&opad, &inner])
}

/// Noise HKDF, three outputs (callers use the first two or all three).
fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let temp = hmac(ck, &[ikm]);
    let o1 = hmac(&temp, &[&[1]]);
    let o2 = hmac(&temp, &[&o1, &[2]]);
    let o3 = hmac(&temp, &[&o2, &[3]]);
    (o1, o2, o3)
}

pub struct NoiseSession {
    role: NoiseRole,
    psk: [u8; 32],
    ck: [u8; 32],
    h: [u8; 32],
    k: Option<[u8; 32]>,
    n: u64,
    e: Option<StaticSecret>,
    re: Option<[u8; 32]>,
    step: u8,
}

impl NoiseSession {
    pub fn new(role: NoiseRole, psk: &[u8; 32]) -> Result<Self, ProtocolError> {
        // The protocol name is longer than HASHLEN, so h = HASH(name), ck = h.
        let h0 = hash(&[NAME]);
        // MixHash(prologue = empty)
        let h = hash(&[&h0, &[]]);
        Ok(Self { role, psk: *psk, ck: h0, h, k: None, n: 0, e: None, re: None, step: 0 })
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k, _) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (ck, th, k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.mix_hash(&th);
        self.k = Some(k);
        self.n = 0;
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.n.to_le_bytes());
        n
    }

    fn encrypt_and_hash(&mut self, pt: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        let Some(k) = self.k else {
            if out.len() < pt.len() {
                return Err(err("noise-write: buffer too small"));
            }
            out[..pt.len()].copy_from_slice(pt);
            self.mix_hash(pt);
            return Ok(pt.len());
        };
        if out.len() < pt.len() + TAG {
            return Err(err("noise-write: buffer too small"));
        }
        let c = ChaCha20Poly1305::new(Key::from_slice(&k));
        let nonce = self.nonce();
        let ct = c
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &self.h })
            .map_err(|_| err("noise-write"))?;
        self.n += 1;
        out[..ct.len()].copy_from_slice(&ct);
        self.mix_hash(&ct);
        Ok(ct.len())
    }

    fn decrypt_and_hash(&mut self, ct: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        let Some(k) = self.k else {
            if out.len() < ct.len() {
                return Err(err("noise-read: buffer too small"));
            }
            out[..ct.len()].copy_from_slice(ct);
            self.mix_hash(ct);
            return Ok(ct.len());
        };
        let c = ChaCha20Poly1305::new(Key::from_slice(&k));
        let nonce = self.nonce();
        let pt = c
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: &self.h })
            .map_err(|_| err("noise-read: decrypt"))?;
        if out.len() < pt.len() {
            return Err(err("noise-read: buffer too small"));
        }
        self.n += 1;
        out[..pt.len()].copy_from_slice(&pt);
        self.mix_hash(ct);
        Ok(pt.len())
    }

    fn dh(&self, re: &[u8; 32]) -> Result<[u8; 32], ProtocolError> {
        let e = self.e.as_ref().ok_or_else(|| err("noise-state"))?;
        let shared = e.diffie_hellman(&PublicKey::from(*re)).to_bytes();
        if shared == [0u8; 32] {
            return Err(err("noise-dh: low-order point"));
        }
        Ok(shared)
    }

    fn gen_ephemeral(&mut self) -> [u8; DHLEN] {
        let mut seed = [0u8; 32];
        crate::sys::fill_random(&mut seed);
        let s = StaticSecret::from(seed);
        let p = PublicKey::from(&s).to_bytes();
        self.e = Some(s);
        p
    }

    pub fn write_handshake(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        let my_turn = match self.role {
            NoiseRole::Initiator => self.step == 0,
            NoiseRole::Responder => self.step == 1,
        };
        if !my_turn {
            return Err(err("noise-write: out of turn"));
        }
        if out.len() < DHLEN {
            return Err(err("noise-write: buffer too small"));
        }
        if self.step == 0 {
            let psk = self.psk;
            self.mix_key_and_hash(&psk);
        }
        let e = self.gen_ephemeral();
        out[..DHLEN].copy_from_slice(&e);
        self.mix_hash(&e);
        self.mix_key(&e);
        if self.step == 1 {
            let re = self.re.ok_or_else(|| err("noise-state"))?;
            let dh = self.dh(&re)?;
            self.mix_key(&dh);
        }
        let n = self.encrypt_and_hash(payload, &mut out[DHLEN..])?;
        self.step += 1;
        Ok(DHLEN + n)
    }

    pub fn read_handshake(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        let my_turn = match self.role {
            NoiseRole::Initiator => self.step == 1,
            NoiseRole::Responder => self.step == 0,
        };
        if !my_turn {
            return Err(err("noise-read: out of turn"));
        }
        if input.len() < DHLEN + TAG {
            return Err(err("noise-read: short message"));
        }
        if self.step == 0 {
            let psk = self.psk;
            self.mix_key_and_hash(&psk);
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&input[..DHLEN]);
        self.mix_hash(&re);
        self.mix_key(&re);
        self.re = Some(re);
        if self.step == 1 {
            let dh = self.dh(&re)?;
            self.mix_key(&dh);
        }
        let n = self.decrypt_and_hash(&input[DHLEN..], out)?;
        self.step += 1;
        Ok(n)
    }

    /// Same contract as the snow-backed `NoiseSession::raw_split`.
    pub fn raw_split(&mut self, role: NoiseRole) -> Result<([u8; 32], [u8; 32]), ProtocolError> {
        if self.step < 2 {
            return Err(ProtocolError::State("handshake not finished at key split".to_string()));
        }
        let (k0, k1, _) = hkdf(&self.ck, &[]);
        Ok(match role {
            NoiseRole::Initiator => (k0, k1),
            NoiseRole::Responder => (k1, k0),
        })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::noise::NoiseSession as Snow;

    /// Both mixed pairings of snow and the in-crate implementation complete a
    /// handshake and derive the same transport keys and payloads.
    #[test]
    fn interoperates_with_snow() {
        let psk = [0x42u8; 32];
        let mut buf = [0u8; 256];
        let mut tmp = [0u8; 256];

        // lite initiator <-> snow responder
        let mut li = NoiseSession::new(NoiseRole::Initiator, &psk).unwrap();
        let mut sr = Snow::new(NoiseRole::Responder, &psk).unwrap();
        let n = li.write_handshake(b"hello", &mut buf).unwrap();
        let m = sr.read_handshake(&buf[..n], &mut tmp).unwrap();
        assert_eq!(&tmp[..m], b"hello");
        let n = sr.write_handshake(b"world!", &mut buf).unwrap();
        let m = li.read_handshake(&buf[..n], &mut tmp).unwrap();
        assert_eq!(&tmp[..m], b"world!");
        let (a, b) = li.raw_split(NoiseRole::Initiator).unwrap();
        assert_eq!((a, b), { let (x, y) = sr.raw_split(NoiseRole::Responder).unwrap(); (y, x) });

        // snow initiator <-> lite responder
        let mut si = Snow::new(NoiseRole::Initiator, &psk).unwrap();
        let mut lr = NoiseSession::new(NoiseRole::Responder, &psk).unwrap();
        let n = si.write_handshake(&[], &mut buf).unwrap();
        lr.read_handshake(&buf[..n], &mut tmp).unwrap();
        let n = lr.write_handshake(&[1, 2, 3], &mut buf).unwrap();
        let m = si.read_handshake(&buf[..n], &mut tmp).unwrap();
        assert_eq!(&tmp[..m], &[1, 2, 3]);
        let (a, b) = si.raw_split(NoiseRole::Initiator).unwrap();
        assert_eq!((a, b), { let (x, y) = lr.raw_split(NoiseRole::Responder).unwrap(); (y, x) });
    }

    #[test]
    fn wrong_psk_is_rejected_and_early_split_refused() {
        let mut buf = [0u8; 128];
        let mut tmp = [0u8; 128];
        let mut i = NoiseSession::new(NoiseRole::Initiator, &[1u8; 32]).unwrap();
        let mut r = NoiseSession::new(NoiseRole::Responder, &[2u8; 32]).unwrap();
        assert!(i.raw_split(NoiseRole::Initiator).is_err());
        let n = i.write_handshake(&[], &mut buf).unwrap();
        assert!(r.read_handshake(&buf[..n], &mut tmp).is_err());
    }
}

#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec::Vec};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::protocol::ProtocolError;

const NONCE_LEN: usize = 12;

pub struct SessionCipher {
    inner: ChaCha20Poly1305,
}

impl SessionCipher {
    pub fn new(key_material: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_material);
        Self {
            inner: ChaCha20Poly1305::new(key),
        }
    }

    pub fn encrypt(
        &self,
        nonce_counter: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce_bytes = nonce_from_counter(nonce_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.inner
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ProtocolError::Crypto("aead-encrypt".to_string()))
    }

    pub fn decrypt(
        &self,
        nonce_counter: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce_bytes = nonce_from_counter(nonce_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.inner
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| ProtocolError::Crypto("aead-decrypt".to_string()))
    }
}

fn nonce_from_counter(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(feature = "std")]
use snow::{Builder, HandshakeState};
#[cfg(not(feature = "std"))]
pub use super::noise_lite::NoiseSession;

#[cfg(feature = "std")]
use crate::protocol::ProtocolError;

#[cfg(feature = "std")]
const NN_NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone, Copy, Debug)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// A Noise handshake in progress. OSTP does not use snow's transport mode: once
/// the handshake finishes we extract the raw Split() keys (see [`raw_split`])
/// and drive our own out-of-order AEAD (see `crypto::aead`), because the wire
/// protocol needs explicit per-frame nonces for reordering that snow's internal
/// nonce counter can't express.
///
/// [`raw_split`]: NoiseSession::raw_split
#[cfg(feature = "std")]
pub struct NoiseSession {
    handshake: Box<HandshakeState>,
}

#[cfg(feature = "std")]
impl NoiseSession {
    pub fn new(
        role: NoiseRole,
        psk: &[u8; 32],
    ) -> Result<Self, ProtocolError> {
        let params = NN_NOISE_PARAMS
            .parse()
            .map_err(|_| ProtocolError::Crypto("noise-params".to_string()))?;

        let mut builder = Builder::new(params);
        builder = builder.psk(0, psk);

        let handshake = match role {
            NoiseRole::Initiator => builder
                .build_initiator()
                .map_err(|_| ProtocolError::Crypto("noise-init".to_string()))?,
            NoiseRole::Responder => builder
                .build_responder()
                .map_err(|_| ProtocolError::Crypto("noise-responder".to_string()))?,
        };

        Ok(Self { handshake: Box::new(handshake) })
    }

    pub fn write_handshake(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        self.handshake
            .write_message(payload, out)
            .map_err(|_| ProtocolError::Crypto("noise-write".to_string()))
    }

    pub fn read_handshake(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        self.handshake
            .read_message(input, out)
            .map_err(|e| ProtocolError::Crypto(format!("noise-read: {:?}", e)))
    }

    /// Derive the two directional transport keys via Noise's Split().
    ///
    /// SECURITY: keys are taken from the final chaining key `ck` (which absorbs
    /// the ephemeral `ee` DH result via MixKey), NOT from the handshake hash `h`
    /// (which only absorbs public transcript data — ephemeral pubkeys and
    /// ciphertexts — and never the DH secret). Deriving from `ck` is what gives
    /// the session forward secrecy: an adversary who later learns the PSK still
    /// cannot recompute these keys without the ephemeral private keys, which are
    /// discarded after the handshake.
    ///
    /// Must only be called once the handshake is finished (both messages of the
    /// NNpsk0 exchange processed); at that point `ck` is final. Returns
    /// `(send_key, recv_key)` for the given role, matching snow's TransportState
    /// direction mapping: split output `.0` is initiator→responder, `.1` is
    /// responder→initiator.
    pub fn raw_split(&mut self, role: NoiseRole) -> Result<([u8; 32], [u8; 32]), ProtocolError> {
        if !self.handshake.is_handshake_finished() {
            return Err(ProtocolError::State("handshake not finished at key split".to_string()));
        }
        let (k0, k1) = self.handshake.dangerously_get_raw_split();
        Ok(match role {
            // Initiator sends on .0 (i→r), receives on .1 (r→i).
            NoiseRole::Initiator => (k0, k1),
            // Responder is the mirror image.
            NoiseRole::Responder => (k1, k0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a full NNpsk0 handshake and confirm both sides derive matching
    /// directional keys. This guards the .0/.1 → send/recv role mapping in
    /// `raw_split`: if it were wrong, the two sides' send/recv keys wouldn't
    /// cross-match and the transport channel would silently fail to decrypt.
    #[test]
    fn raw_split_keys_agree_across_roles() {
        let psk = [7u8; 32];
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, &psk).unwrap();
        let mut responder = NoiseSession::new(NoiseRole::Responder, &psk).unwrap();

        // msg1: initiator -> responder
        let mut buf1 = [0u8; 1024];
        let n1 = initiator.write_handshake(&[], &mut buf1).unwrap();
        let mut tmp = [0u8; 1024];
        responder.read_handshake(&buf1[..n1], &mut tmp).unwrap();

        // msg2: responder -> initiator
        let mut buf2 = [0u8; 1024];
        let n2 = responder.write_handshake(&[], &mut buf2).unwrap();
        initiator.read_handshake(&buf2[..n2], &mut tmp).unwrap();

        let (i_send, i_recv) = initiator.raw_split(NoiseRole::Initiator).unwrap();
        let (r_send, r_recv) = responder.raw_split(NoiseRole::Responder).unwrap();

        // What the initiator sends with, the responder must receive with.
        assert_eq!(i_send, r_recv, "initiator send key must equal responder recv key");
        assert_eq!(r_send, i_recv, "responder send key must equal initiator recv key");
        // The two directions use distinct keys.
        assert_ne!(i_send, i_recv, "the two directions must not share a key");
    }

    /// raw_split must refuse to hand out keys before the handshake is complete —
    /// keys taken from a half-mixed chaining key would be wrong and insecure.
    #[test]
    fn raw_split_rejected_before_handshake_finishes() {
        let psk = [9u8; 32];
        let mut initiator = NoiseSession::new(NoiseRole::Initiator, &psk).unwrap();
        // No messages exchanged yet: handshake not finished.
        assert!(initiator.raw_split(NoiseRole::Initiator).is_err());
    }
}

use snow::{Builder, HandshakeState, TransportState};

use crate::protocol::ProtocolError;

const NN_NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone, Copy, Debug)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

pub enum NoiseSession {
    Handshake(Box<HandshakeState>),
    Transport(TransportState),
}

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

        Ok(Self::Handshake(Box::new(handshake)))
    }

    pub fn write_handshake(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        match self {
            NoiseSession::Handshake(hs) => hs
                .write_message(payload, out)
                .map_err(|_| ProtocolError::Crypto("noise-write".to_string())),
            NoiseSession::Transport(_) => Err(ProtocolError::State("noise already in transport".to_string())),
        }
    }

    pub fn read_handshake(&mut self, input: &[u8], out: &mut [u8]) -> Result<usize, ProtocolError> {
        match self {
            NoiseSession::Handshake(hs) => hs
                .read_message(input, out)
                .map_err(|_| ProtocolError::Crypto("noise-read".to_string())),
            NoiseSession::Transport(_) => Err(ProtocolError::State("noise already in transport".to_string())),
        }
    }

    pub fn handshake_hash(&self, out: &mut [u8]) -> Result<(), ProtocolError> {
        match self {
            NoiseSession::Handshake(hs) => {
                let hash = hs.get_handshake_hash();
                if out.len() != hash.len() {
                    return Err(ProtocolError::Crypto("handshake hash length mismatch".to_string()));
                }
                out.copy_from_slice(hash);
                Ok(())
            }
            NoiseSession::Transport(_) => Err(ProtocolError::State("noise already in transport".to_string())),
        }
    }

    pub fn into_transport(self) -> Result<Self, ProtocolError> {
        match self {
            NoiseSession::Handshake(hs) => {
                let transport = hs
                    .into_transport_mode()
                    .map_err(|_| ProtocolError::Crypto("noise-transport".to_string()))?;
                Ok(NoiseSession::Transport(transport))
            }
            NoiseSession::Transport(_) => Ok(self),
        }
    }
}

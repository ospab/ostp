//! Which wire version a profile speaks, and the machine configuration for it.
//!
//! A profile with the server's public key (`pk` in a link, `server_pk` in a
//! config) speaks protocol v6; without it, v5. The client never moves from one
//! to the other by itself: the profile decides, and a v6 profile that gets no
//! answer says why (see [`v6_unanswered`]).

use ostp_core::crypto::{derive_all_secrets, derive_v6_secrets, ServerStatic};
use ostp_core::protocol::V6Handshake;
use ostp_core::{NoiseRole, PaddingStrategy, ProtocolConfig, TrafficProfile};

/// The configuration of the client's side of a handshake. `server_pk` decides
/// the version: `Some` is v6 (the server is authenticated by its key), `None`
/// is v5, byte for byte what 0.4.x does.
pub(crate) fn initiator_config(
    access_key: &[u8],
    server_pk: Option<[u8; 32]>,
    session_id: u32,
    handshake_payload: Vec<u8>,
    profile: TrafficProfile,
    mtu: usize,
) -> ProtocolConfig {
    let (secrets, v6) = match server_pk {
        Some(pk) => {
            let v6 = derive_v6_secrets(access_key);
            (v6.base.clone(), Some(V6Handshake { server: ServerStatic::Public(pk), hs: v6.hs }))
        }
        None => (derive_all_secrets(access_key), None),
    };
    ProtocolConfig {
        psk: secrets.psk,
        session_id,
        handshake_payload,
        padding_strategy: PaddingStrategy::Profile(profile),
        obfuscation_key: secrets.obfuscation_key,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        v6,
        ..ProtocolConfig::with_defaults(NoiseRole::Initiator, mtu)
    }
}

/// What a v6 profile says when the server never answered its handshake. A
/// server stays silent to anything it cannot read, so from the client's side
/// "nothing came back" is all there is to go on; this names the two causes
/// that a v6 profile has and what to do about them.
pub fn v6_unanswered(server_addr: &str) -> String {
    format!(
        "{server_addr} did not answer the protocol v6 handshake. This profile carries the server's key, so it speaks v6; \
         the server is either older than 0.5.0 or its server key has changed. Ask for a new link or subscription \
         (the server's owner can see the key with `ostp key`). If the address or the network is the problem, \
         the same silence looks like this too."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostp_core::{OstpEvent, ProtocolAction, ProtocolMachine};

    fn first(cfg: ProtocolConfig) -> Vec<u8> {
        let mut m = ProtocolMachine::new(cfg).unwrap();
        match m.on_event(OstpEvent::Start).unwrap() {
            ProtocolAction::SendDatagram(d) => d.to_vec(),
            _ => panic!("no handshake datagram"),
        }
    }

    /// The version really changes what goes on the wire, and only `pk` changes it.
    #[test]
    fn the_key_decides_the_version() {
        let (_, public) = ostp_core::crypto::noise::generate_server_key();
        let make = |pk| initiator_config(b"key", pk, 9, ostp_core::build_handshake_payload(b"key", 9), TrafficProfile::JsonRpc, 1200);
        let v5 = make(None);
        assert!(v5.v6.is_none());
        let v6 = make(Some(public));
        assert!(v6.v6.is_some());
        assert_ne!(v5.psk, v6.psk, "v5 and v6 derive different secrets from one key");

        // A v6 datagram carries the key's tag: a server that holds this
        // access key finds it, and a v5 datagram has none.
        let secrets = derive_v6_secrets(b"key");
        let d6 = first(v6);
        assert_eq!(ostp_core::protocol::v6_handshake_session_id(&secrets.hs, &d6), Some(9));
        let d5 = first(v5);
        assert_eq!(ostp_core::protocol::v6_handshake_session_id(&secrets.hs, &d5), None);
    }

    #[test]
    fn the_unanswered_message_names_both_causes_and_the_fix() {
        let m = v6_unanswered("vpn.example.com:443");
        assert!(m.contains("older than 0.5.0") && m.contains("key has changed") && m.contains("new link"), "{m}");
    }
}

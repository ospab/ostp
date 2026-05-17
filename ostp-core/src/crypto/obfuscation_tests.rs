#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that derive_all_secrets is deterministic — same input always
    /// produces the same output.
    #[test]
    fn test_derive_deterministic() {
        let key = b"test_access_key_12345";
        let s1 = derive_all_secrets(key);
        let s2 = derive_all_secrets(key);

        assert_eq!(s1.obfuscation_key, s2.obfuscation_key, "obf_key must be deterministic");
        assert_eq!(s1.psk, s2.psk, "psk must be deterministic");
        assert_eq!(s1.handshake_pad_min, s2.handshake_pad_min, "pad_min must be deterministic");
        assert_eq!(s1.handshake_pad_max, s2.handshake_pad_max, "pad_max must be deterministic");
    }

    /// Verifies that different keys produce different secrets.
    #[test]
    fn test_derive_different_keys() {
        let s1 = derive_all_secrets(b"key_alpha");
        let s2 = derive_all_secrets(b"key_beta");

        assert_ne!(s1.obfuscation_key, s2.obfuscation_key);
        assert_ne!(s1.psk, s2.psk);
    }

    /// Verifies that the legacy API matches derive_all_secrets output.
    #[test]
    fn test_legacy_api_consistency() {
        let key = b"consistency_check_key";
        let secrets = derive_all_secrets(key);
        assert_eq!(secrets.obfuscation_key, derive_obfuscation_key(key));
        assert_eq!(secrets.psk, derive_psk(key));
    }

    /// Verifies handshake padding range is within valid bounds.
    #[test]
    fn test_padding_range_valid() {
        for i in 0..100 {
            let key = format!("test_key_{}", i);
            let s = derive_all_secrets(key.as_bytes());
            assert!(s.handshake_pad_min >= 16, "pad_min must be >= 16, got {}", s.handshake_pad_min);
            assert!(s.handshake_pad_min < 80, "pad_min must be < 80, got {}", s.handshake_pad_min);
            assert!(s.handshake_pad_max > s.handshake_pad_min, "pad_max must be > pad_min");
            assert!(s.handshake_pad_max <= s.handshake_pad_min + 175,
                "pad_max out of range: {} > {} + 175", s.handshake_pad_max, s.handshake_pad_min);
        }
    }

    /// End-to-end test: obfuscate a handshake packet on the "client" side,
    /// then deobfuscate on the "server" side using the same access key.
    /// This simulates the exact flow that caused "Unauthorized probe" errors.
    #[test]
    fn test_handshake_obfuscation_roundtrip() {
        let access_key = b"my_real_access_key_v2";
        let secrets = derive_all_secrets(access_key);

        // Simulate client building a handshake packet
        let session_id: u32 = 0xDEADBEEF;
        let fake_noise_payload = [0x42u8; 48]; // Typical Noise_NNpsk0 handshake size
        let noise_len = fake_noise_payload.len() as u16;

        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id.to_be_bytes());      // [0..4]
        packet.extend_from_slice(&noise_len.to_be_bytes());        // [4..6]
        packet.extend_from_slice(&fake_noise_payload);             // [6..54]
        packet.extend_from_slice(&[0xAA; 64]);                     // padding

        // Obfuscate (client side)
        obfuscate_packet_inplace(&mut packet, &secrets.obfuscation_key, true);

        // At this point, bytes [0..6] are masked and should look random
        let masked_sid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_ne!(masked_sid, session_id, "session_id must be masked on wire");

        // Deobfuscate (server side) — using same key
        deobfuscate_packet_inplace(&mut packet, &secrets.obfuscation_key, true);

        // Verify session_id is recovered
        let recovered_sid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(recovered_sid, session_id, "session_id must be recovered after deobfuscation");

        // Verify noise_len is recovered
        let recovered_noise_len = u16::from_be_bytes([packet[4], packet[5]]);
        assert_eq!(recovered_noise_len, noise_len, "noise_len must be recovered");

        // Verify noise payload is intact
        assert_eq!(&packet[6..6 + noise_len as usize], &fake_noise_payload,
            "noise payload must be intact after round-trip");
    }

    /// Verifies that deobfuscating with the WRONG key does NOT recover
    /// the session_id — this is what prevents unauthorized probes.
    #[test]
    fn test_wrong_key_produces_garbage() {
        let correct_key = b"correct_key";
        let wrong_key = b"wrong_key";

        let correct_secrets = derive_all_secrets(correct_key);
        let wrong_secrets = derive_all_secrets(wrong_key);

        let session_id: u32 = 0x12345678;
        let fake_noise = [0x55u8; 48];

        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id.to_be_bytes());
        packet.extend_from_slice(&(48u16).to_be_bytes());
        packet.extend_from_slice(&fake_noise);
        packet.extend_from_slice(&[0x00; 32]);

        // Obfuscate with correct key
        obfuscate_packet_inplace(&mut packet, &correct_secrets.obfuscation_key, true);

        // Try to deobfuscate with WRONG key
        let mut wrong_trial = packet.clone();
        deobfuscate_packet_inplace(&mut wrong_trial, &wrong_secrets.obfuscation_key, true);
        let wrong_sid = u32::from_be_bytes([wrong_trial[0], wrong_trial[1], wrong_trial[2], wrong_trial[3]]);

        // Should NOT match — this is what the dispatcher checks
        assert_ne!(wrong_sid, session_id, "wrong key must NOT recover session_id");

        // Deobfuscate with correct key — must work
        deobfuscate_packet_inplace(&mut packet, &correct_secrets.obfuscation_key, true);
        let correct_sid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(correct_sid, session_id, "correct key must recover session_id");
    }

    /// Verifies data packet obfuscation round-trip (non-handshake path).
    #[test]
    fn test_data_packet_obfuscation_roundtrip() {
        let secrets = derive_all_secrets(b"data_test_key");

        let session_id: u32 = 0xCAFEBABE;
        let nonce: u64 = 42;
        let ciphertext = [0x77u8; 64];

        let mut packet = Vec::new();
        packet.extend_from_slice(&session_id.to_be_bytes());  // [0..4]
        packet.extend_from_slice(&nonce.to_be_bytes());        // [4..12]
        packet.extend_from_slice(&ciphertext);                 // [12..]

        obfuscate_packet_inplace(&mut packet, &secrets.obfuscation_key, false);

        // Masked
        let masked_sid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_ne!(masked_sid, session_id);

        // Deobfuscate
        deobfuscate_packet_inplace(&mut packet, &secrets.obfuscation_key, false);

        let recovered_sid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let recovered_nonce = u64::from_be_bytes([
            packet[4], packet[5], packet[6], packet[7],
            packet[8], packet[9], packet[10], packet[11],
        ]);

        assert_eq!(recovered_sid, session_id);
        assert_eq!(recovered_nonce, nonce);
        assert_eq!(&packet[12..], &ciphertext);
    }
}

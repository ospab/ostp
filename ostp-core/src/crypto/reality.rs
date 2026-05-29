use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

const REALITY_INFO: &[u8] = b"ostp-reality-v1";
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Number of TLS records sent by the server during the fake handshake phase.
/// Client must read and discard this many records before starting RealityStream.
/// Layout: 1× ServerHello (0x16) + 1× CCS (0x14) + 3× fake encrypted records (0x17)
pub const REALITY_SERVER_HANDSHAKE_RECORDS: usize = 5;

/// Generates an X25519 keypair
pub fn generate_x25519_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Derives the Auth Key and Data Key from the X25519 shared secret
pub fn derive_keys(shared_secret: &[u8; 32]) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 64];
    hk.expand(REALITY_INFO, &mut okm).expect("HKDF expand failed");
    
    let auth_key = ChaCha20Poly1305::new_from_slice(&okm[0..32]).unwrap();
    let data_key = ChaCha20Poly1305::new_from_slice(&okm[32..64]).unwrap();
    (auth_key, data_key)
}

/// Creates an authenticated Session ID payload (32 bytes)
/// sid: 8 bytes, timestamp: 8 bytes. Encrypted with ChaCha20Poly1305 (16 byte tag). Total = 32 bytes.
pub fn generate_session_id(auth_aead: &ChaCha20Poly1305, sid: &[u8; 8]) -> [u8; 32] {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut plaintext = [0u8; 16];
    plaintext[0..8].copy_from_slice(sid);
    plaintext[8..16].copy_from_slice(&ts.to_be_bytes());
    
    let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce since auth key is ephemeral per connection
    let ciphertext = auth_aead.encrypt(nonce, plaintext.as_ref()).expect("encryption failed");
    
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&ciphertext);
    session_id
}

/// Verifies and decrypts the Session ID payload. Returns (sid, timestamp)
pub fn verify_session_id(auth_aead: &ChaCha20Poly1305, session_id: &[u8; 32]) -> Option<([u8; 8], u64)> {
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = auth_aead.decrypt(nonce, session_id.as_ref()).ok()?;
    
    if plaintext.len() != 16 {
        return None;
    }
    
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&plaintext[0..8]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&plaintext[8..16]);
    let ts = u64::from_be_bytes(ts_bytes);
    
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Allow up to 60 seconds of clock drift
    if ts > now + 60 || ts < now.saturating_sub(60) {
        return None; // Replay protection / stale connection
    }
    
    Some((sid, ts))
}

/// Builds a fake TLS 1.3 ClientHello matching Chrome's fingerprint
pub fn build_client_hello(sni: &str, session_id: &[u8; 32], c_pub: &PublicKey) -> Bytes {
    let mut ext = BytesMut::new();
    
    // SNI Extension
    let sni_bytes = sni.as_bytes();
    ext.put_u16(0x0000); // Type: server_name
    ext.put_u16((sni_bytes.len() + 5) as u16);
    ext.put_u16((sni_bytes.len() + 3) as u16); // Server Name list length
    ext.put_u8(0x00); // Name Type: host_name
    ext.put_u16(sni_bytes.len() as u16);
    ext.put_slice(sni_bytes);
    
    // Supported Groups
    ext.put_u16(0x000a); // Type
    ext.put_u16(8); // Length
    ext.put_u16(6); // List length
    ext.put_u16(0x001d); // x25519
    ext.put_u16(0x0017); // secp256r1
    ext.put_u16(0x0018); // secp384r1

    // Key Share
    let pub_bytes = c_pub.as_bytes();
    ext.put_u16(0x0033); // Type
    ext.put_u16((pub_bytes.len() + 6) as u16); // Length
    ext.put_u16((pub_bytes.len() + 4) as u16); // ClientShares length
    ext.put_u16(0x001d); // Group: x25519
    ext.put_u16(pub_bytes.len() as u16);
    ext.put_slice(pub_bytes);
    
    // Supported Versions
    ext.put_u16(0x002b); // Type
    ext.put_u16(5); // Length
    ext.put_u8(4); // List length
    ext.put_u16(0x0304); // TLS 1.3
    ext.put_u16(0x0303); // TLS 1.2
    
    // ALPN
    let alpn = b"\x02h2\x08http/1.1";
    ext.put_u16(0x0010); // Type
    ext.put_u16((alpn.len() + 2) as u16);
    ext.put_u16(alpn.len() as u16);
    ext.put_slice(alpn);

    // Signature Algorithms
    ext.put_u16(0x000d); // Type
    ext.put_u16(10); // Length
    ext.put_u16(8); // List length
    ext.put_u16(0x0403); // ecdsa_secp256r1_sha256
    ext.put_u16(0x0804); // rsa_pss_rsae_sha256
    ext.put_u16(0x0401); // rsa_pkcs1_sha256
    ext.put_u16(0x0503); // ecdsa_secp384r1_sha384

    let mut handshake = BytesMut::new();
    handshake.put_u16(0x0303); // Client Version
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    handshake.put_slice(&random); // Random
    
    handshake.put_u8(32); // Session ID length
    handshake.put_slice(session_id); // Session ID
    
    // Cipher Suites
    handshake.put_u16(6); // Length
    handshake.put_u16(0x1301); // TLS_AES_128_GCM_SHA256
    handshake.put_u16(0x1303); // TLS_CHACHA20_POLY1305_SHA256
    handshake.put_u16(0x1302); // TLS_AES_256_GCM_SHA384
    
    // Compression
    handshake.put_u8(1); // Length
    handshake.put_u8(0); // null
    
    // Extensions
    handshake.put_u16(ext.len() as u16);
    handshake.put_slice(&ext);
    
    let handshake_len = handshake.len();
    
    let mut record = BytesMut::new();
    record.put_u8(0x16); // Handshake
    record.put_u16(0x0301); // TLS 1.0 (Compatibility)
    record.put_u16((handshake_len + HANDSHAKE_HEADER_LEN) as u16); // Length
    
    record.put_u8(0x01); // ClientHello
    record.put_u8((handshake_len >> 16) as u8);
    record.put_u8((handshake_len >> 8) as u8);
    record.put_u8(handshake_len as u8);
    record.put_slice(&handshake);

    // Append ChangeCipherSpec for TLS 1.3 middlebox compatibility (RFC 8446 §D.4)
    // This makes the flow look like: ClientHello → ServerHello → CCS → AppData
    // instead of the DPI-suspicious: ClientHello → AppData directly.
    let mut out = BytesMut::new();
    out.put_slice(&record);
    out.put_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out.freeze()
}

pub struct ParsedClientHello {
    pub sni: String,
    pub session_id: [u8; 32],
    pub c_pub: PublicKey,
}

/// Parses a TLS ClientHello. Returns None if invalid or missing required fields.
pub fn parse_client_hello(mut buf: &[u8]) -> Option<ParsedClientHello> {
    if buf.len() < RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN {
        return None;
    }
    
    // Record Header
    let typ = buf.get_u8();
    if typ != 0x16 { return None; } // Not a handshake
    let _version = buf.get_u16();
    let record_len = buf.get_u16() as usize;
    
    if buf.len() < record_len {
        return None; // Incomplete record
    }
    
    let mut payload = &buf[..record_len];
    
    // Handshake Header
    let hs_type = payload.get_u8();
    if hs_type != 0x01 { return None; } // Not ClientHello
    let hs_len_hi = payload.get_u8() as usize;
    let hs_len_mid = payload.get_u8() as usize;
    let hs_len_lo = payload.get_u8() as usize;
    let hs_len = (hs_len_hi << 16) | (hs_len_mid << 8) | hs_len_lo;
    
    if payload.len() < hs_len { return None; }
    
    let mut ch = &payload[..hs_len];
    let _client_version = ch.get_u16();
    if ch.len() < 32 { return None; }
    ch.advance(32); // Skip Random
    
    let sid_len = ch.get_u8() as usize;
    if sid_len != 32 || ch.len() < 32 { return None; }
    
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&ch[..32]);
    ch.advance(32);
    
    let ciphers_len = ch.get_u16() as usize;
    if ch.len() < ciphers_len { return None; }
    ch.advance(ciphers_len);
    
    let comp_len = ch.get_u8() as usize;
    if ch.len() < comp_len { return None; }
    ch.advance(comp_len);
    
    let ext_len = ch.get_u16() as usize;
    if ch.len() < ext_len { return None; }
    
    let mut exts = &ch[..ext_len];
    
    let mut parsed_sni = None;
    let mut parsed_c_pub = None;
    
    while exts.len() >= 4 {
        let ext_type = exts.get_u16();
        let ext_len = exts.get_u16() as usize;
        if exts.len() < ext_len { break; }
        
        let mut ext_data = &exts[..ext_len];
        
        if ext_type == 0x0000 { // SNI
            let _list_len = ext_data.get_u16() as usize;
            if ext_data.len() >= 3 {
                let name_type = ext_data.get_u8();
                if name_type == 0x00 { // Hostname
                    let name_len = ext_data.get_u16() as usize;
                    if ext_data.len() >= name_len {
                        if let Ok(name) = std::str::from_utf8(&ext_data[..name_len]) {
                            parsed_sni = Some(name.to_string());
                        }
                    }
                }
            }
        } else if ext_type == 0x0033 { // Key Share
            let _client_shares_len = ext_data.get_u16() as usize;
            while ext_data.len() >= 4 {
                let group = ext_data.get_u16();
                let key_ex_len = ext_data.get_u16() as usize;
                if ext_data.len() < key_ex_len { break; }
                
                if group == 0x001d && key_ex_len == 32 { // X25519
                    let mut pub_bytes = [0u8; 32];
                    pub_bytes.copy_from_slice(&ext_data[..32]);
                    parsed_c_pub = Some(PublicKey::from(pub_bytes));
                }
                ext_data.advance(key_ex_len);
            }
        }
        
        exts.advance(ext_len);
    }
    
    match (parsed_sni, parsed_c_pub) {
        (Some(sni), Some(c_pub)) => Some(ParsedClientHello { sni, session_id, c_pub }),
        _ => None,
    }
}

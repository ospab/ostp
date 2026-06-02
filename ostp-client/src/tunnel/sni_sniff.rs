pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Basic TLS ClientHello parser
    // Must be at least 43 bytes to contain anything useful
    if data.len() < 43 {
        return None;
    }

    // TLS Record layer: Handshake (22)
    if data[0] != 0x16 {
        return None;
    }

    // Record layer version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2)
    if data[1] != 0x03 {
        return None;
    }

    // Handshake type: ClientHello (1)
    if data[5] != 0x01 {
        return None;
    }

    let mut pos = 43; // Skip fixed ClientHello header

    // Skip Session ID
    if pos >= data.len() { return None; }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Skip Cipher Suites
    if pos + 2 > data.len() { return None; }
    let cipher_suites_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_suites_len;

    // Skip Compression Methods
    if pos >= data.len() { return None; }
    let comp_methods_len = data[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions
    if pos + 2 > data.len() { return None; }
    let extensions_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() { return None; }

    while pos + 4 <= extensions_end {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 { // Server Name Indication (SNI)
            if pos + 5 <= extensions_end {
                let list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
                let name_type = data[pos + 2];
                if name_type == 0 { // Hostname
                    let name_len = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);
                    if pos + 5 + name_len <= extensions_end {
                        let sni_bytes = &data[pos + 5..pos + 5 + name_len];
                        if let Ok(sni) = std::str::from_utf8(sni_bytes) {
                            return Some(sni.to_string());
                        }
                    }
                }
            }
            break;
        }
        pos += ext_len;
    }

    None
}

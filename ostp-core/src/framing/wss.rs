use rand::RngCore;

pub enum WssFrameResult {
    Incomplete,
    Frame { payload: Vec<u8>, total_len: usize },
}

pub fn encode_wss_frame(payload: &[u8], masked: bool) -> Vec<u8> {
    let len = payload.len();
    let mut header = Vec::with_capacity(14 + len);
    header.push(0x82); // FIN + Binary
    
    let mask_bit = if masked { 0x80 } else { 0x00 };
    
    if len <= 125 {
        header.push(mask_bit | (len as u8));
    } else if len <= 65535 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    
    if masked {
        let mut mask = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask);
        header.extend_from_slice(&mask);
        
        for (i, &b) in payload.iter().enumerate() {
            header.push(b ^ mask[i % 4]);
        }
    } else {
        header.extend_from_slice(payload);
    }
    
    header
}

pub fn decode_wss_frame(buffer: &[u8]) -> WssFrameResult {
    if buffer.len() < 2 {
        return WssFrameResult::Incomplete;
    }
    let is_masked = (buffer[1] & 0x80) != 0;
    let payload_len_7 = (buffer[1] & 0x7F) as usize;
    
    let (header_len, payload_len) = if payload_len_7 == 126 {
        if buffer.len() < 4 { return WssFrameResult::Incomplete; }
        (4, u16::from_be_bytes([buffer[2], buffer[3]]) as usize)
    } else if payload_len_7 == 127 {
        if buffer.len() < 10 { return WssFrameResult::Incomplete; }
        (10, u64::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9]]) as usize)
    } else {
        (2, payload_len_7)
    };
    
    let mask_offset = header_len;
    let full_header_len = header_len + if is_masked { 4 } else { 0 };
    let total_frame_len = full_header_len + payload_len;
    
    if buffer.len() < total_frame_len {
        return WssFrameResult::Incomplete;
    }
    
    let mut payload = buffer[full_header_len..total_frame_len].to_vec();
    if is_masked {
        let mask = [buffer[mask_offset], buffer[mask_offset+1], buffer[mask_offset+2], buffer[mask_offset+3]];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    
    WssFrameResult::Frame { payload, total_len: total_frame_len }
}

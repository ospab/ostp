//! TURN (RFC 5766) allocation and channel binding for NAT traversal.
//!
//! Implements the minimal STUN/TURN message flow needed to allocate a relay
//! address and bind a channel to the OSTP server. All crypto (MD5, SHA-1,
//! HMAC-SHA1) is implemented inline to avoid external dependencies.

use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Real RFC-5766 TURN allocation with HMAC-SHA1 long-term credentials.
///
/// Flow:
///   1. Send Allocate (unauthenticated) -> get 401 with realm + nonce
///   2. Compute HMAC-SHA1 key = MD5(username:realm:password)
///   3. Re-send Allocate with MESSAGE-INTEGRITY
///   4. Extract XOR-RELAYED-ADDRESS from success response
///   5. Send ChannelBind to bind channel 0x4000 to the OSTP server addr
///
/// Returns the relay address string like "1.2.3.4:12345".
pub async fn perform_turn_allocation(
    socket: &UdpSocket,
    turn_addr: &str,
    username: &str,
    password: &str,
    ostp_server_addr: &str,
) -> Result<String> {
    use std::net::ToSocketAddrs;

    let turn_sock: std::net::SocketAddr = turn_addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("TURN DNS resolution failed: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("TURN addr resolved to nothing"))?;

    let transaction_id = {
        use rand::Rng;
        let mut id = [0u8; 12];
        rand::thread_rng().fill(&mut id);
        id
    };

    // ── Step 1: unauthenticated Allocate ─────────────────────────────
    // REQUESTED-TRANSPORT attr: 0x0019, value = 17 (UDP) + 3 reserved bytes
    let req_transport = stun_attr(0x0019, &[17u8, 0, 0, 0]);
    let alloc_req = build_stun_msg(0x0003, &transaction_id, &req_transport);

    socket.send_to(&alloc_req, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN send Allocate failed: {e}"))?;

    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_millis(3000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN Allocate response timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN recv failed: {e}"))?;

    let resp = &buf[..n];
    if resp.len() < 20 {
        anyhow::bail!("TURN response too short");
    }

    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);

    // 0x0113 = Allocate Error Response
    if msg_type != 0x0113 {
        anyhow::bail!("Expected TURN 401 error response, got type 0x{:04x}", msg_type);
    }

    // Parse realm and nonce from the error response attributes
    let mut realm: Option<String> = None;
    let mut nonce: Option<String> = None;
    {
        let mut idx = 20usize;
        while idx + 4 <= n {
            let atype = u16::from_be_bytes([resp[idx], resp[idx + 1]]);
            let alen = u16::from_be_bytes([resp[idx + 2], resp[idx + 3]]) as usize;
            idx += 4;
            if idx + alen > n { break; }
            let val = &resp[idx..idx + alen];
            match atype {
                0x0014 => realm = Some(String::from_utf8_lossy(val).to_string()), // REALM
                0x0015 => nonce = Some(String::from_utf8_lossy(val).to_string()), // NONCE
                _ => {}
            }
            idx += alen;
            let pad = (4 - (alen % 4)) % 4;
            idx += pad;
        }
    }

    let realm = realm.ok_or_else(|| anyhow::anyhow!("TURN 401: no REALM in response"))?;
    let nonce = nonce.ok_or_else(|| anyhow::anyhow!("TURN 401: no NONCE in response"))?;

    // ── Step 2: Compute long-term credential key per RFC 5389 §15.4 ──
    // key = MD5(username ":" realm ":" password)
    let key_input = format!("{}:{}:{}", username, realm, password);
    let key = md5_hash(key_input.as_bytes());

    // HMAC-SHA1 of the message (MESSAGE-INTEGRITY attribute, RFC 5389 §15.4)
    let mut attrs2 = Vec::new();
    attrs2.extend_from_slice(&stun_attr(0x0006, username.as_bytes())); // USERNAME
    attrs2.extend_from_slice(&stun_attr(0x0014, realm.as_bytes()));    // REALM
    attrs2.extend_from_slice(&stun_attr(0x0015, nonce.as_bytes()));    // NONCE
    attrs2.extend_from_slice(&req_transport);                           // REQUESTED-TRANSPORT

    // For MESSAGE-INTEGRITY we need the full message length including the MI attr (24 bytes)
    let mi_placeholder_len = attrs2.len() + 4 + 20; // +4 header, +20 HMAC-SHA1
    let mut msg_for_hmac = build_stun_msg(0x0003, &transaction_id, &attrs2);
    // Set length field to include the upcoming MI attr
    let new_len = (mi_placeholder_len - 20) as u16; // total attrs length including MI
    msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());
    // Append MI header (without value)
    msg_for_hmac.extend_from_slice(&0x0008_u16.to_be_bytes()); // attr type
    msg_for_hmac.extend_from_slice(&20_u16.to_be_bytes());      // attr len

    let hmac = hmac_sha1(&key, &msg_for_hmac);
    let mut final_attrs = attrs2.clone();
    final_attrs.extend_from_slice(&stun_attr(0x0008, &hmac)); // MESSAGE-INTEGRITY

    let alloc_req2 = build_stun_msg(0x0003, &transaction_id, &final_attrs);

    socket.send_to(&alloc_req2, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN authenticated Allocate send failed: {e}"))?;

    let (n2, _) = timeout(Duration::from_millis(5000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN authenticated Allocate timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN recv2 failed: {e}"))?;

    let resp2 = &buf[..n2];
    if resp2.len() < 20 {
        anyhow::bail!("TURN auth response too short");
    }
    let msg_type2 = u16::from_be_bytes([resp2[0], resp2[1]]);
    // 0x0103 = Allocate Success Response
    if msg_type2 != 0x0103 {
        anyhow::bail!("TURN Allocate auth failed, response type 0x{:04x}", msg_type2);
    }

    // ── Step 3: Parse XOR-RELAYED-ADDRESS ────────────────────────────
    let relay_addr_str = {
        let mut relayed: Option<String> = None;
        let mut idx = 20usize;
        while idx + 4 <= n2 {
            let atype = u16::from_be_bytes([resp2[idx], resp2[idx + 1]]);
            let alen = u16::from_be_bytes([resp2[idx + 2], resp2[idx + 3]]) as usize;
            idx += 4;
            if idx + alen > n2 { break; }
            let val = &resp2[idx..idx + alen];
            if atype == 0x0016 && alen >= 8 { // XOR-RELAYED-ADDRESS
                let x_port = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
                let x_ip = [val[4], val[5], val[6], val[7]];
                let ip = std::net::Ipv4Addr::new(
                    x_ip[0] ^ 0x21, x_ip[1] ^ 0x12, x_ip[2] ^ 0xA4, x_ip[3] ^ 0x42,
                );
                relayed = Some(format!("{}:{}", ip, x_port));
            }
            idx += alen;
            let pad = (4 - (alen % 4)) % 4;
            idx += pad;
        }
        relayed.ok_or_else(|| anyhow::anyhow!("TURN: no XOR-RELAYED-ADDRESS in response"))?
    };

    // ── Step 4: ChannelBind to the OSTP server ────────────────────────
    let ostp_sock: std::net::SocketAddr = ostp_server_addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("OSTP server DNS resolution failed: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("OSTP server addr resolved to nothing"))?;

    let channel_number: u16 = 0x4000;
    let mut peer_addr_attr = Vec::new();
    peer_addr_attr.push(0u8); // reserved
    peer_addr_attr.push(0x01u8); // family IPv4
    peer_addr_attr.extend_from_slice(&(ostp_sock.port() ^ 0x2112).to_be_bytes()); // XOR port
    if let std::net::IpAddr::V4(ipv4) = ostp_sock.ip() {
        let octets = ipv4.octets();
        peer_addr_attr.push(octets[0] ^ 0x21);
        peer_addr_attr.push(octets[1] ^ 0x12);
        peer_addr_attr.push(octets[2] ^ 0xA4);
        peer_addr_attr.push(octets[3] ^ 0x42);
    } else {
        anyhow::bail!("TURN ChannelBind: IPv6 OSTP server not yet supported");
    }

    let mut cb_attrs = Vec::new();
    // CHANNEL-NUMBER attr: 0x000C
    cb_attrs.extend_from_slice(&stun_attr(0x000C, &[
        (channel_number >> 8) as u8, channel_number as u8, 0, 0
    ]));
    // XOR-PEER-ADDRESS attr: 0x0012
    cb_attrs.extend_from_slice(&stun_attr(0x0012, &peer_addr_attr));
    cb_attrs.extend_from_slice(&stun_attr(0x0006, username.as_bytes()));
    cb_attrs.extend_from_slice(&stun_attr(0x0014, realm.as_bytes()));
    cb_attrs.extend_from_slice(&stun_attr(0x0015, nonce.as_bytes()));

    // Compute MESSAGE-INTEGRITY for ChannelBind too
    let mi_len2 = cb_attrs.len() + 4 + 20;
    let mut cb_for_hmac = build_stun_msg(0x0009, &transaction_id, &cb_attrs);
    cb_for_hmac[2..4].copy_from_slice(&((mi_len2 - 20) as u16).to_be_bytes());
    cb_for_hmac.extend_from_slice(&0x0008_u16.to_be_bytes());
    cb_for_hmac.extend_from_slice(&20_u16.to_be_bytes());
    let cb_hmac = hmac_sha1(&key, &cb_for_hmac);
    cb_attrs.extend_from_slice(&stun_attr(0x0008, &cb_hmac));

    let cb_req = build_stun_msg(0x0009, &transaction_id, &cb_attrs);
    socket.send_to(&cb_req, turn_sock).await
        .map_err(|e| anyhow::anyhow!("TURN ChannelBind send failed: {e}"))?;

    let (n3, _) = timeout(Duration::from_millis(3000), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("TURN ChannelBind response timed out"))?
        .map_err(|e| anyhow::anyhow!("TURN ChannelBind recv failed: {e}"))?;

    let resp3 = &buf[..n3];
    if resp3.len() < 4 {
        anyhow::bail!("TURN ChannelBind response too short");
    }
    let cb_resp_type = u16::from_be_bytes([resp3[0], resp3[1]]);
    // 0x0109 = ChannelBind Success Response
    if cb_resp_type != 0x0109 {
        anyhow::bail!("TURN ChannelBind failed, response type 0x{:04x}", cb_resp_type);
    }

    Ok(relay_addr_str)
}

// ── STUN message helpers ─────────────────────────────────────────────────────

fn build_stun_msg(msg_type: u16, tx_id: &[u8; 12], attrs: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + attrs.len());
    msg.extend_from_slice(&msg_type.to_be_bytes());
    msg.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    msg.extend_from_slice(&0x2112A442_u32.to_be_bytes()); // Magic Cookie
    msg.extend_from_slice(tx_id);
    msg.extend_from_slice(attrs);
    msg
}

fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    // Pad to 4-byte boundary
    let pad = (4 - (value.len() % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

// ── Cryptographic primitives (inline, zero external deps) ────────────────────

/// Pure-Rust MD5 hash (16 bytes). Used for TURN long-term credential key derivation.
fn md5_hash(input: &[u8]) -> [u8; 16] {
    // RFC 1321 MD5 constants
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let msg_len = input.len();
    let bit_len = (msg_len as u64) * 8;

    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, item) in m.iter_mut().enumerate() {
            *item = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g) = match i {
                0..=15  => ((b & c) | (!b & d),              i),
                16..=31 => ((d & b) | (!d & c),              (5*i + 1) % 16),
                32..=47 => (b ^ c ^ d,                        (3*i + 5) % 16),
                _       => (c ^ (b | !d),                     (7*i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

/// HMAC-SHA1 for TURN MESSAGE-INTEGRITY (RFC 2104 + RFC 5389 §15.4).
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;

    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = sha1_hash(key);
        k[..20].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner_hash = sha1_hash(&inner);

    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    sha1_hash(&outer)
}

/// Pure-Rust SHA-1 (RFC 3174).
fn sha1_hash(input: &[u8]) -> [u8; 20] {
    let msg_len = input.len();
    let bit_len = (msg_len as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80usize {
            let (f, k) = match i {
                0..=19  => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d,           0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _       => (b ^ c ^ d,           0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..(i+1)*4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

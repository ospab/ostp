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
                let _list_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
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

/// Most bytes read from a new TUN connection to find its ClientHello.
/// A post-quantum ClientHello (Chrome, Firefox) is about 1.8 KB and comes in
/// two TCP segments; its extensions are in random order, so the server name
/// can be in the second one.
pub const SNIFF_MAX: usize = 8192;

/// Reads the first bytes a program sends on a new connection into `buf`
/// (emptied first), waiting at most `wait` in all. When they start a TLS
/// handshake record, reads on until the whole record is in (up to
/// `SNIFF_MAX`), so `extract_sni` sees all of the ClientHello. Whatever was
/// read is in `buf`, to be sent on before anything else.
pub async fn read_first_bytes<S>(stream: &mut S, buf: &mut Vec<u8>, wait: std::time::Duration)
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    buf.clear();
    let deadline = tokio::time::Instant::now() + wait;
    let mut chunk = [0u8; 2048];
    loop {
        let want = if buf.len() >= 5 && buf[0] == 0x16 {
            (5 + u16::from_be_bytes([buf[3], buf[4]]) as usize).min(SNIFF_MAX)
        } else if buf.is_empty() {
            1
        } else if buf[0] == 0x16 {
            5 // the record header is not complete yet
        } else {
            return; // not TLS: the first read is all
        };
        if buf.len() >= want {
            return;
        }
        let room = (SNIFF_MAX - buf.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..room])).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
}

/// The server name of a ClientHello when it can be sent to the server as
/// the destination: a DNS name (letters, digits, `-`, `_`, dots, with at
/// least one dot), not an address. Lower case, without a final dot.
pub fn routable_sni(sni: &str) -> Option<String> {
    let name = sni.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.contains('.') || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let ok = name.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    // A name that is all digits and dots would be read as an address.
    let numeric = name.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    (ok && !numeric).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello carrying `name` in its SNI extension, after `pad`
    /// bytes of another extension (like a post-quantum key share).
    fn client_hello(name: &str, pad: usize) -> Vec<u8> {
        let mut ext = Vec::new();
        // a padding extension first, so the name comes at the end
        ext.extend_from_slice(&[0x00, 0x15]);
        ext.extend_from_slice(&(pad as u16).to_be_bytes());
        ext.extend(std::iter::repeat(0u8).take(pad));
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_the_name() {
        assert_eq!(extract_sni(&client_hello("www.youtube.com", 10)).as_deref(), Some("www.youtube.com"));
    }

    #[tokio::test]
    async fn a_client_hello_in_two_segments_is_read_whole() {
        let hello = client_hello("rr3---sn-abc.googlevideo.com", 1600);
        let (mut app, mut flow) = tokio::io::duplex(65536);
        let (first, second) = hello.split_at(1200);
        let (first, second) = (first.to_vec(), second.to_vec());
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            app.write_all(&first).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            app.write_all(&second).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut buf = Vec::new();
        read_first_bytes(&mut flow, &mut buf, std::time::Duration::from_secs(2)).await;
        assert_eq!(buf, hello);
        assert_eq!(extract_sni(&buf).as_deref(), Some("rr3---sn-abc.googlevideo.com"));
        // The first part alone: the record is cut and the name not found.
        assert_eq!(extract_sni(&hello[..1200]), None);
    }

    #[tokio::test]
    async fn other_protocols_get_one_read_and_silence_ends_the_wait() {
        let (mut app, mut flow) = tokio::io::duplex(1024);
        {
            use tokio::io::AsyncWriteExt;
            app.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        }
        let mut buf = Vec::new();
        read_first_bytes(&mut flow, &mut buf, std::time::Duration::from_millis(50)).await;
        assert_eq!(buf, b"GET / HTTP/1.1\r\n");

        // A server-first protocol: the program sends nothing.
        let (_app2, mut flow2) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();
        read_first_bytes(&mut flow2, &mut buf, std::time::Duration::from_millis(50)).await;
        assert!(buf.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn only_dns_names_are_routable() {
        assert_eq!(routable_sni("WWW.Google.com.").as_deref(), Some("www.google.com"));
        assert_eq!(routable_sni("rr1---sn-abc.googlevideo.com").as_deref(), Some("rr1---sn-abc.googlevideo.com"));
        assert_eq!(routable_sni("142.250.74.14"), None);
        assert_eq!(routable_sni("::1"), None);
        assert_eq!(routable_sni("1.2.3"), None);
        assert_eq!(routable_sni("localhost"), None);
        assert_eq!(routable_sni(""), None);
        assert_eq!(routable_sni("a b.example"), None);
        assert_eq!(routable_sni("a..example"), None);
        assert_eq!(routable_sni(&format!("{}.example", "a".repeat(64))), None);
    }
}

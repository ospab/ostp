//! IPv4 fragment reassembly for the TUN → netstack path.
//!
//! Why this exists: the userspace netstack (netstack-smoltcp) parses each IP
//! packet it receives and, for UDP, runs `UdpPacket::new_checked` on the IP
//! payload. An IP *fragment* passes the IP-level check but fails the UDP one —
//! the UDP length field describes the whole datagram while the fragment carries
//! only a slice — so the netstack drops it with `wire::Error` and the datagram
//! never reaches the tunnel. Large UDP datagrams (game traffic, e.g. Roblox
//! sending >MTU packets that the OS fragments on the way to the TUN) therefore
//! vanish entirely, and the app times out.
//!
//! smoltcp 0.2.2 does no reassembly of its own, so we do it here, between the
//! TUN read and the netstack: fragments are buffered by (src, dst, id, proto),
//! and only a fully reassembled datagram is handed on. Non-fragmented packets
//! pass straight through untouched.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// A fragment group is discarded if not completed within this window, matching
/// the usual IP reassembly timeout. Prevents a lost tail fragment from pinning
/// memory forever.
const REASM_TIMEOUT: Duration = Duration::from_secs(3);
/// Cap on concurrently tracked fragment groups, so a flood of first-fragments
/// with no tail cannot grow memory without bound.
const MAX_GROUPS: usize = 4096;
/// A reassembled IPv4 datagram cannot exceed this (total-length is 16-bit).
const MAX_DATAGRAM: usize = 65_535;

type Key = (u32, u32, u16, u8); // src, dst, identification, protocol

struct Group {
    /// fragment_offset (bytes) → that fragment's IP payload.
    parts: BTreeMap<usize, Vec<u8>>,
    /// IP header of the offset-0 fragment, reused for the reassembled packet.
    header: Option<Vec<u8>>,
    /// Total payload length, known once the last fragment (MF=0) is seen.
    total_len: Option<usize>,
    first_seen: Instant,
}

pub struct Reassembler {
    groups: HashMap<Key, Group>,
    last_sweep: Instant,
}

impl Reassembler {
    pub fn new() -> Self {
        Self { groups: HashMap::new(), last_sweep: Instant::now() }
    }

    /// Feed one frame read from the TUN. Returns the packet(s) to forward to the
    /// netstack: the frame itself when it is not a fragment, a single fully
    /// reassembled datagram when this frame completes one, or nothing when the
    /// frame was buffered as an incomplete fragment.
    pub fn process(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        self.maybe_sweep();

        let Some(v4) = Ipv4View::parse(frame) else {
            // Not a parseable IPv4 packet (e.g. IPv6) — pass through unchanged;
            // reassembly is not our job for it.
            return Some(frame.to_vec());
        };

        // A packet is fragmented iff MF is set or it carries a non-zero offset.
        if !v4.more_fragments && v4.frag_offset == 0 {
            return Some(frame.to_vec());
        }

        let key = (v4.src, v4.dst, v4.id, v4.protocol);
        let now = Instant::now();

        if self.groups.len() >= MAX_GROUPS && !self.groups.contains_key(&key) {
            // Under pressure, drop the oldest incomplete group to make room
            // rather than refusing the new one outright.
            if let Some(oldest) = self
                .groups
                .iter()
                .min_by_key(|(_, g)| g.first_seen)
                .map(|(k, _)| *k)
            {
                self.groups.remove(&oldest);
            }
        }

        let group = self.groups.entry(key).or_insert_with(|| Group {
            parts: BTreeMap::new(),
            header: None,
            total_len: None,
            first_seen: now,
        });

        // Ignore a payload that would push the datagram past the legal maximum.
        if v4.frag_offset + v4.payload.len() > MAX_DATAGRAM {
            self.groups.remove(&key);
            return None;
        }

        group.parts.insert(v4.frag_offset, v4.payload.to_vec());
        if v4.frag_offset == 0 {
            group.header = Some(v4.header.to_vec());
        }
        if !v4.more_fragments {
            // The last fragment fixes the total length.
            group.total_len = Some(v4.frag_offset + v4.payload.len());
        }

        // Complete? Walk fragments from offset 0 and require they tile the whole
        // datagram with no hole. Overlaps are tolerated as long as coverage is
        // contiguous (BTreeMap keeps them offset-ordered).
        let (Some(total), Some(header)) = (group.total_len, group.header.clone()) else {
            return None;
        };
        let mut expected = 0usize;
        for (&off, part) in &group.parts {
            if off > expected {
                return None; // hole before this fragment
            }
            let end = off + part.len();
            if end > expected {
                expected = end;
            }
        }
        if expected < total {
            return None; // not fully covered yet
        }

        // Reassemble: header + payload bytes [0, total), then fix the header so
        // it describes a single unfragmented datagram.
        let mut payload = vec![0u8; total];
        for (&off, part) in &group.parts {
            let end = (off + part.len()).min(total);
            if off < total {
                payload[off..end].copy_from_slice(&part[..end - off]);
            }
        }
        self.groups.remove(&key);
        Some(build_reassembled(&header, &payload))
    }

    fn maybe_sweep(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) < Duration::from_secs(1) {
            return;
        }
        self.last_sweep = now;
        self.groups.retain(|_, g| now.duration_since(g.first_seen) < REASM_TIMEOUT);
    }
}

/// A read-only view over an IPv4 header and its payload.
struct Ipv4View<'a> {
    header: &'a [u8],
    payload: &'a [u8],
    src: u32,
    dst: u32,
    id: u16,
    protocol: u8,
    more_fragments: bool,
    frag_offset: usize,
}

impl<'a> Ipv4View<'a> {
    fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < 20 {
            return None;
        }
        if frame[0] >> 4 != 4 {
            return None; // not IPv4
        }
        let ihl = ((frame[0] & 0x0f) as usize) * 4;
        if ihl < 20 || frame.len() < ihl {
            return None;
        }
        let total_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        // Trust the smaller of declared length and what we actually read.
        let total_len = total_len.min(frame.len()).max(ihl);
        let id = u16::from_be_bytes([frame[4], frame[5]]);
        let flags_frag = u16::from_be_bytes([frame[6], frame[7]]);
        let more_fragments = flags_frag & 0x2000 != 0;
        let frag_offset = ((flags_frag & 0x1fff) as usize) * 8;
        let protocol = frame[9];
        let src = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
        let dst = u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]);
        Some(Ipv4View {
            header: &frame[..ihl],
            payload: &frame[ihl..total_len],
            src,
            dst,
            id,
            protocol,
            more_fragments,
            frag_offset,
        })
    }
}

/// Stitch the offset-0 header onto a full payload, clearing the fragment fields
/// and fixing total-length and header checksum so the netstack sees one clean
/// datagram.
fn build_reassembled(header0: &[u8], payload: &[u8]) -> Vec<u8> {
    let ihl = header0.len();
    let mut out = Vec::with_capacity(ihl + payload.len());
    out.extend_from_slice(header0);
    out.extend_from_slice(payload);

    let total = (ihl + payload.len()) as u16;
    out[2..4].copy_from_slice(&total.to_be_bytes());
    // Clear flags (except keep DF? no — a reassembled datagram is not a
    // fragment and DF is irrelevant here) and the fragment offset.
    out[6] = 0;
    out[7] = 0;
    // Recompute the IPv4 header checksum over the (possibly options-bearing)
    // header only.
    out[10] = 0;
    out[11] = 0;
    let cksum = ipv4_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&cksum.to_be_bytes());
    out
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal IPv4 header for tests. `mf` = more-fragments, `offset`
    // in bytes (must be /8), `payload_len` fills total_length.
    fn ipv4(id: u16, mf: bool, offset: usize, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut h = vec![0u8; 20];
        h[0] = 0x45; // v4, ihl 5
        h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        h[4..6].copy_from_slice(&id.to_be_bytes());
        let flags_frag = (if mf { 0x2000u16 } else { 0 }) | ((offset / 8) as u16 & 0x1fff);
        h[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        h[9] = 17; // UDP
        h[12..16].copy_from_slice(&[10, 1, 0, 2]);
        h[16..20].copy_from_slice(&[13, 249, 8, 109]);
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn passes_non_fragmented_through() {
        let mut r = Reassembler::new();
        let pkt = ipv4(1, false, 0, &[1, 2, 3, 4]);
        assert_eq!(r.process(&pkt), Some(pkt));
    }

    #[test]
    fn reassembles_two_fragments() {
        let mut r = Reassembler::new();
        // 16 bytes of "UDP" payload split as 8 + 8.
        let first = ipv4(42, true, 0, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let second = ipv4(42, false, 8, &[8, 9, 10, 11, 12, 13, 14, 15]);

        assert_eq!(r.process(&first), None, "first fragment must be buffered");
        let whole = r.process(&second).expect("second fragment completes it");

        // Header says unfragmented, total length 36, payload is the full 16.
        assert_eq!(whole[0] >> 4, 4);
        assert_eq!(u16::from_be_bytes([whole[2], whole[3]]), 36);
        assert_eq!(whole[6] & 0x20, 0, "MF must be cleared");
        assert_eq!(u16::from_be_bytes([whole[6], whole[7]]) & 0x1fff, 0, "offset cleared");
        assert_eq!(&whole[20..], &(0u8..16).collect::<Vec<_>>()[..]);
        // A correctly checksummed header sums to zero when the check field is
        // included in the computation.
        assert_eq!(ipv4_checksum(&whole[..20]), 0, "header checksum must verify");
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let mut r = Reassembler::new();
        let first = ipv4(7, true, 0, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let last = ipv4(7, false, 16, &[16, 17, 18, 19]);
        let mid = ipv4(7, true, 8, &[8, 9, 10, 11, 12, 13, 14, 15]);

        assert_eq!(r.process(&last), None);
        assert_eq!(r.process(&first), None);
        let whole = r.process(&mid).expect("last piece completes it");
        assert_eq!(&whole[20..], &(0u8..20).collect::<Vec<_>>()[..]);
    }

    #[test]
    fn incomplete_group_yields_nothing() {
        let mut r = Reassembler::new();
        let first = ipv4(9, true, 0, &[0; 8]);
        // Tail never arrives.
        assert_eq!(r.process(&first), None);
    }
}

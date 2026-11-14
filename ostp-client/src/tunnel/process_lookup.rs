//! Which program owns a local socket, for per-process exclusions.
//!
//! The tunnel only sees a connection's local address: the source address of
//! a packet on the TUN device, or the peer address of a connection to the
//! local proxy. The operating system's socket tables map that address to a
//! process id, and the process id to an executable name.

use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// The executable name ("Telegram.exe", "firefox") of the process that owns
/// the local socket `local`, if the platform can tell.
///
/// This is a blocking call (it reads the system's socket tables); call it
/// from `spawn_blocking` on a busy runtime.
///
/// Sockets of this process itself are never reported: in TUN mode the
/// tunnel's own connections to the local proxy would otherwise be excluded
/// by a pattern that happens to match "ostp".
pub fn process_owning(proto: Proto, local: SocketAddr) -> Option<String> {
    let pid = platform::owning_pid(proto, local)?;
    if pid == std::process::id() {
        return None;
    }
    platform::process_name(pid)
}

/// How well a socket-table row matches the address being looked up.
/// `None`: another socket. A socket bound to the wildcard address or an
/// IPv4 address seen through an IPv4-mapped IPv6 one still matches, just
/// less well than an exact address.
fn row_match(row: SocketAddr, wanted: SocketAddr) -> Option<u8> {
    if row.port() != wanted.port() {
        return None;
    }
    let (row_ip, wanted_ip) = (canonical(row.ip()), canonical(wanted.ip()));
    if row_ip == wanted_ip {
        Some(2)
    } else if row_ip.is_unspecified() || wanted_ip.is_unspecified() {
        Some(1)
    } else {
        None
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Picks the owner of the best-matching row from `(address, owner)` rows.
#[cfg_attr(not(any(target_os = "windows", target_os = "linux", target_os = "android")), allow(dead_code))]
fn best_owner<T>(rows: impl IntoIterator<Item = (SocketAddr, T)>, wanted: SocketAddr) -> Option<T> {
    let mut best: Option<(u8, T)> = None;
    for (addr, owner) in rows {
        match row_match(addr, wanted) {
            Some(2) => return Some(owner),
            Some(score) if best.as_ref().is_none_or(|(s, _)| score > *s) => best = Some((score, owner)),
            _ => {}
        }
    }
    best.map(|(_, owner)| owner)
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{best_owner, Proto};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use winapi::shared::minwindef::{DWORD, ULONG};
    use winapi::shared::tcpmib::{MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID};
    use winapi::shared::udpmib::{MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID};
    use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use winapi::um::iphlpapi::{GetExtendedTcpTable, GetExtendedUdpTable};

    const AF_INET: ULONG = 2;
    const AF_INET6: ULONG = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;

    /// Calls `GetExtendedTcpTable`/`GetExtendedUdpTable` until the buffer is
    /// big enough (the table can grow between the two calls).
    fn fetch(proto: Proto, family: ULONG) -> Option<Vec<u64>> {
        // u64 elements keep the buffer aligned for the table structs.
        let mut buf: Vec<u64> = vec![0; 2048];
        for _ in 0..4 {
            let mut size = (buf.len() * 8) as DWORD;
            let ret = unsafe {
                match proto {
                    Proto::Tcp => GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0),
                    Proto::Udp => GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut size, 0, family, UDP_TABLE_OWNER_PID, 0),
                }
            };
            match ret {
                NO_ERROR => return Some(buf),
                ERROR_INSUFFICIENT_BUFFER => buf.resize(size as usize / 8 + 64, 0),
                _ => return None,
            }
        }
        None
    }

    fn port(raw: DWORD) -> u16 {
        u16::from_be(raw as u16)
    }

    fn v4(raw: DWORD, p: DWORD) -> SocketAddr {
        // dwLocalAddr holds the address in network byte order.
        SocketAddr::new(Ipv4Addr::from(raw.to_ne_bytes()).into(), port(p))
    }

    fn v6(raw: [u8; 16], p: DWORD) -> SocketAddr {
        SocketAddr::new(Ipv6Addr::from(raw).into(), port(p))
    }

    pub fn owning_pid(proto: Proto, local: SocketAddr) -> Option<u32> {
        let mut rows: Vec<(SocketAddr, u32)> = Vec::new();
        unsafe {
            if let Some(buf) = fetch(proto, AF_INET) {
                match proto {
                    Proto::Tcp => {
                        let t = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                        let rows_ptr = t.table.as_ptr();
                        for i in 0..t.dwNumEntries as usize {
                            let r = &*rows_ptr.add(i);
                            rows.push((v4(r.dwLocalAddr, r.dwLocalPort), r.dwOwningPid));
                        }
                    }
                    Proto::Udp => {
                        let t = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                        let rows_ptr = t.table.as_ptr();
                        for i in 0..t.dwNumEntries as usize {
                            let r = &*rows_ptr.add(i);
                            rows.push((v4(r.dwLocalAddr, r.dwLocalPort), r.dwOwningPid));
                        }
                    }
                }
            }
            if let Some(buf) = fetch(proto, AF_INET6) {
                match proto {
                    Proto::Tcp => {
                        let t = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                        let rows_ptr = t.table.as_ptr();
                        for i in 0..t.dwNumEntries as usize {
                            let r = &*rows_ptr.add(i);
                            rows.push((v6(r.ucLocalAddr, r.dwLocalPort), r.dwOwningPid));
                        }
                    }
                    Proto::Udp => {
                        let t = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                        let rows_ptr = t.table.as_ptr();
                        for i in 0..t.dwNumEntries as usize {
                            let r = &*rows_ptr.add(i);
                            rows.push((v6(r.ucLocalAddr, r.dwLocalPort), r.dwOwningPid));
                        }
                    }
                }
            }
        }
        // pid 0 is the "System Idle Process": TIME_WAIT rows and the like.
        best_owner(rows.into_iter().filter(|(_, pid)| *pid != 0), local)
    }

    pub fn process_name(pid: u32) -> Option<String> {
        use std::os::windows::ffi::OsStringExt;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winbase::QueryFullProcessImageNameW;
        use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

        // PROCESS_QUERY_LIMITED_INFORMATION is granted for far more processes
        // (elevated, other users', packaged apps) than the full query and VM
        // read access GetModuleBaseNameW needs.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buffer = [0u16; 1024];
            let mut len = buffer.len() as DWORD;
            let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len);
            CloseHandle(handle);
            if ok == 0 || len == 0 {
                return None;
            }
            let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len as usize]));
            path.file_name().map(|n| n.to_string_lossy().into_owned())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{best_owner, Proto};
    use std::net::SocketAddr;

    pub fn owning_pid(proto: Proto, local: SocketAddr) -> Option<u32> {
        let files: [&str; 2] = match proto {
            Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
            Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
        };
        let rows = files
            .iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .flat_map(|text| text.lines().skip(1).filter_map(super::parse_proc_net_line).collect::<Vec<_>>())
            .filter(|(_, inode)| *inode != 0);
        let inode = best_owner(rows, local)?;
        pid_with_socket(inode)
    }

    /// Scans every process's open files for `socket:[inode]`. Reading other
    /// users' descriptors needs root, which ostpd has.
    fn pid_with_socket(inode: u64) -> Option<u32> {
        let wanted = format!("socket:[{inode}]");
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else { continue };
            for fd in fds.flatten() {
                if std::fs::read_link(fd.path()).is_ok_and(|t| t.as_os_str() == wanted.as_str()) {
                    return Some(pid);
                }
            }
        }
        None
    }

    pub fn process_name(pid: u32) -> Option<String> {
        let dir = std::path::PathBuf::from(format!("/proc/{pid}"));
        if let Ok(exe) = std::fs::read_link(dir.join("exe")) {
            if let Some(name) = exe.file_name() {
                // A replaced binary reads as "name (deleted)".
                let name = name.to_string_lossy();
                return Some(name.trim_end_matches(" (deleted)").to_string());
            }
        }
        std::fs::read_to_string(dir.join("comm")).ok().map(|c| c.trim().to_string())
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "android")))]
mod platform {
    use super::Proto;
    use std::net::SocketAddr;

    pub fn owning_pid(_proto: Proto, _local: SocketAddr) -> Option<u32> {
        None
    }

    pub fn process_name(_pid: u32) -> Option<String> {
        None
    }
}

/// One row of `/proc/net/{tcp,udp}{,6}`: the local address and the socket
/// inode. Addresses are printed as the raw in-memory words in hex, so each
/// 32-bit group converts back with the host's byte order.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn parse_proc_net_line(line: &str) -> Option<(SocketAddr, u64)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (addr_hex, port_hex) = fields[1].split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(u32::from_str_radix(addr_hex.get(i * 8..i * 8 + 8)?, 16).ok()?.to_ne_bytes())
    };
    let ip: IpAddr = match addr_hex.len() {
        8 => std::net::Ipv4Addr::from(word(0)?).into(),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            std::net::Ipv6Addr::from(bytes).into()
        }
        _ => return None,
    };
    let inode = fields[9].parse().ok()?;
    Some((SocketAddr::new(ip, port), inode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_exact_address_beats_a_wildcard_and_other_ports_never_match() {
        let rows = vec![
            (sa("127.0.0.1:5000"), "other port"),
            (sa("0.0.0.0:4000"), "wildcard"),
            (sa("10.0.0.2:4000"), "other address"),
            (sa("127.0.0.1:4000"), "exact"),
        ];
        assert_eq!(best_owner(rows.clone(), sa("127.0.0.1:4000")), Some("exact"));
        assert_eq!(best_owner(rows.clone(), sa("192.168.1.5:4000")), Some("wildcard"));
        assert_eq!(best_owner(rows, sa("127.0.0.1:6000")), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_rows_match_ipv4_addresses() {
        let rows = vec![(sa("[::ffff:127.0.0.1]:4000"), "dual-stack")];
        assert_eq!(best_owner(rows, sa("127.0.0.1:4000")), Some("dual-stack"));
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_proc_net_lines() {
        let v4 = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";
        assert_eq!(parse_proc_net_line(v4), Some((sa("127.0.0.1:8080"), 123456)));
        let v6 = "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 42 1 0 100 0 0 10 0";
        assert_eq!(parse_proc_net_line(v6), Some((sa("[::1]:80"), 42)));
        assert_eq!(parse_proc_net_line("  sl  local_address rem_address   st"), None);
    }

    /// The real tables: this test binary's own sockets are found, and then
    /// left out as belonging to the tunnel itself.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn finds_the_owner_of_a_real_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        let own = Some(std::process::id());
        assert_eq!(platform::owning_pid(Proto::Tcp, client.local_addr().unwrap()), own);
        assert_eq!(process_owning(Proto::Tcp, client.local_addr().unwrap()), None);

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(platform::owning_pid(Proto::Udp, udp.local_addr().unwrap()), own);

        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            platform::process_name(std::process::id()).as_deref(),
            exe.file_name().and_then(|n| n.to_str())
        );
    }
}

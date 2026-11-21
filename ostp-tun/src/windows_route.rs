// Windows routing table helpers. A default route through ostp_tun takes all traffic;
// routes via the physical gateway keep the server and excluded networks outside it.
// Process exclusions are not handled here.

#[cfg(target_os = "windows")]
pub mod sys {
    use std::mem;
    use std::net::Ipv4Addr;
    use std::ptr;

    use winapi::shared::ipmib::{MIB_IPFORWARDROW, MIB_IPFORWARDTABLE};
    use winapi::shared::minwindef::{DWORD, ULONG};
    use winapi::shared::winerror::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use winapi::um::iphlpapi::{
        DeleteIpForwardEntry, GetAdaptersAddresses, GetIpForwardTable,
    };
    use winapi::um::iptypes::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES,
    };
    use winapi::shared::ws2def::AF_INET;

    fn ipv4_to_dword(ip: Ipv4Addr) -> DWORD {
        u32::from_ne_bytes(ip.octets())
    }

    fn dword_to_ipv4(dw: DWORD) -> Ipv4Addr {
        Ipv4Addr::from(dw.to_ne_bytes())
    }

    /// Returns the (gateway_ip, interface_index) of the physical default IPv4 route,
    /// excluding any route that goes through an interface named "ostp_tun".
    pub fn get_default_ipv4_route() -> Option<(Ipv4Addr, u32)> {
        // Enumerate adapters to find the ostp_tun interface index, so we can skip it.
        let tun_index = get_interface_index("ostp_tun");

        unsafe {
            let mut size: ULONG = 0;
            let mut ret = GetIpForwardTable(ptr::null_mut(), &mut size, 0);
            if ret != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }

            let mut buf: Vec<u8> = vec![0; size as usize];
            let table = buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;

            ret = GetIpForwardTable(table, &mut size, 0);
            if ret != NO_ERROR {
                return None;
            }

            let entries = std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize);

            let mut best_gw = None;
            let mut best_metric = u32::MAX;
            let mut best_ifindex = 0u32;

            for row in entries {
                // Only consider default routes (0.0.0.0/0)
                if row.dwForwardDest == 0 && row.dwForwardMask == 0 {
                    // Skip the TUN interface
                    if let Some(ti) = tun_index {
                        if row.dwForwardIfIndex == ti {
                            continue;
                        }
                    }
                    // and a blackhole through 127.0.0.1 that older versions
                    // added for the kill switch and may have left in this boot.
                    if dword_to_ipv4(row.dwForwardNextHop).is_loopback() {
                        continue;
                    }
                    let metric = row.dwForwardMetric1;
                    if metric < best_metric {
                        best_metric = metric;
                        best_gw = Some(dword_to_ipv4(row.dwForwardNextHop));
                        best_ifindex = row.dwForwardIfIndex;
                    }
                }
            }

            best_gw.map(|gw| (gw, best_ifindex))
        }
    }

    pub fn add_ipv4_route(
        dest: Ipv4Addr,
        mask: Ipv4Addr,
        nexthop: Ipv4Addr,
        if_index: u32,
        metric: u32,
    ) -> Result<(), String> {
        // route.exe instead of CreateIpForwardEntry, which failed with ERROR_BAD_ARGUMENTS
        // (160) for every route here.
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let out = Command::new("route")
            .args([
                "add",
                &dest.to_string(),
                "mask",
                &mask.to_string(),
                &nexthop.to_string(),
                "metric",
                &metric.to_string(),
                "if",
                &if_index.to_string(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("could not run route.exe: {e}"))?;

        if out.status.success() {
            Ok(())
        } else {
            // route.exe prints its diagnostics to stdout, not stderr.
            let msg = String::from_utf8_lossy(&out.stdout);
            let msg = msg.trim();
            Err(format!(
                "route add failed (exit {:?}): {}",
                out.status.code(),
                if msg.is_empty() { "no output" } else { msg }
            ))
        }
    }

    pub fn delete_ipv4_route(
        dest: Ipv4Addr,
        mask: Ipv4Addr,
        nexthop: Ipv4Addr,
        if_index: u32,
    ) -> Result<(), String> {
        let mut row: MIB_IPFORWARDROW = unsafe { mem::zeroed() };
        row.dwForwardDest = ipv4_to_dword(dest);
        row.dwForwardMask = ipv4_to_dword(mask);
        row.dwForwardNextHop = ipv4_to_dword(nexthop);
        row.dwForwardIfIndex = if_index;

        let ret = unsafe { DeleteIpForwardEntry(&mut row) };
        if ret == NO_ERROR || ret == 2 {
            Ok(())
        } else {
            Err(format!("DeleteIpForwardEntry failed: {}", ret))
        }
    }

    pub fn get_interface_index(name: &str) -> Option<u32> {
        unsafe {
            let mut size: ULONG = 0;
            let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            let mut ret = GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut size,
            );
            // GetAdaptersAddresses reports a short buffer as ERROR_BUFFER_OVERFLOW
            // (unlike GetIpForwardTable's ERROR_INSUFFICIENT_BUFFER). Checking only
            // the latter made every lookup fail, so the TUN adapter was never
            // skipped when picking the physical default route.
            if ret != ERROR_BUFFER_OVERFLOW && ret != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }

            let mut buf: Vec<u8> = vec![0; size as usize];
            let addresses = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;

            ret = GetAdaptersAddresses(AF_INET as u32, flags, ptr::null_mut(), addresses, &mut size);
            if ret != NO_ERROR {
                return None;
            }

            let mut curr = addresses;
            while !curr.is_null() {
                let friendly_name_ptr = (*curr).FriendlyName;
                if !friendly_name_ptr.is_null() {
                    let mut len = 0;
                    while *friendly_name_ptr.offset(len) != 0 {
                        len += 1;
                    }
                    let slice = std::slice::from_raw_parts(friendly_name_ptr, len as usize);
                    let friendly_name = String::from_utf16_lossy(slice);
                    if friendly_name == name {
                        return Some((*(*curr).u.s()).IfIndex);
                    }
                }
                curr = (*curr).Next;
            }
            None
        }
    }

    /// Deletes every route to `dest`/`mask`, whatever its gateway, so stale bypass routes
    /// from an earlier session (e.g. before a network change) do not linger.
    pub fn delete_routes_for_dest(dest: Ipv4Addr, mask: Ipv4Addr) {
        unsafe {
            let mut size: ULONG = 0;
            if GetIpForwardTable(ptr::null_mut(), &mut size, 0) != ERROR_INSUFFICIENT_BUFFER {
                return;
            }
            let mut buf: Vec<u8> = vec![0; size as usize];
            let table = buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
            if GetIpForwardTable(table, &mut size, 0) != NO_ERROR {
                return;
            }
            let want_dest = ipv4_to_dword(dest);
            let want_mask = ipv4_to_dword(mask);
            let entries =
                std::slice::from_raw_parts_mut((*table).table.as_mut_ptr(), (*table).dwNumEntries as usize);
            for row in entries {
                if row.dwForwardDest == want_dest && row.dwForwardMask == want_mask {
                    // Delete the exact existing row (its own nexthop/ifindex).
                    let _ = DeleteIpForwardEntry(row);
                }
            }
        }
    }

    /// Netmask for a prefix length (0..=32).
    pub fn prefix_mask(prefix: u8) -> Ipv4Addr {
        let p = u32::from(prefix.min(32));
        let bits: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
        Ipv4Addr::from(bits)
    }

    /// Network address of `ip`/`prefix` (host bits cleared; route.exe rejects them).
    pub fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(ip) & u32::from(prefix_mask(prefix)))
    }

    /// Add bypass routes for a list of networks (the server, resolved excluded domains,
    /// excluded IPs and CIDRs). Each one gets a route via the physical gateway so it
    /// bypasses the TUN. Returns the (network, prefix, gw, if_index) rows that were
    /// successfully added, for later cleanup.
    pub fn add_bypass_routes(
        nets: &[(Ipv4Addr, u8)],
        gw: Ipv4Addr,
        if_index: u32,
        metric: u32,
    ) -> Vec<(Ipv4Addr, u8, Ipv4Addr, u32)> {
        let mut added = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for &(ip, prefix) in nets {
            let prefix = prefix.min(32);
            let net = network_of(ip, prefix);
            let mask = prefix_mask(prefix);
            // The server IP is passed both as server_ip and inside the exclusions, so
            // dedupe to avoid a guaranteed "already exists" failure on the second add.
            if !seen.insert((net, prefix)) {
                continue;
            }
            // Purge any pre-existing route for this dest (e.g. a stale route via an
            // old gateway from a previous session) so add_ipv4_route below installs
            // the correct one instead of failing with ERROR_OBJECT_ALREADY_EXISTS.
            delete_routes_for_dest(net, mask);
            match add_ipv4_route(net, mask, gw, if_index, metric) {
                Ok(()) => {
                    added.push((net, prefix, gw, if_index));
                }
                Err(e) => {
                    // `net` is the address of an excluded site or of the server.
                    tracing::warn!("bypass route add {} via {gw} (if {if_index}) failed: {e}", ostp_core::logpriv::fmt_target(format_args!("{net}/{prefix}")));
                }
            }
        }
        added
    }

    /// Remove all bypass routes previously added by add_bypass_routes.
    pub fn remove_bypass_routes(routes: &[(Ipv4Addr, u8, Ipv4Addr, u32)]) {
        for &(net, prefix, gw, if_index) in routes {
            let _ = delete_ipv4_route(net, prefix_mask(prefix), gw, if_index);
        }
    }
}

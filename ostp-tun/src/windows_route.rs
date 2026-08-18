/// Windows routing table utilities for OSTP split tunneling.
///
/// The approach used here matches how sing-box/v2rayN implement split tunneling on Windows:
/// - A high-priority default route (metric=1) via ostp_tun captures ALL traffic.
/// - Per-host /32 routes via the REAL gateway with an even lower metric (=0, auto-managed by OS)
///   force excluded IPs to bypass the TUN.
/// - Process-based exclusions are NOT supported via pure routing — they would require WFP.
///   Instead, we surface a diagnostic warning in logs.

#[cfg(target_os = "windows")]
pub mod sys {
    use std::mem;
    use std::net::Ipv4Addr;
    use std::ptr;

    use winapi::shared::ipmib::{MIB_IPFORWARDROW, MIB_IPFORWARDTABLE};
    use winapi::shared::minwindef::{DWORD, ULONG};
    use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
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
        // Installed through route.exe rather than CreateIpForwardEntry.
        //
        // The legacy CreateIpForwardEntry API was failing here with error 160
        // (ERROR_BAD_ARGUMENTS) on every single route — server-IP bypass and TUN
        // default route alike — which left the server IP routed INTO the tunnel
        // (a loop that froze the link for seconds under load) and the default
        // route uninstalled. route.exe resolves the interface and validates the
        // gateway itself, and is what the teardown path already uses, so it
        // succeeds where the hand-built MIB_IPFORWARDROW did not.
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        // route add <dest> mask <mask> <gateway> metric <m> if <ifindex>
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
            if ret != ERROR_INSUFFICIENT_BUFFER {
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

    /// Delete every routing-table entry whose destination is `dest`/`mask`,
    /// regardless of its gateway or interface. Used to purge stale bypass routes
    /// left by a previous session (possibly pointing at an old gateway after a
    /// network change) so a fresh, correct one can be installed. (Ported from 0.3.x b6e78c1.)
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

    /// Add bypass routes for a list of resolved IP addresses (typically from exclusion config).
    /// Each IP gets a /32 host route via the physical gateway so it bypasses the TUN.
    /// Returns list of (ip, gw, if_index) that were successfully added, for later cleanup.
    pub fn add_bypass_routes(
        ips: &[Ipv4Addr],
        gw: Ipv4Addr,
        if_index: u32,
        metric: u32,
    ) -> Vec<(Ipv4Addr, Ipv4Addr, u32)> {
        let mut added = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mask = Ipv4Addr::new(255, 255, 255, 255);
        for &ip in ips {
            // The server IP is passed both as server_ip and inside bypass_ips, so
            // dedupe to avoid a guaranteed "already exists" failure on the second add.
            if !seen.insert(ip) {
                continue;
            }
            // Purge any pre-existing /32 for this dest (e.g. a stale route via an
            // old gateway from a previous session) so add_ipv4_route below installs
            // the correct one instead of failing with ERROR_OBJECT_ALREADY_EXISTS.
            delete_routes_for_dest(ip, mask);
            match add_ipv4_route(ip, mask, gw, if_index, metric) {
                Ok(()) => {
                    added.push((ip, gw, if_index));
                }
                Err(e) => {
                    tracing::warn!("bypass route add {ip}/32 via {gw} (if {if_index}) failed: {e}");
                }
            }
        }
        added
    }

    /// Remove all bypass routes previously added by add_bypass_routes.
    pub fn remove_bypass_routes(routes: &[(Ipv4Addr, Ipv4Addr, u32)]) {
        for &(ip, gw, if_index) in routes {
            let mask = Ipv4Addr::new(255, 255, 255, 255);
            let _ = delete_ipv4_route(ip, mask, gw, if_index);
        }
    }
}

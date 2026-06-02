#[cfg(target_os = "windows")]
pub fn get_process_name_from_port(port: u16) -> Option<String> {
    use winapi::shared::minwindef::{DWORD, ULONG};
    use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
    use winapi::um::iphlpapi::GetExtendedTcpTable;
    use winapi::shared::tcpmib::{MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID};

    let mut size: ULONG = 0;
    let table_class = 5; // TCP_TABLE_OWNER_PID_ALL
    let mut table = vec![0u8; 1024];

    unsafe {
        let mut ret = GetExtendedTcpTable(
            table.as_mut_ptr() as *mut _,
            &mut size,
            0,
            2, // AF_INET
            table_class,
            0,
        );

        if ret == ERROR_INSUFFICIENT_BUFFER {
            table.resize(size as usize, 0);
            ret = GetExtendedTcpTable(
                table.as_mut_ptr() as *mut _,
                &mut size,
                0,
                2, // AF_INET
                table_class,
                0,
            );
        }

        if ret == 0 {
            let tcp_table = &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let row_ptr = &tcp_table.table[0] as *const MIB_TCPROW_OWNER_PID;
            for i in 0..tcp_table.dwNumEntries {
                let row = &*row_ptr.add(i as usize);
                // Local port is in network byte order
                let local_port = u16::from_be(row.dwLocalPort as u16);
                if local_port == port {
                    return get_process_name_from_pid(row.dwOwningPid);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_process_name_from_pid(pid: u32) -> Option<String> {
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::GetModuleBaseNameW;
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use winapi::um::handleapi::CloseHandle;
    use std::os::windows::ffi::OsStringExt;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = [0u16; 1024];
        let len = GetModuleBaseNameW(handle, std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32);
        CloseHandle(handle);

        if len > 0 {
            let name = std::ffi::OsString::from_wide(&buffer[..len as usize]);
            return Some(name.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn get_process_name_from_port(port: u16) -> Option<String> {
    use std::fs;
    use std::io::{BufRead, BufReader};

    let mut target_inode = None;
    let hex_port = format!("{:04X}", port);

    let check_net_file = |path: &str| -> Option<u64> {
        let file = fs::File::open(path).ok()?;
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).filter_map(Result::ok) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let local_addr = parts[1];
                if local_addr.ends_with(&format!(":{}", hex_port)) {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        return Some(inode);
                    }
                }
            }
        }
        None
    };

    target_inode = check_net_file("/proc/net/tcp")
        .or_else(|| check_net_file("/proc/net/tcp6"))
        .or_else(|| check_net_file("/proc/net/udp"))
        .or_else(|| check_net_file("/proc/net/udp6"));

    let target_inode = target_inode?;
    let socket_str = format!("socket:[{}]", target_inode);

    for entry in fs::read_dir("/proc").ok()?.filter_map(Result::ok) {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        if !pid_str.chars().all(char::is_numeric) {
            continue;
        }

        let fd_dir = entry.path().join("fd");
        if let Ok(fd_entries) = fs::read_dir(fd_dir) {
            for fd_entry in fd_entries.filter_map(Result::ok) {
                if let Ok(target) = fs::read_link(fd_entry.path()) {
                    if target.to_string_lossy() == socket_str {
                        let exe_path = entry.path().join("exe");
                        if let Ok(exe_link) = fs::read_link(exe_path) {
                            if let Some(name) = exe_link.file_name() {
                                return Some(name.to_string_lossy().into_owned());
                            }
                        }
                        if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
                            return Some(comm.trim().to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn get_process_name_from_port(_port: u16) -> Option<String> {
    None
}

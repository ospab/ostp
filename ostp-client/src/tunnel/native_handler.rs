use anyhow::{anyhow, Result};
use tokio::sync::watch;

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub async fn run_native_tunnel(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    use std::net::ToSocketAddrs;
    use std::process::Command;
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use futures::{StreamExt, SinkExt};

    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;

    let debug = config.debug;
    tracing::info!("Initializing NATIVE TUN tunnel (smoltcp)...");

    let server_ip = config.ostp.server_addr.to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve remote server IP: {}", e))?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow!("Could not resolve host IP for routing exclusion"))?;
    
    let server_ip_str = server_ip.to_string();

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg.tun_name("ostp_tun")
           .address((10, 1, 0, 2))
           .netmask((255, 255, 255, 0))
           .destination((10, 1, 0, 1))
           .mtu(config.ostp.mtu as u16)
           .up();

    #[cfg(target_os = "linux")]
    tun_cfg.platform_config(|config| {
        config.packet_information(false);
    });

    let dev = tun::create(&tun_cfg)
        .map_err(|e| anyhow!("Failed to create TUN device: {}", e))?;
    let dev = tun::AsyncDevice::new(dev)
        .map_err(|e| anyhow!("Failed to make TUN device async: {}", e))?;

    tracing::info!("TUN device created natively.");

    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let current_exe = std::env::current_exe()?.to_string_lossy().into_owned();

        let setup_script = format!(
            "$remote_ip = '{}'\n\
            $exe_path = '{}'\n\
            $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -notmatch 'ostp' -and $_.InterfaceAlias -notmatch 'tun' -and $_.InterfaceAlias -notmatch 'wintun' }} | Sort-Object RouteMetric | Select-Object -First 1\n\
            if ($route) {{\n\
                $gw = $route.NextHop\n\
                $ifIndex = $route.InterfaceIndex\n\
                if ($gw -eq '0.0.0.0' -or $gw -eq '::') {{\n\
                    New-NetRoute -DestinationPrefix \"$remote_ip/32\" -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
                }} else {{\n\
                    New-NetRoute -DestinationPrefix \"$remote_ip/32\" -NextHop $gw -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
                }}\n\
                if ($gw -ne '0.0.0.0') {{\n\
                    New-NetRoute -DestinationPrefix \"$gw/32\" -NextHop '0.0.0.0' -InterfaceIndex $ifIndex -RouteMetric 1 -ErrorAction SilentlyContinue\n\
                }}\n\
            }}\n\
            New-NetFirewallRule -DisplayName 'OSTP Tunnel In' -Direction Inbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n\
            New-NetFirewallRule -DisplayName 'OSTP Tunnel Out' -Direction Outbound -Program $exe_path -Action Allow -Enabled True -ErrorAction SilentlyContinue\n\
            netsh interface ipv4 set interface name=\"ostp_tun\" metric=1\n\
            New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'ostp_tun' -NextHop '10.1.0.1' -RouteMetric 1 -ErrorAction SilentlyContinue\n",
            server_ip_str, current_exe
        );
        let _ = tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", &setup_script])
                .output()
        }).await.unwrap()?;
        
        if let Some(ref dns) = config.dns_server {
            if !dns.is_empty() {
                let net_setup = format!("netsh interface ipv4 set dnsservers name=\"ostp_tun\" static {} primary\n", dns);
                let _ = tokio::task::spawn_blocking(move || {
                    Command::new("powershell")
                        .creation_flags(CREATE_NO_WINDOW)
                        .args(["-NoProfile", "-Command", &net_setup])
                        .output()
                }).await.unwrap()?;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Get real gateway before routing through TUN
        let gw_out = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok());
        
        let real_gw = gw_out.as_deref().and_then(|s| {
            // "default via 192.168.1.1 dev eth0" -> "192.168.1.1"
            s.split_whitespace().skip_while(|w| *w != "via").nth(1).map(|s| s.to_string())
        });
        let real_dev = gw_out.as_deref().and_then(|s| {
            s.split_whitespace().skip_while(|w| *w != "dev").nth(1).map(|s| s.to_string())
        });

        // Add exclusion route for server IP via real gateway (bypass TUN)
        if let (Some(ref gw), Some(ref dev)) = (&real_gw, &real_dev) {
            let _ = Command::new("ip").args(["route", "add", &format!("{}/32", server_ip_str), "via", gw, "dev", dev]).output();
        }

        // Add default route through TUN (lower metric to take priority)
        let _ = Command::new("ip").args(["route", "add", "default", "via", "10.1.0.1", "dev", "ostp_tun", "metric", "10"]).output();
    }

    let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(config.ostp.mtu)
        .build()?;

    let mut runner_task = tokio::spawn(async move {
        if let Some(runner) = tcp_runner {
            let _ = runner.await;
        }
    });

    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut tun_read, mut tun_write) = tokio::io::split(dev);

    let mut tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let frame = buf[..n].to_vec();
                    if stack_sink.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut stack_to_tun = tokio::spawn(async move {
        while let Some(Ok(frame)) = stack_stream.next().await {
            if tun_write.write_all(frame.as_slice()).await.is_err() {
                break;
            }
        }
    });

    let udp_proxy_addr = config.local_proxy.bind_addr.clone();
    let debug_udp = config.debug;
    let mut udp_proxy_task = tokio::spawn(async move {
        if let Some(udp_sock) = udp_socket {
            let (mut rx, tx) = udp_sock.split();
            let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));
            while let Some((payload, src, dst)) = rx.next().await {
                if payload.is_empty() { continue; }
                if dst.port() == 53 {
                    let tx_clone = tx.clone();
                    let proxy_addr = udp_proxy_addr.clone();
                    tokio::spawn(async move {
                        if debug_udp { tracing::info!("Native TUN intercepted UDP DNS to {}", dst); }
                        if let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await {
                            if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                            let mut buf = [0u8; 2];
                            if socks.read_exact(&mut buf).await.is_err() || buf[0] != 5 || buf[1] != 0 { return; }
                            
                            let mut req = vec![5, 1, 0];
                            match dst.ip() {
                                std::net::IpAddr::V4(v4) => { req.push(1); req.extend_from_slice(&v4.octets()); }
                                std::net::IpAddr::V6(v6) => { req.push(4); req.extend_from_slice(&v6.octets()); }
                            }
                            req.extend_from_slice(&dst.port().to_be_bytes());
                            if socks.write_all(&req).await.is_err() { return; }
                            
                            let mut rep = [0u8; 10];
                            if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }

                            let len = payload.len() as u16;
                            let mut dns_req = Vec::with_capacity(2 + payload.len());
                            dns_req.extend_from_slice(&len.to_be_bytes());
                            dns_req.extend_from_slice(&payload);

                            if socks.write_all(&dns_req).await.is_ok() {
                                let mut len_buf = [0u8; 2];
                                if socks.read_exact(&mut len_buf).await.is_ok() {
                                    let resp_len = u16::from_be_bytes(len_buf) as usize;
                                    let mut response_buf = vec![0u8; resp_len];
                                    if socks.read_exact(&mut response_buf).await.is_ok() {
                                        let _ = tx_clone.lock().await.send((response_buf, dst, src)).await;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    let proxy_addr = config.local_proxy.bind_addr.clone();
    let mut tcp_accept_task = tokio::spawn(async move {
        if let Some(mut listener) = tcp_listener {
            while let Some((mut stream, _local, remote)) = listener.next().await {
                let proxy_addr = proxy_addr.clone();
                tokio::spawn(async move {
                    if debug { tracing::info!("Native TUN intercepted TCP to {}", remote); }
                    if let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await {
                        // SOCKS5 bypass handshake locally (loopback)
                        if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                        let mut buf = [0u8; 2];
                        if socks.read_exact(&mut buf).await.is_err() || buf[0] != 5 || buf[1] != 0 { return; }
                        
                        let ip = remote.ip();
                        let port = remote.port();
                        let mut req = vec![5, 1, 0];
                        match ip {
                            std::net::IpAddr::V4(v4) => {
                                req.push(1);
                                req.extend_from_slice(&v4.octets());
                            }
                            std::net::IpAddr::V6(v6) => {
                                req.push(4);
                                req.extend_from_slice(&v6.octets());
                            }
                        }
                        req.extend_from_slice(&port.to_be_bytes());
                        if socks.write_all(&req).await.is_err() { return; }
                        
                        let mut rep = [0u8; 10];
                        if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }

                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut socks).await;
                    }
                });
            }
        }
    });

    tracing::info!("NATIVE TUN tunnel active.");

    tokio::select! {
        _ = shutdown.changed() => {}
        _ = &mut runner_task => {}
        _ = &mut tun_to_stack => {}
        _ = &mut stack_to_tun => {}
        _ = &mut udp_proxy_task => {}
        _ = &mut tcp_accept_task => {}
    }

    tracing::info!("Deactivating NATIVE TUN tunnel...");
    // Cleanup routes
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let cleanup_script = format!(
            "$remote_ip = '{}'\n\
             Remove-NetRoute -DestinationPrefix \"$remote_ip/32\" -Confirm:$false -ErrorAction SilentlyContinue\n\
             Remove-NetFirewallRule -DisplayName 'OSTP Tunnel*' -ErrorAction SilentlyContinue\n\
             netsh interface ipv4 set dnsservers name=\"ostp_tun\" source=dhcp 2>$null\n",
            server_ip_str
        );
        let _ = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-Command", &cleanup_script])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        // Remove default route via TUN and server exclusion route
        let _ = Command::new("ip").args(["route", "del", "default", "dev", "ostp_tun"]).output();
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", server_ip_str)]).output();
    }

    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub async fn run_native_tunnel(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
) -> Result<()> {
    Err(anyhow!("Native TUN tunnel is only supported on Windows/Linux currently"))
}

#[cfg(target_os = "android")]
pub async fn run_native_tunnel_from_fd(
    config: crate::config::ClientConfig,
    mut shutdown: watch::Receiver<bool>,
    fd: i32,
) -> Result<()> {
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use futures::{StreamExt, SinkExt};
    use std::os::unix::io::{FromRawFd, AsRawFd};

    let debug = config.debug;
    tracing::info!("Initializing NATIVE TUN tunnel on Android (FD {})", fd);

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let tun_stream = tokio::io::unix::AsyncFd::new(file)?;

    let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(config.ostp.mtu)
        .build()?;

    let mut runner_task = tokio::spawn(async move {
        if let Some(mut runner) = tcp_runner {
            let _ = runner.await;
        }
    });

    let (mut stack_sink, mut stack_stream) = stack.split();

    let mut tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let mut guard = match tun_stream.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            let n = match guard.try_io(|inner| {
                let res = unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        Err(err)
                    } else {
                        Ok(res) // Return error as success to break gracefully
                    }
                } else {
                    Ok(res)
                }
            }) {
                Ok(Ok(n)) if n > 0 => n as usize,
                Ok(Ok(_)) => break, // EOF or Error
                Ok(Err(_)) => continue, // Should not happen with try_io
                Err(_would_block) => continue,
            };

            let frame = buf[..n].to_vec();
            if stack_sink.send(frame).await.is_err() {
                break;
            }
        }
    });

    let write_fd = unsafe { libc::dup(fd) };
    if write_fd < 0 {
        return Err(anyhow!("Failed to dup tun fd"));
    }
    unsafe {
        let flags = libc::fcntl(write_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
    let tun_write_stream = tokio::io::unix::AsyncFd::new(write_file)?;

    let mut stack_to_tun = tokio::spawn(async move {
        while let Some(Ok(frame)) = stack_stream.next().await {
            let mut written = 0;
            while written < frame.len() {
                let mut guard = match tun_write_stream.writable().await {
                    Ok(g) => g,
                    Err(_) => break,
                };
                
                let res = guard.try_io(|inner| {
                    let res = unsafe { libc::write(inner.as_raw_fd(), frame[written..].as_ptr() as *const libc::c_void, frame.len() - written) };
                    if res < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            Err(err)
                        } else {
                            Ok(res)
                        }
                    } else {
                        Ok(res)
                    }
                });

                match res {
                    Ok(Ok(n)) if n > 0 => written += n as usize,
                    Ok(Ok(_)) => break,
                    Ok(Err(_)) => continue,
                    Err(_) => continue,
                }
            }
        }
    });

    let udp_proxy_addr = config.local_proxy.bind_addr.clone();
    let debug_udp = config.debug;
    let mut udp_proxy_task = tokio::spawn(async move {
        if let Some(udp_sock) = udp_socket {
            let (mut rx, tx) = udp_sock.split();
            let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));
            while let Some((payload, src, dst)) = rx.next().await {
                if payload.is_empty() { continue; }
                if dst.port() == 53 {
                    let tx_clone = tx.clone();
                    let proxy_addr = udp_proxy_addr.clone();
                    tokio::spawn(async move {
                        if debug_udp { tracing::info!("Native TUN intercepted UDP DNS to {}", dst); }
                        if let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await {
                            if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                            let mut buf = [0u8; 2];
                            if socks.read_exact(&mut buf).await.is_err() || buf[0] != 5 || buf[1] != 0 { return; }
                            
                            let mut req = vec![5, 1, 0];
                            match dst.ip() {
                                std::net::IpAddr::V4(v4) => { req.push(1); req.extend_from_slice(&v4.octets()); }
                                std::net::IpAddr::V6(v6) => { req.push(4); req.extend_from_slice(&v6.octets()); }
                            }
                            req.extend_from_slice(&dst.port().to_be_bytes());
                            if socks.write_all(&req).await.is_err() { return; }
                            
                            let mut rep = [0u8; 10];
                            if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }

                            let len = payload.len() as u16;
                            let mut dns_req = Vec::with_capacity(2 + payload.len());
                            dns_req.extend_from_slice(&len.to_be_bytes());
                            dns_req.extend_from_slice(&payload);

                            if socks.write_all(&dns_req).await.is_ok() {
                                let mut len_buf = [0u8; 2];
                                if socks.read_exact(&mut len_buf).await.is_ok() {
                                    let resp_len = u16::from_be_bytes(len_buf) as usize;
                                    let mut response_buf = vec![0u8; resp_len];
                                    if socks.read_exact(&mut response_buf).await.is_ok() {
                                        let _ = tx_clone.lock().await.send((response_buf, dst, src)).await;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    let proxy_addr = config.local_proxy.bind_addr.clone();
    let mut tcp_accept_task = tokio::spawn(async move {
        if let Some(mut listener) = tcp_listener {
            while let Some((mut stream, _local, remote)) = listener.next().await {
                let proxy_addr = proxy_addr.clone();
                tokio::spawn(async move {
                    if debug { tracing::info!("Native TUN intercepted TCP to {}", remote); }
                    if let Ok(mut socks) = tokio::net::TcpStream::connect(&proxy_addr).await {
                        if socks.write_all(&[5, 1, 0]).await.is_err() { return; }
                        let mut buf = [0u8; 2];
                        if socks.read_exact(&mut buf).await.is_err() || buf[0] != 5 || buf[1] != 0 { return; }
                        
                        let ip = remote.ip();
                        let port = remote.port();
                        let mut req = vec![5, 1, 0];
                        match ip {
                            std::net::IpAddr::V4(v4) => {
                                req.push(1);
                                req.extend_from_slice(&v4.octets());
                            }
                            std::net::IpAddr::V6(v6) => {
                                req.push(4);
                                req.extend_from_slice(&v6.octets());
                            }
                        }
                        req.extend_from_slice(&port.to_be_bytes());
                        if socks.write_all(&req).await.is_err() { return; }
                        
                        let mut rep = [0u8; 10];
                        if socks.read_exact(&mut rep).await.is_err() || rep[1] != 0 { return; }

                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut socks).await;
                    }
                });
            }
        }
    });

    tracing::info!("NATIVE TUN (Android) tunnel active.");

    tokio::select! {
        _ = shutdown.changed() => {}
        _ = &mut runner_task => {}
        _ = &mut tun_to_stack => {}
        _ = &mut stack_to_tun => {}
        _ = &mut udp_proxy_task => {}
        _ = &mut tcp_accept_task => {}
    }

    tracing::info!("Deactivating NATIVE TUN tunnel...");
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub async fn run_native_tunnel_from_fd(
    _config: crate::config::ClientConfig,
    _shutdown: watch::Receiver<bool>,
    _fd: i32,
) -> Result<()> {
    Err(anyhow!("Native TUN from FD is only supported on Android"))
}

